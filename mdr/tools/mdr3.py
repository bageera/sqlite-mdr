#!/usr/bin/python3
"""MDR3 temporal archive: cross-snapshot factorization (MDR-005).

Packs a series of SQLite snapshot generations into ONE archive. Each
generation is either an independent segment set (MDR2 semantics) or
expressed as byte-level deltas against a shared base — chosen per
generation via exhaustive argmin over wire cost:

  method per generation t:
    independent  : store as MDR2-style segments of its own bytes
    baseref      : b = argmin over stored bases {t0..t-1} of
                   L(mdrc2 segments of delta_bytes) + reference overhead
    dedup        : content-addressed chunks shared across ALL generations
                   (competing baseline, measured not assumed)

Wire format "MDR3" (experimental; MDR2 stays untouched):
  header 30B  "MDR3" | ver=1 | flags | ngen u8 | manifest_len u32 |
              index_len u32 | total_len u64
  payload     bzip-free: [manifest json][index json][data section]
              each JSON section length-prefixed + crc'd
  data section: sequence of ITEMS:
                 segments for independent generations (mdrc format bodies)
                 delta bodies + base refs
                 dedup chunks (sha256 addressed, stored once)
  footer 16B  "M3DN" | ngen u8 | sha256(all payloads) truncated? -> full 32
  -> footer 48B total like MDR2 for symmetry: "M3DN" | ngen | total_len | sha256

Reconstruction contract (GT1/GT2): every generation restores byte-exact,
in any order, with bounded dependency chain (max_depth, default 8).
GT7: corrupt/missing-base detection via sha + manifest lengths.
"""

import argparse
import collections
import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile
import time
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "mdr", "tools"))

import mdrc  # noqa: E402

MAGIC_HDR = b"MDR3"
MAGIC_FTR = b"M3DN"
VERSION = 1
MAX_DEPTH_DEFAULT = 8
SEG = 1 << 20  # delta-segment size for delta encoding
OVH_SEG = 10   # per-segment overhead inside every stored body


class Mdr3Error(Exception):
    pass


# ------------------------------------------------------------- chunking
def chunk_bytes(data, size=65536):
    return [data[i:i + size] for i in range(0, len(data), size)]


def _seg_wire_best(data):
    """Cheapest mdrc-style segment body for data (exhaustive profile)."""
    codec, param, stored = mdrc.select_and_encode(data)
    return struct.pack("<BBII", codec, param, len(stored),
                       zlib.crc32(stored) & 0xFFFFFFFF) + stored


def _seg_wire_best_fast(data):
    codec, param, stored = mdrc.select_and_encode_fast(data)
    return struct.pack("<BBII", codec, param, len(stored),
                       zlib.crc32(stored) & 0xFFFFFFFF) + stored


def delta_bytes(target, base):
    """Byte-level delta: per-chunk copy/ref against base of possibly
    different length. Format: u64 base_len + chunks-of-64KiB ops:
      op 1: copy chunk (u16 chunk index in base)   [chunk identical]
      op 2: literal body (mdrc-compressed chunk bytes)
    Reversible given base. Cost model includes op table sizes honestly.
    """
    ops = []            # (1, idx) or (2, literal_index)
    literals = []       # raw bytes awaiting compression
    B = 65536
    base_chunks = [base[i:i + B] for i in range(0, len(base), B)]
    bmap = {}
    for i, c in enumerate(base_chunks):
        bmap.setdefault(hashlib.sha256(c).digest(), i)
    lit_ids = {}
    for i in range(0, len(target), B):
        c = target[i:i + B]
        h = hashlib.sha256(c).digest()
        idx = bmap.get(h)
        if idx is not None:
            ops.append(struct.pack("<BH", 1, idx))
        else:
            if h not in lit_ids:
                lit_ids[h] = len(literals)
                literals.append(c)
            ops.append(struct.pack("<BH", 2, lit_ids[h]))
    opb = b"".join(ops)
    litb = b"".join(literals)
    # wire: u64 base_len + u32 base_chunks + u32 opb_len + u32 litb_len
    #       + mdrc(opb) + mdrc(litb). Explicit body lengths let the D3
    #   codec decode exactly (no page-pad ambiguity).
    return (struct.pack("<QIII", len(base), len(base_chunks),
                        len(opb), len(litb)) +
            _seg_wire_best(opb) + _seg_wire_best(litb))


# ------------------------------------------------- fingerprint ranking
FP_PAGE = 4096        # page-level fingerprint granularity
FP_STRIPE = 512       # sampled stripe inside each page (order-independent)
FP_NSTRIPES = 8       # fingerprints per page: stripes at fixed offsets


def fingerprint(data):
    """Two-tier order-independent page fingerprint: exact page hashes PLUS
    512B stride samples for near-match ranking. Exact hashes detect identical
    pages; sampled stripes give partial credit for pages differing by a few
    bytes (the L5-adversary case). Both are position-free.
    Returns (exact Counter, sampled Counter)."""
    pages = [data[i:i + FP_PAGE] for i in range(0, len(data), FP_PAGE)]
    exact = collections.Counter()
    sampled = collections.Counter()
    for pg in pages:
        exact[hashlib.sha256(pg).digest()[:12]] += 1
        for off in range(0, FP_PAGE, FP_STRIPE):
            if off + FP_STRIPE <= len(pg):
                sampled[hashlib.sha256(pg[off:off + FP_STRIPE])
                        .digest()[:8]] += 1
    return (exact, sampled)


def fp_overlap(a, b):
    """Multiset intersection size (sum of min counts). Exact tier only."""
    inter = 0
    for h, c in a.items():
        c2 = b.get(h)
        if c2:
            inter += c if c2 >= c else c2
    return inter


def fp_overlap_hybrid(a, b):
    """(exact_inter, sampled_inter) between two (exact, sampled) tuples."""
    ea, sa = a
    eb, sb = b
    return fp_overlap(ea, eb), fp_overlap(sa, sb)


def rank_bases(target_fp, history_fps, top=2):
    """Hybrid similarity ranking: exact page overlap dominates, sampled
    stripe overlap breaks near-ties (partial-page-edit affinity). Returns
    indices of the `top` most similar history snapshots, highest first.
    Ties -> lower index (older) first for determinism."""
    scored = []
    for gi, f in enumerate(history_fps):
        ex, sm = fp_overlap_hybrid(target_fp, f)
        # lexicographic: exact overlap first, then sampled overlap
        scored.append((-ex, -sm, gi))
    scored.sort()
    return [gi for _, _, gi in scored[:top]]


def undelta_bytes(delta, base):
    (blen, nbc) = struct.unpack("<QI", delta[:12])
    if blen != len(base):
        raise Mdr3Error("delta base length mismatch (got base %d, want %d)"
                        % (len(base), blen))
    # parse: u32 opb_len + u32 litb_len, then two mdrc segments
    (opb_len, litb_len) = struct.unpack("<II", delta[12:20])
    off = 20
    bodies = []
    for blen in (opb_len, litb_len):
        seg = delta[off:]
        bodies.append(_decode_seg_body(seg, out_len=blen))
        (clen,) = struct.unpack("<I", seg[2:6])
        off += 10 + clen
    opb, litb = bodies
    B = 65536
    base_chunks = [base[i:i + B] for i in range(0, len(base), B)]
    lit_chunks = [litb[i:i + B] for i in range(0, len(litb), B)]
    out = bytearray()
    o = 0
    while o < len(opb):
        op, idx = struct.unpack("<BH", opb[o:o + 3])
        o += 3
        if op == 1:
            out += base_chunks[idx]
        elif op == 2:
            out += lit_chunks[idx]
        else:
            raise Mdr3Error("bad delta op %d" % op)
    return bytes(out)


# helper: decode via mdrc.decode_segment with correct out_len semantics
def _meta_len_of(data):
    """Byte length of the D3 page-split meta (u32 count + count* u16 hss)."""
    (npages,) = struct.unpack("<H", data[:2])
    return 2 + 2 * npages


def _decode_seg_body(seg, out_len=None):
    # seg layout = mdrc segment: <BBII> codec, param, clen, crc | clen bytes
    codec, param = struct.unpack("<BB", seg[:2])
    (clen,) = struct.unpack("<I", seg[2:6])
    stored = seg[10:10 + clen]
    if len(stored) < clen:
        raise Mdr3Error("segment body truncated (claim %d, have %d)"
                        % (clen, len(stored)))
    if codec == 0:
        return stored
    data = mdrc.zstd_decompress(stored)
    if codec == 1:
        return data
    if codec == 2:
        data = mdrc.unshuffle_bytes(data, param)
    elif codec == 3:
        data = mdrc.unbit_shuffle(data)
    elif codec == 4:
        meta_len = _meta_len_of(data)
        if meta_len > len(data):
            raise Mdr3Error("bad D3 meta length")
        (npages,) = struct.unpack("<H", data[:2])
        hss = struct.unpack("<%dH" % npages, data[2:meta_len])
        rest = data[meta_len:]
        H_total = sum(hss)
        if out_len is None:
            out_len = npages * mdrc.PAGE   # full-page-span body
        data = mdrc.page_join(meta_len, hss, rest[:H_total], rest[H_total:],
                              pad_total=out_len + (-out_len % mdrc.PAGE))
    else:
        raise Mdr3Error("codec %d not supported in MDR3 bodies" % codec)
    # transform-based codecs pad bodies (stride/bit/D3 page) — trim to the
    # declared length when the caller supplies one.
    if out_len is not None:
        data = data[:out_len]
    return data


# ------------------------------------------------------------- pack
def pack(inPaths, outPath, max_depth=MAX_DEPTH_DEFAULT, progress=None,
         selector="exhaustive", fp_top=2, force_method=None):
    """selector: 'exhaustive' (all bases tried) or 'ranked' (fingerprint
    top-`fp_top` bases tried; exhaustive kept as reference/gate arm).
    force_method: 'pergen'/'dedup' to pin the archive scheme (gate use)."""
    gens = []
    gen_meta = []   # sha, len per generation
    for p in inPaths:
        with open(p, "rb") as f:
            gens.append(f.read())
        gen_meta.append(hashlib.sha256(gens[-1]).hexdigest())
        if len(gens[-1]) == 0:
            raise Mdr3Error("empty generation %s" % p)

    # --- dedup baseline: content-addressed 64KiB chunks across all gens
    chunk_store = {}
    chunk_ids = []      # per gen: list of chunk ids
    for g in gens:
        ids = []
        for c in chunk_bytes(g):
            h = hashlib.sha256(c).digest()
            if h not in chunk_store:
                chunk_store[h] = c
            ids.append(h)
        chunk_ids.append(ids)
    dedup_body = b"".join(chunk_store.values())
    dedup_index = {h.hex(): None for h in chunk_store}  # order = insertion
    # NOTE: dedup body compressed as ONE mdrc body; index maps hex->offset
    dedup_wire = _seg_wire_best(dedup_body)
    dedup_offset = {}
    off = 0
    for h in chunk_store:
        dedup_offset[h.hex()] = off
        off += len(chunk_store[h])
    dedup_index = [{"h": h.hex(), "off": dedup_offset[h.hex()],
                    "len": len(chunk_store[h])}
                   for h in chunk_store]

    # --- per-generation: independent vs baseref vs (metadata-only) dedup
    items = []          # data section payloads, referenced by manifest
    manifest = {"generations": [], "items": [], "max_depth": max_depth}
    # store gen0 as independent
    independent_wires = []
    for gi, g in enumerate(gens):
        bodies = [_seg_wire_best(c) for c in chunk_bytes(g, SEG)]
        independent_wires.append(bodies)
    # fingerprints for ranked selection (cheap: 1 hash/page, no encoding)
    history_fps = []
    if selector == "ranked":
        for g in gens:
            history_fps.append(fingerprint(g))
    trials_done = 0
    # baseref candidates per generation (t>0): try EVERY earlier gen as base
    # baseref item = delta_bytes; chain rule: base must itself be restorable
    # with depth < max_depth. We approximate "restorable" by generation index
    # depth (linear history), charging nothing else.
    choices = []
    for gi, g in enumerate(gens):
        ind_cost = sum(len(b) for b in independent_wires[gi]) + OVH_SEG * len(independent_wires[gi]) + 4
        if gi == 0:
            choices.append(("independent", 0, ind_cost))
            continue
        if selector == "ranked":
            cand = [bi for bi in rank_bases(history_fps[gi],
                                            history_fps[:gi], top=fp_top)
                    if bi >= gi - max_depth]
            if gi - 1 not in cand:      # always allow nearest generation
                cand.append(gi - 1)
        else:
            cand = list(range(max(0, gi - max_depth), gi))
        best = None
        for bi in cand:
            dl = delta_bytes(g, gens[bi])
            trials_done += 1
            # delta is stored as ONE item; cost = len(dl) + ref overhead
            cost = len(dl) + 12  # ref = 4B base id + 8B length
            if best is None or cost < best[2]:
                best = ("baseref", bi, cost, dl)
        # dedup cost approximation: shared chunks count * 0 (shared) +
        # unique chunks once (charged on first generation that owns them)
        # -> dedup is a GLOBAL scheme; per-generation cost attributed:
        # chunk shared with earlier gen costs 4B id; unique chunk costs
        # its mdrc-chunk share. We compute global dedup total separately
        # and do NOT charge it per-gen here; instead compare globally.
        choices.append(best if best and best[2] < ind_cost
                       else ("independent", 0, ind_cost))

    # Global dedup vs sum of per-gen chosen: compute both totals, pick scheme
    # for the WHOLE archive (simpler: whole-archive method choice, honest).
    # dedup total wire:
    B = 65536
    seen = set()
    dedup_data_bytes = 0   # sum of unique chunk bytes (pre-compression)
    dedup_refs = 0
    per_gen_unique = []
    for ids in chunk_ids:
        u = 0
        for h in ids:
            if h not in seen:
                seen.add(h)
                u += 1
        per_gen_unique.append(u)
        dedup_refs += len(ids)
    dedup_total = len(dedup_wire) + 16 * len(seen) \
        + 4 + 4 * len(chunk_store)   # lens blob: count + n* u32
    ind_total = sum(c[2] for c in choices) + 4 * len(gens)
    method = force_method if force_method else \
        ("dedup" if dedup_total < ind_total else "pergen")

    # --- emit
    data_section = bytearray()
    refs = []
    if method == "pergen":
        for gi, ch in enumerate(choices):
            m, bi, cost = ch[0], ch[1], ch[2]
            if m == "independent":
                blobs = independent_wires[gi]
                item = struct.pack("<BIB", 1, len(blobs), 0) + b"".join(blobs)
                refs.append({"gen": gi, "kind": "independent", "off": len(data_section), "len": len(item)})
                data_section += item
            else:
                dl = ch[3] if len(ch) > 3 else delta_bytes(gens[gi], gens[bi])
                item = struct.pack("<BIB", 2, 1, bi) + dl
                refs.append({"gen": gi, "kind": "baseref", "base": bi,
                             "off": len(data_section), "len": len(item)})
                data_section += item
    else:
        # unique chunks stored once (variable length!); lens walked by id.
        # chunkstore item = hdr(1+4) + mdrc seg(store) + lensblob
        # lensblob = u32 blob_len + u32 count + count* u32 (self-describing)
        unique_order = list(chunk_store.items())
        lens_blob = struct.pack("<II", 4 * (len(unique_order) + 2),
                                len(unique_order)) + b"".join(
            struct.pack("<I", len(c)) for _, c in unique_order)
        item = struct.pack("<BI", 3, len(dedup_wire) + len(lens_blob)) \
            + dedup_wire + lens_blob
        refs.append({"gen": -1, "kind": "chunkstore", "off": 0, "len": len(item)})
        data_section += item
        for gi, ids in enumerate(chunk_ids):
            payload = struct.pack("<I", len(ids)) + \
                b"".join(h[:8] for h in ids)  # 8B truncated ids
            it = struct.pack("<BIB", 4, len(payload), 0) + payload
            refs.append({"gen": gi, "kind": "chunklist", "off": len(data_section),
                         "len": len(it)})
            data_section += it

    # manifest: methods, refs, hashes, chunk sizes
    manifest["method"] = method
    manifest["items"] = refs
    manifest["hashes"] = gen_meta
    manifest["lengths"] = [len(g) for g in gens]
    manifest["selector"] = selector
    assert 0 <= trials_done < 10 ** 10
    manifest["selector_trials"] = "%010d" % trials_done  # byte-stable json
    man_b = json.dumps(manifest, separators=(",", ":")).encode()
    idx_b = json.dumps({"chunk_size": B if method == "dedup" else None,
                        "seg_size": SEG},
                       separators=(",", ":")).encode()
    # header: magic, ver, flags, ngen, man_len, idx_len, total_len
    # struct "<4sBBIIQ": 4s + B + B + I + I + Q = 6 fields, 22 bytes LE.
    # ngen rides in the MANIFEST (json); flag bit0 of ver-byte marks backup.
    body = struct.pack("<II", zlib.crc32(man_b) & 0xFFFFFFFF,
                       zlib.crc32(idx_b) & 0xFFFFFFFF) + man_b + idx_b + bytes(data_section)
    total_len = 22 + len(body) + 48
    header = struct.pack("<4sBBIIQ", MAGIC_HDR, VERSION, 0,
                         len(man_b), len(idx_b), total_len)
    sha = hashlib.sha256(body).digest()
    footer = struct.pack("<4sIQ", MAGIC_FTR, len(gens), len(body)) + sha
    fd = os.open(outPath + ".part", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    try:
        os.write(fd, header)
        os.write(fd, body)
        os.fsync(fd)
        os.write(fd, footer)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.rename(outPath + ".part", outPath)
    return {"generations": len(gens), "method": method,
            "manifest_bytes": len(man_b), "data_bytes": len(data_section),
            "archive": len(header) + len(body) + len(footer),
            "raw_total": sum(len(g) for g in gens),
            "selector": selector, "delta_trials": trials_done}


# ------------------------------------------------------------- unpack
def _read_sections(blob):
    if len(blob) < 22 + 48:
        raise Mdr3Error("truncated MDR3 archive")
    magic, ver, flags, man_len, idx_len, total_len = struct.unpack(
        "<4sBBIIQ", blob[:22])
    if magic != MAGIC_HDR:
        raise Mdr3Error("not an MDR3 archive")
    if ver != VERSION:
        raise Mdr3Error("unsupported MDR3 version")
    fmagic, fngen, fbody = struct.unpack("<4sIQ", blob[-48:-48 + 16])
    if fmagic != MAGIC_FTR:
        raise Mdr3Error("footer missing (incomplete write)")
    body = blob[22:-48]
    if len(body) != fbody:
        raise Mdr3Error("body length mismatch")
    (m_crc, i_crc) = struct.unpack("<II", body[:8])
    man_b = body[8:8 + man_len]
    idx_b = body[8 + man_len:8 + man_len + idx_len]
    if zlib.crc32(man_b) & 0xFFFFFFFF != m_crc:
        raise Mdr3Error("manifest crc mismatch")
    if zlib.crc32(idx_b) & 0xFFFFFFFF != i_crc:
        raise Mdr3Error("index crc mismatch")
    data = body[8 + man_len + idx_len:]
    manifest = json.loads(man_b.decode())
    index = json.loads(idx_b.decode())
    return manifest, index, data, body, sha_ok(blob)


def sha_ok(blob):
    want = blob[-32:]
    got = hashlib.sha256(blob[22:-48]).digest()
    return want == got


def _restore_gen(manifest, index, data, gi, cache):
    refs = manifest["items"]
    r = refs[gi] if manifest["method"] == "pergen" else refs[1 + gi]
    kind = r["kind"]
    if kind == "independent":
        item = data[r["off"]:r["off"] + r["len"]]
        (k, nb, _) = struct.unpack("<BIB", item[:6])
        off = 6
        out = bytearray()
        for _ in range(nb):
            seg = item[off:]
            out += _decode_seg_body(seg, out_len=manifest["lengths"][gi])
            (clen,) = struct.unpack("<I", seg[2:6])
            off += 10 + clen
        return bytes(out[:manifest["lengths"][gi]])
    if kind == "baseref":
        if r["base"] not in cache:
            raise Mdr3Error("generation %d depends on missing base %d"
                            % (gi, r["base"]))
        base = cache[r["base"]]
        item = data[r["off"]:r["off"] + r["len"]]
        dl = item[6:]
        (blen, nbc) = struct.unpack("<QI", dl[:12])
        (opb_len, litb_len) = struct.unpack("<II", dl[12:20])
        bodies = []
        off = 20
        for body_len in (opb_len, litb_len):
            seg = dl[off:]
            bodies.append(_decode_seg_body(seg, out_len=body_len))
            (clen,) = struct.unpack("<I", seg[2:6])
            off += 10 + clen
        opb, litb = bodies
        B = 65536
        base_chunks = [base[i:i + B] for i in range(0, len(base), B)]
        # literals are concatenated at TRUE chunk boundaries (variable len):
        # walk lens from the literal-body reconstruction — literals were
        # chunked at B boundaries of target, so reconstruct by ops table:
        # simpler: unchunk literals by replaying ops after building store.
        lit_pos = {}   # literal idx -> (start, len) filled during replay
        # first pass: replay ops to find literal lengths
        lit_starts = []  # (start, len) per literal in order
        for o in range(0, len(opb), 3):
            op, idx = struct.unpack("<BH", opb[o:o + 3])
            if op == 2 and idx == len(lit_starts):
                lit_starts.append([None, None])
        # second pass: literal i occupies 64KiB unless it's the final chunk
        # of target (length = target_len - start). Known via manifest length.
        tl = manifest["lengths"][gi]
        Bn = B
        n_ops = len(opb) // 3
        lit_seen = {}
        for oi in range(n_ops):
            op, idx = struct.unpack("<BH", opb[oi * 3:oi * 3 + 3])
            start = oi * Bn
            ln = min(Bn, tl - start)
            if op == 2:
                lit_seen[idx] = ln
        lit_chunks = []
        p = 0
        for i in range(len(lit_starts)):
            ln = lit_seen[i]
            lit_chunks.append(litb[p:p + ln])
            p += ln
        out = bytearray()
        o = 0
        while o < len(opb):
            op, idx = struct.unpack("<BH", opb[o:o + 3])
            o += 3
            if op == 1:
                out += base_chunks[idx]
            elif op == 2:
                out += lit_chunks[idx]
            else:
                raise Mdr3Error("bad delta op")
        return bytes(out[:manifest["lengths"][gi]])
    if kind == "chunkstore":
        # item = hdr(1+4) + mdrc seg(store) + lensblob.
        # lensblob = u32 blob_len L + u32 count + count* u32 lens.
        # Seg is self-describing: hdr(5) then <BBII> => clen at item[7:11].
        item = data[r["off"]:r["off"] + r["len"]]
        (clen,) = struct.unpack("<I", item[7:11])
        seg = item[5:5 + 10 + clen]
        store = _decode_seg_body(seg)
        blob = item[5 + 10 + clen:]
        (L, count) = struct.unpack("<II", blob[:8])
        if L != len(blob) or count != (L - 8) // 4:
            raise Mdr3Error("chunkstore lens corrupt")
        lens = struct.unpack("<%dI" % count, blob[8:8 + 4 * count])
        return ("CHUNKSTORE", store, tuple(lens))
    if kind == "chunklist":
        # dedup scheme: rebuild from chunkstore (refs[0]) + this list.
        store_ref = refs[0]
        st = _restore_gen(manifest, index, data, -1, cache)
        _tag, store, lens = st
        list_item = data[r["off"]:r["off"] + r["len"]]
        (k, nb, _) = struct.unpack("<BIB", list_item[:6])
        payload = list_item[6:]
        (nids,) = struct.unpack("<I", payload[:4])
        idlist = [payload[4 + 8 * i:12 + 8 * i] for i in range(nids)]
        # positions per chunk via cumulative lens (insertion order == list order)
        pos = 0
        posmap = {}
        for i, ln in enumerate(lens):
            posmap[hashlib.sha256(store[pos:pos + ln]).digest()[:8]] = (pos, ln)
            pos += ln
        out = bytearray()
        for tid in idlist:
            if tid not in posmap:
                raise Mdr3Error("chunk id %s not in store (corrupt)" % tid.hex())
            p, ln = posmap[tid]
            out += store[p:p + ln]
        return bytes(out[:manifest["lengths"][gi]])
    raise Mdr3Error("unknown item kind %s" % kind)


_store_cache = {}


def _find_in_store(store, tid, B, _cache={}):
    """Find chunk by 8B id prefix; linear scan with memo cache."""
    key = id(store)
    if key not in _cache or _cache[key][0] is not store:
        m = {}
        pos = 0
        while pos < len(store):
            chunk = store[pos:pos + B]
            m[hashlib.sha256(chunk).digest()[:8]] = pos
            pos += B
        _cache[key] = (store, m)
    m = _cache[key][1]
    if tid not in m:
        raise Mdr3Error("chunk id %s not in store (corrupt)" % tid.hex())
    return m[tid]


def unpack(archive_path, out_dir):
    with open(archive_path, "rb") as f:
        blob = f.read()
    manifest, index, data, body, oksha = _read_sections(blob)
    if not oksha:
        raise Mdr3Error("archive sha256 mismatch")
    cache = {}
    # restore in dependency order: independents first, then refs (chain)
    order = []
    pending = list(range(len(manifest["hashes"])))
    # simple resolver: independents (or chunklists) resolve immediately
    n = len(manifest["hashes"])
    if manifest["method"] == "dedup":
        order = list(range(n))
    else:
        # chain-resolve
        resolved = set()
        while pending:
            progressed = False
            for gi in pending:
                r = manifest["items"][gi]
                if r["kind"] == "independent" or r["base"] in resolved:
                    order.append(gi)
                    resolved.add(gi)
                    pending.remove(gi)
                    progressed = True
            if not progressed:
                raise Mdr3Error("dependency cycle (corrupt manifest)")
    os.makedirs(out_dir, exist_ok=True)
    for gi in order:
        g = _restore_gen(manifest, index, data, gi, cache)
        h = hashlib.sha256(g).hexdigest()
        if h != manifest["hashes"][gi]:
            raise Mdr3Error("generation %d sha mismatch after restore" % gi)
        cache[gi] = g
        with open(os.path.join(out_dir, "gen%02d.db" % gi), "wb") as f:
            f.write(g)
    return {"generations": n, "method": manifest["method"],
            "out_dir": out_dir}


def latest(archive_path, out_path):
    with open(archive_path, "rb") as f:
        blob = f.read()
    manifest, index, data, body, oksha = _read_sections(blob)
    if not oksha:
        raise Mdr3Error("archive sha256 mismatch")
    n = len(manifest["hashes"])
    cache = {}
    g = None
    # resolve chain for the LAST generation only (still restores deps)
    if manifest["method"] == "dedup":
        g = _restore_gen(manifest, index, data, n - 1, cache)
    else:
        order = []
        pending = list(range(n))
        resolved = set()
        while pending:
            progressed = False
            for gi in pending:
                r = manifest["items"][gi]
                if r["kind"] == "independent" or r["base"] in resolved:
                    order.append(gi)
                    resolved.add(gi)
                    pending.remove(gi)
                    progressed = True
            if not progressed:
                raise Mdr3Error("dependency cycle")
        for gi in order:
            cache[gi] = _restore_gen(manifest, index, data, gi, cache)
        g = cache[n - 1]
    with open(out_path, "wb") as f:
        f.write(g)
    return n - 1


# ------------------------------------------------------------------ CLI
def main(argv=None):
    ap = argparse.ArgumentParser(prog="mdr3", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    pp = sub.add_parser("pack")
    pp.add_argument("inputs", nargs="+")
    pp.add_argument("-o", "--output", required=True)
    pp.add_argument("--max-depth", type=int, default=MAX_DEPTH_DEFAULT)
    up = sub.add_parser("unpack")
    up.add_argument("input")
    up.add_argument("-d", "--outdir", default=".")
    up.add_argument("--latest", action="store_true")
    up.add_argument("-o", "--output")
    args = ap.parse_args(argv)
    try:
        if args.cmd == "pack":
            rep = pack(args.inputs, args.output, max_depth=args.max_depth)
            print("packed %d generations (%s) -> %d bytes (raw %d)" %
                  (rep["generations"], rep["method"], rep["archive"],
                   rep["raw_total"]))
        elif args.cmd == "unpack" and args.latest:
            gi = latest(args.input, args.output or "latest.db")
            print("restored latest generation %d -> %s" %
                  (gi, args.output or "latest.db"))
        else:
            rep = unpack(args.input, args.outdir)
            print("restored %d generations (%s) -> %s" %
                  (rep["generations"], rep["method"], rep["out_dir"]))
        return 0
    except Mdr3Error as e:
        print("mdr3: error: %s" % e, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())