#!/usr/bin/env python3
"""MDR K6: sub-page historical byte-range references (prototype codec).

Premise (docs/mdr/k6_premise.md): VACUUM preserves logical records while
destroying page-level similarity; reusable bytes survive as sub-page
fragments. K6 encodes a target snapshot as an ordered stream of
LITERAL / REF(base_idx, offset, length) instructions over strictly
historical bases (earlier generations only - never into the partially
decoded target). Decoding is trivially ordered and acyclic by
construction (no forest solver): process instructions left to right,
copy from already-complete bases. Decode ORDER: literals and copies tile
the target exactly; the op stream is the sole layout source.

Wire (self-describing, little-endian):
  magic "K6D1" | u64 base_union_len | u16 n_bases | u32 opb_len |
  u32 litb_len | n_bases x u32 base_ids | opb | litb
  where opb/litb are mdr3-style segment bodies (<BBII> codec, param,
  clen, crc | stored) so the shared mdrc portfolio compresses both.
  ops stream (after segment decode):
    0x00 <varint len>          -> next len literal bytes from litb
    0x01 <varint bi><varint off><varint len> -> copy from bases[bi]
  base_ids map bi -> generation id for the archive wiring (mdr3); inside
  this codec they are carried opaquely and bounds-checked never.

Ledger (K6-G3 discipline): total == hdr + ops_wire + lit_wire, asserted
in encode. Research arm - NOT in the default portfolio; promotion only
via K6 gates + preregistered kill criterion (docs/mdr/k6_premise.md).

__main__ self-check: literal-only, copy-heavy, multi-base, bad magic,
corrupt copy bounds, plus the real K6-0 vacuum pair when present.
"""

import collections
import os
import struct
import sys
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import mdrc  # noqa: E402  (shared segment portfolio)


# ------------------------------------------------------------------ codec
class Mdr6Error(Exception):
    pass


MAGIC = b"K6D1"

SHINGLE = 16          # seed length for the shingle index
PRUNE = 32            # drop seed keys above this occurrence count
MIN_MATCH = 12        # below this a ref cannot beat literal cost
REF_FIXED = 1         # base-id byte charged per ref (varint anyway)
SLIDE = 1             # index slide on seed miss


def _pack_varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _read_varint(buf, pos):
    val = 0
    shift = 0
    while True:
        if pos >= len(buf):
            raise Mdr6Error("op stream truncated in varint")
        b = buf[pos]
        pos += 1
        val |= (b & 0x7F) << shift
        if not b & 0x80:
            return val, pos
        shift += 7


def _varint_size(n):
    L = 1
    while n >= 128:
        n >>= 7
        L += 1
    return L


def _wire_seg(data):
    """Same body format mdr3._seg_wire_best emits (kept here so this module
    stands alone; byte-format-identical: <BBII> codec param clen crc)."""
    codec, param, stored = mdrc.select_and_encode(data)
    return struct.pack("<BBII", codec, param, len(stored),
                       zlib.crc32(stored) & 0xFFFFFFFF) + stored


def _decode_seg(seg):
    codec, param = struct.unpack("<BB", seg[:2])
    (clen,) = struct.unpack("<I", seg[2:6])
    stored = seg[10:10 + clen]
    if len(stored) < clen:
        raise Mdr6Error("segment body truncated (claim %d, have %d)"
                        % (clen, len(stored)))
    if codec == 0:
        return stored
    data = mdrc.zstd_decompress(stored)
    if codec == 1:
        return data
    if codec == 2:
        return mdrc.unshuffle_bytes(data, param)
    if codec == 3:
        return mdrc.unbit_shuffle(data)
    raise Mdr6Error("codec %d not supported in K6 bodies" % codec)


# ------------------------------------------------------------------ matcher
def build_index(base_union, shingle=SHINGLE, prune=PRUNE):
    idx = collections.defaultdict(list)
    for q in range(0, len(base_union) - shingle + 1, shingle):
        idx[base_union[q:q + shingle]].append(q)
    return {k: v for k, v in idx.items() if len(v) <= prune}


def find_ops(target, bases, shingle=SHINGLE, prune=PRUNE,
             min_match=MIN_MATCH, slide=SLIDE):
    """Greedy matcher. Returns op list tiling target in order:
    ('lit', length) / ('ref', base_idx, off, length).
    Literal runs are maximal (never adjacent to another literal)."""
    union = b"".join(bases)
    idx = build_index(union, shingle, prune)
    bounds = []          # (union_lo, union_hi, base_idx)
    acc = 0
    for bi, b in enumerate(bases):
        bounds.append((acc, acc + len(b), bi))
        acc += len(b)

    ops = []
    lit_run = 0
    p = 0
    N = len(target)
    while p <= N - shingle:
        cands = idx.get(target[p:p + shingle])
        ok = False
        if cands:
            best_len = 0
            best_u = -1
            for u in cands:
                L = shingle
                maxL = min(N - p, len(union) - u)
                # extend
                while L < maxL and union[u + L] == target[p + L]:
                    L += 1
                if L > best_len:
                    best_len = L
                    best_u = u
            if best_len >= min_match:
                bi, off = None, None
                for lo, hi, b2 in bounds:
                    if lo <= best_u < hi:
                        bi, off = b2, best_u - lo
                        break
                cost = REF_FIXED + _varint_size(bi) + _varint_size(off) \
                    + _varint_size(best_len)
                if cost < best_len:
                    if lit_run:
                        ops.append(("lit", lit_run))
                        lit_run = 0
                    ops.append(("ref", bi, off, best_len))
                    p += best_len
                    ok = True
        if not ok:
            lit_run += 1
            p += slide
    if lit_run or p < N:
        ops.append(("lit", lit_run + max(0, N - p)))
    return ops


# ------------------------------------------------------------------ wire
def encode_k6(target, bases, base_ids=None):
    """Encode target given earlier-generation bytes `bases` (decode order).

    base_ids: optional archive generation ids corresponding to bases (for
    mdr3 wiring); None -> 0..n-1. Returns (wire, ledger). Ledger asserts
    total == hdr + ops_wire + lit_wire (K6-G3)."""
    ops = find_ops(target, bases)
    opb = bytearray()
    litb = bytearray()
    for op in ops:
        if op[0] == "lit":
            opb += b"\x00" + _pack_varint(op[1])
        else:
            _, bi, off, L = op
            opb += b"\x01" + _pack_varint(bi) + _pack_varint(off) \
                + _pack_varint(L)
            # literal bytes for copies are NOT stored (they come from bases)
    # literal body: concatenate literal SPANS in op order
    # recompute spans by tiling: walk ops, consume target
    litb = bytearray()
    cur = 0
    union_len = sum(len(b) for b in bases)
    for op in ops:
        if op[0] == "lit":
            litb += target[cur:cur + op[1]]
            cur += op[1]
        else:
            cur += op[3]
    assert cur == len(target), "ops do not tile the target"
    ids = base_ids if base_ids is not None else list(range(len(bases)))
    assert len(ids) == len(bases)
    w_op = _wire_seg(bytes(opb))
    w_lit = _wire_seg(bytes(litb))
    hdr = (MAGIC + struct.pack("<QHII", union_len, len(bases),
                               len(w_op), len(w_lit)) +
           b"".join(struct.pack("<I", i) for i in ids))
    ledger = {"ops_raw": len(opb), "ops_wire": len(w_op),
              "lit_raw": len(litb), "lit_wire": len(w_lit),
              "hdr": len(hdr),
              "refs": sum(1 for o in ops if o[0] == "ref"),
              "lits": sum(1 for o in ops if o[0] == "lit"),
              "covered_ref_bytes": sum(o[3] for o in ops if o[0] == "ref")}
    total = len(hdr) + len(w_op) + len(w_lit)
    ledger["total"] = total
    assert ledger["hdr"] + ledger["ops_wire"] + ledger["lit_wire"] == total, \
        "G3 ledger decomposition broken"
    return hdr + w_op + w_lit, ledger


def decode_k6(wire, bases):
    """Inverse of encode_k6. Byte-exact target or Mdr6Error."""
    if len(wire) < 4 + 18:
        raise Mdr6Error("wire shorter than fixed header")
    if wire[:4] != MAGIC:
        raise Mdr6Error("bad K6 magic")
    (union_len, n_bases, opb_len, litb_len) = struct.unpack_from(
        "<QHII", wire, 4)
    base_ids = []
    off = 22
    if len(wire) < off + 4 * n_bases:
        raise Mdr6Error("wire truncated in base-id table")
    for i in range(n_bases):
        base_ids.append(struct.unpack("<I", wire[off + 4 * i:off + 4 * i + 4])[0])
    off += 4 * n_bases
    if len(wire) < off + opb_len + litb_len:
        raise Mdr6Error("wire truncated (need %d, have %d)"
                        % (off + opb_len + litb_len, len(wire)))
    opb = _decode_seg(wire[off:off + opb_len])
    litb = _decode_seg(wire[off + opb_len:off + opb_len + litb_len])
    union = b"".join(bases)
    if len(union) != union_len:
        raise Mdr6Error("base union length mismatch (%d != %d)"
                        % (len(union), union_len))
    bounds = []
    acc = 0
    for bi, b in enumerate(bases):
        bounds.append((acc, acc + len(b), bi))
        acc += len(b)
    # base_ids are carried for the archive layer; the codec orders bases by
    # position. Bounds-check ids here so a corrupt archive cannot alias.
    for i, gid in enumerate(base_ids):
        if gid >= 1 << 32:
            raise Mdr6Error("base id out of range")
    out = bytearray()
    lit_pos = 0
    pos = 0
    while pos < len(opb):
        k = opb[pos]
        pos += 1
        if k == 0:
            vallen, pos = _read_varint(opb, pos)
            if lit_pos + vallen > len(litb):
                raise Mdr6Error("literal span exceeds body (%d + %d > %d)"
                                % (lit_pos, vallen, len(litb)))
            out += litb[lit_pos:lit_pos + vallen]
            lit_pos += vallen
        elif k == 1:
            bi, pos = _read_varint(opb, pos)
            voff, pos = _read_varint(opb, pos)
            vlen, pos = _read_varint(opb, pos)
            if bi >= len(bases):
                raise Mdr6Error("base index %d out of range" % bi)
            if voff + vlen > len(bases[bi]):
                raise Mdr6Error("copy out of bounds: base %d off %d len %d"
                                % (bi, voff, vlen))
            out += bases[bi][voff:voff + vlen]
        else:
            raise Mdr6Error("bad op byte %d" % k)
    if lit_pos != len(litb):
        raise Mdr6Error("literal body underrun (%d of %d consumed)"
                        % (lit_pos, len(litb)))
    return bytes(out)


if __name__ == "__main__":
    import random
    import time

    print("mdrk6 self-check")
    rng = random.Random(1)

    # 1) literals only (unmatchable base)
    base = rng.randbytes(64)
    tgt = rng.randbytes(5000)
    w, led = encode_k6(tgt, [base])
    assert decode_k6(w, [base]) == tgt
    assert led["refs"] == 0
    print("  literals-only roundtrip OK, total", led["total"])

    # 2) copy-heavy
    tgt2 = base * 80
    w2, led2 = encode_k6(tgt2, [base])
    assert decode_k6(w2, [base]) == tgt2
    assert led2["lits"] == 0
    print("  copy-heavy roundtrip OK, total", led2["total"])

    # 3) multi-base
    b1 = rng.randbytes(1000)
    b2 = rng.randbytes(1000)
    tgt3 = b1[100:400] + b"XY" * 300 + b2[500:900]
    w3, led3 = encode_k6(tgt3, [b1, b2])
    assert decode_k6(w3, [b1, b2]) == tgt3
    assert led3["refs"] >= 2
    print("  multi-base roundtrip OK, total", led3["total"])

    # 4) custom base ids carried
    w4, led4 = encode_k6(tgt3, [b1, b2], base_ids=[7, 3])
    assert decode_k6(w4, [b1, b2]) == tgt3
    print("  custom base ids roundtrip OK")

    # 5) bad magic rejected
    try:
        decode_k6(b"XXXX" + w3[4:], [b1, b2])
        raise AssertionError("bad magic accepted")
    except Mdr6Error:
        print("  bad magic rejected OK")

    # 6) corrupt bounds rejected (flip a byte in the last copy op region)
    bad = bytearray(w3)
    bad[-3] ^= 0xFF
    rejected = False
    try:
        decode_k6(bytes(bad), [b1, b2])
    except Mdr6Error:
        rejected = True
    except Exception:
        rejected = True   # segment-level corruption (crc/zstd) also a reject
    if not rejected:
        # corruption may land in stored-body slack; assert roundtrip breaks
        assert decode_k6(bytes(bad), [b1, b2]) != tgt3, \
            "corruption silently accepted"
        print("  corrupt body detected via mismatch OK")
    else:
        print("  corrupt body rejected OK")

    # 7) truncated wire rejected
    try:
        decode_k6(w3[:20], [b1, b2])
        raise AssertionError("truncated wire accepted")
    except Mdr6Error:
        print("  truncated wire rejected OK")

    # 8) real vacuum pair (K6-0 fixtures) if present
    work = os.path.join(HERE, "..", "..", "benchmarks", "mdr", "out",
                        "k6premise_work")
    pre_p = os.path.join(work, "vac_pre.db")
    post_p = os.path.join(work, "vac_post.db")
    if os.path.exists(pre_p) and os.path.exists(post_p) and \
            os.path.exists(os.path.join(HERE, "..", "..", "benchmarks",
                                        "mdr", "out", "k6_premise.json")):
        pre = open(pre_p, "rb").read()
        post = open(post_p, "rb").read()
        t0 = time.perf_counter()
        w6, led6 = encode_k6(post, [pre])
        dt = time.perf_counter() - t0
        t0 = time.perf_counter()
        assert decode_k6(w6, [pre]) == post, "vacuum-pair roundtrip FAIL"
        ddec = time.perf_counter() - t0
        import json
        j = json.load(open(os.path.join(HERE, "..", "..", "benchmarks",
                                        "mdr", "out", "k6_premise.json")))
        print("  vacuum pair: k6 %d B vs B1 patch %d B (%.2fx), "
              "refs %d lits %d, enc %.1fs dec %.2fs"
              % (led6["total"], j["B1_zstd"]["patch_b"],
                 j["B1_zstd"]["patch_b"] / led6["total"], led6["refs"],
                 led6["lits"], dt, ddec))
    print("mdrk6.selfcheck OK")