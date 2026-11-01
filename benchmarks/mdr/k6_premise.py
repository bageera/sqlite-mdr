#!/usr/bin/python3
"""K6-0: sub-page cross-snapshot reuse premise + baseline registration.

Reproduces (from scratch, deterministic seeds):
  P1  build fragmentation->VACUUM db pair (fixtures in a scratch dir)
  P2  page/chunk identity census (exact 4KiB pages, 32/64KiB chunks)
  P3  stripe-index near-match census + residual histogram at page grain
  P4  32B block conservation both directions
  P5  B0 = mdr3 pack [pre, post] selector=ranked  (complete archive bytes)
  P6  B1 = zstd-19(pre) + zstd-19 --patch-from post  (roundtrip asserted)

Emits benchmarks/mdr/out/k6_premise.json. Exit nonzero on any gate-style
assert so silent drift is impossible. Run background (B0 pack is slow).

Usage: python3 k6_premise.py [--workdir DIR]
"""

import collections
import hashlib
import json
import os
import random
import shutil
import sqlite3
import struct
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "mdr", "tools"))

import mdr3  # noqa: E402

OUT = os.path.join(HERE, "out")
ROWS = 8000
PAYLOAD = 700
DELETE_MOD = 3
STRIPE = 512
CENSUS_W = 32
CENSUS_STRIDE = 32


def build_pair(workdir):
    pre = os.path.join(workdir, "vac_pre.db")
    post = os.path.join(workdir, "vac_post.db")
    for p in (pre, post):
        if os.path.exists(p):
            os.unlink(p)
    con = sqlite3.connect(pre)
    con.execute("PRAGMA page_size=4096")
    con.execute("CREATE TABLE t(id INTEGER PRIMARY KEY, b BLOB)")
    con.executemany("INSERT INTO t VALUES(?,?)",
                    [(i, random.Random(i).randbytes(PAYLOAD))
                     for i in range(ROWS)])
    con.commit()
    con.execute("DELETE FROM t WHERE id %% %d = 0" % DELETE_MOD)
    con.commit()
    con.close()
    shutil.copyfile(pre, post)
    con = sqlite3.connect(post)
    con.execute("VACUUM")
    con.commit()
    con.close()
    return pre, post


def pages(d, size=4096):
    return [d[i:i + size] for i in range(0, len(d), size)]


def exact_overlap(a, b, size):
    sa = {hashlib.sha256(x).digest() for x in pages(a, size)}
    sb = {hashlib.sha256(x).digest() for x in pages(b, size)}
    return len(sa & sb), len(sa), len(sb)


def stripe_census(pre_pages, post_pages):
    """Best near-match per post page via 512B stripe index over pre pages;
    byte-diff residual of the top-3 candidates."""
    idx = {}
    for pi, pg in enumerate(pre_pages):
        for off in range(0, 4096, STRIPE):
            if off + STRIPE <= len(pg):
                h = hashlib.sha256(pg[off:off + STRIPE]).digest()[:8]
                idx.setdefault(h, []).append(pi)
    import heapq
    hist = collections.Counter()
    probed = 0
    for pg in post_pages:
        cands = {}
        for off in range(0, 4096, STRIPE):
            if off + STRIPE <= len(pg):
                h = hashlib.sha256(pg[off:off + STRIPE]).digest()[:8]
                for ci in idx.get(h, ()):
                    cands[ci] = cands.get(ci, 0) + 1
        probed += len(cands)
        best = None
        top = (heapq.nsmallest(3, cands.items(), key=lambda kv: -kv[1])
               if cands else [])
        for ci, _ in top:
            diff = sum(1 for a, b in zip(pg, pre_pages[ci]) if a != b)
            best = diff if best is None else min(best, diff)
        if best is None:
            hist["no-stripe-hit"] += 1
        elif best == 0:
            hist["0"] += 1
        elif best < 64:
            hist["1-63"] += 1
        elif best < 128:
            hist["64-127"] += 1
        elif best < 256:
            hist["128-255"] += 1
        elif best < 1024:
            hist["256-1023"] += 1
        elif best < 3000:
            hist["1024-2999"] += 1
        else:
            hist["3000+"] += 1
    return hist, probed / max(1, len(post_pages))


def block_conservation(a, b, w=CENSUS_W, stride=CENSUS_STRIDE):
    """% of 32B blocks (stride 32) in `a` found exact in `b`."""
    sb = set(b[o:o + w] for o in range(0, len(b) - w + 1, stride))
    hit = sum(1 for o in range(0, len(a) - w + 1, stride)
              if a[o:o + w] in sb)
    return 100.0 * hit / max(1, len(range(0, len(a) - w + 1, stride)))


def b0_mdr3(pre, post, workdir):
    arc = os.path.join(workdir, "k6pair.mdr3")
    t0 = time.perf_counter()
    rep = mdr3.pack([pre, post], arc, selector="ranked")
    dt = time.perf_counter() - t0
    od = arc + "_res"
    shutil.rmtree(od, ignore_errors=True)
    mdr3.unpack(arc, od)
    for i, p in enumerate((pre, post)):
        assert open(os.path.join(od, "gen%02d.db" % i), "rb").read() == \
            open(p, "rb").read(), "B0 not byte-exact gen%d" % i
    shutil.rmtree(od)
    return {"archive": rep["archive"], "method": rep["method"],
            "pack_s": round(dt, 1)}


def b1_zstd(pre, post, workdir):
    patch = os.path.join(workdir, "post.zst.patched")
    pre19 = os.path.join(workdir, "pre.zst")
    r = subprocess.run(["zstd", "-q", "--patch-from", pre, "-19", "-f",
                        post, "-o", patch], capture_output=True, text=True)
    assert r.returncode == 0, "zstd patch-from failed: " + r.stderr
    r2 = subprocess.run(["zstd", "-q", "-19", "-f", pre, "-o", pre19],
                        capture_output=True, text=True)
    assert r2.returncode == 0, "zstd -19 failed: " + r2.stderr
    rt = os.path.join(workdir, "post.rt")
    r3 = subprocess.run(["zstd", "-d", "-q", "--patch-from", pre, "-f",
                         patch, "-o", rt], capture_output=True, text=True)
    assert r3.returncode == 0, "zstd patch decode failed: " + r3.stderr
    assert open(rt, "rb").read() == open(post, "rb").read(), \
        "B1 patch not byte-exact"
    return {"patch_b": os.path.getsize(patch),
            "pre19_b": os.path.getsize(pre19),
            "total_b": os.path.getsize(patch) + os.path.getsize(pre19)}


def main():
    workdir = sys.argv[sys.argv.index("--workdir") + 1] \
        if "--workdir" in sys.argv else \
        os.path.join(OUT, "k6premise_work")
    os.makedirs(workdir, exist_ok=True)
    os.makedirs(OUT, exist_ok=True)
    res = {"workdir": workdir, "pair": {}, "logical_rows": {},
           "identity": {}, "stripe": {}, "conservation32B": {},
           "B0_mdr3": {}, "B1_zstd": {}}

    pre, post = build_pair(workdir)
    d1 = open(pre, "rb").read()
    d2 = open(post, "rb").read()
    p1, p2 = pages(d1), pages(d2)
    res["pair"] = {"pre_b": len(d1), "post_b": len(d2),
                   "pre_pages": len(p1), "post_pages": len(p2)}

    # logical content preserved?
    for db, n in ((pre, "pre"), (post, "post")):
        con = sqlite3.connect(db)
        rows = con.execute("SELECT id, b FROM t ORDER BY id").fetchall()
        con.close()
        res.setdefault("logical_rows", {})[n] = hashlib.sha256(
            repr(rows).encode()).hexdigest()[:16]
    res["logical_identical"] = (res["logical_rows"]["pre"] ==
                                res["logical_rows"]["post"])

    # P2 page/chunk identity
    p_ex = exact_overlap(d1, d2, 4096)
    c32 = exact_overlap(d1, d2, 32768)
    c64 = exact_overlap(d1, d2, 65536)
    res["identity"] = {"page4k_exact": p_ex[0], "chunk32k_exact": c32[0],
                       "chunk64k_exact": c64[0]}
    print("P2 identity: 4K pages %d, 32K chunks %d, 64K chunks %d"
          % (p_ex[0], c32[0], c64[0]), flush=True)

    # P3 stripe near-match + histogram
    hist, avg_probed = stripe_census(p1, p2)
    res["stripe"] = {"histogram": dict(hist),
                     "avg_candidate_pages_per_query": round(avg_probed, 2)}
    lt128 = hist["0"] + hist["1-63"] + hist["64-127"]
    res["stripe"]["pages_lt128B_residual"] = lt128
    print("P3 stripe: pages with <128B residual: %d/%d (%.2f%%)"
          % (lt128, len(p2), 100.0 * lt128 / len(p2)), flush=True)

    # P4 32B block conservation
    res["conservation32B"] = {"post_in_pre": round(block_conservation(d2, d1), 1),
                              "pre_in_post": round(block_conservation(d1, d2), 1)}
    print("P4 32B conservation: post-in-pre %.1f%%, pre-in-post %.1f%%"
          % (res["conservation32B"]["post_in_pre"],
             res["conservation32B"]["pre_in_post"]), flush=True)

    # P5 B0 mdr3
    res["B0_mdr3"] = b0_mdr3(pre, post, workdir)
    print("P5 B0 mdr3: %d (method %s)" % (res["B0_mdr3"]["archive"],
                                          res["B0_mdr3"]["method"]), flush=True)

    # P6 B1 zstd patch-from
    res["B1_zstd"] = b1_zstd(pre, post, workdir)
    print("P6 B1 zstd: patch %d + pre19 %d = %d"
          % (res["B1_zstd"]["patch_b"], res["B1_zstd"]["pre19_b"],
             res["B1_zstd"]["total_b"]), flush=True)

    res["margin_b1_minus_b0"] = res["B1_zstd"]["total_b"] - res["B0_mdr3"]["archive"]

    with open(os.path.join(OUT, "k6_premise.json"), "w") as f:
        json.dump(res, f, indent=2)
    print("results:", os.path.join(OUT, "k6_premise.json"))

    # premise sanity (not a pass/fail on compression, on the MEASUREMENT):
    assert res["identity"]["page4k_exact"] == 0, "premise drift: exact pages appeared"
    assert res["logical_identical"], "premise drift: logical content changed"
    assert res["conservation32B"]["post_in_pre"] > 25, \
        "premise drift: sub-page reuse below signal floor"
    return 0


if __name__ == "__main__":
    sys.exit(main())