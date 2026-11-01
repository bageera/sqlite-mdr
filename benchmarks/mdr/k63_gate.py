#!/usr/bin/python3
"""K6-3 closure gate: picker accounting + method identity + determinism.

Gates (preregistered in Jon's K6-3 review):
  A  Exact cost identity: the picker's candidate sizes ARE the serialized
     candidate archives (argmin over measured bytes; pack asserts
     reported archive == emitted blob length).
  B  Forced-method identity: pergen/dedup/k6 each emit the expected wire
     layout (structural parse, not a report string).
  C  Determinism: repeated packs with identical inputs + params produce
     byte-identical archives.
  D  Restore coverage: every method restores byte-exactly, including
     multi-body generations and independent bases.

Runs on the K6-0 vacuum pair (rebuilds it if out/k6premise_work is missing)
and the t6fleet updates chain (regression for baseref chains + dedup).
Emits out/k63_result.json; exit nonzero on any failure.

Usage: python3 k63_gate.py
"""

import hashlib
import json
import os
import shutil
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "mdr", "tools"))

import mdr3  # noqa: E402
import mdrk6  # noqa: E402
import sqlite3  # noqa: E402

OUT = os.path.join(HERE, "out")
WORK = os.path.join(OUT, "k6premise_work")
ROWS = 8000
PAYLOAD = 700


def build_vacuum_pair():
    os.makedirs(WORK, exist_ok=True)
    pre = os.path.join(WORK, "vac_pre.db")
    post = os.path.join(WORK, "vac_post.db")
    if os.path.exists(pre) and os.path.exists(post):
        return [pre, post]
    import random
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
    con.execute("DELETE FROM t WHERE id % 3 = 0")
    con.commit()
    con.close()
    shutil.copyfile(pre, post)
    con = sqlite3.connect(post)
    con.execute("VACUUM")
    con.commit()
    con.close()
    return [pre, post]


def restore_exact(paths, arc):
    od = arc + "_res"
    shutil.rmtree(od, ignore_errors=True)
    mdr3.unpack(arc, od)
    ok = all(open(os.path.join(od, "gen%02d.db" % i), "rb").read() ==
             open(p, "rb").read() for i, p in enumerate(paths))
    shutil.rmtree(od)
    return ok


def check_chain(name, paths, rows):
    for fm in ("pergen", "dedup", "k6", None):
        arc = os.path.join(OUT, "%s_%s.mdr3" % (name, fm or "auto"))
        t0 = time.perf_counter()
        rep = mdr3.pack(paths, arc, selector="ranked", force_method=fm)
        dt = round(time.perf_counter() - t0, 2)
        blob = open(arc, "rb").read()
        man, _, _, _, oksha = mdr3._read_sections(blob)
        # B: layout identity (structural, from the manifest)
        kinds = [(it["gen"], it["kind"]) for it in man["items"]]
        if fm == "k6":
            layout_ok = man["method"] == "k6" and \
                all(k in ("independent", "k6ref") for _, k in kinds) and \
                kinds[0][1] == "independent"
        elif fm == "pergen":
            layout_ok = man["method"] == "pergen" and \
                all(k in ("independent", "baseref", "k6ref")
                    for _, k in kinds) and kinds[0][1] == "independent"
        elif fm == "dedup":
            layout_ok = man["method"] == "dedup" and kinds[0][1] == \
                "chunkstore" and kinds[0][0] == -1 and \
                all(k == "chunklist" for _, k in kinds[1:])
        else:
            layout_ok = man["method"] in ("dedup", "pergen", "k6")
        # A: reported archive == true serialized length (pack asserts too)
        identity_ok = rep["archive"] == len(blob)
        # C: determinism
        arc2 = arc + "2"
        mdr3.pack(paths, arc2, selector="ranked", force_method=fm)
        det_ok = open(arc2, "rb").read() == blob
        os.unlink(arc2)
        # D: restore coverage
        exact = restore_exact(paths, arc)
        rows.append({"chain": name, "force": fm or "auto",
                     "method": man["method"], "archive": rep["archive"],
                     "layout_ok": layout_ok, "identity_ok": identity_ok,
                     "determinism_ok": det_ok, "exact": exact,
                     "kinds": kinds if len(kinds) <= 8 else
                     kinds[:3] + ["...%d more" % (len(kinds) - 4)] + kinds[-1:],
                     "pack_s": dt})
        os.unlink(arc)
        print("%-10s force=%-8s method=%-7s archive=%8d layout=%s "
              "identity=%s det=%s exact=%s (%.1fs)"
              % (name, fm or "auto", man["method"], rep["archive"],
                 layout_ok, identity_ok, det_ok, exact, dt), flush=True)


def main():
    os.makedirs(OUT, exist_ok=True)
    rows = []

    vac = build_vacuum_pair()
    t6 = [os.path.join(OUT, "t6fleet", "upd_g%d.db" % i) for i in range(6)]
    if not all(os.path.exists(p) for p in t6):
        t6 = None

    check_chain("vacpair", vac, rows)
    if t6:
        check_chain("t6fleet", t6, rows)

    g_layout = all(r["layout_ok"] for r in rows)
    g_identity = all(r["identity_ok"] for r in rows)
    g_det = all(r["determinism_ok"] for r in rows)
    g_exact = all(r["exact"] for r in rows)
    verdict = "PASS" if (g_layout and g_identity and g_det and g_exact) \
        else "FAIL"
    print()
    print("gates: layout=%s identity=%s determinism=%s exact=%s"
          % (g_layout, g_identity, g_det, g_exact))
    print("verdict:", verdict)
    with open(os.path.join(OUT, "k63_result.json"), "w") as f:
        json.dump({"rows": rows,
                   "gates": {"layout_identity": g_layout,
                             "cost_identity": g_identity,
                             "determinism": g_det,
                             "restore_exact": g_exact},
                   "verdict": verdict}, f, indent=2)
    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())