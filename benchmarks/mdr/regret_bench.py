#!/usr/bin/python3
"""Selector-regret benchmark: exhaustive vs fast profile on the MDR-004 fleet.

Reports per db: archive bytes (both), pack seconds (both), regret bytes
= fast_wire - exhaustive_wire, and their selection disagreements.
No targets assumed; this is the measurement the MDR-005 review asked for
before any heuristic is trusted at scale.
"""

import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "mdr", "tools"))

import mdrc  # noqa: E402

OUT = os.path.join(HERE, "out")
FLEET = os.path.join(OUT, "fleet")


def main():
    names = [f for f in sorted(os.listdir(FLEET)) if f.endswith((".db", ".bin"))]
    rows = []
    print("%-16s %10s %10s %8s %9s %9s %9s" %
          ("db", "exh_bytes", "fast_bytes", "regret", "exh_s", "fast_s", "speedup"))
    t_exh = t_fast = 0
    for name in names:
        path = os.path.join(FLEET, name)
        a = os.path.join(OUT, "r_exh.mdr")
        b = os.path.join(OUT, "r_fast.mdr")
        t0 = time.perf_counter()
        ra = mdrc.pack(path, a, segment_size=1 << 20, profile="exhaustive")
        s_exh = time.perf_counter() - t0
        t0 = time.perf_counter()
        rb = mdrc.pack(path, b, segment_size=1 << 20, profile="fast")
        s_fast = time.perf_counter() - t0
        # sanity: fast archive must unpack byte-exact too
        back = os.path.join(OUT, "r_fast.rest")
        mdrc.unpack(b, back)
        import hashlib
        with open(path, "rb") as f:
            src = f.read()
        with open(back, "rb") as f:
            got = f.read()
        exact = hashlib.sha256(src).digest() == hashlib.sha256(got).digest()
        os.unlink(back)
        regret = rb["archive"] - ra["archive"]
        rows.append({"name": name, "exhaustive": ra["archive"],
                     "fast": rb["archive"], "regret": regret,
                     "exh_s": round(s_exh, 3), "fast_s": round(s_fast, 3),
                     "exact": exact})
        t_exh += s_exh
        t_fast += s_fast
        print("%-16s %10d %10d %+8d %9.3f %9.3f %8.1f  exact=%s" %
              (name, ra["archive"], rb["archive"], regret,
               s_exh, s_fast, s_exh / max(s_fast, 1e-6), exact))
    print("%-16s %10s %10s %+8d %9.3f %9.3f %8.1f" %
          ("TOTAL", sum(r["exhaustive"] for r in rows),
           sum(r["fast"] for r in rows),
           sum(r["regret"] for r in rows), t_exh, t_fast,
           t_exh / max(t_fast, 1e-6)))
    result = {"rows": rows, "total_exhaustive_s": round(t_exh, 3),
              "total_fast_s": round(t_fast, 3),
              "total_regret_bytes": sum(r["regret"] for r in rows),
              "all_exact": all(r["exact"] for r in rows)}
    with open(os.path.join(OUT, "regret_result.json"), "w") as f:
        json.dump(result, f, indent=2)
    print("saved:", os.path.join(OUT, "regret_result.json"))
    return 0


if __name__ == "__main__":
    sys.exit(main())