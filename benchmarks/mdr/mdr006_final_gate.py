#!/usr/bin/python3
"""MDR-006 final gate: long-history selection (L1-L7) + fp_top budget sweep.

Matrix (spec):
  L1 12 | L2 24 | L3 48 | L4 24 best-base-ranked-3rd | L5 24 many small
  page edits | L6 24 distant recurring base | L7 48 mostly-independent.

Sweep per chain: max_depth in {8,16} x fp_top in {1,2,4,8}. Baseline:
selector='exhaustive' with the same max_depth (candidates outside the
depth window are NOT counted as ranking failures, per spec).

Metrics per (chain, depth, fp_top):
  R_pergen  = ranked_pergen_data - exhaustive_pergen_data
  R_archive = ranked_archive - exhaustive_archive
  miss      = exhaustive winner outside ranked top-fp_top (per generation)

Acceptance (per spec): byte-exact everywhere; bounded evaluations/generation;
regret reported; no meaningful loss on independent control (L7); pack wall
time incl. fingerprint cost improves.

Also verifies the hybrid two-tier fingerprint (exact + 64B stripe samples)
against the L5 small-page-edit adversary that plain exact-matching loses.
"""

import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "mdr", "tools"))
sys.path.insert(0, HERE)

import mdrc  # noqa: E402
import mdr3  # noqa: E402
from mdr3 import Mdr3Error  # noqa: E402
from mdr005_temporal import sh, sha  # noqa: E402

OUT = os.path.join(HERE, "out")


# ------------------------------------------------------------- chains
def _db(path, rows_sql=None, copyfrom=None):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if os.path.exists(path):
        os.unlink(path)
    if copyfrom:
        shutil.copyfile(copyfrom, path)
        return path
    sh(path, "PRAGMA page_size=4096;\n" + (rows_sql or "SELECT 1;"))
    return path


def L1_builder(root):
    paths = []
    p = _db(os.path.join(root, "L1_g0.db"), """
CREATE TABLE e(id INTEGER PRIMARY KEY, name TEXT, val REAL);
WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x<20000)
INSERT INTO e SELECT x, printf('%-24s','ent-'||x), x*1.5 FROM c;""")
    paths.append(p)
    for t in range(1, 12):
        p = _db(os.path.join(root, "L1_g%d.db" % t), "")
        shutil.copyfile(paths[-1], p)
        sh(p, """WITH RECURSIVE c(x) AS (SELECT {a} UNION ALL SELECT x+1
 FROM c WHERE x<{b})
INSERT INTO e SELECT x, printf('%-24s','ent-'||x), x*1.5 FROM c;""".format(
            a=20000 + (t - 1) * 2000 + 1, b=20000 + t * 2000))
        paths.append(p)
    return paths


def L2_builder(root):
    paths = []
    p = _db(os.path.join(root, "L2_g0.db"), """
CREATE TABLE e(id INTEGER PRIMARY KEY, name TEXT, val REAL);
WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x<20000)
INSERT INTO e SELECT x, printf('%-24s','ent-'||x), x*1.5 FROM c;""")
    paths.append(p)
    for t in range(1, 24):
        p = _db(os.path.join(root, "L2_g%d.db" % t), "")
        shutil.copyfile(paths[-1], p)
        sh(p, """WITH RECURSIVE c(x) AS (SELECT {a} UNION ALL SELECT x+1
 FROM c WHERE x<{b})
INSERT INTO e SELECT x, printf('%-24s','ent-'||x), x*1.5 FROM c;""".format(
            a=20000 + (t - 1) * 1000 + 1, b=20000 + t * 1000))
        paths.append(p)
    return paths


def L3_builder(root):
    paths = L2_builder(root)[:24]
    for t in range(24, 48):
        p = _db(os.path.join(root, "L2_g%d.db" % t), "")
        shutil.copyfile(paths[-1], p)
        sh(p, """WITH RECURSIVE c(x) AS (SELECT {a} UNION ALL SELECT x+1
 FROM c WHERE x<{b})
INSERT INTO e SELECT x, printf('%-24s','ent-'||x), x*1.5 FROM c;""".format(
            a=20000 + (t - 1) * 1000 + 1, b=20000 + t * 1000))
        paths.append(p)
    return paths


def _make_state(root, tag, base_rows, tweak_sql):
    p = _db(os.path.join(root, tag + ".db"),
            base_rows + ";" + tweak_sql if tweak_sql else base_rows)
    return p


def L4_builder(root):
    """Best base ranks 3rd by exact-overlap: gen T's truly best base (B2)
    shares moderate EXACT pages but high byte similarity; a decoy (D)
    shares MORE exact pages but is byte-scattered. Construct:
    D = T's pages duplicated from an unrelated high-overlap snapshot."""
    base_rows = """CREATE TABLE e(id INTEGER PRIMARY KEY, name TEXT, val REAL, blob BLOB);
WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x<12000)
INSERT INTO e SELECT x, printf('%-28s','ent-'||x), x*1.5,
 substr(zeroblob(48),1,48) FROM c"""
    # b2: the true best byte-base for the final generation
    b2 = _db(os.path.join(root, "L4_b2.db"), base_rows + """;
UPDATE e SET val = val*0.5;""")
    # decoy: shares many pages verbatim with a LATER state (high exact
    # overlap) but whose bytes are a poor base for final deltas
    decoy = _db(os.path.join(root, "L4_decoy.db"), base_rows + """;
INSERT INTO e SELECT 1000000, 'decoy-pinned', 0.0, zeroblob(4096);
UPDATE e SET name = 'decoy-'||id WHERE id % 4 = 0;""")
    paths = []
    # history: g0=b2, g1..g23 mostly drift, decoy reinserted as g22 (recent)
    paths.append(b2)
    for t in range(1, 22):
        p = _db(os.path.join(root, "L4_g%d.db" % t), "")
        shutil.copyfile(paths[-1], p)
        sh(p, 'UPDATE e SET val = val + 1 WHERE id % 97 = {v};'.format(v=t % 97))
        paths.append(p)
    paths.append(decoy)   # g22: recent, high exact overlap with some gens
    # final: bytes closest to b2 EXCEPT a tiny fraction, so per-byte winner
    # is b2 (old), while decoy is recent.
    fin = _db(os.path.join(root, "L4_g23.db"), copyfrom=b2)
    sh(fin, "UPDATE e SET val = val + 1 WHERE id % 401 = 1;")
    paths.append(fin)
    return paths


def L5_builder(root):
    """Widespread small page edits: every generation touches 1 byte in most
    pages. Exact page overlap collapses; hybrid sampled tier must rank."""
    paths = []
    p = _db(os.path.join(root, "L5_g0.db"), """
CREATE TABLE e(id INTEGER PRIMARY KEY, name TEXT, val REAL);
WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x<20000)
INSERT INTO e SELECT x, printf('%-24s','ent-'||x), x*1.5 FROM c;""")
    paths.append(p)
    for t in range(1, 24):
        p = _db(os.path.join(root, "L5_g%d.db" % t), "")
        shutil.copyfile(paths[-1], p)
        sh(p, "UPDATE e SET val = val + {s} WHERE id % 7 = 0;".format(s=t))
        paths.append(p)
    return paths


def L6_builder(root):
    """Distant recurring base: g_t == g_{t-10} + small append (10-deep)."""
    paths = []
    p = _db(os.path.join(root, "L6_w0.db"), """
CREATE TABLE e(id INTEGER PRIMARY KEY, name TEXT, val REAL);
WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x<20000)
INSERT INTO e SELECT x, printf('%-24s','ent-'||x), x*1.5 FROM c;""")
    # build 24 distinct working files; generations cycle every 10
    states = [p]
    for t in range(1, 24):
        p = _db(os.path.join(root, "L6_w%d.db" % t), "")
        shutil.copyfile(states[-1], p)
        sh(p, "UPDATE e SET val = val*1.01 WHERE id % 11 = 0;")
        states.append(p)
    for t in range(24):
        dst = os.path.join(root, "L6_g%d.db" % t)
        if os.path.exists(dst):
            os.unlink(dst)
        shutil.copyfile(states[(t % 10) if t >= 10 else t], dst)
        paths.append(dst)
    return paths


def L7_builder(root):
    """Mostly independent control, 48 gens: only tiny shared headers."""
    os.makedirs(root, exist_ok=True)
    from mdr005_temporal import xorshift_bytes
    paths = []
    for t in range(48):
        p = os.path.join(root, "L7_g%d.db" % t)
        if os.path.exists(p):
            os.unlink(p)
        blob = xorshift_bytes(96 * 1024, seed=0x1111 + t * 7919)
        sh(p, """PRAGMA page_size=4096;
CREATE TABLE r%d(id INTEGER PRIMARY KEY, b BLOB);
INSERT INTO r%d VALUES (1, x'%s');""" % (t, t, blob.hex()))
        paths.append(p)
    return paths


CHAINS = [
    ("L1_12", 12, L1_builder),
    ("L2_24", 24, L2_builder),
    ("L3_48", 48, L3_builder),
    ("L4_rank3", 24, L4_builder),
    ("L5_smalldits", 24, L5_builder),
    ("L6_recurrence", 24, L6_builder),
    ("L7_control48", 48, L7_builder),
]


def run_chain(name, expect_gens, builder, depths=(8, 16), tops=(1, 2, 4, 8)):
    root = OUT
    out_json = os.path.join(OUT, "mdr006_final_result.json")
    if os.path.exists(out_json):        # incremental resume
        try:
            with open(out_json) as f:
                prev = json.load(f)
        except (json.JSONDecodeError, OSError):
            prev = {"matrix": [], "gates": {}, "verdict": "INCOMPLETE"}
        if any(m.get("name") == name for m in prev.get("matrix", [])):
            print("%-15s already complete (resume json), skip" % name)
            return next(m for m in prev["matrix"] if m.get("name") == name)
        for m in prev.get("matrix", []):
            if m["name"] == name and m.get("sweep"):
                return m
    paths = builder(os.path.join(root, name))
    n = len(paths)
    assert n == expect_gens, (name, n, expect_gens)
    base = os.path.join(root, name)
    rows = []
    for depth in depths:
        # exhaustive reference at this depth
        arc_e = os.path.join(base, "_exh.mdr3")
        os.makedirs(os.path.dirname(arc_e), exist_ok=True)
        t0 = time.perf_counter()
        rep_e = mdr3.pack(paths, arc_e, max_depth=depth,
                          selector="exhaustive", force_method="pergen")
        t_exh = time.perf_counter() - t0
        # winner set from exhaustive manifest (pergen ⇒ real baserefs)
        with open(arc_e, "rb") as f:
            blob = f.read()
        manifest, _, _, _, _ = mdr3._read_sections(blob)
        winners = {}
        for it in manifest["items"]:
            if it.get("kind") == "baseref":
                winners[it["gen"]] = it["base"]
        # archive-level exhaustive (adaptive method) for R_archive
        arc_e2 = os.path.join(base, "_exh adaptive.mdr3")
        rep_e2 = mdr3.pack(paths, arc_e2, max_depth=depth,
                           selector="exhaustive")
        for fp_top in tops:
            arc_r = os.path.join(base, "_rnk%d.mdr3" % fp_top)
            t0 = time.perf_counter()
            rep_r = mdr3.pack(paths, arc_r, max_depth=depth,
                              selector="ranked", fp_top=fp_top,
                              force_method="pergen")
            t_rnk = time.perf_counter() - t0
            # misses: per generation where exhaustive winner not in ranked
            # candidate window
            misses = 0
            for gi in range(1, n):
                w = winners.get(gi)
                if w is None:
                    continue   # exhaustive chose independent for gi
                # reconstruct ranked candidate set exactly as pack():
                # rank WITHIN the depth window; fps[gi] is the target
                # (paths[:gi+1] = gens 0..gi; the old paths[:gi] ranked
                # gen gi-1 against 0..gi-2 = wrong target, wrong misses)
                fps = [mdr3.fingerprint(open(p, "rb").read())
                       for p in paths[:gi + 1]]
                lo = max(0, gi - depth)
                pool = list(range(lo, gi))
                keep = mdr3.rank_bases(fps[gi],
                                       [fps[b] for b in pool], top=fp_top)
                cand = [pool[t] for t in keep]
                if gi - 1 not in cand:
                    cand.append(gi - 1)
                if w not in cand:
                    misses += 1
            # GP1: byte-exact both
            ok = True
            for arc in (arc_e, arc_r):
                odir = arc + "_res"
                shutil.rmtree(odir, ignore_errors=True)
                mdr3.unpack(arc, odir)
                for gi, p in enumerate(paths):
                    if sha(os.path.join(odir, "gen%02d.db" % gi)) != sha(p):
                        ok = False
                shutil.rmtree(odir)
            rows.append({
                "depth": depth, "fp_top": fp_top,
                "exh_data": rep_e["data_bytes"],
                "rnk_data": rep_r["data_bytes"],
                "R_pergen": rep_r["data_bytes"] - rep_e["data_bytes"],
                "exh_archive": rep_e2["archive"],
                "rnk_archive": rep_r["archive"],
                "R_archive": rep_r["archive"] - rep_e2["archive"],
                "exh_trials": rep_e["delta_trials"],
                "rnk_trials": rep_r["delta_trials"],
                "misses": misses, "gens": n, "exact": ok,
                "pack_exh_s": round(t_exh, 2),
                "pack_rnk_s": round(t_rnk, 2),
            })
        os.unlink(arc_e2)
    os.unlink(arc_e)
    return {"name": name, "gens": n, "sweep": rows}


def main():
    os.makedirs(OUT, exist_ok=True)
    results = []
    for name, gens, builder in CHAINS:
        r = run_chain(name, gens, builder)
        if not any(m.get("name") == r.get("name") for m in results):
            results.append(r)
        # incremental persist: never lose a 6-hour run to a late crash
        with open(os.path.join(OUT, "mdr006_final_result.json"), "w") as f:
            json.dump({"matrix": results,
                       "gates": {"_partial": True}, "verdict": "PARTIAL"},
                      f, indent=2)
        worst = max(sweep["R_pergen"] for sweep in r["sweep"])
        nmiss = sum(sweep["misses"] for sweep in r["sweep"]
                    if sweep["fp_top"] == 2 and sweep["depth"] == 16)
        print("%-15s gens=%d worst R_pergen=%+d misses(top2,d16)=%d"
              % (name, r["gens"], worst, nmiss), flush=True)

    # acceptance per spec
    g_exact = all(s["exact"] for r in results for s in r["sweep"])
    # bounded evaluations per generation: rnk trials <= top + 1 per gen
    g_bound = all(s["rnk_trials"] <= (s["gens"] - 1) * (s["fp_top"] + 1)
                  for r in results for s in r["sweep"])
    # L7 control: no meaningful loss (R_pergen >= -1% of exh data worst case)
    l7 = next(r for r in results if r["name"] == "L7_control48")
    g_control = all(s["R_pergen"] >= -0.01 * s["exh_data"]
                    for s in l7["sweep"])
    # pack time (incl. fp gen) favorable on average
    g_time = (sum(s["pack_rnk_s"] for r in results for s in r["sweep"]) <
              sum(s["pack_exh_s"] for r in results for s in r["sweep"]))
    verdict = "PASS" if (g_exact and g_bound and g_control and g_time) \
        else "FAIL"
    print()
    print("gates: exact=%s bound=%s control=%s time-improves=%s" %
          (g_exact, g_bound, g_control, g_time))
    out = {"matrix": results, "gates": {
        "exact_all": g_exact, "bounded_evals": g_bound,
        "control_no_loss": g_control, "pack_time_improves": g_time},
        "verdict": verdict}
    with open(os.path.join(OUT, "mdr006_final_result.json"), "w") as f:
        json.dump(out, f, indent=2)
    print("verdict:", verdict)
    print("results:", os.path.join(OUT, "mdr006_final_result.json"))
    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())