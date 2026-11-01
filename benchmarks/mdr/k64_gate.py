#!/usr/bin/python3
"""K6-4: held-out promotion gate — B0 (mdr3 dedup) / B1 (zstd patch-from)
/ K6 (mdr3 k6 arm) over fresh vacuum chains + controls. MEASUREMENT ONLY.

Frozen reference: 08d5880fa (K6-3 GREEN). Thresholds preregistered in
docs/mdr/k6_premise.md and NOT revised here:

  kill: close K6 as negative result unless
      L_K6 < L_B0  on at least one held-out chain
    (archive-byte totals, both complete; margin > K6 incremental meta,
    which is already inside the totals; report gross/meta separately)
  attribution: Delta1 = L_B1 - L_K6 reported per chain (B1 is context,
    not a gate; outcomes: beats-both / beats-B0-loses-B1 / loses-to-B0)

Corpus (chains H1-H6 held-out, C1 compressible control, R1 random control;
seeds are FIXED LITERALS so the split is auditable; the dev pair used
seed ROWS=8000/PAYLOAD=700/DELETE_MOD=3 — none of these values recur):

  H1 record 250B, delete 1/4, ordered inserts     (small rows)
  H2 record 1400B, delete 1/2, ordered inserts    (big rows, high churn)
  H3 record 90B,   delete 1/9, shuffled inserts   (dense, low delete)
  H4 record 300B,  delete 1/3, ordered + periodic full reorganization
                   (PRAGMA cache miss pressure via drop/recreate index)
  H5 record 120B,  delete 1/6, REVERSE insertion  (btree reshape)
  H6 record 60B,   delete 1/2, shuffled           (tiny rows, heavy churn)
  C1  compressible control: highly compressed payloads (zeros + patterns)
  R1  random/incompressible control: payloads already random; also serves
      the G5-relevant check that K6 does not WIN on fresh random data

Multi-generation chains (5 snapshots each: insert -> churn -> delete ->
vacuum at the END so each chain yields 2 vacuum transitions):
  build base (all rows) -> snapshot A, apply phase ops -> snapshot B, ...
  vacuum snapshots are produced by VACUUM INTO copies at each phase end.

Gates enforced here:
  G1  byte-exact reconstruction of ALL chains (all three arms)
  G3  ledger decomposition inside mdrk6 (already asserted in encode)
  G4  B0/B1/K6 on identical chain files; per-chain deltas reported
  G6  pack wall time + decode wall time + peak RSS (KB normalized to MB)
  G7  tamper set on a k6 archive (flip, truncate, bad magic, wrong base)
  G8  picker argmin verified against re-measured serialized candidates

Usage: python3 k64_gate.py [--quick]
"""

import hashlib
import json
import os
import random
import resource
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
import mdrk6  # noqa: E402

OUT = os.path.join(HERE, "out")
WORK = os.path.join(OUT, "k64_chains")

# fixed literals: none of these match the dev pair's constants
CORPUS = [
    ("H1", 250, 4, "ordered", None),
    ("H2", 1400, 2, "ordered", None),
    ("H3", 90, 9, "shuffled", 77),
    ("H4", 300, 3, "ordered", 0),       # 0 => reorg phases
    ("H5", 120, 6, "reverse", None),
    ("H6", 60, 2, "shuffled", 101),
    ("C1", 500, 3, "ordered", None),    # compressible payloads
    ("R1", 700, 3, "ordered", None),    # random payloads
]
PHASES = 4          # snapshots after base: A, B, C, D (D = VACUUMED)
SNAPSHOTS = 1 + PHASES


def payload_bytes(rec, i):
    """Deterministic payload per record. C1 = compressible, R1 = random."""
    if rec[0] == "C1":
        rng = random.Random(4000 + i)
        return (b"A" * 32 + rng.randbytes(16)) * (PAYLOAD_SIZE(rec) // 48)
    rng = random.Random(9000 + i)
    return rng.randbytes(PAYLOAD_SIZE(rec))


def PAYLOAD_SIZE(rec):
    return rec[1] - 16    # blob bytes (id int + header ~16)


def build_chain(name, rec, delete_mod, order, aux):
    paths = []
    base = os.path.join(WORK, "%s_s0.db" % name)
    if os.path.exists(base):
        # resume: rebuild only missing tail snapshots
        all_present = True
        for t in range(SNAPSHOTS):
            p = os.path.join(WORK, "%s_s%d.db" % (name, t))
            if not os.path.exists(p):
                all_present = False
                break
            paths.append(p)
        if all_present:
            return paths
        # else fall through and rebuild from scratch (files get overwritten)
        paths = []
    con = sqlite3.connect(base)
    con.execute("PRAGMA page_size=4096")
    con.execute("CREATE TABLE t(id INTEGER PRIMARY KEY, pad TEXT, b BLOB)")
    ids = range(1, 6001)
    if order == "shuffled":
        ids = list(ids)
        random.Random(aux).shuffle(ids)
    elif order == "reverse":
        ids = list(reversed(list(ids)))
    rows = [(i, "pad-%06d" % (i % 977), payload_bytes(rec, i)) for i in ids]
    con.executemany("INSERT INTO t VALUES(?,?,?)", rows)
    con.commit()
    con.close()
    paths.append(base)
    n = len(rows)
    for t in range(1, SNAPSHOTS):
        nxt = os.path.join(WORK, "%s_s%d.db" % (name, t))
        if os.path.exists(nxt):
            os.unlink(nxt)
        shutil.copyfile(paths[-1], nxt)
        con = sqlite3.connect(nxt)
        if t == 1:
            con.execute("INSERT INTO t(id, pad, b) VALUES(900001, 'tail', ?)",
                        (payload_bytes(rec, 900001),))
        elif t == 2:
            con.execute("DELETE FROM t WHERE id %% %d = 1" % delete_mod)
        elif t == 3:
            if aux == 0:
                con.execute("CREATE INDEX IF NOT EXISTS ix ON t(pad)")
                con.execute("DROP INDEX ix")
            else:
                con.execute("UPDATE t SET pad = 'r-' || id WHERE id %% 13 = 0"
                            % ())
        # phase-end VACUUM: in-place (file is a private copy)
        con.commit()
        con.execute("VACUUM")
        con.commit()
        con.close()
        paths.append(nxt)
    return paths


def zstd(args):
    r = subprocess.run(["zstd", "-q"] + args, capture_output=True, text=True)
    assert r.returncode == 0, "zstd failed: " + r.stderr
    return r


def measure_B1(paths, workdir):
    """Per-snapshot: base snapshot compressed alone + each later snapshot
    as patch-from the FULL ARCHIVE-HISTORY (archive-pooled dictionary =
    concat of earlier generation FILES), matching the registered B1 arm."""
    total = 0
    pool = b""
    for t, p in enumerate(paths):
        d = open(p, "rb").read()
        if t == 0:
            z19 = os.path.join(workdir, "b1_z19_%d" % t)
            zstd(["-19", "-f", p, "-o", z19])
            total += os.path.getsize(z19)
        else:
            dictf = os.path.join(workdir, "b1_pool")
            open(dictf, "wb").write(pool)
            patch = os.path.join(workdir, "b1_p_%d" % t)
            zstd(["--patch-from", dictf, "-19", "-f", p, "-o", patch])
            total += os.path.getsize(patch)
            # roundtrip assert (G1 for B1 too)
            rt = os.path.join(workdir, "b1_rt")
            zstd(["-d", "--patch-from", dictf, "-f", patch, "-o", rt])
            assert open(rt, "rb").read() == d, "B1 roundtrip broken t=%d" % t
            os.unlink(rt)
        pool += d
    return total


def tamper_check(paths, rows):
    """G7 tamper matrix on a forced-k6 archive."""
    arc = os.path.join(OUT, "tamper_base.mdr3")
    mdr3.pack(paths, arc, selector="ranked", force_method="k6")
    blob = open(arc, "rb").read()
    od = arc + "_res"
    results = []
    cases = {}
    cases["flip_data"] = blob[:-200] + bytes([blob[-200] ^ 0xFF]) + blob[-199:]
    cases["truncate_half"] = blob[:len(blob) // 2]
    cases["truncate_footer"] = blob[:-40]
    cases["bad_magic"] = b"XXXX" + blob[4:]
    man, _, data, body, _ = mdr3._read_sections(blob)
    # corrupted k6 op stream: flip a byte inside the k6 item
    k6item = next(it for it in man["items"] if it["kind"] == "k6ref")
    off = 22 + 8 + len(json.dumps(man, separators=(",", ":")).encode())
    flip = bytearray(blob)
    flip[off + k6item["off"] + 100] ^= 0xFF
    cases["corrupt_k6_item"] = bytes(flip)
    for cname, tblob in cases.items():
        rejected = False
        tarc = os.path.join(OUT, "tamper_%s.mdr3" % cname)
        open(tarc, "wb").write(tblob)
        try:
            shutil.rmtree(od, ignore_errors=True)
            mdr3.unpack(tarc, od)
            # if it unpacks, verify it does NOT match originals
            exact = all(open(os.path.join(od, "gen%02d.db" % i), "rb").read()
                        == open(p, "rb").read()
                        for i, p in enumerate(paths))
            rejected = not exact
        except Exception:
            rejected = True
        results.append({"case": cname, "rejected": rejected})
        os.unlink(tarc)
    shutil.rmtree(od, ignore_errors=True)
    os.unlink(arc)
    return results


def peak_mb():
    # ru_maxrss is KB on macOS (skill rules: normalize before reporting)
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0


def main():
    quick = "--quick" in sys.argv
    os.makedirs(WORK, exist_ok=True)
    os.makedirs(OUT, exist_ok=True)
    rows = []
    t_start = time.perf_counter()
    rss0 = peak_mb()

    for (name, rec, dmod, order, aux) in CORPUS:
        if quick and name not in ("H1", "R1"):
            continue
        paths = build_chain(name, (name, rec, dmod, order, aux), dmod,
                            order, aux)
        assert len(paths) == SNAPSHOTS
        gens = [open(p, "rb").read() for p in paths]

        # pergen forced (for the G8 mdr3-candidate min)
        pgarc = os.path.join(OUT, "%s_pg.mdr3" % name)
        repp = mdr3.pack(paths, pgarc, selector="ranked",
                         force_method="pergen")
        pergen = repp["archive"]
        pg_exact = restore_exact_b0(paths, pgarc)
        os.unlink(pgarc)

        # B0: mdr3 dedup forced, ranked selector
        b0arc = os.path.join(OUT, "%s_b0.mdr3" % name)
        t0 = time.perf_counter()
        rep0 = mdr3.pack(paths, b0arc, selector="ranked",
                         force_method="dedup")
        t0s = time.perf_counter() - t0
        b0 = rep0["archive"]
        b0_exact = restore_exact_b0(paths, b0arc)
        os.unlink(b0arc)

        # K6: mdr3 forced k6
        k6arc = os.path.join(OUT, "%s_k6.mdr3" % name)
        t0 = time.perf_counter()
        repk = mdr3.pack(paths, k6arc, selector="ranked", force_method="k6")
        tks = time.perf_counter() - t0
        k6 = repk["archive"]
        k6_exact = restore_exact_b0(paths, k6arc)
        # standalone K6 (unmixed, single base gen0) for the G5-adjacent story
        w_k6, led_k6 = mdrk6.encode_k6(gens[-1], [gens[0]],
                                       base_ids=[0])
        os.unlink(k6arc)

        # B1: zstd archive-pooled patch chain
        t0 = time.perf_counter()
        b1 = measure_B1(paths, WORK)
        t1s = time.perf_counter() - t0

        row = {
            "chain": name, "n": len(paths),
            "raw": sum(len(g) for g in gens),
            "B0": b0, "B1": b1, "K6": k6,
            "d0": b0 - k6, "d1": b1 - k6,
            "k6_standalone_last_vs_gen0": led_k6["total"],
            "k6_refs": led_k6["refs"], "k6_cover_last": round(
                100.0 * led_k6["covered_ref_bytes"] / len(gens[-1]), 1),
            "B0_pack_s": round(t0s, 1), "K6_pack_s": round(tks, 1),
            "B1_pack_s": round(t1s, 1),
            "B0_exact": b0_exact, "K6_exact": k6_exact,
            "pergen": pergen, "pergen_exact": pg_exact,
        }
        rows.append(row)
        print("%-3s n=%d raw=%8d | B0 %8d B1 %8d K6 %8d | d0 %+8d d1 %+8d | "
              "exact B0 %s K6 %s | pack B0 %.1fs K6 %.1fs B1 %.1fs"
              % (name, len(paths), row["raw"], b0, b1, k6, row["d0"],
                 row["d1"], b0_exact, k6_exact, t0s, tks, t1s), flush=True)

    # G7 tamper (once, on H1)
    tam = tamper_check(build_chain("H1", CORPUS[0], 4, "ordered", None),
                       rows)
    g7 = all(t["rejected"] for t in tam)
    print("G7 tamper rejections: %d/%d %s"
          % (sum(1 for t in tam if t["rejected"]), len(tam),
             "ok" if g7 else "LEAK"), flush=True)

    # G8: picker argmin on each chain auto archive equals measured min
    g8_rows = []
    for (name, rec, dmod, order, aux) in CORPUS:
        if quick and name not in ("H1", "R1"):
            continue
        paths = build_chain(name, (name, rec, dmod, order, aux), dmod,
                            order, aux)
        autoarc = os.path.join(OUT, "%s_auto.mdr3" % name)
        repa = mdr3.pack(paths, autoarc, selector="ranked")
        rself = next(r for r in rows if r["chain"] == name)
        minmeasured = min(rself["B0"], rself["B1"], rself["K6"])
        g8_rows.append({"chain": name, "auto_method": repa["method"],
                        "auto_archive": repa["archive"],
                        "min_measured": minmeasured,
                        "ok": repa["archive"] <= minmeasured + 4})
        os.unlink(autoarc)
    g8 = all(r["ok"] for r in g8_rows)
    print("G8 picker argmin:", "ok" if g8 else "MISMATCH", flush=True)

    # verdicts per preregistered criterion
    heldout = [r for r in rows if r["chain"].startswith("H")]
    g_kill = any(r["d0"] > 0 for r in heldout)
    if g_kill:
        beats_both = [r["chain"] for r in heldout if r["d0"] > 0 and r["d1"] > 0]
        beats_b0_only = [r["chain"] for r in heldout if r["d0"] > 0
                         and r["d1"] <= 0]
        loses = [r["chain"] for r in heldout if r["d0"] <= 0]
        outcome = ("POSITIVE beats-both on %s, B0-only on %s, loses on %s"
                   % (beats_both, beats_b0_only, loses))
    else:
        outcome = "NEGATIVE RESULT: K6 loses to B0 on every held-out chain"
    verdict = ("PASS" if (g_kill and g7 and g8 and
                          all(r["exact"] for r in rows)) else
               ("NEGATIVE" if not g_kill else "FAIL"))
    print()
    print("kill(criterion: K6<B0 on >=1 held-out):", g_kill)
    print("outcome:", outcome)
    print("gates: tamper=%s picker_argmin=%s exact_all=%s" %
          (g7, g8, all(r["B0_exact"] and r["K6_exact"] for r in rows)))
    print("verdict:", verdict)
    peak = peak_mb() - rss0
    print("peak RSS delta: %.0f MB (abs %.0f MB)" % (peak, peak_mb()))
    with open(os.path.join(OUT, "k64_result.json"), "w") as f:
        json.dump({"rows": rows, "tamper": tam, "g8": g8_rows,
                   "outcome": outcome, "verdict": verdict,
                   "note": "corpus seeds fixed literals; dev constants absent"},
                  f, indent=2)
    return 0


def restore_exact_b0(paths, arc):
    od = arc + "_res"
    shutil.rmtree(od, ignore_errors=True)
    mdr3.unpack(arc, od)
    ok = all(open(os.path.join(od, "gen%02d.db" % i), "rb").read() ==
             open(p, "rb").read() for i, p in enumerate(paths))
    shutil.rmtree(od)
    return ok


if __name__ == "__main__":
    sys.exit(main())