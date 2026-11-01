# MDR K6-0: Sub-page cross-snapshot reuse — premise + baseline registration

Status: PREMISE ESTABLISHED (measured 2026-10-31). This doc records the
motivating measurement, the baseline line K6 must beat, and the B0/B1/K6
arm definitions. No engine code changes yet.

## Premise: logical similarity does not imply page similarity

Fixture: db with 8,000 rows x 700B opaque payloads (seeded random), page
size 4096; DELETE 1/3 of rows; VACUUM into a second snapshot. Logical
content identical (50/50 sampled rows byte-identical across pair).

Measured (census, not archive savings) — script-reproduced numbers:

- Exact 4KiB page reuse: 0/1072 pages, 0 identical 64KiB / 32KiB chunks.
- Stripe-indexed near-match: 0.09% of pages (1/1072) have a best page
  match with <128B residual. Residual histogram: ~50% of pages at 1-3KB
  differing bytes, ~50% no stripe hit. Page-reference-page carries a
  1-3KB residual on half of all vertices — barely beats raw at 4KiB.
- 32B block census (stride 32, exact): post-in-pre 29.7%, pre-in-post
  24.0%. Asymmetric because 1/3 of rows were deleted; the files differ in
  size and block distribution.

Probe correction (recorded for the record): the first inline measurement
of this census read 51.8% pre-in-post and 0.2% near-match — that run had
accidentally VACUUMed the source file in place and then measured a
double-vacuumed pair (a near-identical-file artifact). The committed
script builds the pair fresh (delete -> copy -> single VACUUM) and all
numbers above are from that reproducible run. Measure from the script,
not from interactive probes.

Conclusion: VACUUM preserves records but rewrites cell packing, order,
and page assignment. Reusable bytes survive as SUB-PAGE fragments. K6
operates at byte-range granularity, not page vertices.

## The wall: baseline line on the motivating pair

| Arm | Definition | Archive bytes (pair) |
| --- | --- | --- |
| B0 | mdr3 pack [pre, post] selector=ranked (dedup method, exact restore both gens) | 5,676,032 |
| B1 | zstd-19(pre) + zstd-19 --patch-from(pre) post, roundtrip-exact | 5,673,280 |

B1 = generic historical LZ with whole-file dictionary window. K6's
registered question: does SQLite-page-aware, fingerprint-pruned matching
structure + exact picker accounting beat this generic window?

Margin available: 2,752 bytes on this pair (0.05%). K6 must win by MORE
than its own metadata overhead, on at least one HELD-OUT chain, or the
graph arm closes as a negative result (kill criterion below).

Interpretation warning: B1's patch file is tiny (23,105B) only because
zstd --patch-from compresses literals with zstd-19 and reuses the
window; the whole-file window subsumes coarse relocation. The K6 arm's
only room to win is finding profitable sub-window structure the LZ
window charges for, or charged-accounting overhead the LZ arm pays and a
page-bounded arm avoids. This margin is the narrowest in MDR history;
treat the kill criterion as live from the start.

Honesty notes:

- These are actual archive bytes (CLI + mdr3 pack), not entropy estimates.
- A 32B match is not automatically profitable: at ~12B instruction cost the
  gross saving cap is 20B. Match profit = extended_len - charged_instr.
- The K6 encoder must charge: literals + references + reference metadata +
  framing. Archive-wide comparison includes shared-base and index bytes.

## Arms

- B0: incumbent. mdr3 (dedup + MDR2 segment portfolio), selector=ranked.
  Promotion gate compares complete-archive bytes, same history input.
- B1: control against "K6 wins only by finer-grained LZ". zstd CLI
  --patch-from with -19 on the same ordered history (per generation:
  compress generation t with archive-pooled history as patch dictionary).
  No SQLite page awareness, no fingerprint pruning.
- K6: page-bounded, shingle-indexed, sub-page historical byte-range
  references, wired as a third METHOD in the mdr3 picker with fully
  charged metadata, per K6-G3/G8. Strictly historical refs only (s < t,
  and within a page only ranges from earlier generations) => acyclic by
  construction; no general forest solver; bounded candidate search.

## Acceptance gates (registered)

- K6-G1: every snapshot reconstructs byte-exactly.
- K6-G2: references strictly historical (s < t), depth-bounded.
- K6-G3: complete actual archive-byte accounting (literals + refs + meta +
  framing); decomposition assert: ledger == emitted bytes.
- K6-G4: comparison against dedup and pergen on identical histories.
- K6-G5 (amended): nonidentical-page, sub-1024B reuse demonstrated on
  HELD-OUT data (page-level-only reuse does not exist per K6-0).
- K6-G6: pack wall time and peak memory measured (ru_maxrss KB on macOS /
  KB on Linux: normalize the unit before reporting).
- K6-G7: corrupt and missing reference rejected; oversized claims rejected
  before allocation (MDR3 tamper discipline).
- K6-G8: picker = exact argmin over complete-archive candidates including
  K6 metadata; standalone K6 losses reported per-workload.

## Kill criterion (preregistered)

Close the graph arm as a NEGATIVE RESULT if K6 does not achieve

    L_K6 < L_dedup+MDR2

on at least one held-out chain, by more than K6's incremental metadata
cost, with both totals as actual final archive bytes (overhead already
included in both totals; report gross reuse saving and incremental
metadata separately so the margin is visible).

Also report the B1 comparison as an attribution question (does the
SQLite-aware structure add value over generic windowed LZ?), not a
second promotion gate.

## What K6 is NOT

- Not a page-vertex graph / minimum directed forest solver (strictly
  historical refs make decode order trivial and cycles impossible).
- Not a braid or fixed-permutation arm (that family is closed).
- Not a claim about VACUUM-specific tuning: the arm must win on held-out
  chains the match finder never saw.

## K6-4 HELD-OUT RESULT (PROMOTED) — 2026-11, closed GREEN

Corpus: 8 chains x 5 snapshots, seed literals committed in k64_gate.py
(dev-pair constants deliberately absent from held-out seeds). Frozen
reference implementation: 08d5880fa + ac8dcbb4f + bf46d7821. Full rows in
benchmarks/mdr/out/k64_result.json; gate: benchmarks/mdr/k64_gate.py.

| Chain | Profile | B0 | B1 | K6 | d0 (B0-K6) | d1 (B1-K6) | K6 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| H1 | 250B rows, delete 1/4 | 1,449,802 | 1,448,417 | 1,445,272 | +4,530 | +3,145 | WIN |
| H2 | 1400B rows, delete 1/2 | 9,053,578 | 8,425,098 | 8,389,346 | +664,232 | +35,752 | WIN |
| H3 | 90B rows, delete 1/9, shuffled | 515,711 | 517,548 | 529,208 | -13,497 | -11,660 | LOSS |
| H4 | 300B rows, index churn | 1,749,296 | 1,747,911 | 1,746,642 | +2,654 | +1,269 | WIN |
| H5 | 120B rows, reverse insert | 675,070 | 676,170 | 671,453 | +3,617 | +4,717 | WIN |
| H6 | 60B rows, delete 1/2 | 331,866 | 333,286 | 368,322 | -36,456 | -35,036 | LOSS |
| C1 | compressible control | 158,282 | 157,326 | 174,550 | -16,268 | -17,224 | LOSS |
| R1 | random control | 4,179,558 | 4,179,903 | 4,172,355 | +7,203 | +7,548 | WIN |

Verdict: PASS on the preregistered kill criterion (K6 < B0 on >=1
held-out chain, margin >> K6 metadata). K6 beats BOTH B0 and B1 on 5/8
chains incl. the random control; per-chain evidence is primary (the H2
win dominates any fleet aggregate; never quote a fleet-wide % alone).

Loss classes (regression classes, preserved, not hidden):
- H3/H6 dense small rows: churn stays inside shared 64KiB chunks; dedup
  absorbs it at ID cost while K6 pays per-ref overhead on many small
  fragments. Dedup's home turf.
- C1 compressible: ordinary compression already fits; references add
  nothing.

The adaptive picker protects the loss classes BY CONSTRUCTION: candidates
are serialized and argmin'd over measured bytes, so a losing K6 candidate
is never the stored archive (G8 verified per chain).

Gate corrections made during the run (recorded, no threshold edits):
- K6 decoder returned codec-4 (D3) literal bodies page-transformed
  (self-checks missed it: dev fixtures never picked D3); fixed with
  declared raw lens (ac8dcbb4f + bf46d7821).
- G8 gate bug: candidate min initially included B1, which the mdr3 picker
  cannot emit; corrected to implemented methods only with pergen measured
  per chain (0966f1d30). B1 remains the standing external attribution
  baseline, never a picker candidate.

## K6-5 CLOSURE (promotion record)

- K6D1 wire semantics FROZEN at the ac8dcbb4f+bf46d7821 layout: magic
  "K6D1" | u64 base_union_len | u16 n_bases | u32 opb_len/litb_len |
  u32 ops_raw/lits_raw (declared raw body lens; required by trim) |
  n_bases x u32 base_ids | opb segment | litb segment. Literal/copy varint
  op stream tiles the target; strictly historical bases only.
- K6 promoted to the default candidate portfolio (serialized argmin over
  dedup/pergen/k6). force_method pins and exhaustive diagnostics remain.
- Decode obligations frozen: D3 page-join for codec-4 bodies; trim to
  declared raw lens; copy bounds checked before application; manifest sha
  verification at restore.
- Hybrid dedup+K6 per-generation items: DEFERRED to a separately gated
  milestone (K6-7 class); do not mutate the frozen wire for it. New
  hypotheses require new item grammar and new gates.
- Next research direction: packing-cost reduction via cheap fingerprints /
  candidate reuse to skip K6 trial-encoding when predicted unprofitable,
  with archive regret measured against the fully emitted minimum
  (exhaustive portfolio retained as the quality reference, mirroring
  MDR-006).