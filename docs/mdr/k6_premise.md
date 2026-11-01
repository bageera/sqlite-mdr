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