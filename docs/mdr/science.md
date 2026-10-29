# The Science Behind MDR

This document records the mathematical and physical reasoning behind MDR's
milestones — what was tried, what it exploited, and what the measurements
decided. It is a map of *why the shipped design is what it is*.

## 1. Problem statement

An SQLite file is a byte stream organized into fixed-size B-tree pages.
Archival storage of *collections* of such files — and successive snapshots of
the *same* database over time — is dominated by redundancy at different
scales:

1. **Byte-scale repetition**: records repeat field-wise (fixed-width text,
   sequential integer keys, page headers).
2. **Page-scale repetition**: whole pages recur (freelist, index interiors,
   repeated layouts).
3. **History-scale repetition**: snapshots differ by small deltas
   (new rows, updated values) while most pages are identical.

Generic compressors (zstd) exploit (1) partially and (3) not at all.
MDR's contribution is measuring *explicit reorderings* that make each layer's
redundancy reachable, and keeping whatever wins under honest accounting.

## 2. The MDR1 5D fold (research centerpiece, not promoted)

### Construction

A page-aligned stream is tiled into blocks of 8⁵ = 32,768 bytes (8 pages).
Each block is permuted by the **base-8 digit reversal**:

For byte index `i`, write `i = (d₀,d₁,d₂,d₃,d₄)₈` (five octal digits, least
significant first) and map it to

```
F(i) = (d₄,d₃,d₂,d₁,d₀)₈
```

Then `F(F(i)) = i`, so fold and unfold are literally the same function — an
**involution on Z/(8⁵)**. Applying `out[F(i)] = in[i]` transposes the block
regarded as a 5-dimensional tensor of shape 8×8×8×8×8, with axis 0 the
coarsest (page-level) coordinate: adjacent bytes in the output come from
input bytes 4096 apart, then 512 apart, and so on.

**Properties verified programmatically (mdr/core/mdr.py self-check):**

- `F` is a bijection on `[0, 8⁵)`: `sorted(F) = [0..8⁵)`.
- `F∘F = id`: exact reversal is an involution.
- Roundtrip through zstd-streamed framing is byte-exact on structured and
  random inputs; SHA-256 equality asserted.

### Why it *can* help compression

SQLite records in a table B-tree place the most repetitive field (the rowid,
fixed-width at a constant stride `r`) at byte positions `p₀ + m·r` inside a
page. Digit reversal with base 8 spreads positions that differ by 4096/r into
contiguity: the fold gathers "one byte from every page in the tile" into
output runs, so a low-entropy byte position across 8 pages becomes one
highly compressible run instead of `r`-strided noise. Formally, for a source
with `k` distinct per-position distributions, any reordering that groups equal
position classes together lowers the empirical match-finder cost
`L(Z(X))` — compression is about *rearranging* the data so its self-similarity
aligns with the matcher's window and step, not creating entropy.

### What the measurements decided (MDR-002 / MDR-003)

- Matched-wire trials on 23 fixtures: fold beats identity framing on
  structured fixtures (up to +362 KB on 1.7 MB of sequential ints), regresses
  14/23 (fragmented or small files).
- **Attribution gate**: the same benefit (and more) is available from an
  ordinary **byte-stride shuffle** that groups every k-th byte. On held-out
  fixtures the 5D fold won **0/8** vs. stride shuffle.
- Verdict: the *geometry* of "gather same-position bytes" is real and useful;
  the specific 5-dimensional realization is not superior to 1–2D field-wise
  shuffles. Higher dimensionality buys nothing measurable here. Fold remains
  in the research suite, excluded from the shipped selector (ADR-004).

**Honest framing**: MDR-002/003 demonstrate that *explicit, reversible
reordering* is worth measuring, and that *adaptive selection between candidate
layouts* is the load-bearing idea — a textbook information-theoretic result
(lifetime of a code: `L = min over layouts`), not a novel geometric law.

## 3. The MDR2 codec (shipped)

### Adaptive selection

For each segment `s` of the source, the selector computes

```
codec*(s) = argmin_c [ L(zstd(T_c(s))) + overhead(c) ]
```

over a portfolio `T_c` of reversible transforms:

| id | transform        | formula                                        |
|----|------------------|------------------------------------------------|
| 0  | stored           | identity (raw fallback, floors expansion)      |
| 1  | zstd             | identity + zstd                                |
| 2  | byte-shuffle     | `T(s)[i·m + j] = s[j·k + i]`, k = stride       |
| 3  | bit-shuffle      | 8×8 bit transpose per byte group               |
| 4  | page-split       | SQLite page headers/cell pointers vs payloads  |

All are bijections on the padded segment; `codec + param` (2 bytes) and
per-segment CRC-32 protect every choice, and every candidate is *actually
encoded* — no estimated-entropy shortcuts, so selection is exact with all
overhead charged.

The bit shuffle is the 8-dim (one axis per bit position) specialization of
the same gather idea from §2; the byte shuffle is the 1D restriction to
`GCD(r, …)`. Their consistent, reproducible advantage over the 5-fold on
held-out data is the empirical answer to "does higher dimensionality help?"

### Integrity and durability model

- Segment bodies CRC-32; whole archive SHA-256 in the footer.
- Footer (`magic, nseg, src_len, sha256`) written **last, after fsync** —
  the physical model is: crash-during-write can leave header+segments on
  disk but never a valid footer, so an incomplete archive is detectable
  rather than silently truncated.
- Unpacker bounds-checks every segment (codec identity, length, CRC) before
  decode, rejects unknown codecs, truncations, src_len blowups.

### Restore contracts

- **byte-exact** (default): `pack` reads bytes; `unpack` reproduces them
  with SHA-256 equality.
- **backup**: SQLite's online backup API captures a consistent database
  image while the source may be live. Physics/protocol note: the source can
  mutate between raw-read and backup-read, so the two captures need not be
  byte-identical; this contract guarantees *database-consistent* state
  (valid schema + data at one instant), not byte equality with a
  separately taken raw copy. This is the same guarantee SQLite's own
  `.backup`/VACUUM INTO provide.

## 4. Measured claims

Every number in the reports comes from executed code in
`benchmarks/mdr/` on recorded fixture sets, with the corpus named. Standing
results (see milestone reports for full tables):

- Fresh 11-db fleet: MDR2 = 4.56 MB vs zstd-19 = 8.33 MB on 55 MB raw
  (**45.2%** saving vs zstd-19 end-to-end).
- Random data control: MDR2 ≤ zstd, stored fallback; never worse than
  tiny fixed overhead (43 B on 1 MiB uniform).
- Corruption/truncation/codec-mismatch: 9/9 rejected, no false-accept.

**No fleet-wide or universal-compression claim is made.** Gains come from
layout regularity, which real databases may or may not have (GA8).

## 5. What MDR deliberately does not assume

- That higher-dimensional transforms are intrinsically better (refuted in
  MDR-003 on held-out data, retained as a lesson).
- That compression ratios transfer across workloads.
- That heuristic selectors are safe before their regret is measured
  (MDR-005 measures selection regret directly).
- That any transform is safe on arbitrary data (stored fallback guarantees
  a floor).

## 6. Future directions with a physical/mathematical basis

- **MDR3 temporal factorization**: compress the *history* `D₀..Dₙ` as
  `Dₜ = Restore(Bₜ, Δₜ)` with shared bases; exploits layer-3 redundancy
  (§1), which per-snapshot codecs cannot see. Bounded dependency chains and
  byte-exact out-of-order restore are the acceptance gates.
- **Read-only compressed VFS** (later): random access into an MDR2 archive
  as a read-only SQLite VFS with immutable-file semantics. Requires the
  archive's segment index to support page-granular seek (a decompression
  bound, since pages are not independently compressed).
- **Selection regret engineering**: replace exhaustive per-segment
  trial-encoding with a sampled heuristic selector, measuring
  `regret = L(fast) − L(exhaustive)` and throughput on the same corpus.