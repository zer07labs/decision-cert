> Study for item O1 of the [v1.1 draft](decision-certificate.v1.1.md). O1 was decided on
> 2026-11-08 as suggested below; see the draft's decision log.

# O1 study: the threshold grid on small tests (2026-11-08)

Produced by [`python/tools/study_grid.py`](../../python/tools/study_grid.py) (its docstring has the
full design), with seeds pinned so the table regenerates byte for byte:

```bash
cd python && uv run python tools/study_grid.py
```

## Design in brief

Synthetic cases where the truth is known exactly. Confidence is uniform on [0.5, 1], and a case is
wrong with probability beta · (1 − c), so the true selective error at a cut λ is beta · (1 − λ) / 2.
Every replicate draws an independent temperature split and threshold split of size n, runs the
reference issuer's `ltt` test (alpha 0.05, delta 0.1) under each grid rule, and scores the chosen
threshold against the truth. There are 1,000 replicates per row.

- **Scenarios.**
  - `easy`: beta 0.3; the best threshold answers 67%.
  - `hard`: beta 0.8; the best threshold answers 25%.
  - `none`: a constant 6% error, so no threshold is truly at or below alpha.
  - `segments`: two certified segments at delta / 3. Segment A is easy and three times as large;
    the row reports the hard segment B.
- **Rules.**
  - `fine/pooled` is v1.
  - `fine/own` keeps v1's cuts but starts each test at its own best temperature-split cut.
  - `coarse/*` uses 20 cuts at the temperature split's confidence quantiles (5% steps).
- **Validity columns.** `violations` is the share of replicates whose true error at the chosen
  threshold is above alpha; it must be at or below delta. `q90` and `q95` are quantiles of the true
  error across replicates, where abstaining on everything counts as 0; `q90` must be at or below
  alpha.

## Findings

1. **Every rule is valid.** No row has violations above 0.078 (delta is 0.1) or `q90` above 0.0496
   (alpha is 0.05). In `none`, at most 2.2% of replicates certify at all.
2. **The coarse grid buys no power.**
   - Below 1,000 cases it certifies at the same rate as v1.
   - At large n it answers fewer cases, because the 5% steps cannot reach the best threshold: `easy`
     at 10,000 answers 0.590 against 0.614, and `hard` 0.193 against 0.216.
   - Its lower violation rate is that slack, not better testing.
3. **A per-test start helps segments a little, at no cost in validity.**
   - Segment B certifies in 0.78 of replicates instead of 0.63 at n 3,000, and in 1.00 instead of
     0.96 at 10,000.
   - Violations and quantiles are unchanged, and without segments it is the same test as v1.
4. **On small tests the limit is the number of cases, not the grid.**
   - At n 300, `easy` certifies in about 31% of replicates under every rule, and `hard` in about 7%.
   - At n 100, almost never.
   - This is O4's question (how many labels a certificate needs), not O1's.

## What this suggests for O1 (adopted 2026-11-08)

- Adopt the per-test start: each certified segment and the remainder start at the cut with the
  smallest p-value on their own temperature-split cases. The list of cuts stays v1's.
- Do not coarsen the grid.
- Carry finding 4 into O4 as guidance on `n_cal`, using this table.

## Results

| scenario | n | rule | certified | coverage (best) | violations | q90 error | q95 error |
|---|---|---|---|---|---|---|---|
| easy | 100 | fine/pooled | 0.04 | 0.026 (0.67) | 0.012 | 0.0000 | 0.0000 |
| easy | 100 | coarse/pooled | 0.04 | 0.025 (0.67) | 0.012 | 0.0000 | 0.0000 |
| easy | 300 | fine/pooled | 0.31 | 0.135 (0.67) | 0.027 | 0.0380 | 0.0440 |
| easy | 300 | coarse/pooled | 0.30 | 0.129 (0.67) | 0.028 | 0.0368 | 0.0440 |
| easy | 1000 | fine/pooled | 0.87 | 0.411 (0.67) | 0.060 | 0.0473 | 0.0505 |
| easy | 1000 | coarse/pooled | 0.88 | 0.410 (0.67) | 0.044 | 0.0467 | 0.0496 |
| easy | 3000 | fine/pooled | 1.00 | 0.561 (0.67) | 0.078 | 0.0493 | 0.0514 |
| easy | 3000 | coarse/pooled | 1.00 | 0.543 (0.67) | 0.033 | 0.0483 | 0.0493 |
| easy | 10000 | fine/pooled | 1.00 | 0.614 (0.67) | 0.073 | 0.0496 | 0.0504 |
| easy | 10000 | coarse/pooled | 1.00 | 0.590 (0.67) | 0.017 | 0.0486 | 0.0490 |
| hard | 100 | fine/pooled | 0.00 | 0.000 (0.25) | 0.000 | 0.0000 | 0.0000 |
| hard | 100 | coarse/pooled | 0.00 | 0.000 (0.25) | 0.000 | 0.0000 | 0.0000 |
| hard | 300 | fine/pooled | 0.07 | 0.017 (0.25) | 0.023 | 0.0000 | 0.0369 |
| hard | 300 | coarse/pooled | 0.06 | 0.012 (0.25) | 0.016 | 0.0000 | 0.0291 |
| hard | 1000 | fine/pooled | 0.43 | 0.070 (0.25) | 0.036 | 0.0418 | 0.0470 |
| hard | 1000 | coarse/pooled | 0.43 | 0.067 (0.25) | 0.032 | 0.0404 | 0.0466 |
| hard | 3000 | fine/pooled | 0.91 | 0.160 (0.25) | 0.053 | 0.0471 | 0.0500 |
| hard | 3000 | coarse/pooled | 0.90 | 0.147 (0.25) | 0.030 | 0.0417 | 0.0485 |
| hard | 10000 | fine/pooled | 1.00 | 0.216 (0.25) | 0.075 | 0.0492 | 0.0506 |
| hard | 10000 | coarse/pooled | 1.00 | 0.193 (0.25) | 0.025 | 0.0414 | 0.0494 |
| none | 100 | fine/pooled | 0.01 | 0.007 (0.00) | 0.007 | 0.0000 | 0.0000 |
| none | 100 | coarse/pooled | 0.01 | 0.008 (0.00) | 0.008 | 0.0000 | 0.0000 |
| none | 300 | fine/pooled | 0.02 | 0.008 (0.00) | 0.017 | 0.0000 | 0.0000 |
| none | 300 | coarse/pooled | 0.02 | 0.011 (0.00) | 0.022 | 0.0000 | 0.0000 |
| none | 1000 | fine/pooled | 0.01 | 0.003 (0.00) | 0.014 | 0.0000 | 0.0000 |
| none | 1000 | coarse/pooled | 0.02 | 0.007 (0.00) | 0.021 | 0.0000 | 0.0000 |
| none | 3000 | fine/pooled | 0.01 | 0.001 (0.00) | 0.012 | 0.0000 | 0.0000 |
| none | 3000 | coarse/pooled | 0.01 | 0.001 (0.00) | 0.013 | 0.0000 | 0.0000 |
| none | 10000 | fine/pooled | 0.01 | 0.000 (0.00) | 0.011 | 0.0000 | 0.0000 |
| none | 10000 | coarse/pooled | 0.00 | 0.000 (0.00) | 0.003 | 0.0000 | 0.0000 |
| segments | 100 | fine/pooled | 0.00 | 0.000 (0.25) | 0.000 | 0.0000 | 0.0000 |
| segments | 100 | fine/own | 0.00 | 0.000 (0.25) | 0.000 | 0.0000 | 0.0000 |
| segments | 100 | coarse/pooled | 0.00 | 0.000 (0.25) | 0.000 | 0.0000 | 0.0000 |
| segments | 100 | coarse/own | 0.00 | 0.000 (0.25) | 0.000 | 0.0000 | 0.0000 |
| segments | 300 | fine/pooled | 0.01 | 0.002 (0.25) | 0.005 | 0.0000 | 0.0000 |
| segments | 300 | fine/own | 0.00 | 0.001 (0.25) | 0.002 | 0.0000 | 0.0000 |
| segments | 300 | coarse/pooled | 0.00 | 0.001 (0.25) | 0.002 | 0.0000 | 0.0000 |
| segments | 300 | coarse/own | 0.00 | 0.000 (0.25) | 0.001 | 0.0000 | 0.0000 |
| segments | 1000 | fine/pooled | 0.14 | 0.023 (0.25) | 0.005 | 0.0259 | 0.0359 |
| segments | 1000 | fine/own | 0.16 | 0.023 (0.25) | 0.005 | 0.0237 | 0.0330 |
| segments | 1000 | coarse/pooled | 0.14 | 0.022 (0.25) | 0.005 | 0.0216 | 0.0318 |
| segments | 1000 | coarse/own | 0.13 | 0.018 (0.25) | 0.002 | 0.0198 | 0.0301 |
| segments | 3000 | fine/pooled | 0.63 | 0.111 (0.25) | 0.023 | 0.0437 | 0.0467 |
| segments | 3000 | fine/own | 0.78 | 0.123 (0.25) | 0.023 | 0.0432 | 0.0463 |
| segments | 3000 | coarse/pooled | 0.60 | 0.099 (0.25) | 0.015 | 0.0402 | 0.0409 |
| segments | 3000 | coarse/own | 0.78 | 0.116 (0.25) | 0.014 | 0.0401 | 0.0408 |
| segments | 10000 | fine/pooled | 0.96 | 0.197 (0.25) | 0.023 | 0.0468 | 0.0484 |
| segments | 10000 | fine/own | 1.00 | 0.202 (0.25) | 0.023 | 0.0468 | 0.0484 |
| segments | 10000 | coarse/pooled | 0.95 | 0.173 (0.25) | 0.005 | 0.0404 | 0.0407 |
| segments | 10000 | coarse/own | 1.00 | 0.180 (0.25) | 0.005 | 0.0404 | 0.0407 |
