> A study of where the `ltt` fixed sequence starts. It is not tied to an open item. It is input for the next spec draft, and
> the owner decides.

# Start-selection study: where the `ltt` fixed sequence starts, on small tests (2026-11-11)

Produced by [`python/tools/study_start.py`](../../python/tools/study_start.py) (its docstring has the full design). Seeds are
pinned, so the table regenerates byte for byte:

```bash
cd python && uv run python tools/study_start.py
```

The table below is that command's output (2,000 replicates per row). It ran in CI, not on a workstation.

## Why

A field case: a credit-approval scorer on public HMDA rows, with 500 cases in each split at alpha 0.1 and delta 0.1, certified
nothing. The reference issuer's start, the cut with the smallest p-value on the temperature split, answered 122 cases there
with 2 errors. On the threshold split the same cut answered 151 with 12, so the sequence stopped at its first step. Meanwhile
a stricter cut (confidence ≥ 0.95, 109 cases, 5 errors) would have rejected on the threshold split if the sequence had
reached it. That raises the question of whether the argmin-p start is too noisy at this size, and whether a different
valid start rule would certify more often without losing validity.

## Design in brief

- **Synthetic cases where the truth is known exactly.**
  - Confidence is uniform on [0.5, 1], and a case is wrong with probability f(c).
  - Each replicate draws independent temperature and threshold splits of size n (250, 500 and 1,000).
  - It runs every rule on the same draw at alpha 0.1 and delta 0.1, and scores the chosen threshold against the true
    selective error.
- **Worlds.**
  - `calibrated`: f = 1 − c; the best threshold answers 40%.
  - `quarter`: f = (1 − c) / 4; every threshold is valid.
  - `near-alpha`: f = 0.13 below c 0.97 and 0 above. Error sits near alpha through most of the confident range, as in the
    field case; the best threshold answers 26%.
  - `above`: a constant 12%, so any certificate is a violation.
- **Rules.**
  - `argmin-p`: the reference issuer.
  - `min-n`: one sequence from the strictest cut with at least `n_min` (22) temperature-split cases, chosen without labels.
  - `bonf4`: four sequences at delta / 4, starting at argmin-p and at 10%, 25% and 50% temperature-split coverage, taking
    the loosest cut reached.
  - `grid20`: 20 quantile cuts, each tested alone at delta / 20 (Bonferroni).
- **Validity.** `violations` (the share of replicates whose chosen threshold has true error above alpha) must be at or below
  delta. `q90` of the true error, with abstaining on everything counted as 0, must be at or below alpha.

## Findings

1. **Every rule is valid in every world and size.**
   - The largest violation rate is 0.071 (argmin-p, `calibrated`, n 1,000) against delta 0.1. No `q90` is above alpha.
   - In `above`, every rule certifies in at most 1.8% of replicates.
   - Validity is not what separates the rules.
2. **The reference issuer's argmin-p start is the most powerful rule in almost every row.**
   - Its mean coverage is the highest in all 9 (world, n) rows that have a valid threshold. It ties `min-n` in
     `near-alpha` at n 250.
   - Its certify rate is the highest in 7 of the 9:
   - `near-alpha`, n 500: it certifies 0.580 against `min-n` 0.517, `bonf4` 0.234 and `grid20` 0.041.
   - `calibrated`, n 500: 0.659 against 0.536 (`bonf4`), 0.378 and 0.271.
   - The two exceptions are both at n 250: `near-alpha`, where `min-n` certifies 0.130 against 0.105, and `quarter`,
     where `bonf4` certifies 0.939 against 0.936 but covers 0.779 against 0.883.
   - The noise in the start is real, but a valid way around it costs more power than it saves.
3. **The multi-start rule (`bonf4`) does not pay at small n.**
   - Splitting delta four ways makes each sequence's test stricter. It certifies less than argmin-p at n 250 and 500, and
     roughly matches it at n 1,000 (0.910 against 0.938 in `calibrated`).
   - It is the most conservative of the sequence rules: its violations are at most 0.018.
4. **A labels-free strict start (`min-n`) stops early when the top is not clean.**
   - At the strictest rejectable cut, one error among 22 cases fails the test.
   - In `quarter` it certifies only about half the time even at n 1,000, where every threshold is valid.
5. **Bonferroni over a coarse grid (`grid20`) is the most conservative.** It is valid, with violations at most 0.005, but
   it gives up most of the power below n 1,000.
6. **The field case is a sample-size question, not a start-rule defect.**
   - In `near-alpha` at n 500, the reference issuer certifies nothing in 42% of replicates. At n 1,000 that falls to 7%.
   - A certificate that certifies nothing is the fail-closed outcome and never a violation.
   - Below about 1,000 cases per split, a model whose error sits near alpha through most of its confident range should
     expect "certifies nothing" often. That is O4's guidance on `n_cal`.

## Input for the next spec draft

- **Keep the argmin-p start.** None of the valid alternatives studied here certifies more often at n 250–1,000, and all of
  them are valid only by paying power.
- **Add guidance, not a field.** In the docs on how many labelled cases to collect, say that the near-alpha case at 500 per
  split certifies nothing about 4 times in 10, and about 1 in 14 at 1,000.
- **Optional, descriptive only:** an issuer diagnostic that reports the start cut's counts on both splits when the sequence
  stops at step 0. It would let an operator see "the start failed on the threshold split" without rerunning. It changes no
  certificate field.
- This study does not cover segments (O1's study did) or alpha other than 0.1.

## Results

| world | n | rule | certified | nothing | coverage (best) | violations | mean error (certified) | q90 error | worst error |
|---|---|---|---|---|---|---|---|---|---|
| calibrated | 250 | argmin-p | 0.323 | 0.677 | 0.085 (0.40) | 0.029 | 0.0655 | 0.0769 | 0.1529 |
| calibrated | 250 | min-n | 0.277 | 0.724 | 0.055 (0.40) | 0.013 | 0.0496 | 0.0524 | 0.1529 |
| calibrated | 250 | bonf4 | 0.194 | 0.806 | 0.048 (0.40) | 0.006 | 0.0620 | 0.0602 | 0.1310 |
| calibrated | 250 | grid20 | 0.044 | 0.956 | 0.012 (0.40) | 0.002 | 0.0660 | 0.0000 | 0.1089 |
| calibrated | 500 | argmin-p | 0.659 | 0.341 | 0.173 (0.40) | 0.051 | 0.0655 | 0.0906 | 0.1351 |
| calibrated | 500 | min-n | 0.378 | 0.623 | 0.073 (0.40) | 0.025 | 0.0484 | 0.0707 | 0.1348 |
| calibrated | 500 | bonf4 | 0.536 | 0.464 | 0.119 (0.40) | 0.009 | 0.0555 | 0.0745 | 0.1272 |
| calibrated | 500 | grid20 | 0.271 | 0.730 | 0.055 (0.40) | 0.001 | 0.0504 | 0.0542 | 0.1186 |
| calibrated | 1000 | argmin-p | 0.938 | 0.062 | 0.278 (0.40) | 0.071 | 0.0741 | 0.0962 | 0.1301 |
| calibrated | 1000 | min-n | 0.468 | 0.532 | 0.117 (0.40) | 0.036 | 0.0623 | 0.0868 | 0.1288 |
| calibrated | 1000 | bonf4 | 0.910 | 0.090 | 0.226 (0.40) | 0.014 | 0.0621 | 0.0846 | 0.1236 |
| calibrated | 1000 | grid20 | 0.764 | 0.236 | 0.152 (0.40) | 0.001 | 0.0496 | 0.0704 | 0.1113 |
| quarter | 250 | argmin-p | 0.936 | 0.064 | 0.883 (1.00) | 0.000 | 0.0589 | 0.0625 | 0.0625 |
| quarter | 250 | min-n | 0.462 | 0.538 | 0.369 (1.00) | 0.000 | 0.0500 | 0.0625 | 0.0625 |
| quarter | 250 | bonf4 | 0.939 | 0.061 | 0.779 (1.00) | 0.000 | 0.0519 | 0.0625 | 0.0625 |
| quarter | 250 | grid20 | 0.853 | 0.147 | 0.671 (1.00) | 0.000 | 0.0492 | 0.0624 | 0.0625 |
| quarter | 500 | argmin-p | 1.000 | 0.000 | 0.994 (1.00) | 0.000 | 0.0622 | 0.0625 | 0.0625 |
| quarter | 500 | min-n | 0.506 | 0.494 | 0.472 (1.00) | 0.000 | 0.0583 | 0.0625 | 0.0625 |
| quarter | 500 | bonf4 | 1.000 | 0.000 | 0.972 (1.00) | 0.000 | 0.0608 | 0.0625 | 0.0625 |
| quarter | 500 | grid20 | 0.999 | 0.001 | 0.932 (1.00) | 0.000 | 0.0583 | 0.0625 | 0.0625 |
| quarter | 1000 | argmin-p | 1.000 | 0.000 | 1.000 (1.00) | 0.000 | 0.0625 | 0.0625 | 0.0625 |
| quarter | 1000 | min-n | 0.512 | 0.488 | 0.492 (1.00) | 0.000 | 0.0600 | 0.0625 | 0.0625 |
| quarter | 1000 | bonf4 | 1.000 | 0.000 | 0.999 (1.00) | 0.000 | 0.0624 | 0.0625 | 0.0625 |
| quarter | 1000 | grid20 | 1.000 | 0.000 | 0.994 (1.00) | 0.000 | 0.0621 | 0.0625 | 0.0625 |
| near-alpha | 250 | argmin-p | 0.105 | 0.894 | 0.017 (0.26) | 0.015 | 0.0672 | 0.0191 | 0.1202 |
| near-alpha | 250 | min-n | 0.130 | 0.870 | 0.017 (0.26) | 0.006 | 0.0628 | 0.0476 | 0.1174 |
| near-alpha | 250 | bonf4 | 0.036 | 0.964 | 0.010 (0.26) | 0.015 | 0.0943 | 0.0000 | 0.1196 |
| near-alpha | 250 | grid20 | 0.006 | 0.994 | 0.002 (0.26) | 0.005 | 0.1042 | 0.0000 | 0.1159 |
| near-alpha | 500 | argmin-p | 0.580 | 0.420 | 0.066 (0.26) | 0.021 | 0.0469 | 0.0789 | 0.1173 |
| near-alpha | 500 | min-n | 0.517 | 0.483 | 0.051 (0.26) | 0.013 | 0.0357 | 0.0647 | 0.1161 |
| near-alpha | 500 | bonf4 | 0.234 | 0.766 | 0.029 (0.26) | 0.018 | 0.0525 | 0.0553 | 0.1158 |
| near-alpha | 500 | grid20 | 0.041 | 0.960 | 0.007 (0.26) | 0.005 | 0.0722 | 0.0000 | 0.1145 |
| near-alpha | 1000 | argmin-p | 0.928 | 0.072 | 0.114 (0.26) | 0.029 | 0.0566 | 0.0891 | 0.1181 |
| near-alpha | 1000 | min-n | 0.499 | 0.501 | 0.062 (0.26) | 0.018 | 0.0563 | 0.0796 | 0.1181 |
| near-alpha | 1000 | bonf4 | 0.821 | 0.179 | 0.083 (0.26) | 0.015 | 0.0431 | 0.0724 | 0.1159 |
| near-alpha | 1000 | grid20 | 0.532 | 0.468 | 0.037 (0.26) | 0.004 | 0.0153 | 0.0471 | 0.1111 |
| above | 250 | argmin-p | 0.013 | 0.987 | 0.005 (0.00) | 0.013 | 0.1200 | 0.0000 | 0.1200 |
| above | 250 | min-n | 0.018 | 0.982 | 0.003 (0.00) | 0.018 | 0.1200 | 0.0000 | 0.1200 |
| above | 250 | bonf4 | 0.010 | 0.990 | 0.003 (0.00) | 0.010 | 0.1200 | 0.0000 | 0.1200 |
| above | 250 | grid20 | 0.002 | 0.998 | 0.001 (0.00) | 0.002 | 0.1200 | 0.0000 | 0.1200 |
| above | 500 | argmin-p | 0.015 | 0.985 | 0.003 (0.00) | 0.015 | 0.1200 | 0.0000 | 0.1200 |
| above | 500 | min-n | 0.018 | 0.982 | 0.001 (0.00) | 0.018 | 0.1200 | 0.0000 | 0.1200 |
| above | 500 | bonf4 | 0.005 | 0.995 | 0.002 (0.00) | 0.005 | 0.1200 | 0.0000 | 0.1200 |
| above | 500 | grid20 | 0.002 | 0.998 | 0.001 (0.00) | 0.002 | 0.1200 | 0.0000 | 0.1200 |
| above | 1000 | argmin-p | 0.016 | 0.984 | 0.002 (0.00) | 0.016 | 0.1200 | 0.0000 | 0.1200 |
| above | 1000 | min-n | 0.018 | 0.982 | 0.001 (0.00) | 0.018 | 0.1200 | 0.0000 | 0.1200 |
| above | 1000 | bonf4 | 0.004 | 0.996 | 0.001 (0.00) | 0.004 | 0.1200 | 0.0000 | 0.1200 |
| above | 1000 | grid20 | 0.001 | 1.000 | 0.000 (0.00) | 0.001 | 0.1200 | 0.0000 | 0.1200 |
