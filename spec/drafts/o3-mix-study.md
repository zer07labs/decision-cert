> Study for item O3 of the [v1.1 draft](decision-certificate.v1.1.md). It supports a
> recommendation; the owner decides.

# O3 study: thresholds when the segment mix shifts (2026-11-08)

Produced by [`python/tools/study_mix.py`](../../python/tools/study_mix.py) (its docstring has the
design). Seeds are pinned, so the table regenerates byte for byte:

```bash
cd python && uv run python tools/study_mix.py
```

## Design in brief

There are two groups whose confidences look alike but whose errors differ: an easy group, and a hard
one with about 2.7 times the error at every confidence. The model's confidence cannot tell them
apart, which is the case where a change in the mix can break a pooled bound. At calibration the hard
group is 20% of cases; at use it is 20%, 35% or 50%.

- **pooled:** no segment declared, one test on all cases (v1).
- **conditional:** the group declared as a segment and both groups certified, each tested on its own
  cases (v1 §1.3, with v1's Bonferroni and the grid start decided for O1).

The use-time selective error over all answered cases is computed exactly from the chosen thresholds
and the use-time mix. There are 1,000 draws per row, with alpha 0.05 and delta 0.1.

## Results

| n_cal | rule | hard share at use | violations | coverage at use |
|---|---|---|---|---|
| 1000 | pooled | 0.2 | 0.065 | 0.259 |
| 1000 | pooled | 0.35 | 0.182 | 0.259 |
| 1000 | pooled | 0.5 | 0.315 | 0.259 |
| 1000 | conditional | 0.2 | 0.014 | 0.175 |
| 1000 | conditional | 0.35 | 0.014 | 0.143 |
| 1000 | conditional | 0.5 | 0.014 | 0.110 |
| 3000 | pooled | 0.2 | 0.084 | 0.406 |
| 3000 | pooled | 0.35 | 0.456 | 0.406 |
| 3000 | pooled | 0.5 | 0.753 | 0.406 |
| 3000 | conditional | 0.2 | 0.021 | 0.394 |
| 3000 | conditional | 0.35 | 0.020 | 0.322 |
| 3000 | conditional | 0.5 | 0.019 | 0.250 |
| 10000 | pooled | 0.2 | 0.100 | 0.456 |
| 10000 | pooled | 0.35 | 0.846 | 0.456 |
| 10000 | pooled | 0.5 | 0.995 | 0.456 |
| 10000 | conditional | 0.2 | 0.022 | 0.485 |
| 10000 | conditional | 0.35 | 0.021 | 0.408 |
| 10000 | conditional | 0.5 | 0.018 | 0.331 |

## Findings

1. **A pooled threshold holds only for the mix it was calibrated on.**
   - With no shift, its violation rate is at or below delta (0.065–0.100; 0.100 is within Monte Carlo
     error of delta).
   - With the hard share at 50%, violations reach 0.315 at `n_cal` 1,000, 0.753 at 3,000 and 0.995
     at 10,000.
   - Larger calibration sets break worse, because the threshold is fitted more tightly to the
     calibration mix.
2. **Conditional testing holds at every mix.** Violations are 0.014–0.022 in every row, because
   each group's own bound holds whatever the proportions.
3. **Its cost is modest and comes from the mix, not from the testing.**
   - Coverage at use falls as more cases come from the hard group.
   - With no shift it answers about as many cases as pooled, and at `n_cal` 10,000 more (0.485
     against 0.456), because the easy group gets its own looser threshold.
   - At `n_cal` 1,000 it answers fewer (0.175 against 0.259), because each group's test is smaller
     (see O4).
4. **v1 can already do this.** Declaring the field as a segment with a floor the groups meet gives
   conditional tests. Nothing new is needed in the procedure or the fields.

## Recommendation for O3 (not decided)

- **No new mechanism or field.** v1's certified segments are segment-conditional testing.
- **Say it in v1.1.**
  - §1.3 notes that a certified segment's bound holds whatever the mix of segments at use.
  - §5 says plainly that the remainder's bound, and any inherited segment's, holds only for the
    mix of cases in the calibration set.
- **Guidance for issuers** (`docs/certificates.md`): declare as a segment any field whose share of
  cases may change and whose error may differ, with a floor its groups can meet.
- A rule that abstains on segments below the floor, instead of pooling them, would trade coverage
  for mix-robustness. It is not recommended for v1.1; it can be revisited with O2 (a shift score),
  which addresses the same risk for the remainder.
