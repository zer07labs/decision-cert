> Study for item O2 of the [v1.1 draft](decision-certificate.v1.1.md). It supports a
> recommendation; the owner decides.

# O2 study: can a label-free score see the shifts that break a certificate? (2026-11-08)

Produced by [`python/tools/study_shift.py`](../../python/tools/study_shift.py) (its docstring has
the design). Seeds are pinned, so the table regenerates byte for byte:

```bash
cd python && uv run python tools/study_shift.py
```

## Design in brief

Each draw issues a pooled `ltt` certificate (alpha 0.05, delta 0.1, `n_cal` 3,000) on the
[O3 study's](o3-mix-study.md) mixture: an easy group and a hard one, 20% hard, with confidences that
look alike. A window of use-time cases then arrives from one of four populations:

- `none`: unchanged, which measures false alarms;
- `mix`: 50% hard, with confidences that look the same;
- `confidence`: confidences move toward the low end, and the error at each confidence is unchanged;
- `concept`: 1.5 times the error at every confidence, and confidences are unchanged.

The true use-time error at the certified threshold is exact. Three label-free scores are tested at
level 0.05 on each window:

- **coverage:** the window's answered share against the certificate's (`coverage` and `n` are
  already in a v1 certificate);
- **confidence:** a Kolmogorov–Smirnov test against the calibration confidences, which would be a
  new field;
- **segment share:** the window's share of the hard group against the calibration share, which
  needs the group observed and a new field.

## Results

497 of 500 draws certified; rates are over those

| population | window | breaks the bound | flagged: coverage | flagged: confidence | flagged: segment share |
|---|---|---|---|---|---|
| none | 1000 | 0.06 | 0.04 | 0.03 | 0.05 |
| none | 5000 | 0.06 | 0.04 | 0.05 | 0.06 |
| mix | 1000 | 0.77 | 0.07 | 0.06 | 1.00 |
| mix | 5000 | 0.77 | 0.06 | 0.05 | 1.00 |
| confidence | 1000 | 0.71 | 1.00 | 1.00 | 0.04 |
| confidence | 5000 | 0.71 | 1.00 | 1.00 | 0.05 |
| concept | 1000 | 0.86 | 0.06 | 0.08 | 0.06 |
| concept | 5000 | 0.86 | 0.05 | 0.06 | 0.03 |

## Findings

1. **Every shift here breaks the bound in most draws.** The certified threshold's true error is above
   alpha in 71–86% of draws, against 6% with no shift.
2. **Coverage drift sees shifts that move confidences, using only v1 fields.** It flags every
   `confidence` window, as the Kolmogorov–Smirnov test does, with false alarms at the test level.
   In this study a stored confidence distribution adds nothing over `coverage`.
3. **A mix shift with confidences that look alike is invisible to every score built on the model's
   output.**
   - Only the segment share sees it, and that needs the group to be observed.
   - When it is observed, declaring it as a certified segment ([O3](o3-mix-study.md)) removes the
     risk, rather than only detecting it.
4. **A concept shift is invisible to every label-free score.**
   - Coverage, confidences and group shares are all unchanged, so every score flags at about its
     false-alarm rate.
   - Only labelled cases from the new population can show it, which is what expiry and
     re-measurement are for.

## Recommendation for O2 (not decided)

- **No shift-score field in v1.1.** The one score that needs no new field, coverage drift, did as
  well here as a stored confidence distribution, and no label-free score can see the concept shifts.
- **Guidance** (`docs/certificates.md`): a consumer can monitor its answered share against the
  certificate's `coverage` (a two-sample test with the certificate's `n`) and treat a significant
  change as a prompt to measure again.
- **§5 in v1.1:** say that label-free monitoring cannot see a change in error at the same confidence,
  or a change in the mix of groups the model cannot tell apart; only labelled cases can.
- A stored confidence distribution could catch shifts that leave the answered share unchanged. That
  was not seen here, so the question goes to v1.2 if evidence for it appears.
