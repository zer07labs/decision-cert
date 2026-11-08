> Study for item H1 of the [v1.2 draft](decision-certificate.v1.2.md) (issue #25). It is the evidence
> for the stored confidence histogram.

# H1 study: what a stored confidence histogram lets a consumer see without labels (2026-11-08)

Produced by [`python/tools/study_histogram.py`](../../python/tools/study_histogram.py) (its docstring
has the design). Seeds are pinned, so the tables regenerate byte for byte:

```bash
cd python && uv run python tools/study_histogram.py
```

## Design in brief

The [O2 study](o2-shift-study.md) found that the answered share, which v1 and v1.1 certificates
already allow a consumer to monitor, saw every shift there that a stored confidence distribution
saw. Its shifts all moved confidences across the threshold. This study adds the shifts that do not:

- `squeeze`: the answered cases' confidences move toward the certified threshold, and their error
  follows their new confidence. The answered share is unchanged by construction, and the error among
  the answered cases rises;
- `abstained`: the abstained cases' confidences move toward 0.5. Nothing answered changes, so the
  bound is unaffected.

It keeps O2's `none` (false alarms), `confidence` (confidences move low) and `concept` (more error at
every confidence). Each draw issues a pooled `ltt` certificate (alpha 0.05, delta 0.1, `n_cal`
3,000, the v1.1 grid start) and its threshold split's histogram. The scores, each tested at level
0.05:

- **coverage:** the window's answered share against `coverage` and `n` (v1, v1.1);
- **KS:** a Kolmogorov–Smirnov test against the threshold split's raw confidences, which needs the
  issuer's data (the reference point);
- **histogram q20 / q10:** the v1.2 shift score (spec §4, `decision_cert.shift_score`) on the 20 or
  10 quantiles of the temperature split's confidences, as the reference issuer learns them;
- **histogram fixed20:** the same score on 20 equal-width bins of [0, 1], fixed in advance.

## Results

498 of 500 draws certified; rates are over those

| population | window | breaks the bound | flagged: coverage | flagged: KS | flagged: histogram q20 | flagged: histogram q10 | flagged: histogram fixed20 |
|---|---|---|---|---|---|---|---|
| none | 1000 | 0.09 | 0.05 | 0.05 | 0.04 | 0.07 | 0.07 |
| none | 5000 | 0.09 | 0.05 | 0.04 | 0.05 | 0.04 | 0.06 |
| confidence | 1000 | 0.74 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |
| confidence | 5000 | 0.74 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |
| squeeze | 1000 | 0.68 | 0.04 | 1.00 | 1.00 | 1.00 | 1.00 |
| squeeze | 5000 | 0.68 | 0.04 | 1.00 | 1.00 | 1.00 | 1.00 |
| abstained | 1000 | 0.09 | 0.05 | 1.00 | 1.00 | 1.00 | 1.00 |
| abstained | 5000 | 0.09 | 0.05 | 1.00 | 1.00 | 1.00 | 1.00 |
| concept | 1000 | 0.89 | 0.05 | 0.06 | 0.07 | 0.05 | 0.06 |
| concept | 5000 | 0.89 | 0.05 | 0.05 | 0.05 | 0.05 | 0.05 |

False alarms (population `none`) with small calibration sets; every one of 500 draws counts,
certified or not:

| n_cal | window | flagged: coverage | flagged: KS | flagged: histogram q20 | flagged: histogram q10 | flagged: histogram fixed20 |
|---|---|---|---|---|---|---|
| 300 | 300 | 0.01 | 0.05 | 0.04 | 0.05 | 0.04 |
| 300 | 1000 | 0.01 | 0.04 | 0.05 | 0.05 | 0.05 |
| 1000 | 300 | 0.06 | 0.05 | 0.04 | 0.05 | 0.05 |

## Findings

1. **A shift inside the answered range breaks the bound and is invisible to the answered share.**
   `squeeze` breaks the bound in 68% of draws; coverage flags it at its false-alarm rate (4%). The
   stored histogram flags it in every window, as the KS test on the raw confidences does.
2. **The histogram does as well as the raw confidences.** On every population here, the shift score
   on 20 (or 10) bins flags as often as the KS test that needs the issuer's data. Quantile and fixed
   bins do equally well on this population; quantile bins keep the bins roughly equally full for
   any model, which suits the chi-square approximation.
3. **It also flags harmless shifts.** `abstained` changes nothing answered, and the histogram flags
   it in every window. A significant shift score is a prompt to measure again, not a finding that the
   bound has failed (spec §5).
4. **False alarms stay at the level**, near 5%, including with 300 calibration cases and a window of
   300, where the expected counts per bin are smallest.
5. **A concept shift stays invisible**, to the histogram as to every label-free score. Only labelled
   cases can show it (spec §5).

## Decision (2026-11-08)

Store the threshold split's confidence histogram per test (spec v1.2 §1.5), on bins learned from
the temperature split or fixed in advance, with the shift score of §4. The reference issuer uses 20
quantile bins and withholds the histogram of a test with fewer than 30 cases. The owner approved
building v1.2 with this item (relayed 2026-11-08).
