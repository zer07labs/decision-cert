> Study for item O4 of the [v1.1 draft](decision-certificate.v1.1.md). It supports a
> recommendation; the owner decides.

# O4 study: how many labelled cases an `ltt` certificate needs (2026-11-08)

Produced by [`python/tools/study_budget.py`](../../python/tools/study_budget.py) (its docstring has
the design). Seeds are pinned, so the table regenerates byte for byte:

```bash
cd python && uv run python tools/study_budget.py
```

## Design in brief

The same synthetic model as the [O1 study](o1-grid-study.md), with the grid start decided for O1.
Model quality is **k\***: the largest share of cases the model can answer with true error at alpha.
0.75 is a strong model for that alpha and 0.25 a weak one. Each cell is 1,000 independent draws of a
temperature split and a threshold split of `n_cal` cases each, so the issuer used 2 · `n_cal`
labelled cases. A cell shows the share of draws that certified, and the mean coverage as a share of
k\*.

## Results


**alpha 0.05** — certified share of draws / mean coverage as a share of k\*

| k\* | n_cal 100 | n_cal 200 | n_cal 300 | n_cal 500 | n_cal 1000 | n_cal 2000 | n_cal 3000 | n_cal 5000 | n_cal 10000 | max violations |
|---|---|---|---|---|---|---|---|---|---|---|
| 0.75 | 0.05 / 0.04 | 0.20 / 0.14 | 0.34 / 0.23 | 0.61 / 0.39 | 0.91 / 0.67 | 1.00 / 0.82 | 1.00 / 0.86 | 1.00 / 0.90 | 1.00 / 0.93 | 0.097 |
| 0.5 | 0.01 / 0.01 | 0.12 / 0.10 | 0.21 / 0.14 | 0.42 / 0.27 | 0.75 / 0.50 | 0.97 / 0.74 | 1.00 / 0.82 | 1.00 / 0.87 | 1.00 / 0.91 | 0.091 |
| 0.25 | 0.00 / 0.00 | 0.01 / 0.01 | 0.04 / 0.04 | 0.15 / 0.11 | 0.38 / 0.26 | 0.77 / 0.52 | 0.92 / 0.66 | 0.99 / 0.79 | 1.00 / 0.87 | 0.089 |

**alpha 0.1** — certified share of draws / mean coverage as a share of k\*

| k\* | n_cal 100 | n_cal 200 | n_cal 300 | n_cal 500 | n_cal 1000 | n_cal 2000 | n_cal 3000 | n_cal 5000 | n_cal 10000 | max violations |
|---|---|---|---|---|---|---|---|---|---|---|
| 0.75 | 0.22 / 0.16 | 0.55 / 0.35 | 0.72 / 0.49 | 0.91 / 0.66 | 1.00 / 0.82 | 1.00 / 0.88 | 1.00 / 0.91 | 1.00 / 0.93 | 1.00 / 0.96 | 0.110 |
| 0.5 | 0.12 / 0.09 | 0.36 / 0.24 | 0.53 / 0.35 | 0.78 / 0.53 | 0.97 / 0.76 | 1.00 / 0.86 | 1.00 / 0.89 | 1.00 / 0.92 | 1.00 / 0.94 | 0.102 |
| 0.25 | 0.02 / 0.03 | 0.11 / 0.07 | 0.24 / 0.16 | 0.42 / 0.28 | 0.79 / 0.54 | 0.97 / 0.75 | 1.00 / 0.82 | 1.00 / 0.87 | 1.00 / 0.92 | 0.091 |

**Validity check.** The largest violation rate in the table, 0.110 (alpha 0.10, k\* 0.75, `n_cal`
10,000), is within Monte Carlo error of delta at 1,000 draws (one standard error is about 0.01).
Rerun with 10,000 draws, the four worst cells give violation rates between 0.090 and 0.092, each
±0.006 (95%), all below delta 0.1:

```bash
cd python && uv run python -c "import sys; sys.path.insert(0, 'tools'); import study_budget as s; print(s.summarise(0.1, 0.75, 10000, 10000))"
```

## Findings

1. **The number of labels a certificate needs depends on the model, not only on alpha.**
   - At alpha 0.05, certifying in about 90% of draws takes `n_cal` around 1,000 for a strong model
     (k\* 0.75), 2,000 for a medium one (0.5), and 3,000 for a weak one (0.25).
   - At alpha 0.10 it takes roughly half as many.
2. **Coverage approaches the best possible slowly.** At alpha 0.05 with a strong model, `n_cal` 1,000
   reaches 67% of the best coverage, 2,000 reaches 82%, and 10,000 reaches 93%.
3. **Small calibration sets rarely certify.** At alpha 0.05 with `n_cal` at or below 300, `ltt`
   certifies in at most about a third of draws, even for a strong model. v1 already offers `crc`
   for small sets, and the v1 refusal (`n_cal` < 1/alpha − 1) stays the hard floor.
4. **Validity holds at every size** (see the check above).

## Recommendation for O4 (not decided)

- **No new field.** A certificate already states every label it used: `n_temperature` + `n_cal`,
  plus `calibration_map.label_budget` when the map was fitted on separate target labels. v1.1 should
  say in §2 that this sum is the certificate's label budget.
- **Guidance, not a rule.** Put the table above in `docs/certificates.md` as planning guidance for
  issuers. Do not make a larger minimum `n_cal` normative, because the right size depends on the
  model, and a certificate that abstains on everything is still valid.
