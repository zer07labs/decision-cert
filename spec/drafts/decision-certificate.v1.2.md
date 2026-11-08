> **v1.2 is in progress** as [`spec/decision-certificate.v1.2.md`](../decision-certificate.v1.2.md),
> which is the specification. This draft is the record of each item, its evidence and its decision.

# Decision certificate, v1.2 (draft)

v1.2 extends [`decision-certificate.v1.1`](../decision-certificate.v1.1.md) with the two items v1.1
left out (*Not in v1.1* in its *Changes from v1*). v1 and v1.1 stay frozen and valid:

- v1 and v1.1 certificates and their conformance fixtures are kept unchanged;
- verifiers accept all three values of `spec`, and verify each against its own schema;
- a v1.2 fixture set is added beside the others.

The owner approved building both items (relayed 2026-11-08): the histogram first (issue #25), then
the `dr` map kind (issue #24).

## Items

### H1. A stored confidence distribution for monitoring without labels (#25): DECIDED (2026-11-08)

**Problem.** v1.1 §4 lets a consumer monitor the share of cases it answers against `coverage`. That
sees shifts that move confidences across the threshold, but not a shift inside the answered range,
which can raise the error at an unchanged answered share. The [O2 study](o2-shift-study.md) left a
stored confidence distribution to v1.2 "if evidence for it appears".

**Evidence.** [`h1-histogram-study.md`](h1-histogram-study.md): a shift inside the answered range
broke the bound in 68% of draws and was invisible to the answered share; a 20-bin histogram flagged
it in every window, as a test on the raw confidences did, with false alarms at the level.

**Decision.** Each test stores its threshold-split cases per bin of the model's confidence
(`confidence_histogram`, nullable, at the top level and in each segment), on one set of edges
(`confidence_bins`) chosen without the threshold split. Verifiers check that the bins rise from 0 to
1 and that each histogram sums to its test's `n`. Spec §4 defines the shift score (Pearson's
chi-square test of homogeneity), §5 what it does not show, and §6 its size, binning and privacy.
Both reference verifiers implement the binning and the score (`Histogram::of`, `shift_score`).

**Changes for verifiers.** Three new fields, required in v1.2 and unknown in v1 and v1.1, and the
checks of §2. A certificate whose fields belong to another `spec` is refused, so the v1.1 fixture
naming v1.2 (`fixtures/v1.1/invalid_unknown_spec.json`) is still refused with the same message.

### D1. A `dr` calibration map kind (#24)

Open: added next. The candidate is in the [v1.1 draft](decision-certificate.v1.1.md) (O5).

## Decision log

| Date | Item | Decision | Evidence |
|---|---|---|---|
| 2026-11-08 | v1.2 | Owner approved building v1.2: #25, then #24 (relayed). | — |
| 2026-11-08 | H1 | Store a confidence histogram per test, with the shift score; withhold below 30 cases. | [`h1-histogram-study.md`](h1-histogram-study.md) |
