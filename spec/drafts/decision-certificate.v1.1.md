> **DRAFT. Nothing here is decided.** Every item below is open. No issuer writes
> `decision-certificate.v1.1` and no verifier accepts it until the owner freezes this text. Where this
> draft and [v1](../decision-certificate.v1.md) differ, v1 is the specification.

# Decision certificate, v1.1 (draft)

v1.1 is a minor revision of [`decision-certificate.v1`](../decision-certificate.v1.md). A frozen v1.1
will have its own `spec` value, `decision-certificate.v1.1`, and its own schema. v1 stays frozen and
valid:

- v1 certificates and the v1 conformance fixtures are kept unchanged;
- verifiers accept both values of `spec`, and verify each against its own schema;
- a v1.1 fixture set is added beside the v1 set.

What changes from v1 is listed as open items. Each item says what problem it addresses, what the
candidates are, what decides it, and what it changes for verifiers. An item becomes text in §1–§5 of
v1.1 only when it is decided. The clarifications already in [`ERRATA.md`](../ERRATA.md) fold into the
v1.1 text unchanged.

## Open items

### O1. The threshold grid for small tests

**Problem.** v1 §1.1 step 3 builds one list of cuts from the temperature split and starts every test
at the cut with the smallest p-value on the whole temperature split. Fixed-sequence testing stops at
the first cut that is not rejected. On a fine grid, a test with few cases can fail at its first cut
even though a looser cut would pass: one or two errors near the top of the threshold split end the
sequence. The result is still valid (it abstains, which never overstates the bound), but it can
abstain on everything where a usable threshold exists.

A test where **no** cut passes, even one picked with hindsight, must keep abstaining on everything.
That is the certificate working, not a defect. For example, on the bank-marketing demo inputs, the
`cellular` segment has no cut at `alpha` 0.05 that passes, so abstaining on every case is correct
for that model.

**Candidates.**

- Start each test (each certified segment and the remainder) at the best cut on that test's own
  temperature-split cases. On its own this was not enough in the one case examined.
- A coarser grid, for example cuts at fixed quantiles of the temperature split's confidences, so
  each step adds enough cases that a single error cannot end the sequence.
- Both.

Every candidate learns the grid from the temperature split only, so fixed-sequence testing stays
valid. The question is power, not validity.

**What decides it.** A simulation study, before any text is frozen. It compares the candidates
with v1 on the share of tests that certify and on coverage, at the same `alpha` and `delta`, across
test-set sizes from the floor to tens of thousands, and checks that the realised selective error
stays at or below `alpha` at the stated rate. The issuer's regression tests pin v1's behaviour on
both cases (no passing cut, and a failing start cut) for comparison.

**Study (2026-11-08).** [`o1-grid-study.md`](o1-grid-study.md). Every rule stayed valid: true
error above `alpha` in at most 7.8% of replicates at `delta` 0.1, and the 90th percentile at or below
`alpha`. A coarse quantile grid bought no power and lost coverage on large tests. A per-test start
certified more often for a segment that differs from the pool, with unchanged validity. Small
tests are limited by their number of cases, which is O4's question. Suggested, not decided: adopt
the per-test start, keep v1's cuts.

**Changes for verifiers.** None beyond the new `spec` value: the procedure is the issuer's. It
changes what a v1.1 certificate's `abstain_below` means, which is why it needs a new `spec` value.

### O2. A shift score

**Problem.** The bound holds under exchangeability. A change in the mix of cases (for example more
cases from one segment) can break the bound while the model's scores look normal, and nothing in a
v1 certificate helps a consumer notice.

**Candidate.** A label-free statistic over the scored population at use time, compared with the
calibration cases. The certificate would carry what a consumer needs to compute it, such as a summary
of the calibration confidences, and a reference level. It would be descriptive, like `ucb`: a prompt
to measure again, never part of the certified claim.

**What decides it.** Whether a single, cheap statistic catches the mix shifts that break the bound
in simulation, at an acceptable false-alarm rate.

**Changes for verifiers.** A new field, so a schema change.

### O3. Segment-conditional thresholds

**Problem.** v1 certifies a segment only when it has at least `floor` threshold-split cases. The rest
are pooled in the remainder, whose threshold is tested on that pooled mix, so a change in the mix can
move its error.

**Candidate.** Tests conditional on segment for every declared segment, with the threshold applied
per segment, and a stated rule for segments below the floor.

**What decides it.** Whether the conditional variant holds `alpha` under a mix shift at acceptable
coverage, against plain v1 testing. It interacts with O1, because conditional tests are smaller.

**Changes for verifiers.** Possibly new fields in `segments[]`.

### O4. `n_cal` and the label budget

**Problem.** v1 records `n_cal` (the threshold split's size) and `calibration_map.label_budget` (the
target labels a map was fitted with), but does not say how many labelled cases a certificate needs.
Small `n_cal` gives a valid but loose certificate.

**Candidate.** State the total labels a certificate used as one budget, and give a recommended minimum
`n_cal` for `ltt` at common `alpha` and `delta`.

**What decides it.** The same simulation as O1: coverage against `n_cal`.

**Changes for verifiers.** Possibly none (guidance), or one field.

### O5. A `dr` calibration map kind

**Problem.** v1 consumers apply only `calibration_map.kind: "temperature"`. A map refitted on few
labels from the target population needs its own kind.

**Candidate.** `kind: "dr"`, `params: {"a": number, "b": [number, ...]}` with one `b` per option. The
probabilities are `softmax(a · log_softmax(scores) + b)`, and `label_budget` is required. The
reference issuer already has the fitting functions (`decision_cert.issue.recal`), but it does not yet
issue certificates with this map.

**What decides it.** Whether certificates with this map are issued at all, and the exact `params`
shape.

**Changes for verifiers.** A new allowed `kind` and its `params` shape in the schema, and the map in
`threshold_for` consumers.

## What does not change

Everything else in v1: canonical JSON (RFC 8785), Ed25519 with strict verification, the certificate
id, the trusted-keys format, unknown fields rejected, §1.4 audit basis, and §5 (what a certificate
does not claim).
