# Decision certificate, v1.3

Status: **implemented, not frozen** (2026-11-10). v1.3 is
[`decision-certificate.v1.2`](decision-certificate.v1.2.md) with two additions from the
[v1.3 draft](drafts/decision-certificate.v1.3.md): C1, `data_hash` binds each case's `cannot_tell`
value (§2), and P1, each test reports its answered cases among the options the consumer automates
(§1.6, §2, §4). Until v1.3 is frozen, its fields and fixtures may still change, so a consumer that
needs a fixed format pins `decision-certificate.v1.2`. The v1.2 spec text applies to a v1.3
certificate except where this document says otherwise. v1, v1.1 and v1.2 stay frozen and valid, and
their certificates, fixtures and verdicts do not change.

**Versions.** Verifiers accept `decision-certificate.v1`, `v1.1`, `v1.2` and `v1.3`, each against
its own schema. v1.3 certificates have the v1.2 fields and three more: `automate_options` and
`automated` at the top level, and `automated` in each segment. They are required in a v1.3
certificate and are unknown fields in an earlier one. An issuer writes v1.3 only when asked
(the reference issuer's `--spec decision-certificate.v1.3`); its default stays v1.2.

A decision certificate is a signed record of **a measured process**. As in v1.2, it describes how
the thresholds were measured and how wide the uncertainty is, and it never guarantees an outcome.

Machine-readable schema: [`decision-certificate.v1.3.schema.json`](decision-certificate.v1.3.schema.json).
Conformance fixtures: [`fixtures/v1.3/`](../fixtures/v1.3/).

## 1. What is measured

§1 to §1.5 are v1.2's. The procedure, the tests, the thresholds and the statement are unchanged:
the claim of §1 covers **every** answered case of a test, whatever option the answer is.

### 1.6 The automated options (P1)

A consumer may decide only some options automatically, for example approvals, and send every other
answer to a person as well as every abstention. `automate_options` names those options. For each
test (the top level and each segment), with its chosen threshold, `automated` reports the test's
cases that are answered **and** whose top option is in `automate_options`. The top option is the
option with the largest calibrated probability; a tie goes to the earliest of the tied options in
`options`, and a consumer breaks ties the same way:

- `coverage`: their number divided by the test's `n`. It is at most the test's `coverage`, and equal
  to it when every option is automated.
- `ucb` and `realized_band`: v1.2 §1.2's formulas applied to those cases' `k` answers and `e`
  errors, at the test's own level `d` and at `level` 0.95. `ucb` is null for `crc`. Both are null
  for an inherited segment, which has no test of its own; its `coverage` is still reported.

These numbers are **descriptive**, like v1.2 §1.2's. **`automated.ucb` is not a bound.** It is the
Clopper–Pearson value at the subset's count of answers and errors, but the threshold was chosen on
the whole test, not on the subset, so it carries no confidence statement, and it can exceed
`alpha`. No bound at `alpha` is claimed for the automated subset: its error can be higher than the
error of all answered cases when the errors sit in the automated option. The certified claim is §1's
statement, about every answered case. The subset has at most as many cases as the test, so its band
is usually as wide or wider (`docs/certificates.md`, "The arithmetic floor"), though a subset with
fewer errors can have a narrower one.

The top option is decided by the certificate's calibration map. An unscored case, or one the rule
abstains on whatever the threshold, is never answered and so never automated.

## 2. Fields

v1.2's fields, with one change and three additions:

| Field | Type | Meaning |
|---|---|---|
| `data_hash` | string | As v1.2, but each entry has a seventh member: `[case_id, label_index, raw_scores \| null, decided_at \| null, segment \| null, propensity \| null, cannot_tell \| null]`. `cannot_tell` is the case's `cannot_tell` value from its prediction (the value the rule of v1.2 §1 compares with `rule.cannot_tell_above`), null when the prediction has none; it is hashed even when `cannot_tell_above` is null. (C1) |
| `automate_options` | string[] | The options the consumer decides automatically: one or more of `options`, each once, in the order of `options`. (P1) |
| `automated` | `{coverage, ucb, realized_band}` | §1.6 for the remainder's test (the top-level fields). `ucb` is a number or null, `realized_band` a v1.2 band or null. |
| `segments[].automated` | `{coverage, ucb, realized_band}` | §1.6 for the segment's test. |

**Checks beyond the schema.** As v1.2, plus:

- `automate_options` names one or more of the options, once each and in their order.
- In each test, `automated.coverage` is in [0, 1] and at most the test's `coverage`, `automated.ucb`
  is in [0, 1] when not null, `automated.realized_band` passes v1.2's band check when not null, and
  `automated.ucb` and `automated.realized_band` are null exactly where the test's `ucb` and
  `realized_band` are.
- When `automate_options` names every option, each test's `automated` equals the test's own
  `coverage`, `ucb` and `realized_band`: the automated cases are then the answered cases.

A verifier cannot check that these numbers were computed from the cases. As with every other
measured field, a re-run from the data does that (v1.2 §2).

## 3. Canonical form and signature

v1.2 §3, unchanged.

## 4. How a consumer uses it

v1.2 §4, plus:

- The consumer also refuses a certificate whose `automate_options` differ from the options it
  decides automatically. A certificate issued with every option automated describes a different
  subset from one issued for approvals only.
- **Automated share** (v1.3). Compare the share of a window's cases the consumer decides
  automatically with the test's `automated.coverage`, by the same two-sample test as the answered
  share (v1.2 §4), against the test's `n`.

## 5. What a certificate does not claim

v1.2 §5 applies in full. In particular, `automated` is not a bound at `alpha` on the automated
cases (§1.6).

## 6. Size, binning and privacy of the histogram

v1.2 §6, unchanged. The histograms cover all of a test's cases, not only the automated ones.

## Changes from v1.2

- C1: `data_hash` binds each case's `cannot_tell` value, the input that decides a cannot-tell
  abstention (§2). Two runs on the same cases with different `cannot_tell` values now give
  different hashes.
- P1: `automate_options`, `automated` and `segments[].automated` (§1.6, §2), with their checks;
  §4's refusal on a different `automate_options` and the automated share.
- `spec` is `decision-certificate.v1.3`. The procedure of v1.2 §1.1 to §1.5 is unchanged, and no
  field of v1.2 changes meaning except `data_hash`, which has one more member per case.

The other items of the [v1.3 draft](drafts/decision-certificate.v1.3.md) (F1, R1, K1, U1, S1 and
M1) stay draft and are not in this spec.
