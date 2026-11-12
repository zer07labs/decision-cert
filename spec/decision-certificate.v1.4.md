# Decision certificate, v1.4

Status: **implemented, not frozen** (2026-11-12). v1.4 is
[`decision-certificate.v1.3`](decision-certificate.v1.3.md) with one addition from the
[cost-weighted abstention draft](drafts/cost-weighted-abstention.md): the cost risk
`selective_cost`, which bounds the expected cost of the answered cases instead of their error rate
(§1.7, §2, §4). Until v1.4 is frozen, its fields and fixtures may still change, so a consumer that
needs a fixed format pins `decision-certificate.v1.2`. The v1.3 spec text applies to a v1.4
certificate except where this document says otherwise. v1, v1.1, v1.2 and v1.3 certificates,
fixtures and verdicts do not change.

**Versions.** Verifiers accept `decision-certificate.v1`, `v1.1`, `v1.2`, `v1.3` and `v1.4`, each
against its own schema. v1.4 certificates have the v1.3 fields and eight more: `cost`, `pvalue`,
`loss_sum` and `realized_cost` at the top level, and `loss_sum` and `realized_cost` in each segment
and in every `automated` block. They are required in a v1.4 certificate and are unknown fields in an earlier
one. An issuer writes v1.4 only when asked (the reference issuer's `--spec
decision-certificate.v1.4`); its default stays v1.2.

A decision certificate is a signed record of **a measured process**. As in v1.3, it describes how
the thresholds were measured and how wide the uncertainty is, and it never guarantees an outcome.

Machine-readable schema: [`decision-certificate.v1.4.schema.json`](decision-certificate.v1.4.schema.json).
Conformance fixtures: [`fixtures/v1.4/`](../fixtures/v1.4/).

## 1. What is measured

§1 to §1.6 are v1.3's. A v1.4 certificate with `risk` `selective_error` or `joint_error` makes the
same claim, by the same procedure, as v1.3.

### 1.7 The cost risk `selective_cost`

**Costs.** The consumer gives a cost matrix `C` over the decision's options, in the order of
`options`: `C[y][o]` is the cost of answering option `o` when the label is `y`. Every entry is a
**whole number** in the consumer's `unit` (cents, points: whatever scale makes the costs whole). The
diagonal is 0, every entry is in [0, `c_max`], and `c_max` is the largest entry, from 1 to 10⁶. A
case answered with top option `o` (v1.3 §1.6) and label `y` has the **normalised loss**
`L = C[y][o] / c_max`, in [0, 1].

**Why whole numbers.** A certificate states sums of costs in two places that must agree exactly: a
test's and its `automated` block's, when every option is automated (§2). A sum of fractions in
floating point depends on the order of its terms, so two correct issuers, or one issuer summing two
ways, can write numbers one unit in the last place apart, and every verifier would refuse the
certificate. A sum of whole numbers below 2⁵³ is exact in any order and any language. So each test
states `loss_sum`, the exact sum of `C[y][o]` over its answered cases, and every other cost number is
computed from it by one division. An issuer refuses costs whose `c_max` times the number of
calibration cases is above 2⁵³.

**The risk.** `R(λ)` is the mean normalised loss of the answered cases at cut `λ`.

**The statement.** With probability at least 1 − `delta` over the calibration draw, `R` at the
chosen threshold is at most `alpha`, for the top-level test and every certified segment at once. In
the consumer's units, the expected cost per answered case is at most `alpha` · `c_max`.

**The procedure** is v1.2 §1.1 with three changes, and everything else (the splits, the
temperature, the grid from the temperature split, fixed-sequence testing from the start, Bonferroni
`d` = `delta` / (1 + k) over the certified segments, inheritance) unchanged:

1. **The start** of each test's fixed sequence is the cut with the smallest Hoeffding–Bentkus
   p-value (step 3) on the test's own temperature-split losses, as v1.1 does with the binomial
   p-value.
2. **The test statistic** at each cut is `S = loss_sum / c_max`, the sum of the normalised losses of
   its `n` answered threshold-split cases, in place of the error count. `loss_sum` is the exact
   whole-number sum of their costs, divided by `c_max` once.
3. **The p-value** of `H_λ: R(λ) > alpha` is Hoeffding–Bentkus (Bates, Angelopoulos, Lei, Malik,
   Jordan, 2021, "Distribution-Free, Risk-Controlling Prediction Sets", JACM):
   `p = min(1, exp(−n · h(min(S/n, alpha), alpha)), e · P(Binomial(n, alpha) ≤ ⌈S⌉))`, with
   `h(a, b) = a ln(a/b) + (1 − a) ln((1 − a)/(1 − b))`, and `p` = 1 when `n` = 0. The ceiling is
   taken of `S` − 10⁻⁹, so that float noise in a sum of whole losses does not move it.

Given `n`, the answered cases' losses are `n` exchangeable draws in [0, 1] with mean `R(λ)`, so the
p-value is valid conditionally on `n`, as v1's binomial p-value is. The fixed-sequence argument
does not use the loss's form (Angelopoulos, Bates, Candès, Jordan, Lei, 2021, "Learn then Test").

**The reported numbers**, for each test with its chosen threshold:

- `ucb`: the Hoeffding–Bentkus upper bound on `R` at level 1 − `d`, the smallest `u` with
  `p(u)` ≤ `d` (found by bisection to 10⁻¹²; 1 when `n` = 0). It is descriptive after selection, as
  in v1 §1.2.
- `realized_band`: v1.2 §1.2's Clopper–Pearson band on the answered cases' **error count**, where
  an error is an answer that is not the label. It still shows how many answers were wrong.
- `loss_sum`: the answered cases' exact sum of costs, a whole number in `unit`. Null when the test
  answered no case, and for an inherited segment.
- `realized_cost`: the answered cases' mean normalised loss, exactly `loss_sum / (c_max · n)` as
  one IEEE 754 double division of two whole numbers (both exact, at most 2⁵³). Descriptive, like
  `realized_band`. Null exactly where `loss_sum` is.
- `automated.loss_sum` and `automated.realized_cost`: the same over the automated cases (v1.3
  §1.6), with `n` their count. **They are not a bound**, for the reason v1.3 §1.6 gives for
  `automated.ucb`.

**Equal costs keep v1's test.** When every off-diagonal entry of `C` is the same, `L` is v1's
error indicator, and Hoeffding–Bentkus is more conservative than the exact binomial on it. An
issuer then writes `risk` `selective_error` with `cost` null: the certificate is byte-identical to
the one issued without a cost (the reference issuer's tests check this). A verifier refuses a
`selective_cost` certificate with equal off-diagonal costs.

**`selective_cost` uses `ltt` only.** A `crc` variant (`joint_cost`) is not in v1.4.

**Small tests.** The statement is over the calibration draw. It is **not conditional on a
certificate issuing**. At a small `n_cal` few draws certify, and over only the draws that did, the
mean risk at the chosen threshold can be above `alpha` (the [cost study](drafts/cost-study.md)
found up to 2.0 × `alpha` at `n_cal` 100, where one or two draws in 1,000 certified). So at small
`n_cal` an issued certificate is weak evidence. This holds for `selective_error` too (up to
2.5 × in the same study). v1.4 does not change it: it is the same open question as the small-test
minimum in the [v1.1 draft's O4](drafts/decision-certificate.v1.1.md) and the
[S1 study](drafts/s1-start-study.md), and one decision will settle both.

## 2. Fields

v1.3's fields, with one new `risk` value and five additions:

| Field | Type | Meaning |
|---|---|---|
| `risk` | adds `"selective_cost"` (with `ltt`) | §1.7 |
| `cost` | `{matrix, c_max, unit}` \| null | `matrix`: integer[][], options × options, row = label, column = answered option, in the order of `options`. `c_max`: its largest entry, an integer from 1 to 10⁶. `unit`: a non-empty string such as `"usd_cents"`, or null; informational only, and it names the scale that makes the costs whole. Non-null exactly when `risk` is `selective_cost`. |
| `loss_sum`, `segments[].loss_sum` | integer \| null | §1.7, for the remainder's and each segment's test. |
| `automated.loss_sum`, `segments[].automated.loss_sum` | integer \| null | §1.7, for the test's automated cases. |
| `pvalue` | `"binomial"` \| `"hoeffding_bentkus"` \| null | The `ltt` p-value: `binomial` for `selective_error`, `hoeffding_bentkus` for `selective_cost`, null for `crc`. |
| `realized_cost` | number \| null | §1.7, for the remainder's test. |
| `segments[].realized_cost` | number \| null | §1.7, for the segment's test. |
| `automated.realized_cost`, `segments[].automated.realized_cost` | number \| null | §1.7, for the test's automated cases. |

`data_hash` is unchanged from v1.3: the losses follow from the labels and scores it binds and from
`cost`, which the certificate states.

**Checks beyond the schema.** As v1.3, plus:

- `cost` is non-null exactly when `risk` is `selective_cost`, and `pvalue` matches `risk` as in the
  table. `selective_cost` pairs with `ltt` only.
- `cost.matrix` is square of side `len(options)`, with a zero diagonal and whole-number entries in
  [0, `c_max`], `c_max` its largest entry and from 1 to 10⁶, and `unit` non-empty when not null. (A
  fractional entry is a type error, as any non-integer integer field is.)
- A `selective_cost` certificate's off-diagonal costs are not all equal.
- Every `loss_sum` and `realized_cost` is null for the error risks, for an inherited segment, and
  wherever its test (or its automated cases) answered no case, and only there.
- Otherwise, with `k` = ⌊`coverage` · `n` + ½⌋ the answered cases (for an `automated` block,
  its `coverage` times its test's `n`): `coverage` is exactly `k / n` (one double division, as an
  issuer writes it, so `k` cannot be moved by rounding; `n` at most 2⁵³), `c_max` · `k` is at most 2⁵³, `loss_sum` is at most
  `c_max` · `k`, and `realized_cost` equals `loss_sum / (c_max · k)` exactly, computed as one
  double division. Every language gets the same bits, so verifiers agree.
- When `automate_options` names every option, each `automated.loss_sum` and
  `automated.realized_cost` equal their test's (the sums compared as integers), with v1.3's other
  `automated` fields.

A verifier cannot check that `ucb` or `loss_sum` was computed from the cases. As with every
other measured field, a re-run from the data does that (v1.2 §2).

## 3. Canonical form and signature

v1.3 §3, unchanged.

## 4. How a consumer uses it

v1.3 §4, plus:

- The consumer also refuses a certificate whose `cost.matrix` differs from the costs it is
  configured with. Changing the costs is re-certification, like changing `automate_options`.
- When it shows the bound of a `selective_cost` certificate, it reports `alpha` · `c_max` in
  `unit`, as an expected cost per answered case.
- A consumer that does not apply cost risks refuses a `selective_cost` certificate, as it would a
  calibration map it does not apply (v1.2 §4).

## 5. What a certificate does not claim

v1.3 §5 applies in full. In addition:

- A `selective_cost` certificate bounds a **measured expected cost** of the answered cases, on
  cases exchangeable with the calibration cases, at the stated `delta`. It says nothing about any
  single decision, and it is not a promised loss, a loss cap or an insured amount.
- The costs are the consumer's input. The certificate does not check that they are right.
- Abstained cases carry no cost here. Total expected cost, review included, is a different
  objective.
- `automated.realized_cost` is descriptive and not a bound (§1.7).
- At small `n_cal`, see §1.7, "Small tests".

## 6. Size, binning and privacy of the histogram

v1.3 §6, unchanged.

## Changes from v1.3

- `risk` `selective_cost` with `ltt`, its Hoeffding–Bentkus p-value, start and `ucb` (§1.7).
- `cost` (whole-number costs), `pvalue`, and `loss_sum` and `realized_cost` at the top level, in
  each segment and in every `automated` block (§2), with their checks; §4's refusal on a different `cost.matrix`.
- `spec` is `decision-certificate.v1.4`. With an error risk, the procedure and every v1.3 field are
  unchanged; equal costs give the certificate issued without a cost.

`joint_cost` (with `crc`) and a betting p-value stay out of v1.4
([draft](drafts/cost-weighted-abstention.md), owner answers 2026-11-12).
