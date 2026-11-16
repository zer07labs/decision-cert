# Measuring when a model may answer: the method behind decision certificates

A model that scores cases can be wrong in ways nobody sees until much later. A decision certificate
records one narrow, checkable measurement instead: on labelled cases like the ones the model will
see, **how often was it wrong on the cases it chose to answer**, and at what confidence cut-off
should it stop answering. The certificate is a signed record of that measurement. It describes a
measured process. It never guarantees an outcome.

This page explains the method. The normative text is the spec, and where the two differ, the spec
is right: [v1.4](../spec/decision-certificate.v1.4.md), which builds on
[v1.3](../spec/decision-certificate.v1.3.md), [v1.2](../spec/decision-certificate.v1.2.md),
[v1.1](../spec/decision-certificate.v1.1.md) and [v1](../spec/decision-certificate.v1.md), with
dated corrections in [`spec/ERRATA.md`](../spec/ERRATA.md).

## Versions

All five spec versions are frozen, and verifiers accept certificates of every one. A certificate's
`spec` field says which procedure produced it and which fields it has.

- **v1** (2026-10-25): the measurement below.
- **v1.1** (2026-11-08): the same fields; each test starts its sequence of candidate thresholds on
  its own cases, and the text states more precisely what a certificate covers.
- **v1.2** (2026-11-08): a stored confidence histogram for monitoring without labels, and a second
  calibration map, `dr`.
- **v1.3** (2026-11-12): the options a consumer decides automatically, with each test's answered
  share and error among them, and each case's `cannot_tell` value bound in `data_hash`.
- **v1.4** (2026-11-12): a cost risk, which bounds the expected cost of the answered cases instead
  of their error rate.

The reference issuer writes v1.2 unless asked for another version.

## The decision rule being measured

The model gives each case a score per option. A calibration map turns the scores into
probabilities, and the top probability is the case's **confidence**. The map is either a
temperature-scaled softmax, with the temperature fitted on part of the labelled cases, or, since
v1.2, a `dr` map: a rescaling of the scores and a shift per option, fitted on a few labelled cases
from the population in use, kept apart from the cases that measure the threshold. The certificate
records how many labels that fit used (`label_budget`).

The rule answers a case when its confidence is at or above a threshold, and abstains otherwise. Two
kinds of case always abstain, whatever the threshold: cases the model did not score, and cases whose
`cannot_tell` value (the model's own signal that it cannot decide) is above the cut the certificate
records (`rule.cannot_tell_above`). Both count as abstentions, so they can never make the measured
error look smaller.

An answered case is an **error** when its top option is not the label. The quantity of interest is
the error rate among answered cases, the *selective error*.

## Picking the threshold without fooling ourselves

Choosing a threshold by looking at the same cases you then report on overstates how good the
threshold is. The method separates the two jobs.

1. **Two disjoint splits.** The labelled cases are split in two. A **temperature split** fits the
   map's temperature and builds the list of candidate thresholds; a **threshold split**, which never
   influences that list, tests them. With a timestamp on every case, the cases are ordered by time
   and the older half is the temperature split; otherwise a seeded permutation decides, and the
   certificate records the seed.
2. **Candidate thresholds.** The candidates are the midpoints between adjacent distinct confidences
   of the temperature split, from strictest to loosest, then 0.
3. **Fixed-sequence testing (Learn-then-Test).** Each test walks down that list. At each candidate
   an exact binomial test asks whether the selective error there could be above the target `alpha`.
   The walk rejects candidates while the p-value is at most the test's level, and stops at the first
   that does not pass; the threshold is the last candidate that passed. Since v1.1, each test starts
   at the candidate that looks best on **its own** temperature-split cases. The order and the start
   are fixed before the threshold split is seen, so the whole walk keeps the error probability of a
   single test.
4. **Segments.** A segment is a value of one declared case field, for example a region. A declared
   segment with at least a declared number of threshold-split cases (the floor) is **certified**: it
   gets its own test and threshold, on its own cases. The other cases, including segments below the
   floor, form the **remainder**, whose test gives the top-level threshold. The confidence `delta`
   is split evenly across the tests (Bonferroni: each runs at `delta` / (1 + k) for k certified
   segments), so the claim holds for all of them at once.
5. **Refusal.** The issuer refuses to certify when the threshold split has fewer than
   1/`alpha` − 1 cases. That is a floor, not a recommendation: near it, a test usually abstains on
   every case. [`docs/certificates.md`](certificates.md#how-many-labelled-cases) gives the numbers of
   cases a useful certificate tends to need.

The resulting claim, under exchangeability of the calibration cases and future cases: with
probability at least `1 − delta` over the draw of the calibration cases, the selective error is at
most `alpha`, for the top level and every certified segment at once.

A weaker variant, conformal risk control (`method: crc`), bounds the *joint* error, the share of
all cases that are answered and wrong, in expectation over the draw of the calibration cases rather
than with probability `1 − delta`. It is offered for small samples, and it is a much weaker claim:
at a coverage of 20%, a joint error of 0.05 allows 25% error among the answered cases. The
certificate names which method and which risk it used.

## Segments and a changing mix

A certified segment's claim is about that segment's cases alone, so it holds whatever share of the
cases the segment has later. The remainder's claim is about the remainder as it was mixed in the
calibration cases. If the shares of groups inside the remainder change, and their errors differ,
its bound can fail. A field whose shares may change, and whose groups may differ in error, is best
declared as a segment with a floor its groups can meet. Segments below the floor carry no bound of
their own: they are decided by the remainder's threshold.

## When nothing passes

Sometimes no threshold passes, and the certificate says so: `abstain_below` is 1.01, and the rule
abstains on every case. That is a result, not a failure. On the public bank-marketing data, with the
demo's logistic-regression model and the clients' contact type declared as a segment, the
`cellular` segment has no threshold at `alpha` 0.05 that passes, even one picked after looking at
the test cases (the [v1.1 draft](../spec/drafts/decision-certificate.v1.1.md) records it). The
model is not good enough there to be trusted at that error rate, so abstaining on those cases is
correct. The same model does certify on the pooled cases: the demo certificate in
[`demo/bank-marketing/`](../demo/bank-marketing/README.md) answers 53% of its 11,303 test cases.

## Costs instead of errors (v1.4)

Not every error costs the same. A wrong approval may cost far more than a wrong decline. With the
cost risk, `selective_cost`, the consumer gives a cost matrix: the cost of answering each option
when the label is each option, in whole numbers of a unit it names (cents, points), with no cost for
a correct answer. Each answered case's loss is its cost divided by the largest cost, so it lies
between 0 and 1, and the test bounds the **mean loss of the answered cases** instead of their error
rate.

The procedure is the same walk down the same candidates, with the Hoeffding–Bentkus p-value in place
of the exact binomial one, because a loss is no longer just 0 or 1. The claim: with probability at
least `1 − delta`, the expected cost per answered case is at most `alpha` times the largest cost, in
the consumer's unit. Costs are whole numbers so that every implementation sums them exactly, in any
order. When every error costs the same, the cost test would only be more conservative than the
binomial one, so the issuer writes the ordinary error certificate instead.

## The options a consumer automates (v1.3)

A consumer may decide only some options automatically, for example approvals, and send every other
answer to a person. Since v1.3 a certificate names those options and reports, for each test, the
share of its cases that are answered with an automated option, with the error among them. These
numbers are descriptive. The claim still covers every answered case, whatever the option: the
threshold was not chosen on the automated cases alone, so their error is not bounded at `alpha`, and
it can be higher than the error of all answered cases.

## The numbers that only describe

Each certificate also reports `ucb` and `realized_band`, Clopper–Pearson intervals at the selected
threshold: `ucb` is the one-sided upper bound at the test's own level, and `realized_band` a
two-sided 95% interval. Because they are computed after the threshold was selected, they are not
confidence statements. They show how much uncertainty there is: a certificate built on 300 cases
shows a wide band, and one built on 30,000 a narrow one. The same holds for the numbers about
automated options (v1.3) and for the mean cost actually observed (v1.4).

## Whose cases, and for how long

- **Audit basis.** The claim covers only the population the labelled cases were drawn from. If
  labels exist only for cases an earlier process acted on, the audit has to sample from all cases,
  with a logged, uniform rate. Public datasets with every case labelled are recorded as
  `full-label`.
- **Expiry.** A certificate has an `expires_at`: the latest case timestamp (or, without timestamps,
  the time it was fitted) plus the number of days the consumer configures. It is a prompt to measure
  again, not a statement that the bound held until that date. After it, a consumer refers every case
  to a person by default, or decides and logs a warning if configured to.

## Watching for change without labels

Labels arrive late or not at all once a model is in use, so a certificate also carries what a
consumer needs to notice that the cases have changed.

- **Answered share.** Every certificate has its `coverage`: if the share of cases the model answers
  drifts away from it, the cases are no longer like the calibration cases. Since v1.3, the same
  comparison works for the share decided automatically.
- **Shift score.** Since v1.2, a certificate also stores how the calibration cases' confidences were
  spread: one histogram per test (the remainder and each segment), on bins chosen without the
  threshold split, with a separate count of the cases the rule abstains on whatever the threshold. A
  consumer bins its own recent cases the same way and compares the two with a chi-square test. That
  sees more than the answered share: cases can drift toward the threshold, and so become more often
  wrong, while the answered share stays the same.

Both comparisons look only at the model's confidences. A significant change is a reason to measure
again. Neither one shows that the error stayed within its bound, and the histogram also flags
changes that do no harm, such as among cases the decision abstains on. A change in how often the
model is wrong at the same confidence is invisible to both, and only new labelled cases can show
it. Checking many windows also raises the chance of a false alarm, as any repeated test does.

The histogram's counts are exact, so for a group with few cases they say something about those
cases' confidences. The reference issuer withholds the histogram of any test with fewer than 30
cases (a configurable minimum), and the remainder's when subtracting the published segments'
histograms from it would single out between 1 and 29 cases.

## What anyone can check

The certificate is canonical JSON (RFC 8785) signed with Ed25519 (RFC 8032, verified strictly), and
its id is `sha256:` of the signed bytes, signature included. That id is frozen: every version of the
spec derives it the same way, and a consumer records it with every decision made under the
certificate. A consumer checks the signature against keys it already trusts and uses the recorded
threshold. Two independent verifiers, in Rust and Python, agree on every conformance fixture of all
five versions, and [`docs/conformance.md`](conformance.md) describes how another implementation
shows the same agreement.

A verifier checks the signature and the fields, not the measurement. The certificate's `data_hash`
binds every labelled case it used: its id, label, raw scores, timestamp, segment and audit
propensity, and since v1.3 its `cannot_tell` value. Whoever holds the data can recompute the hash,
re-run the measurement and must get the same thresholds and counts.

## Limits

A certificate says nothing about a single decision, about cases unlike the calibration cases
(another time, population or product), about fairness or legality, or about the quality of the
labels themselves. When the scored model's manifest hash is null, the model itself cannot be
verified. More specifically:

- **The mix.** The remainder's bound, and so the threshold of every segment below the floor, holds
  for the mix of cases in the calibration set.
- **Choices made after looking.** The certification cases must not have been used to train, tune or
  choose the model, the threshold or `alpha`. Issuing several certificates on the same cases and
  keeping the best is selection that the bound does not cover, and a certificate does not record how
  many were issued.
- **Small samples.** The claim is over the draw of the calibration cases, not conditional on a
  certificate being issued. With few cases, few draws certify, and a certificate that does issue is
  weak evidence.
- **A `dr` map** shapes the probabilities only. The bound is still measured on the threshold split,
  so it covers the population the splits were drawn from.
- **Costs** are the consumer's input; the certificate does not check that they are right.

## References

- A. N. Angelopoulos, S. Bates, E. J. Candès, M. I. Jordan, L. Lei. *Learn then Test: Calibrating
  Predictive Algorithms to Achieve Risk Control.* 2021.
- A. N. Angelopoulos, S. Bates, A. Fisch, L. Lei, T. Schuster. *Conformal Risk Control.* 2022.
- S. Bates, A. N. Angelopoulos, L. Lei, J. Malik, M. I. Jordan. *Distribution-Free,
  Risk-Controlling Prediction Sets.* Journal of the ACM, 2021.
- C. J. Clopper, E. S. Pearson. *The Use of Confidence or Fiducial Limits Illustrated in the Case of
  the Binomial.* Biometrika, 1934.
- RFC 8785, *JSON Canonicalization Scheme (JCS)*; RFC 8032, *Edwards-Curve Digital Signature
  Algorithm (EdDSA)*.
