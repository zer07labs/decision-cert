> **DRAFT.** Not reviewed, not for posting. It stays in this repository until the owner says
> otherwise. Where it and the [spec](../../spec/decision-certificate.v1.md) differ, the spec is right.

# Measuring when a model may answer: the method behind decision certificates

A model that scores cases can be wrong in ways nobody sees until much later. A decision certificate
records one narrow, checkable measurement instead: on labelled cases like the ones the model will
see, **how often was it wrong on the cases it chose to answer**, and at what confidence cut-off
should it stop answering. The certificate is a signed record of that measurement. It describes a
measured process. It never guarantees an outcome.

## The decision rule being measured

The model gives each case a score per option. A temperature-scaled softmax turns the scores into
probabilities (or, since v1.2, a `dr` map: a rescaling and a per-option shift refitted on a few
labels from a shifted population, kept apart from both splits), and the top probability is the case's **confidence**. The rule answers a case when
its confidence is at or above a threshold, and abstains otherwise. Cases the model did not score
count as abstentions, so missing scores can never make the measured error look smaller.

An answered case is an **error** when its top option is not the label. The quantity of interest is
the error rate among answered cases, the *selective error*.

## Picking the threshold without fooling ourselves

Choosing a threshold by looking at the same cases you then report on overstates how good the
threshold is. The method separates the two jobs.

1. **Two disjoint splits.** One split fits the temperature and builds the list of candidate
   thresholds. The other split, which never influences that list, tests them. With timestamps, the
   older half fits and the newer half tests.
2. **Fixed-sequence testing (Learn-then-Test).** Candidates are tested from strictest to loosest.
   For each one, an exact binomial test asks whether the selective error could be above the target
   `alpha`. Testing stops at the first candidate that does not pass, and the loosest passing one is
   the threshold. Because the order is fixed in advance, the whole sequence keeps the error
   probability of a single test, `delta`.
3. **Segments.** A declared segment (for example a region) with enough cases gets its own test and
   threshold. The level is split across the segments and the remainder (Bonferroni), so the claim
   holds for all of them at once.
4. **Refusal.** With too few cases to make the test meaningful, the issuer refuses to certify.

The resulting claim, under exchangeability of the calibration cases and future cases: with
probability at least `1 − delta` over the draw of the calibration cases, the selective error is at
most `alpha`, for the top level and every certified segment.

A weaker variant, conformal risk control, bounds the *joint* error (answered and wrong) in
expectation. It suits small samples, and the certificate names which method was used.

## When nothing passes

Sometimes no threshold passes, and the certificate says so: `abstain_below` is 1.01, and the rule
abstains on every case. That is a result, not a failure. On the public bank-marketing data, with a
small logistic-regression model and the clients' contact type declared as a segment, the `cellular`
segment has no threshold at `alpha` 0.05 that passes, even one picked after looking at the test
cases. The model is not good enough there to be trusted at that error rate, so abstaining on those
cases is correct. The same model does certify on the pooled cases (see `demo/bank-marketing/`).

## The numbers that only describe

Each certificate also reports `ucb` and `realized_band`, Clopper–Pearson intervals at the selected
threshold. Because they are computed after the threshold was selected, they are not confidence
statements. They show how much uncertainty there is: a certificate built on 300 cases shows a wide
band, and one built on 30,000 a narrow one.

## Whose cases, and for how long

- **Audit basis.** The claim covers only the population the labelled cases were drawn from. If
  labels exist only for cases an earlier process acted on, the audit has to sample from all cases,
  with a logged, uniform rate. Public datasets with every case labelled are recorded as
  `full-label`.
- **Expiry.** A certificate has an `expires_at`. It is a prompt to measure again, not a statement
  that the bound held until that date.

## Watching for change without labels

Labels arrive late or not at all once a model is in use, so a certificate also carries what a
consumer needs to notice that the cases have changed. Every certificate has its `coverage`: if the
share of cases the model answers drifts away from it, the cases are no longer like the calibration
cases. Since v1.2, a certificate also stores how the calibration cases' confidences were spread, as
a histogram per threshold, on bins chosen without the threshold split. A consumer bins its own
recent cases the same way and compares the two with a chi-square test. That sees more than the
answered share: cases can drift toward the threshold, and so become more often wrong, while the
answered share stays the same.

Both comparisons look only at the model's confidences. A significant change is a reason to measure
again. Neither one shows that the error stayed within its bound, and the histogram also flags
changes that do no harm, such as among cases the decision abstains on. A change in how often the
model is wrong at the same confidence is invisible to both, and only new labelled cases can show
it.

The histogram's counts are exact, so for a group with few cases they say something about those
cases' confidences. The reference issuer leaves out the histogram of any group with fewer than 30
cases.

## What anyone can check

The certificate is canonical JSON (RFC 8785) signed with Ed25519, and its id is the hash of the
signed bytes. A consumer checks the signature against keys it already trusts and uses the recorded
threshold. Two independent verifiers, in Rust and Python, agree on every conformance fixture, and
`docs/conformance.md` describes how another implementation shows the same agreement.

## Limits

A certificate says nothing about a single decision, about cases unlike the calibration cases
(another time, population or product), about fairness or legality, or about the quality of the
labels themselves. When the scored model's manifest hash is null, the model itself cannot be
verified.

## References

- A. N. Angelopoulos, S. Bates, E. J. Candès, M. I. Jordan, L. Lei. *Learn then Test: Calibrating
  Predictive Algorithms to Achieve Risk Control.* 2021.
- A. N. Angelopoulos, S. Bates, A. Fisch, L. Lei, T. Schuster. *Conformal Risk Control.* 2022.
