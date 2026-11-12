# Profile: credit approval

How a deployment that automates part of a credit-approval decision uses a v1.2 certificate: one
certificate per deployment, stating the measured error of the cases it decides automatically and
how many it decides, plus a label-free drift alarm. The profile adds no field and no rule: it is the
[v1.2 spec](../spec/decision-certificate.v1.2.md) applied to one binary decision. A certificate
describes a measured process and never guarantees an outcome.

The fixtures [`fixtures/v1.2/valid_basic.json`](../fixtures/v1.2/valid_basic.json) and
[`valid_segments_unicode.json`](../fixtures/v1.2/valid_segments_unicode.json) are certificates of
this shape: domain `hmda-approval`, decision `approved`, options `yes`, `no`.

## What the certificate states

| The deployment's question | Where it is |
|---|---|
| Which cases are decided automatically? | Those with confidence ≥ `abstain_below` (a certified segment's own, else the top-level one); the rest go to a person. |
| What share is that? | `coverage`, measured on the `n` threshold-split cases. |
| What is the error among them? | The claim: with probability at least 1 − `delta` over the calibration draw, at most `alpha` (`method: ltt`, `risk: selective_error`). `realized_band` and `ucb` show how wide the uncertainty is (descriptive, spec §1.2). |
| Is today's traffic still like the calibration cases? | The shift score of a window of recent cases against `confidence_histogram` (spec §4). |

**The error target is chosen, the coverage is measured.** The operator picks `alpha`, the error
budget for the automated cases; the procedure finds the loosest threshold whose error it can bound
at `alpha`, and `coverage` reports how many cases that threshold decides. A deployment that wants a
target coverage chooses `alpha` before issuing (from earlier data, never by issuing at several
`alpha` values on the same cases and keeping the one it likes: that is selection the bound does not
cover). A certificate never states the error at a coverage fixed in advance.

## Issuing

```yaml
# domain.yaml
id: credit-approval
decisions:
  - id: approved
    kind: noul
    question: Approve the application?
certificate:
  ttl_days: 90
  on_expired: refer        # an expired certificate sends every case to a person
  segments:                # optional: a field whose shares may change and whose error may differ
    field: product
    values: ["card", "auto", "mortgage"]
    floor: 1000
  histogram_min_n: 30
  keys:
    "ed25519:<16 hex>": <base64url public key>
```

```bash
python -m decision_cert.issue certify --predictions preds.jsonl --data labelled.jsonl \
    --domain-dir credit-approval --backend <name> --key operator.pem \
    --alpha 0.05 --delta 0.1 --audit full-label      # public data: every row is labelled
```

With a few labels from a population that has shifted since the model was trained, `--map dr
--recal-data recal.jsonl --prior prior.json` refits the calibration map on those cases (spec v1.2
§1.1 step 2).

## Deciding and monitoring

```python
from decision_cert import Histogram, loads, shift_score, verify

v = verify(loads(open("certificate.json").read()), keys)
threshold = v.threshold_for(case_product)
conf = v.confidence(raw_scores)            # None: a map this package does not apply, so refuse
automated = conf is not None and not cannot_tell and conf >= threshold

# Daily: the window's confidences (None for unscored or cannot-tell cases) against the stored histogram
stored = v.histogram_for(case_product)
if stored is not None:
    window = Histogram.of(v.confidence_bins(), recent_confidences)
    if shift_score(stored, window).p_value < 0.01:
        ...  # alarm: label a fresh sample and issue a new certificate
```

Also compare the window's automated share with `coverage` (spec §4). Use one window per threshold:
a certified segment's own cases, or everything the top-level threshold decides.

## Approvals only (v1.3)

A deployment that approves automatically and sends every "no" answer to a person, as well as every
abstention, decides fewer cases than `coverage` counts, and the error among them can differ from the
error of all answered cases. A v1.3 certificate
([spec](../spec/decision-certificate.v1.3.md)) states both:

```bash
python -m decision_cert.issue certify ... --spec decision-certificate.v1.3 --automate-options approved=yes
```

```python
assert v.automate_options() == ("yes",)   # refuse a certificate for other automated options
auto = v.automated_for(case_product)      # coverage, ucb, realized_band of the approvals it answers
```

The bound at `alpha` still covers every answered case. `automated` describes the approvals at the
chosen threshold (spec v1.3 §1.6): `automated.ucb` is not a bound and can exceed `alpha`, because
the threshold was chosen on all answered cases. Measured on at most as many cases, its band is
usually as wide or wider. Compare a window's approval share with `automated.coverage` as well as
its answered share with `coverage`.

## What this does not claim

Spec v1.2 §5 applies in full. For credit approval in particular:

- Nothing about any single applicant, or about applicants unlike the calibration cases (another
  lender, region, period or product).
- The bound covers the population the labelled cases were sampled from. Where labels exist only for
  approved applications, an audit sample of all applications is needed (spec §1.4, and
  [below](#selective-labels-an-audit-sample)); otherwise the bound is about approved applications
  only.
- Nothing about fairness, legality or regulatory compliance, or the quality of the labels.
- The drift alarm looks at confidences only. A quiet alarm does not show that the bound still
  holds; an alarm does not show that it has failed.

## Selective labels: an audit sample

In credit the label that matters often comes from the outcome (repaid or not), and an outcome
exists only for applications that were approved. Certifying on approved applications alone measures
the error on the population an earlier process chose, which is not the population the model decides.
Spec §1.4 asks for an audit sample drawn from **all** applications instead.

**What the label is.** The domain defines the correct decision for a case. Two sources work:

- **A reviewer's decision.** Each audit case is decided in full by a person following the written
  policy, blind to the model's answer. Every audited case gets a label, approved or not, so there is
  no selection by the earlier process. The bound is then about agreement with that review.
- **The outcome.** The label is derived from repayment over a fixed performance period. An
  outcome exists only if the application was approved, so the audit has to approve its sample
  whatever the earlier process would have done. That is a credit-policy decision with a cost, and the
  deployment's, not this library's.

**How the sample is drawn.**

1. At decision time, for every application in the window, draw an independent coin with a fixed
   probability `rate`, before the model's score or any earlier decision is seen. The draw must not
   depend on the case.
2. Label every case the coin selects, and log `rate` as the case's `propensity`. Every selected case
   keeps its label in the data, including the ones that are slow, costly or unfavourable to label.
   Log the propensity only on the cases the coin selected. Under `--audit sample` the issuer refuses
   a row that logs a propensity above 0 but has no label, and counts the other unlabelled rows it
   skips (in the diagnostics and on stderr). It cannot see a
   case left out of the data altogether, so dropping cases is a selection the bound does not cover.
   The same holds for a case the audit selected that has neither a prediction nor a label for the
   decision: the issuer counts only the cases scored for the decision, so that case is as invisible
   as one left out of the data. Score every selected case.
3. With outcome labels, the window must end at least one full performance period before the
   certificate is issued, so that every selected case has an outcome. Early outcomes only would bias
   the sample towards early defaults. `expires_at` counts from the window's end (`window.end` +
   `ttl_days`), so `ttl_days` must cover the performance period as well as the time the certificate
   is meant to be used; with a 12-month period, the profile's `ttl_days: 90` expires it before it is
   issued.
4. Issue with `--audit sample`. The certificate records `audit.mode: sample`, `rate`, `n` and
   `propensity_logged: true`.

**How large.** The audit needs the labelled rows of the [small-n table](certificates.md#how-many-labelled-cases)
for the `alpha` and the coverage expected, and in practice twice the simulation `n_cal` above it
(those sizes count the threshold split only). So `rate`
≈ rows needed / applications in the window. For example, 2,000 labelled rows from a window of
100,000 applications is a `rate` of 0.02. Each certified segment needs its own cases, so a
segment with a small share of applications sets the rate: a product with 5% of applications and a
floor of 1,000 threshold-split cases needs about 2,000 of its rows labelled, which is a `rate` of 0.4
from a window of 100,000, so about 40,000 labelled rows in all at one uniform rate.

**What v1.2 does not support.** v1.2 certifies **uniform** audit samples only: every case's
propensity must be the same, and the issuer refuses differing propensities. A design that samples
declined applications more heavily, or one rate per segment, needs bounds weighted by inverse
propensity, which are not exact binomial tests and are not in v1.2. Such a design is an open
question for a later spec. Until then, use one rate for the window and raise it until the smallest
certified segment has its cases.

