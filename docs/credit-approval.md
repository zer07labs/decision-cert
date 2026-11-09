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

## What this does not claim

Spec v1.2 §5 applies in full. For credit approval in particular:

- Nothing about any single applicant, or about applicants unlike the calibration cases (another
  lender, region, period or product).
- The bound covers the population the labelled cases were sampled from. Where labels exist only for
  approved applications, an audit sample of all applications is needed (spec §1.4); otherwise the
  bound is about approved applications only.
- Nothing about fairness, legality or regulatory compliance, or the quality of the labels.
- The drift alarm looks at confidences only. A quiet alarm does not show that the bound still
  holds; an alarm does not show that it has failed.
