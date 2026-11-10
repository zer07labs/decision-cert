# What a certificate gives a model validation

Model risk guidance such as the US supervisory guidance SR 11-7 (2011) asks model risk management
to cover a model's intended use, its limits and how changes are controlled, and a validation to
cover its conceptual soundness, ongoing monitoring and outcomes analysis. This page maps a v1.2 certificate
([spec](../spec/decision-certificate.v1.2.md)) onto those headings. It says what each field shows
and what the validation still has to do itself.

A certificate is **evidence for one part of a validation**: a signed, reproducible measurement of
how often one model's automated answers to one decision were wrong on a stated set of labelled
cases, and of how many cases it answered. It describes a measured process and
never guarantees an outcome. It is not a validation, a validation report or an approval.

## The mapping

| Validation heading | What the certificate gives | What it does not give |
|---|---|---|
| **Intended use** | `domain`, `decision`, `options`: the decision it covers. `segments`: the declared groups and which of them have their own bound. `window`: the period the labelled cases came from. `expires_at` and the consumer's `on_expired`: when it stops applying. | Which business process, which population and which product it is meant for, who uses it, and what it must not be used for. Those belong in the model's documentation. The certificate does not bind the population, and a consumer can apply it to cases it was not measured on. |
| **Conceptual soundness** | The method is named and public: `method` (`ltt` or `crc`), `risk`, `alpha`, `delta`, the procedure of spec §1.1, the `calibration_map`, and the `rule` (`cannot_tell_above`, unscored cases count as abstentions). The statement it makes is in spec §1, with the condition it rests on, exchangeability. | Anything about the model itself: its design, features, training data, or whether its scores make sense for the decision. The certificate treats the model as a black box that outputs scores. |
| **Outcomes analysis** | The measured result on held-out labelled cases: `n`, `coverage`, `abstain_below`, `ucb`, `realized_band`, per certified segment and for the remainder (the top-level fields); `n_cal` is the whole threshold split. The map is never fitted on the threshold split, and the grid uses no label or confidence of it. `data_hash` binds each labelled case's id, label, raw scores, timestamp, segment and propensity (both splits, and a `dr` map's recalibration cases), so whoever holds the data and the domain config can re-run the measurement and must reproduce it. | Back-testing over several periods: one certificate covers one `window`. Benchmarking against other models, the quality of the labels, and the error on cases the model abstains on, which a person decides. |
| **Ongoing monitoring** | A label-free drift alarm: the shift score of recent confidences against `confidence_histogram` (spec §4), and the answered share against `coverage`. `expires_at` forces a new measurement. | Whether the bound still holds. A quiet alarm does not show that; an alarm does not show that it has failed (spec §5). Fresh labels and a new certificate are the only re-measurement. How often to check, and what to do on an alarm, are the deployment's decisions (see the false-alarm note below). |
| **Limits** | Spec §5 lists what a certificate does not claim, and the consumer's `abstain_reason` records each case sent to a person. | A statement of the model's limits for the use it is put to. |
| **Change control** | `model_id` (backend and model version) and `manifest_hash` (when the issuer is given a manifest) identify what was measured. `signer_key_id` and the signature show which key signed it, and an edit to any field breaks the signature. The certificate id names one exact certificate for an inventory. | A binding of the preprocessing, feature schema, rules engine or deployment configuration, unless the operator puts them in the manifest. Key revocation and rotation. Any record of other certificates issued on the same cases. A later spec may cover these; v1.2 does not. |

## What a validator should check

- **Re-run it.** Given the labelled cases, the predictions and the split seed, the reference issuer
  reproduces the measurement: the same `data_hash`, thresholds and counts. The verifiers check only
  the signature and the fields, not the measurement.
- **The labelled cases are a fair sample.** The bound covers the population the cases were sampled
  from (spec §1.4). Where labels exist only for cases an earlier process acted on (in credit, the
  approved applications), see the audit sample in
  [`credit-approval.md`](credit-approval.md#selective-labels-an-audit-sample).
- **No case was used twice.** The certification cases must not have been used to train, tune or
  choose the model, its prompt, or the alpha. The issuer checks only that a `dr` map's
  recalibration cases are disjoint from the splits, and a verifier cannot check even that; the rest is the operator's process to show.
- **Alpha was chosen before the measurement.** Issuing at several values of `alpha` on the same
  cases and keeping the best is selection that the bound does not cover. v1.2 has no record that
  shows how many certificates were issued.
- **Enough cases.** A certificate that abstains on everything (`abstain_below` 1.01) is a valid
  result. See the counts a test needs in
  [`certificates.md`](certificates.md#how-many-labelled-cases).
- **Drift alarms and false alarms.** A test at p < 0.01 run every day raises about one false alarm
  every 100 days on an unchanged population, and more when several segments are checked. Choose the
  threshold for the alarm rate the deployment can act on.
- **Segments.** A certified segment's bound holds whatever its share later; the remainder's bound
  holds only at the mix it was measured on (`certificates.md`, "Segments and a changing mix").
  Nothing in a certificate is a fairness, legality or compliance finding.
