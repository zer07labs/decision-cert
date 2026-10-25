# Decision certificates

A decision certificate records how one model's answers to one decision were measured: the labelled
cases, the threshold chosen, how many cases it answers, and a bound on the error of those answers
at a stated confidence. It is signed by whoever ran the measurement. The normative definition is
[`spec/decision-certificate.v1.md`](../spec/decision-certificate.v1.md); this page is how to use it.

## What a certificate claims, and what it does not

For `method: ltt` (the default) the claim is:

> With probability at least 1 − `delta` over the draw of the calibration cases, the error rate of the
> answered cases is at most `alpha`, for the top-level threshold and every certified segment at once,
> **provided future cases are exchangeable with the calibration cases.**

It does **not** claim:

- **Single decisions or unlike cases.** Anything about one decision, or about cases unlike the
  calibration cases: another period, population or product. Drift breaks exchangeability, which is
  why certificates expire.
- **Label quality or fairness.** That the labels were right, or that the decisions are fair or lawful.
- **That `ucb` and `realized_band` are confidence intervals.** They are computed after the threshold
  was chosen, so they describe the measurement's width only. A certificate built on 300 cases shows
  a wide band.
- **Bounds for inherited segments.** A segment below the floor (`inherited: true`) carries no bound
  of its own.
- **Unsampled populations.** The bound covers only the population the labelled cases were sampled
  from. If only the cases an incumbent process approved got labels, it says nothing about the rest.
- **For `method: crc`, a high-probability bound.** That method bounds the *average* share of cases
  that are answered and wrong, which is a weaker claim, and the certificate names it
  (`risk: joint_error`).

## Issuing one

The operator runs this in their own environment, with their own key. decisiond never holds a
customer's signing key.

```bash
dk certify keygen --out operator.pem            # once; prints the `certificate.keys` entry to trust
dk eval --domain <id> --data calib.jsonl --backends <name>          # predictions on a calibration split
dk certify --predictions reports/predictions/<name>.jsonl --data calib.jsonl \
    --domain-dir domains/<id> --backend <name> --key operator.pem \
    --audit sample --in-environment             # or --audit full-label on a fully labelled public set
dk certify verify --calibration domains/<id>/calibration/<name>.json --domain-dir domains/<id>
```

- **Output.** `domains/<id>/calibration/<backend>.json` gets, per decision, the temperature, the
  certified `abstain_below` and the signed `certificate`. The server loads that file at startup.
  `<backend>.certify.json` holds aggregate diagnostics.
- **`--in-environment`** writes nothing else. Without it, `<backend>.certify-cases.jsonl` lists each
  case id with its split, confidence and error, for debugging. That file stays out of a customer's
  outputs. No mode ever writes case payloads.
- **Audit basis.**
  - `--audit sample` (default, for live data): the rows must be an audit sample, every row
    logging the same propensity > 0.
  - `--audit full-label` (public sets): every row must be labelled.
- **Refusals.** `dk certify` exits 3 when the threshold split has fewer than 1/`alpha` − 1 cases,
  and 1 for any other refusal: a missing label or prediction, mismatched options, or an unknown
  model version.
- **Threshold.** When no threshold passes, the certificate says so: `abstain_below: 1.01`, which
  abstains on every case.

## Domain config

```yaml
certificate:
  ttl_days: 90              # expires_at = latest decided_at (else fitted_at) + ttl_days
  on_expired: refer         # refer: abstain with abstain_reason "certificate_expired"; warn: decide and log
  segments:                 # optional: one case field, its declared values, and the floor per segment
    field: region
    values: [north, south]
    floor: 200
  keys:                     # trusted signing keys: key id → base64url raw Ed25519 public key
    "ed25519:1f217282bf49a241": TA1U9XSMsXFbAw3EnYGLKL6vxjYJo8xvWh2eTirq6Yo
```

Segment values are only ever the declared ones, and must be quoted strings in YAML (`'1.50'`,
`'yes'`). A case whose field holds anything else, or a non-string, is decided by the top-level
threshold. Timestamps are normalised to UTC whole seconds (no offset means UTC) before the split.
`dk certify` warns when `expires_at` is already past, as it is for old timestamped data with a
short `ttl_days`; with `on_expired: refer` such a certificate abstains on everything.

## In the server

- **Loading.** decisiond verifies every certificate when the domain loads, and refuses the domain
  (startup fails) when a certificate:
  - doesn't match the schema;
  - isn't signed by a trusted key;
  - names another domain, decision, option order or backend;
  - uses a calibration map other than `temperature`, or disagrees with the calibration entry's
    temperature or threshold;
  - was measured with another `cannot_tell_above`;
  - certifies segments by another field, or a segment value the domain no longer declares.

  Calibration files without a certificate load as before.
- **Deciding.** Each decision made under a certificate carries `certificate_id` (`sha256:` of the
  signed certificate's canonical bytes). A case in a certified segment uses that segment's
  threshold.
- **Expiry.** After `expires_at`, `on_expired: refer` abstains with
  `abstain_reason: "certificate_expired"`; `warn` decides and logs a warning.

## Worked example (T2, B1, 2026-10-25)

`dk certify --audit full-label` on B1's predictions for the T2 (HMDA approval) calibration split,
alpha 0.05 and delta 0.1:

- **Result:** certified, `abstain_below` 0.9389, answering 40.9% of the 3,079 threshold-split cases,
  with `ucb` 0.0494.
- **Expiry:** without `decided_at` on the rows, it expires 90 days after it was fitted.
- **Verification:** the server loaded it and returned the same `certificate_id` as
  `dk certify verify`.

P7's evidence pack reissues certificates like this one, with the signing key outside the repo.
