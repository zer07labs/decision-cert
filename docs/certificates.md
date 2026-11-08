# Decision certificates

A decision certificate records how one model's answers to one decision were measured: the labelled
cases, the threshold chosen, how many cases it answers, and a bound on the error of those answers
at a stated confidence. It is signed by whoever ran the measurement. The normative definition is
[`spec/decision-certificate.v1.1.md`](../spec/decision-certificate.v1.1.md) (certificates issued
under [v1](../spec/decision-certificate.v1.md) stay valid); this page is how to use it.

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
- **Any mix of groups.** The remainder's bound, and so every inherited segment's threshold, holds for
  the mix of cases the calibration set had. A certified segment's bound holds at any mix.
- **Unsampled populations.** The bound covers only the population the labelled cases were sampled
  from. If only the cases an incumbent process approved got labels, it says nothing about the rest.
- **For `method: crc`, a high-probability bound.** That method bounds the *average* share of cases
  that are answered and wrong, which is a weaker claim, and the certificate names it
  (`risk: joint_error`).

## Issuing one

Whoever runs the measurement issues the certificate, in their own environment, with their own
Ed25519 key. The issuer of a certificate never needs anyone else's signing key, and nobody else
holds theirs. This section describes what any issuer does, following
[spec §1](../spec/decision-certificate.v1.1.md#1-what-is-measured). The reference issuer is
`decision_cert.issue` (`pip install 'decision-cert[issue]'`); its commands are shown with each step.

1. **Generate a signing key once** and publish its trusted-keys entry: the key id (`ed25519:` + the
   first 16 hex chars of SHA-256 of the raw public key) and the base64url raw public key. The
   private key never leaves the issuer's environment.
2. **Score a labelled calibration set** with the model: one row per case with the case id, the
   label, the raw score per option, and optionally `decided_at`, a segment value and the audit
   propensity.
3. **Run the procedure** of spec §1.1: split, fit the calibration map on the temperature split,
   build the grid, test each certified segment and the remainder, compute the descriptive `ucb`
   and `realized_band` (§1.2).
4. **Sign** the canonical (RFC 8785) bytes of the certificate without `signature`, and attach the
   signature.
   With the reference issuer, steps 1 and 3–4:

   ```bash
   python -m decision_cert.issue keygen --out operator.pem    # prints the trusted-keys entry
   python -m decision_cert.issue certify --predictions preds.jsonl --data labelled.jsonl \
       --domain-dir my-domain --backend my-model --key operator.pem [--audit full-label] [--in-environment]
   ```

   `--predictions` holds one row per case and decision (`case_id`, `decision`, `model`, `version`,
   `raw_scores`, or `status: "no_answer"`); `--data` holds the labelled rows (`case_id`, `case`,
   `labels`, and optionally `decided_at` and `propensity`). The output is
   `<domain>/calibration/<backend>.json`. Exit code 3 means too few cases.
5. **Verify what was written** with the trusted-keys file, as a consumer will:

```bash
cd rust && cargo run --features cli -- verify cert.json --keys trusted-keys.json
cd python && uv run python -m decision_cert verify cert.json --keys trusted-keys.json
```

What an issuer writes, and what it refuses:

- **Output.** Per decision, the calibration parameters, the certified `abstain_below` and the
  signed certificate. Aggregate diagnostics may be written beside it. Case payloads are never
  written, and per-case debugging output stays in the issuer's environment.
- **Audit basis** (spec §1.4).
  - `sample` (live data): the labelled rows must be an audit sample, every row logging the same
    propensity > 0.
  - `full-label` (public sets): every row in the window must be labelled.
- **Refusals.** An issuer refuses when the threshold split has fewer than 1/`alpha` − 1 cases, and
  on a missing label or prediction, mismatched options, or an unknown model version.
- **Threshold.** When no threshold passes, the certificate says so: `abstain_below: 1.01`, which
  abstains on every case.
- **Spec.** The reference issuer writes `decision-certificate.v1.1`. `--spec decision-certificate.v1`
  issues by the v1 procedure, to reproduce an earlier certificate.

### How many labelled cases

A certificate's label budget is `n_temperature` + `n_cal`, plus `calibration_map.label_budget` when
that is not null (spec §2). The refusal floor, 1/`alpha` − 1 threshold-split cases, is not a
recommendation: near it, an `ltt` certificate usually abstains on everything. How many cases a useful
certificate needs depends on the model. A simulation study
([`spec/drafts/o4-budget-study.md`](../spec/drafts/o4-budget-study.md), `delta` 0.1) gives these
threshold-split sizes for certifying in about 90% of draws. The temperature split is the same size,
so the label budget is twice `n_cal`. They are guidance only:

| Model (the share of cases it can answer at `alpha`) | `alpha` 0.05 | `alpha` 0.10 |
|---|---|---|
| strong (75%) | `n_cal` ≈ 1,000 | ≈ 500 |
| medium (50%) | ≈ 2,000 | ≈ 1,000 |
| weak (25%) | ≈ 3,000 | ≈ 2,000 |

With fewer cases, `crc` gives a weaker claim (an average, §1), or a larger `alpha` may be the honest
choice.

### Segments and a changing mix

Declare as a segment any case field whose shares may change in use and whose groups may differ in
error, with a floor its groups can meet. A certified segment is tested on its own cases, so its bound
holds whatever share it has later. The remainder's bound holds only at the mix it was measured on: in
the [O3 study](../spec/drafts/o3-mix-study.md), raising a harder group's share from 20% to 50% broke
a pooled threshold in most draws, but not the same group certified as a segment.

## Domain config

A consumer declares, per domain, how certificates are trusted and applied:

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
An issuer should warn when `expires_at` is already past, as it is for old timestamped data with a
short `ttl_days`; with `on_expired: refer` such a certificate abstains on everything.

## In a consumer

Spec §4 is normative; in short:

- **Loading.** A consumer verifies every certificate when the domain loads, and refuses the domain
  when a certificate:
  - doesn't match the schema;
  - isn't signed by a trusted key;
  - names another domain, decision, option order or backend;
  - uses a calibration map the consumer does not apply (v1 and v1.1: `temperature`), or disagrees with the
    calibration entry's temperature or threshold;
  - was measured with another `cannot_tell_above`;
  - certifies segments by another field, or a segment value the domain no longer declares.
- **Deciding.** Each decision made under a certificate carries `certificate_id` (`sha256:` of the
  signed certificate's canonical bytes). A case in a certified segment uses that segment's
  threshold.
- **Expiry.** After `expires_at`, `on_expired: refer` abstains with
  `abstain_reason: "certificate_expired"`; `warn` decides and logs a warning.
- **Monitoring without labels.** Compare the share of cases answered with the certificate's
  `coverage`, for example with a two-sample test of proportions against `n` threshold-split cases.
  A significant change is a prompt to measure again. It shows shifts that move the model's
  confidences. It cannot show a change in error at the same confidence, or a change in the mix of
  groups the model cannot tell apart; only labelled cases can
  ([O2 study](../spec/drafts/o2-shift-study.md)).

## Example: reading a certificate

[`fixtures/valid_basic.json`](../fixtures/valid_basic.json) is shaped like a certificate for a
yes/no approval decision on a fully labelled public lending dataset (`audit.mode: full-label`),
with `method: ltt`, `alpha` 0.05 and `delta` 0.1. Its numbers are test material, but read as a
real certificate they say:

- **Measured:** 5,000 labelled cases, split by a seeded permutation into 2,500 for the
  calibration map and 2,500 for the threshold test.
- **Result:** `abstain_below` 0.8829, answering 41.2% of the 2,500 threshold-split cases.
- **Claim:** with probability at least 0.9 over the draw of those cases, the error rate among
  answered cases is at most 0.05, while future cases are exchangeable with them.
- **Descriptive only:** `ucb` 0.033 and `realized_band` [0.001, 0.043] show how wide the
  measurement is; they are not confidence intervals (§1.2).
- **Expiry:** without `decided_at` on the rows, it expires `ttl_days` (here 90) after it was fitted.
- **Not claimed:** anything about one decision, about another population or period, about label
  quality or fairness.

## Signing keys

**Losing or leaking a signing key: replace it, never recover it.** Generate a new key, replace the
trusted-keys entry, and record the retired key id with the date. Certificates signed by the retired
id then verify only against a key map that still lists it. A key used for published examples or
test material is never trusted by a live domain, and a live domain gets its own key. See
[`SECURITY.md`](../SECURITY.md).
