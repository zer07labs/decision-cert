# Decision certificates

A decision certificate records how one model's answers to one decision were measured: the labelled
cases, the threshold chosen, how many cases it answers, and a bound on the error of those answers
at a stated confidence. It is signed by whoever ran the measurement. The normative definition is
[`spec/decision-certificate.v1.2.md`](../spec/decision-certificate.v1.2.md) (certificates issued
under [v1](../spec/decision-certificate.v1.md) and [v1.1](../spec/decision-certificate.v1.1.md) stay
valid); this page is how to use it.

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
- **That a quiet shift score means the bound holds.** The v1.2 confidence histogram describes the
  calibration cases. Comparing use-time cases with it shows where confidences moved, never that the
  error stayed within `alpha`, and a flagged shift can be a harmless one.

## Issuing one

Whoever runs the measurement issues the certificate, in their own environment, with their own
Ed25519 key. The issuer of a certificate never needs anyone else's signing key, and nobody else
holds theirs. This section describes what any issuer does, following
[spec §1](../spec/decision-certificate.v1.2.md#1-what-is-measured). The reference issuer is
`decision_cert.issue` (`pip install 'decision-cert[issue]'`); its commands are shown with each step.

1. **Generate a signing key once** and publish its trusted-keys entry: the key id (`ed25519:` + the
   first 16 hex chars of SHA-256 of the raw public key) and the base64url raw public key. The
   private key never leaves the issuer's environment.
2. **Score a labelled calibration set** with the model: one row per case with the case id, the
   label, the raw score per option, and optionally `decided_at`, a segment value and the audit
   propensity.
3. **Run the procedure** of spec §1.1: split, fit the calibration map (a temperature on the
   temperature split, or, v1.2, a `dr` map on a separate recalibration set),
   build the grid, test each certified segment and the remainder, compute the descriptive `ucb`
   and `realized_band` (§1.2), and (v1.2) each test's confidence histogram (§1.5).
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
- **Refusals.** An issuer refuses when the threshold split has fewer than 1/`alpha` − 1 cases; on a
  missing label (any row under `full-label`; under `sample`, a row the audit selected, one that logs a
  propensity above 0); on a labelled case with no prediction, mismatched options, or an unknown model
  version. Log `propensity` only on the rows the audit selected. Under `sample`, the other rows scored
  for the decision without a label are skipped, counted in the diagnostics as
  `n_skipped_unlabelled`, and reported by `certify`.
- **Threshold.** When no threshold passes, the certificate says so: `abstain_below: 1.01`, which
  abstains on every case.
- **Spec.** The reference issuer writes `decision-certificate.v1.2`. `--spec decision-certificate.v1.1`
  writes the same test without the confidence histogram, for consumers that do not read v1.2 yet;
  `--spec decision-certificate.v1` issues by the v1 procedure, to reproduce an earlier certificate.
  `--spec decision-certificate.v1.3` ([spec](../spec/decision-certificate.v1.3.md), implemented,
  not frozen) adds, with `--automate-options approved=yes` (once per decision, default every
  option), each test's answered
  share and error among the cases whose answer is an automated option. Those numbers are
  descriptive, and the bound still covers every answered case. v1.3's `data_hash` also binds each
  case's `cannot_tell` value.
- **Histograms** (v1.2). Bins at the 20-quantiles of the temperature split's confidences, and per
  test the threshold-split cases per bin. A test with fewer than `histogram_min_n` cases (default
  30) gets `null` instead, so that a few cases' confidences are not published one by one (spec §6).
- **`dr` map** (v1.2). `--map dr --recal-data recal.jsonl --prior prior.json` fits
  softmax(a · scores + b) on labelled cases from the population in use, disjoint from `--data` (the
  predictions file covers them too), under a prior `{"mu_a", "sigma_a", "sigma_b"}` learned from
  earlier shifts (`decision_cert.issue.recal.meta_prior`). `label_budget` records how many there
  were, and `data_hash` covers them. The temperature split then only builds the grid and the bins.
  The bound is still measured on the threshold split, so it covers the population the splits came
  from.

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

**The arithmetic floor.** Below the no-error counts a test cannot pass whatever the model, because
the exact binomial p-value (spec §1.1 step 5) cannot reach the test level. With `delta` 0.10 and no
certified segments:

- an `ltt` test needs `m` = ⌈ln `delta` / ln(1 − `alpha`)⌉ answered threshold-split cases with
  **no** errors: 45 at `alpha` 0.05, 22 at 0.10 and 11 at 0.20;
- the threshold split is the larger half of the labelled cases (`n_cal` = ⌈rows / 2⌉), so the
  labelled rows needed are 2 · ⌈`m` / coverage⌉ − 1 when the test answers a share `coverage` of its
  cases.

| `ltt`, `delta` 0.10 | answered, no errors | rows at coverage 100% | 75% | 50% | 25% |
|---|---|---|---|---|---|
| `alpha` 0.05 | 45 | 89 | 119 | 179 | 359 |
| `alpha` 0.10 | 22 | 43 | 59 | 87 | 175 |
| `alpha` 0.20 | 11 | 21 | 29 | 43 | 87 |
| `alpha` 0.05, errors at half `alpha` | 184 | 367 | 491 | 735 | 1,471 |
| `alpha` 0.10, errors at half `alpha` | 91 | 181 | 243 | 363 | 727 |
| `alpha` 0.20, errors at half `alpha` | 38 | 75 | 101 | 151 | 303 |

The "errors at half `alpha`" rows are not floors: they are where a model whose error among the
answered cases is half of `alpha` starts to pass, with the errors at their expected number rounded
half up, as the smallest count from which every larger count passes. Real error counts vary from
draw to draw, which is why the simulation table above, which asks for certifying in 90% of draws,
needs several times more. With k certified segments every test, the remainder's included, runs at
the level `delta` / (1 + k), and each segment is a test on its own cases: with no errors a test
needs 59 answered cases at `alpha` 0.05 for k = 1 (72 for k = 3), 29 (36) at 0.10 and 14 (17) at
0.20.

A `crc` test passes with no errors at `n_cal` ≥ 1/`alpha` − 1 (19, 9 and 4, so 37, 17 and 7 rows),
whatever the coverage; this is the issuer's refusal floor. It bounds the average joint error, not the
error of the answered cases (§1): at coverage 25% and `alpha` 0.10 it allows 40% error among them.

The issuer warns when an `ltt` test has fewer threshold-split cases than its `m`: such a test
abstains on everything. It never changes the method for you; `--method crc` is a separate claim to
choose explicitly.

**A certificate that issues at a small `n_cal` is weak evidence.** The statement is over the
calibration draw, not conditional on a certificate issuing. At small `n_cal` few draws certify, and
over only the draws that did, the mean risk at the chosen threshold can be above `alpha`: up to
2.5 × at `n_cal` 100 in the cost study, where one or two draws in 1,000 certified. Prefer the sizes
in the table above. Whether to set a minimum is an open question
([v1.1 draft, O4](../spec/drafts/decision-certificate.v1.1.md); spec v1.4 §1.7).

### Cost-weighted abstention (v1.4)

`--spec decision-certificate.v1.4 --cost approved=costs.json` (once per decision) certifies the
expected cost of the answered cases instead of their error rate
([spec v1.4](../spec/decision-certificate.v1.4.md), implemented, not frozen). The file is
`{"matrix": [[...]], "unit": "usd" | null}`, row = label, column = answered option, in the order of
the options, with a zero diagonal. The bound is `alpha` · `c_max` per answered case, in `unit`.
`--method crc` cannot take a cost.

**When a cost matrix pays** ([cost study](../spec/drafts/cost-study.md), `delta` 0.1, the same
synthetic model as the table above):

- **Cheap errors dominate** (most errors are the cheap kind, the ratio 5:1 or more): fewer labels
  and more coverage than the error certificate. At `alpha` 0.05 and a strong model, about 500
  threshold-split cases instead of 1,000.
- **Equal costs**: the cost test would need up to twice the labels for the same claim, and gives
  nothing. The issuer writes the error certificate instead, byte-identical to the one issued
  without a cost.
- **Expensive errors dominate**: about the equal-cost count, so up to twice the error
  certificate's labels for little gain. Keep the error certificate unless the cost bound itself is
  what the consumer needs.

O4's guidance above (about 1,000 threshold-split cases at `alpha` 0.05 for a strong model) stands
for the error certificate; a cost certificate needs more when expensive errors dominate. The study
found every cell valid (the largest violation rate 0.050 against `delta` 0.1).

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
  histogram_min_n: 30       # issuer, v1.2: withhold (null) the histogram of a test with fewer cases
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
  - uses a calibration map the consumer does not apply (v1 and v1.1 consumers apply `temperature`;
    v1.2 defines `temperature` and `dr`, which `Verified::probabilities` applies), or disagrees with
    the calibration entry's map or threshold;
  - was measured with another `cannot_tell_above`;
  - certifies segments by another field, or a segment value the domain no longer declares.
- **Deciding.** Each decision made under a certificate carries `certificate_id` (`sha256:` of the
  signed certificate's canonical bytes). A case in a certified segment uses that segment's
  threshold.
- **Expiry.** After `expires_at`, `on_expired: refer` abstains with
  `abstain_reason: "certificate_expired"`; `warn` decides and logs a warning.
- **Monitoring without labels.** Two scores, both prompts to measure again and neither a finding
  about the bound:
  - **Answered share** (any spec): compare the share of cases answered with the certificate's
    `coverage`, for example with a two-sample test of proportions against `n` threshold-split cases.
    It shows shifts that move confidences across the threshold.
  - **Shift score** (v1.2, spec §4): bin a window of confidences on `confidence_bins` and compare it
    with the stored histogram of the same test. It also shows shifts inside the answered range,
    which can raise the error while the answered share stays put
    ([H1 study](../spec/drafts/h1-histogram-study.md)), and shifts among abstained cases, which are
    harmless.

  ```python
  from decision_cert import Histogram, shift_score, verify
  v = verify(cert, keys)
  window = Histogram.of(v.confidence_bins(), confidences)    # None: unscored or above cannot_tell_above
  shift_score(v.histogram_for(segment), window).p_value       # small: measure again
  ```

  The Rust crate has the same functions (`Histogram::of`, `shift_score`, `Verified::histogram_for`).
  Neither score can show a change in error at the same confidence, or a change in the mix of groups
  the model cannot tell apart; only labelled cases can
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
