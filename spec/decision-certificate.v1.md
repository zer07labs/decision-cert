# Decision certificate, v1

Status: **frozen** (2026-10-25, after review of the field set). Any change to the fields or their
meaning is `decision-certificate.v2`: v1 verifiers reject unknown fields, because a verifier must
not silently ignore a field whose meaning it doesn't know.

A decision certificate is a signed record of **a measured process**: one model's answers to one
decision, calibrated on a stated set of labelled cases, with thresholds chosen so that the error of
the answered cases is bounded at a stated confidence. It describes how the thresholds were measured
and how wide the uncertainty is. **It never guarantees an outcome**: the bound holds only while
future cases are exchangeable with the calibration cases, and it says nothing about any single
decision.

Machine-readable schema: [`decision-certificate.v1.schema.json`](decision-certificate.v1.schema.json).
Reference implementations: `py/decisionkit/certify.py` (issue, verify) and the Rust crate
`server/crates/decision-cert` (verify, apply). Conformance fixtures: `tests/fixtures/cert_conformance/`.

## 1. What is measured

A model gives each case a raw score per option. The certificate's `calibration_map` turns those into
probabilities (v1 issuers write `kind: "temperature"`: softmax of the scores divided by
`params.temperature`). The case's **confidence** is the top probability. The decision **answers** a
case when `confidence >= threshold` and abstains otherwise. The threshold is the case's certified
segment's `abstain_below` (§1.3), else the top-level `abstain_below`.

The measured rule is the whole of that: `rule.cannot_tell_above` records the `cannot_tell` cut that
was in force (a case above it abstains), and cases the model did not score count as abstentions
(`rule.unscored: "abstain"`), so they can never lower the measured error.

An answered case is an **error** when its top option is not the label.

| `method` | `risk` | Statement (under exchangeability of calibration and future cases) |
|---|---|---|
| `ltt` | `selective_error` | With probability at least `1 − delta` over the draw of the calibration cases, P(error \| answered) is at most `alpha`, for the top-level test and every certified segment simultaneously. |
| `crc` | `joint_error` | In expectation over the calibration draw, P(answered and error) is at most `alpha`. `delta` is null. Offered for small `n_cal`. It is weaker than `ltt`: with coverage 0.2, `alpha` 0.05 permits 25% error among the answered cases. |

`ltt` is Learn-then-Test (Angelopoulos et al., 2021) with fixed-sequence testing and exact binomial
p-values. `crc` is conformal risk control (Angelopoulos et al., 2022) with loss bound 1.

### 1.1 Procedure (normative)

1. **Splits.** The labelled cases are split into two disjoint parts, a **temperature split** and a
   **threshold split** (`n_cal` = the threshold split's size). When every case has a timestamp
   (`split.method: "time"`), cases are ordered by (`decided_at`, `case_id`) and the older half is the
   temperature split. Otherwise (`"seeded"`) a permutation seeded by `split.seed` decides. Every
   `decided_at` is first **normalised** to the certificate's timestamp form, UTC with whole seconds
   (fraction truncated; a timestamp with no offset is UTC), and that form is what is ordered,
   hashed (§2) and reported in `window`.
2. **Calibration map.** `params.temperature` minimises NLL on the temperature split's scored cases.
3. **Grid.** Built from the temperature split only:
   - the cuts are the midpoints between its adjacent distinct confidences, descending, then 0.0;
   - the grid starts at the cut with the smallest `ltt` p-value on the temperature split's own labels
     (on ties, the strictest such cut).

   The grid never depends on the threshold split, so fixed-sequence testing on it is valid.
4. **Tests.** The threshold split is divided into the certified segments (§1.3) and the
   **remainder** (every other case). One test runs on each certified segment and one on the
   remainder. The remainder's result is the top-level `abstain_below`. So each threshold is tested on
   exactly the cases it will decide.
5. **`ltt` test** on a set of cases at level `d`, for each cut λ down the grid:
   - `n_λ` = cases with confidence ≥ λ, and `e_λ` = errors among them;
   - p-value = P(Binomial(n_λ, alpha) ≤ e_λ), which is 1 when `n_λ` = 0;
   - reject while p ≤ `d`, and stop at the first non-rejection.

   The chosen threshold is the last rejected cut. If none is rejected it is 1.01, which abstains on
   every case.
6. **`crc` test** on a set of n cases: the last cut, going down the grid, before the first cut with
   `(e_λ + 1) / (n + 1) > alpha`. If the first cut already fails, it is 1.01. Joint error only grows
   down the grid, so this is the loosest passing cut.
7. **Level.** `ltt` tests run at `d = delta / (1 + k)`, where `k` is the number of certified
   segments (Bonferroni over the 1 + k families). `crc` needs no correction: an expectation bound
   on each part bounds the mixture.
8. **Refusal.** Issuers refuse to certify when `n_cal < 1/alpha − 1`.

### 1.2 `ucb` and `realized_band` are descriptive

For each test's chosen threshold, from its `n` answered cases with `e` errors:

- `ucb`: the one-sided Clopper–Pearson upper bound at level `1 − d`.
  - For `e < n`: `Beta.ppf(1 − d, e + 1, n − e)`.
  - For `e = n` or `n = 0`: 1.
  - Null for `crc`.
- `realized_band`: the two-sided Clopper–Pearson interval at `level` (v1 issuers write 0.95).
  - `low = Beta.ppf((1 − level)/2, e, n − e + 1)`, or 0 when e = 0.
  - `high = Beta.ppf((1 + level)/2, e + 1, n − e)`, or 1 when e = n.
  - `[0, 1]` when n = 0.

Both are computed at the **selected** threshold, so after selection neither is a confidence
statement. The certified claim is §1's statement. These two numbers show how wide the
uncertainty is: a certificate built on 300 cases shows a wide band.

### 1.3 Segments

The domain config declares at most one segment field and its allowed values (`certificate.segments`:
`field`, `values`, `floor`). A case's segment is its case field's value when that is a string.
 A segment counts only if its value is one of the declared values. Values
never come from free text in cases. A case field that is not a JSON string (a number, boolean,
object, null) is never a segment, so no rendering of non-strings has to agree between issuer and
consumer. Declared values are non-empty strings (quote them in YAML). A declared segment with at least `floor` threshold-split cases
is **certified**: it gets its own test and threshold. One below the floor stays in the remainder, is
listed with `inherited: true`, and carries no bound of its own (`ucb` and `realized_band` null).

### 1.4 Audit basis

The bound covers the population the labelled cases were sampled from. In selective-label settings
the audit must sample from all cases, not only those an incumbent process acted on. `audit.mode`:

- `sample`: cases sent for labelling by an audit process with logged propensity. Every case needs a
  propensity > 0. v1 requires a **uniform** propensity (`rate`); weighted bounds for non-uniform audit
  designs are not in v1.
- `full-label`: every case in the window has a label (public sets). `rate` is 1 by construction and
  `propensity_logged` is false.

## 2. Fields

Every field is required; nullable ones are marked.

| Field | Type | Meaning |
|---|---|---|
| `spec` | `"decision-certificate.v1"` | |
| `domain` | string | Domain id. |
| `decision` | string | Decision id within the domain. |
| `options` | string[] | The decision's option ids in score order. Scores are positional, so a reordered domain no longer matches. |
| `model_id` | string | `<backend>/<model>@<version>`, from the predictions; issuers refuse when model or version is unknown. |
| `manifest_hash` | string \| null | `sha256:<hex>` of the model's P2 provenance manifest file. Null when it has none (e.g. a vendor): then the scored function can't be verified. |
| `data_hash` | string | `sha256:<hex>` of the JCS bytes of a list with one entry per labelled case used (both splits), sorted bytewise by UTF-8 `case_id`: `[case_id, label_index, raw_scores \| null, decided_at \| null, segment \| null, propensity \| null]`. Unlabelled cases are excluded. Only an auditor holding the data can recompute it. |
| `n_cal` | integer | Threshold-split size. |
| `n_temperature` | integer | Temperature-split size. |
| `split` | `{method, seed}` | `method`: `"time"` or `"seeded"`. `seed`: an integer, or null for `"time"`. |
| `calibration_map` | `{kind, params, label_budget}` | `kind` names the map, and `params` is an object of numbers. `label_budget` (integer \| null) is the number of target labels the map was fitted with, when that is part of its claim. v1 issuers write `{"kind": "temperature", "params": {"temperature": T}, "label_budget": null}`. |
| `rule` | `{cannot_tell_above, unscored}` | `cannot_tell_above`: number in [0, 1] \| null. `unscored`: `"abstain"`. |
| `alpha` | number | In (0, 1). |
| `delta` | number \| null | In (0, 1); null for `crc`. |
| `method` | `"ltt"` \| `"crc"` | |
| `risk` | `"selective_error"` \| `"joint_error"` | Fixed by `method` (§1). |
| `n` | integer | Threshold-split cases in the remainder: the cases the top-level test ran on. |
| `abstain_below` | number | The top-level threshold, in [0, 1.01]. 1.01 abstains on everything. |
| `coverage` | number | Share of the remainder answered at `abstain_below`. |
| `ucb` | number \| null | §1.2. |
| `realized_band` | `{level, low, high}` | §1.2. |
| `segments` | array | `{field, value, n, abstain_below, coverage, ucb, realized_band, inherited}`, one per declared value with at least one threshold-split case, sorted bytewise by `value`. Empty without segments. |
| `window` | `{start, end}` \| null | Earliest and latest `decided_at`; null unless every case has one. |
| `fitted_at` | timestamp | |
| `expires_at` | timestamp | `window.end` (else `fitted_at`) + the domain's `certificate.ttl_days`. |
| `audit` | `{mode, rate, n, propensity_logged}` | §1.4. `n` = labelled cases used (both splits). |
| `issuer` | `{tool, version}` | The library that issued it, e.g. `{"tool": "decisionkit-calib", "version": "0.1.0"}`. |
| `signer_key_id` | string | `ed25519:` + the first 16 hex chars of SHA-256 of the raw 32-byte public key. |
| `signature` | string | base64url (no padding) Ed25519 signature (§3). |

The **certificate id** is not a field. It is `sha256:` + hex SHA-256 of the signed certificate's JCS
bytes (signature included).

Timestamps are RFC 3339 UTC, whole seconds, `Z` suffix (`2026-10-25T12:00:00Z`).

## 3. Canonical form and signature

- **Numbers** are finite IEEE-754 doubles: no NaN, no infinities, no −0. Integers stay below 2^53.
- **Canonical bytes**: RFC 8785 (JCS) of the JSON object.
- **Signature**: Ed25519 (RFC 8032) over the canonical bytes of the object without `signature`.
- **Verifiers** canonicalise the received JSON value as parsed, never a re-serialised typed struct, so
  number formatting can't drift between languages.
- **The signer** is the operator running the calibration in their own environment, with their own key.
  decisiond never holds a signing key for a customer's certificate.

## 4. How a consumer uses it

decisiond loads a certificate from `calibration/<backend>.json`, under the decision's `certificate`
key. Each of these refuses to load the domain:

- the certificate doesn't match the schema, or its signature doesn't verify against the domain's
  trusted keys (`certificate.keys`);
- `domain`, `decision` or `options` differ from the domain config;
- `model_id` doesn't start with `<backend>/` for the file it sits in;
- `calibration_map.kind` isn't one the server applies (v1: `temperature`), or its temperature or
  `abstain_below` differ from the calibration entry;
- `rule.cannot_tell_above` differs from the domain's;
- a certified segment's field isn't the domain's declared segment field, or its value is no longer
  declared (its cases would fall to a threshold not measured on them).

Once loaded, decisiond:

- returns `certificate_id` on every decision made under the certificate;
- applies a certified segment's threshold when the case's segment value matches it;
- after `expires_at`, follows `certificate.on_expired`:
  - `refer` (default) abstains with `abstain_reason: "certificate_expired"`;
  - `warn` decides as before and logs a warning.

## 5. What a certificate does not claim

- **Single decisions and unlike cases.** Nothing about any single decision, or about cases unlike the
  calibration cases (another time, population or product).
- **Expiry.** It is a prompt to re-measure, not a statement that the bound held until then.
- **Descriptive numbers.** `ucb` and `realized_band` are descriptive after selection (§1.2). Inherited
  segments carry no bound of their own.
- **The population.** The bound covers only the population the audit sampled from.
- **Unverifiable models.** A null `manifest_hash` means the scored model can't be verified.
- **Fairness, legality, labels.** Nothing about fairness or legality, or the quality of the labels
  themselves.
- **`crc`.** It certifies an average, not a high-probability bound.

---

## Note, 2026-11-07: implementations (not part of the frozen text)

The "Reference implementations" and "Conformance fixtures" lines at the top of this document name
the paths these files had in the repository where the spec was written. In this repository:

- Rust crate (verify, apply): [`rust/`](../rust/), `rust/src/lib.rs`.
- Conformance fixtures: [`fixtures/`](../fixtures/).
- The reference issuer is not in this repository yet.

The frozen text above is unchanged.
