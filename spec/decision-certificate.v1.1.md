# Decision certificate, v1.1

Status: **frozen** (2026-11-08). v1.1 revises [`decision-certificate.v1`](decision-certificate.v1.md)
(frozen 2026-10-25), which stays frozen and valid. The fields are the same as v1's. What changes is
one step of the procedure (§1.1 step 3, the grid start) and the text: clarifications that v1 kept in
[`ERRATA.md`](ERRATA.md) are folded in, and §1.3, §2 and §5 state more precisely what a certificate
covers. Any change to the fields or their meaning is `decision-certificate.v2`: verifiers reject
unknown fields, because a verifier must not silently ignore a field whose meaning it doesn't know.

**Versions.** A certificate's `spec` says which procedure produced it. Verifiers accept both
`decision-certificate.v1` and `decision-certificate.v1.1`, each against its own schema; the two
schemas accept the same certificates apart from the value of `spec`. A v1.1 issuer writes
`decision-certificate.v1.1`.

A decision certificate is a signed record of **a measured process**: one model's answers to one
decision, calibrated on a stated set of labelled cases, with thresholds chosen so that the error of
the answered cases is bounded at a stated confidence. It describes how the thresholds were measured
and how wide the uncertainty is. **It never guarantees an outcome**: the bound holds only while
future cases are exchangeable with the calibration cases, and it says nothing about any single
decision.

Machine-readable schema: [`decision-certificate.v1.1.schema.json`](decision-certificate.v1.1.schema.json).
Reference implementations: the Rust crate [`rust/`](../rust/) (verify, apply; the oracle), the Python
verifier [`python/`](../python/) (module `decision_cert`) and the Python issuer (module
`decision_cert.issue`). Conformance fixtures: [`fixtures/`](../fixtures/) (v1) and
[`fixtures/v1.1/`](../fixtures/v1.1/).

## 1. What is measured

A model gives each case a raw score per option. The certificate's `calibration_map` turns those into
probabilities (v1.1 issuers write `kind: "temperature"`: softmax of the scores divided by
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
   - each test of step 4 (each certified segment, and the remainder) starts at the cut with the
     smallest `ltt` p-value on **its own** temperature-split cases (the temperature-split cases of
     that segment, or of the remainder), on ties the strictest such cut. A test with no
     temperature-split cases of its own starts at the cut with the smallest p-value on the whole
     temperature split. The p-values here use `alpha`, as in step 5.

   The grid never depends on the threshold split, so fixed-sequence testing on it is valid. (v1 started
   every test at the cut that was best on the whole temperature split. On a test whose cases differ
   from the pool, that start can fail at once although a looser cut would pass; starting each test on
   its own cases certifies such tests more often at the same validity.)
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
8. **Refusal.** Issuers refuse to certify when `n_cal < 1/alpha − 1`. That is a floor, not a
   recommendation: an `ltt` certificate on a few hundred cases usually abstains on everything. The
   number of cases a useful certificate needs depends on the model as well as on `alpha` (see
   [`docs/certificates.md`](../docs/certificates.md)); `crc` is offered for small sets.

### 1.2 `ucb` and `realized_band` are descriptive

For each test's chosen threshold, from its `n` answered cases with `e` errors:

- `ucb`: the one-sided Clopper–Pearson upper bound at level `1 − d`.
  - For `e < n`: `Beta.ppf(1 − d, e + 1, n − e)`.
  - For `e = n` or `n = 0`: 1.
  - Null for `crc`.
- `realized_band`: the two-sided Clopper–Pearson interval at `level` (v1.1 issuers write 0.95).
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

A certified segment's statement (§1) is about that segment's cases alone, so it holds whatever share
of cases each segment has at use. The remainder's statement, which also decides inherited
segments, is about the remainder as it was mixed in the calibration cases. If the shares of groups
inside the remainder change, and their errors differ, its bound can fail. A field whose shares may
change, and whose groups may differ in error, is best declared as a segment with a floor its groups
can meet.

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
| `spec` | `"decision-certificate.v1.1"` | `"decision-certificate.v1"` for a certificate produced by the v1 procedure. |
| `domain` | string | Domain id. |
| `decision` | string | Decision id within the domain. |
| `options` | string[] | The decision's option ids in score order. Scores are positional, so a reordered domain no longer matches. |
| `model_id` | string | `<backend>/<model>@<version>`, from the predictions; issuers refuse when model or version is unknown. |
| `manifest_hash` | string \| null | `sha256:<hex>` of the model's provenance manifest file. Null when it has none (e.g. a vendor): then the scored function can't be verified. |
| `data_hash` | string | `sha256:<hex>` of the JCS bytes of a list with one entry per labelled case used (both splits), sorted bytewise by UTF-8 `case_id`: `[case_id, label_index, raw_scores \| null, decided_at \| null, segment \| null, propensity \| null]`. Unlabelled cases are excluded. Only an auditor holding the data can recompute it. |
| `n_cal` | integer | Threshold-split size. |
| `n_temperature` | integer | Temperature-split size. |
| `split` | `{method, seed}` | `method`: `"time"` or `"seeded"`. `seed`: an integer, or null for `"time"`. |
| `calibration_map` | `{kind, params, label_budget}` | `kind` names the map, and `params` is an object of numbers. `label_budget` (integer \| null) is the number of target labels the map was fitted with, when those are not cases of either split. v1.1 issuers write `{"kind": "temperature", "params": {"temperature": T}, "label_budget": null}`. |
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
| `issuer` | `{tool, version}` | The library that issued it, e.g. `{"tool": "decision-cert", "version": "0.3.0"}`. Not checked by verifiers. |
| `signer_key_id` | string | `ed25519:` + the first 16 hex chars of SHA-256 of the raw 32-byte public key. |
| `signature` | string | base64url (no padding) Ed25519 signature (§3). |

The **certificate id** is not a field. It is `sha256:` + hex SHA-256 of the signed certificate's JCS
bytes (signature included).

**Label budget.** The labelled cases a certificate used are `n_temperature` + `n_cal`, plus
`calibration_map.label_budget` when that is not null. Together they are its label budget.

**Integers** (every `integer` field) are written without a fraction or exponent: `2500.0`, `25e2`
and `-0` are rejected, although JSON Schema 2020-12 counts `2500.0` as an integer. `number` fields
accept integers (`"rate": 1`).

**Timestamps** are exactly `YYYY-MM-DDTHH:MM:SSZ` (uppercase `T` and `Z`, UTC, whole seconds, no
offset, no fraction), naming a real calendar date and time (`2026-10-25T12:00:00Z`). As RFC 3339
allows, a leap second (`:60`) and the year `0000` are accepted.

## 3. Canonical form and signature

- **Numbers** are finite IEEE-754 doubles: no NaN, no infinities, no −0. Issuers keep integers below
  2^53. Verifiers do not reject a larger integer, but canonicalise every number through a double, as
  the reference does, so `9007199254740993` canonicalises as `9007199254740992`.
- **Canonical bytes**: RFC 8785 (JCS) of the JSON object.
- **Signature**: Ed25519 (RFC 8032) over the canonical bytes of the object without `signature`,
  verified strictly: on top of the RFC 8032 equation, a verifier rejects a small-order public key, a
  small-order `R`, and `S` at or above the group order (as ed25519-dalek's `verify_strict` does).
- **Verifiers** canonicalise the received JSON value as parsed, never a re-serialised typed struct, so
  number formatting can't drift between languages.
- **The signer** is the operator running the calibration in their own environment, with their own key.
  Nobody else holds a signing key for another operator's certificates.

## 4. How a consumer uses it

A consumer loads a certificate for a decision and refuses it when:

- the certificate doesn't match its schema, or its signature doesn't verify against the consumer's
  trusted keys;
- `domain`, `decision` or `options` differ from the consumer's configuration;
- `model_id` doesn't start with `<backend>/` for the backend the consumer scores with;
- `calibration_map.kind` isn't one the consumer applies (v1.1: `temperature`), or its parameters or
  thresholds differ from the ones in force;
- `rule.cannot_tell_above` differs from the one in force;
- a certified segment's field isn't the consumer's declared segment field, or its value is no longer
  declared (its cases would fall to a threshold not measured on them).

Once loaded, the consumer:

- records `certificate_id` with every decision made under the certificate;
- applies a certified segment's threshold when the case's segment value matches it, else the
  top-level `abstain_below`;
- after `expires_at`, either abstains or decides with a warning, as configured.

**Monitoring without labels.** A consumer can compare the share of cases it answers with the
certificate's `coverage` (a two-sample test against `n`). A significant change is a prompt to measure
again. It shows changes that move the model's confidences; §5 lists what it cannot show.

## 5. What a certificate does not claim

- **Single decisions and unlike cases.** Nothing about any single decision, or about cases unlike the
  calibration cases (another time, population or product).
- **Expiry.** It is a prompt to re-measure, not a statement that the bound held until then.
- **Descriptive numbers.** `ucb` and `realized_band` are descriptive after selection (§1.2). Inherited
  segments carry no bound of their own.
- **The mix.** The remainder's bound, and so the threshold of every inherited segment, holds for the
  mix of cases in the calibration set (§1.3). Certified segments do not depend on the mix.
- **The population.** The bound covers only the population the audit sampled from.
- **Unverifiable models.** A null `manifest_hash` means the scored model can't be verified.
- **Fairness, legality, labels.** Nothing about fairness or legality, or the quality of the labels
  themselves.
- **`crc`.** It certifies an average, not a high-probability bound.
- **What monitoring without labels can see.** Comparing the answered share with `coverage` (§4)
  shows shifts that move the model's confidences. It cannot show a change in error at the same
  confidence, or a change in the mix of groups the model cannot tell apart. Only labelled cases from
  the population in use can show those.


## Changes from v1

- §1.1 step 3: each test starts at the best cut on its own temperature-split cases (v1: on the whole
  temperature split). The list of cuts is unchanged.
- §1.1 step 8, §1.3, §2, §4, §5: clarifications (the refusal floor, mix dependence, the label budget,
  monitoring without labels and its limits), and the v1 errata on integers, timestamps, large
  integers and strict signatures folded in. §4 is written for any consumer.
- `spec` is `decision-certificate.v1.1`. No field is added, removed or changes meaning.
- Not in v1.1: a `dr` calibration map kind, and a stored confidence distribution for monitoring;
  both are left for a later revision.

The evidence for each change is in [`drafts/`](drafts/): the v1.1 draft and its studies.
