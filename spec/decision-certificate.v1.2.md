# Decision certificate, v1.2

Status: **frozen** (2026-11-08). v1.2 adds the stored confidence histogram (§1.5, §4, §6) and the
`dr` calibration map kind (§1, §1.1, §2). Corrections go in [`ERRATA.md`](ERRATA.md). v1.2 extends
[`decision-certificate.v1.1`](decision-certificate.v1.1.md) (frozen 2026-11-08) and
[`decision-certificate.v1`](decision-certificate.v1.md) (frozen 2026-10-25), which both stay frozen and
valid.

**Versions.** A certificate's `spec` says which procedure produced it and which fields it has.
Verifiers accept `decision-certificate.v1`, `decision-certificate.v1.1` and
`decision-certificate.v1.2`, each against its own schema. v1 and v1.1 certificates have the same
fields. v1.2 certificates have those fields and three more: `confidence_bins` and
`confidence_histogram` at the top level, and `confidence_histogram` in each segment. They are
required in a v1.2 certificate and are unknown fields in a v1 or v1.1 one. A v1.2 issuer writes
`decision-certificate.v1.2`. Verifiers still reject unknown fields and unknown `spec` values, because a
verifier must not silently ignore a field whose meaning it doesn't know. v1.1 said that any change to
the fields is v2. v1.2 adds fields under a new `spec` value instead: a verifier that does not know
v1.2 refuses its certificates as an unknown spec, so nothing is ignored silently, and v1 and v1.1
certificates mean what they did.

A decision certificate is a signed record of **a measured process**: one model's answers to one
decision, calibrated on a stated set of labelled cases, with thresholds chosen so that the error of
the answered cases is bounded at a stated confidence. It describes how the thresholds were measured
and how wide the uncertainty is. **It never guarantees an outcome**: the bound holds only while
future cases are exchangeable with the calibration cases, and it says nothing about any single
decision.

Machine-readable schema: [`decision-certificate.v1.2.schema.json`](decision-certificate.v1.2.schema.json).
Reference implementations: the Rust crate [`rust/`](../rust/) (verify, apply, monitor; the oracle),
the Python verifier [`python/`](../python/) (module `decision_cert`) and the Python issuer (module
`decision_cert.issue`). Conformance fixtures: [`fixtures/`](../fixtures/) (v1),
[`fixtures/v1.1/`](../fixtures/v1.1/) and [`fixtures/v1.2/`](../fixtures/v1.2/).

## 1. What is measured

A model gives each case a raw score per option. The certificate's `calibration_map` turns those into
probabilities. v1.2 defines two kinds:

- `temperature`: softmax of the scores divided by `params.temperature`;
- `dr`: softmax of `a · s_j + b_j` over the options `j`, where `s_j` is option `j`'s score, `a` is
  `params.a` and `b_j` is `params.b<j>` (`b0` for the first option). The map rescales the scores and
  shifts each option, so a model can be moved to a population whose base rates and confidence
  differ, on few labels from that population.

The case's **confidence** is the top probability. The decision **answers** a
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

The procedure is v1.1's, apart from the `dr` map in step 2.

1. **Splits.** The labelled cases are split into two disjoint parts, a **temperature split** and a
   **threshold split** (`n_cal` = the threshold split's size). When every case has a timestamp
   (`split.method: "time"`), cases are ordered by (`decided_at`, `case_id`) and the older half is the
   temperature split. Otherwise (`"seeded"`) a permutation seeded by `split.seed` decides. Every
   `decided_at` is first **normalised** to the certificate's timestamp form, UTC with whole seconds
   (fraction truncated; a timestamp with no offset is UTC), and that form is what is ordered,
   hashed (§2) and reported in `window`.
2. **Calibration map.** For `temperature`, `params.temperature` minimises NLL on the temperature
   split's scored cases. For `dr`, the parameters are fitted on a separate **recalibration set** of
   `label_budget` labelled cases, disjoint from both splits, and nothing from the threshold split is
   used. The reference issuer fits `a` and `b` by maximum a posteriori on the recalibration set's
   scored cases, under a Gaussian prior learned from earlier shifts. The fit may use the
   recalibration set and anything chosen before it. The temperature split then serves only the grid
   (step 3) and the bins (§1.5). Either way the map is fixed before the threshold split is tested,
   so the tests of steps 4–7 are unchanged.
3. **Grid.** Built from the temperature split only:
   - the cuts are the midpoints between its adjacent distinct confidences, descending, then 0.0;
   - each test of step 4 (each certified segment, and the remainder) starts at the cut with the
     smallest `ltt` p-value on **its own** temperature-split cases (the temperature-split cases of
     that segment, or of the remainder), on ties the strictest such cut. A test with no
     temperature-split cases of its own starts at the cut with the smallest p-value on the whole
     temperature split. The p-values here use `alpha`, as in step 5.

   The grid uses no label or confidence of the threshold split. It depends on the threshold split
   only through which segments are certified (§1.3: their case counts), so fixed-sequence testing
   on it stays valid.
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
- `realized_band`: the two-sided Clopper–Pearson interval at `level` (v1.2 issuers write 0.95).
  - `low = Beta.ppf((1 − level)/2, e, n − e + 1)`, or 0 when e = 0.
  - `high = Beta.ppf((1 + level)/2, e + 1, n − e)`, or 1 when e = n.
  - `[0, 1]` when n = 0.

Both are computed at the **selected** threshold, so after selection neither is a confidence
statement. The certified claim is §1's statement. These two numbers show how wide the
uncertainty is: a certificate built on 300 cases shows a wide band.

### 1.3 Segments

The domain config declares at most one segment field and its allowed values (`certificate.segments`:
`field`, `values`, `floor`). A case's segment is its case field's value when that is a string.
A segment counts only if its value is one of the declared values. Values never come from free text
in cases. A case field that is not a JSON string (a number, boolean, object, null) is never a
segment, so no rendering of non-strings has to agree between issuer and consumer. Declared values
are non-empty strings (quote them in YAML). A declared segment with at least `floor` threshold-split
cases is **certified**: it gets its own test and threshold. One below the floor stays in the
remainder, is listed with `inherited: true`, and carries no bound of its own (`ucb` and
`realized_band` null).

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
  propensity > 0. v1.2 requires a **uniform** propensity (`rate`); weighted bounds for non-uniform
  audit designs are not in v1.2.
- `full-label`: every case in the window has a label (public sets). `rate` is 1 by construction and
  `propensity_logged` is false.

### 1.5 Confidence histogram (normative)

A v1.2 certificate stores, for each test, how the confidences of the threshold-split cases it ran
on were spread, so that a consumer can compare the cases it sees with them without labels and
without the issuer's data (§4). The histogram describes the measurement; it is not part of the
certified claim.

1. **Bins.** `confidence_bins` lists the bin edges `b_0 < b_1 < … < b_k`, with `b_0 = 0`,
   `b_k = 1` and 1 ≤ k ≤ 100. Bin `i` holds the confidences `c` with `b_i ≤ c < b_{i+1}`; the last
   bin also holds `c = 1`. The edges are chosen without the threshold split: fixed in advance, or
   learned from the temperature split only, as the grid is (§1.1 step 3). The reference issuer uses
   the 20-quantiles of the confidences of the temperature split's scored cases not above
   `rule.cannot_tell_above`, rounded to 4 decimals, with
   repeats and any edge at 0 or 1 dropped.
2. **Counts.** For each test (the remainder, and each segment, certified or inherited),
   `confidence_histogram.counts[i]` is the number of that test's threshold-split cases whose
   confidence is in bin `i`, and `confidence_histogram.unscored` the number the rule abstains on
   whatever the threshold: unscored cases, and cases above `rule.cannot_tell_above`. The counts and
   `unscored` sum to the test's `n`. An inherited segment's cases are counted both in its own
   histogram and in the remainder's.
3. **Withholding.** An issuer may write `null` in place of a histogram, for a test with too few
   cases to publish (§6). The reference issuer withholds the histogram of a test with fewer than
   `certificate.histogram_min_n` cases (default 30), and the remainder's histogram when it would
   reveal fewer than that many cases by subtraction (§6). `confidence_bins` is always present.

## 2. Fields

Every field is required; nullable ones are marked.

| Field | Type | Meaning |
|---|---|---|
| `spec` | `"decision-certificate.v1.2"` | `"decision-certificate.v1.1"` or `"decision-certificate.v1"` for a certificate under those specs, which have none of the v1.2 fields. |
| `domain` | string | Domain id. |
| `decision` | string | Decision id within the domain. |
| `options` | string[] | The decision's option ids in score order. Scores are positional, so a reordered domain no longer matches. |
| `model_id` | string | `<backend>/<model>@<version>`, from the predictions; issuers refuse when model or version is unknown. |
| `manifest_hash` | string \| null | `sha256:<hex>` of the model's provenance manifest file. Null when it has none (e.g. a vendor): then the scored function can't be verified. |
| `data_hash` | string | `sha256:<hex>` of the JCS bytes of a list with one entry per labelled case used (both splits, and a `dr` map's recalibration set), sorted bytewise by UTF-8 `case_id`: `[case_id, label_index, raw_scores \| null, decided_at \| null, segment \| null, propensity \| null]`. Unlabelled cases are excluded. Only an auditor holding the data can recompute it. |
| `n_cal` | integer | Threshold-split size. |
| `n_temperature` | integer | Temperature-split size. |
| `split` | `{method, seed}` | `method`: `"time"` or `"seeded"`. `seed`: an integer, or null for `"time"`. |
| `calibration_map` | `{kind, params, label_budget}` | `kind` names the map, and `params` is an object of numbers. `label_budget` (integer \| null) is the number of target labels the map was fitted with, when that is part of its claim. `temperature`: `{"kind": "temperature", "params": {"temperature": T}, "label_budget": null}`, with `T` > 0. `dr`: `{"kind": "dr", "params": {"a": a, "b0": …, "b<k−1>": …}, "label_budget": m}`, with `a` > 0, one `b` per option, and `m` ≥ 1 the recalibration set's labelled cases (§1.1 step 2). |
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
| `segments` | array | `{field, value, n, abstain_below, coverage, ucb, realized_band, inherited, confidence_histogram}`, one per declared value with at least one threshold-split case, sorted bytewise by `value`. Empty without segments. |
| `window` | `{start, end}` \| null | Earliest and latest `decided_at`; null unless every case has one. |
| `fitted_at` | timestamp | |
| `expires_at` | timestamp | `window.end` (else `fitted_at`) + the domain's `certificate.ttl_days`. |
| `audit` | `{mode, rate, n, propensity_logged}` | §1.4. `n` = labelled cases in the two splits; a `dr` map's recalibration set is counted by `label_budget`. |
| `issuer` | `{tool, version}` | The library that issued it, e.g. `{"tool": "decision-cert", "version": "0.4.0"}`. Not checked by verifiers. |
| `confidence_bins` | number[] | §1.5: 2 to 101 bin edges, rising strictly from 0 to 1. |
| `confidence_histogram` | `{counts, unscored}` \| null | §1.5: the remainder's threshold-split cases per bin (`counts`, integers, one per bin) and the ones the rule abstains on whatever the threshold (`unscored`). Null when withheld. Each segment carries its own, for its cases. |
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

**Checks beyond the schema.** A JSON Schema cannot compare one field with another, so verifiers
also reject a v1.2 certificate when:

- `confidence_bins` does not rise strictly, or does not end at 1 (the schema fixes the first edge at
  0 and the length);
- a histogram that is not null has a number of `counts` other than the number of bins
  (`len(confidence_bins) − 1`), or its `counts` and `unscored` do not sum to its test's `n` (the
  top level's `n` for the top-level histogram, the segment's `n` for a segment's);
- a `temperature` map's `params` are not exactly `temperature`, above 0;
- a `dr` map's `params` are not exactly `a`, above 0, and `b0` to `b<k−1>` for the certificate's `k`
  options, or its `label_budget` is null or below 1.

A `calibration_map.kind` v1.2 does not define is not checked: the certificate verifies, and a
consumer that does not apply that kind refuses it (§4).

And they reject any certificate whose fields belong to another `spec`: a v1.2 certificate without a
v1.2 field (refused as a spec it is not: "spec is not consistent with the fields"), or a v1 or v1.1
certificate with one (an unknown field).

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

- the certificate doesn't match its schema and the checks of §2, or its signature doesn't verify
  against the consumer's trusted keys;
- `domain`, `decision` or `options` differ from the consumer's configuration;
- `model_id` doesn't start with `<backend>/` for the backend the consumer scores with;
- `calibration_map.kind` isn't one the consumer applies (v1.2 defines `temperature` and `dr`), or
  its parameters or thresholds differ from the ones in force;
- `rule.cannot_tell_above` differs from the one in force;
- a certified segment's field isn't the consumer's declared segment field, or its value is no longer
  declared (its cases would fall to a threshold not measured on them).

Once loaded, the consumer:

- records `certificate_id` with every decision made under the certificate;
- applies a certified segment's threshold when the case's segment value matches it, else the
  top-level `abstain_below`;
- after `expires_at`, follows its configured policy:
  - `refer` (default) abstains with `abstain_reason: "certificate_expired"`;
  - `warn` decides as before and logs a warning.

**Monitoring without labels.** Both scores below are descriptive. A significant change is a prompt to
measure again, never a finding that the bound has failed, and no change is never a finding that it
holds (§5).

- **Answered share** (any spec). Compare the share of a window's cases the consumer answers with the
  certificate's `coverage`, by a two-sample test against `n`. It shows changes that move the model's
  confidences across the threshold.
- **Shift score** (v1.2). Over a window of cases decided by one threshold (a certified segment's,
  or the top-level one), the consumer builds the window's histogram on `confidence_bins` exactly as
  §1.5 step 2 builds the certificate's: each case's confidence in its bin, and the cases the rule
  abstains on whatever the threshold in `unscored`. A case above `rule.cannot_tell_above` is passed as
  unscored (`None` in the reference functions), as the issuer counted it, or the window shows a
  shift that is not there. The baseline is the histogram of the same test:
  the certified segment's own, else the top level's, including for cases of an inherited segment.
  The shift score is Pearson's chi-square test of homogeneity between the two:
  - the columns are the bins and the unscored count, and a column empty in both histograms is
    dropped;
  - with `O_rj` the count of row `r` (certificate, window) in column `j`, `N_r` the row's total,
    `C_j` the column's total and `N = N_1 + N_2`, the statistic is
    `X² = Σ_j Σ_r (O_rj − E_rj)² / E_rj` with `E_rj = N_r · C_j / N`;
  - the degrees of freedom are the number of columns kept, minus 1, and the p-value is the upper
    tail of the chi-square distribution there: `Q(df/2, X²/2)`, the regularised upper incomplete
    gamma function;
  - with an empty row, or fewer than two columns kept, there is nothing to compare: `X²` 0, df 0,
    p-value 1.

  Implementations agree on the counts and the degrees of freedom exactly, and on the statistic and
  the p-value up to floating-point rounding (the reference implementations agree to 1e-9
  relative). A withheld histogram (null) gives no shift score for its test. The shift score sees
  changes in where confidences fall, inside the answered range and the abstained range as well as
  across the threshold. The evidence is in [`drafts/h1-histogram-study.md`](drafts/h1-histogram-study.md).

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
- **A `dr` map.** The bound is measured on the threshold split with the map fixed, so it covers the
  population the splits were sampled from, like any map. The recalibration set only shapes the map:
  `label_budget` counts the labels it used, and says nothing about how well the map fits the cases
  in use or about a population the splits did not sample.
- **What monitoring without labels can see.** Both scores of §4 look only at the model's
  confidences. They cannot show a change in error at the same confidence, or a change in the mix of
  groups the model cannot tell apart. Only labelled cases from the population in use can show those.
- **What the shift score means.** The confidence histogram describes the threshold split; it is not
  part of the certified claim.
  - A shift score that is not significant does not show that the bound still holds.
  - A significant one does not show that it has failed: confidences can move among cases the
    decision abstains on, or in ways that do not raise the error.
  - The p-value treats the window's cases as independent draws, and checking many windows raises the
    chance of a false alarm, as any repeated test does.

## 6. Size, binning and privacy of the histogram

- **Size.** At most 101 edges, and per test at most 100 counts and one `unscored`: a certificate
  with `s` segments carries at most 101 + 101 × (1 + `s`) numbers for its histograms. The reference
  issuer writes at most 21 edges and 20 counts per test.
- **Binning.** Every test's histogram uses the same edges, so they can be compared with each other
  and with a window. The edges never depend on the threshold split. Edges learned from the
  temperature split (the reference issuer's quantiles) keep the bins roughly equally full, which
  suits the chi-square test. Fixed edges reveal nothing about the data.
- **What it reveals.** The number of threshold-split cases per bin of the model's top confidence,
  per test, and through quantile edges, the temperature split's confidence quantiles rounded to 4
  decimals. It holds no case id, label, feature, raw score, timestamp or chosen option, and nothing
  about errors.
- **What it does not protect.** The counts are exact, not noised: a histogram is not differentially
  private. For a test with few cases, a count can single out a case's confidence to within a bin.
  Histograms can also be subtracted: the remainder's counts every inherited segment's cases, so
  the remainder's minus the published inherited ones is the histogram of the cases left over, and
  two certificates on overlapping cases can be compared. An issuer that must not publish this
  withholds the histogram (null) for such tests, or uses fixed edges. The reference issuer withholds
  a test's histogram below 30 cases by default, and the remainder's when the cases left over by that
  subtraction number between 1 and 29. It does not look across certificates.

## Changes from v1.1

- New fields: `confidence_bins`, `confidence_histogram` at the top level and in each segment (§1.5,
  §2), with the checks beyond the schema of §2.
- §4: the shift score, a label-free comparison of a window with the stored histogram; §5: what it
  does and does not show; §6: its size, binning and privacy.
- A second calibration map kind, `dr` (§1, §1.1 step 2, §2), fitted on a recalibration set
  disjoint from both splits and counted by `label_budget`; `data_hash` covers that set too. v1.2
  verifiers check the parameters of both kinds v1.2 defines (§2).
- `spec` is `decision-certificate.v1.2`. The procedure of §1.1 to §1.4 is v1.1's apart from the `dr`
  map, and no field of v1.1 changes meaning.

The evidence is in [`drafts/`](drafts/): the [v1.2 draft](drafts/decision-certificate.v1.2.md) and
its studies. The `dr` map's candidate and decision are in the
[v1.1 draft](drafts/decision-certificate.v1.1.md) (O5) and the v1.2 draft (D1).
