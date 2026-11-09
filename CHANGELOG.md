# Changelog

All notable changes to this repository. The spec (`decision-certificate.v1`, `v1.1`) is versioned
separately and is frozen; this log covers the crate, the verifiers, the fixtures and the docs.

## Unreleased

- **Spec v1.2 frozen** (2026-11-08) with its two items, the histogram (#25) and the `dr` map (#24).
- **Spec v1.2, the confidence histogram** (#25):
  `spec/decision-certificate.v1.2.md` and its schema. New fields `confidence_bins` and
  `confidence_histogram` (top level and per segment, nullable when withheld): each test's
  threshold-split cases per confidence bin, on bins chosen without the threshold split. The
  procedure is v1.1's. §4 defines a label-free shift score (Pearson's chi-square test of
  homogeneity against the stored histogram), §5 what it does not show, §6 its size, binning and
  privacy limits. Evidence: `spec/drafts/h1-histogram-study.md` (`python/tools/study_histogram.py`).
- **Verifiers accept v1, v1.1 and v1.2.** New constant `SPEC_V1_2`; `SPECS` has three entries. A
  v1.2 certificate must carry the v1.2 fields and a v1 or v1.1 one must not; v1.2 histograms must
  match the bins and sum to their test's `n`. The unknown-spec message now names all three specs, and
  a certificate whose fields belong to another spec is refused as "spec is not consistent with the
  fields", so `fixtures/v1.1/invalid_unknown_spec.json` keeps its verdict and message.
- **Monitoring functions** in both verifiers, kept in lockstep by the differential test:
  `Histogram::of` / `Histogram.of`, `bin_of`, `shift_score`, `chi2_sf`, and
  `Verified::confidence_bins` and `histogram_for`.
- **The issuer writes v1.2** with 20 quantile bins from the temperature split, and withholds the
  histogram of a test with fewer than `certificate.histogram_min_n` cases (default 30), and the
  remainder's when subtracting the published inherited segments' would reveal fewer cases than that.
  `--spec decision-certificate.v1.1` writes the same test without it. The package carries the v1.2
  schema.
- **`fixtures/v1.2/`**: the v1.2 conformance set and its manifest, from `gen_positive_fixtures.py`.
  The v1 and v1.1 sets are byte-unchanged.
- `docs/certificates.md`, `docs/conformance.md` and `docs/drafts/method.md`: monitoring with the
  histogram, its limits, and the v1.2 fixtures.
- **Spec v1.2, the `dr` calibration map** (#24): `kind: "dr"`, softmax(a · scores + b), with params
  `a` (> 0) and `b0` to `b<k−1>`, and a required `label_budget`: the cases the map was fitted on, from a
  recalibration set disjoint from both splits, which `data_hash` also covers. No new field. v1.2
  verifiers check the params of both kinds v1.2 defines, and leave other kinds to consumers.
- **Applying a map** in both verifiers, kept in lockstep by the differential test:
  `probabilities` and `confidence` (free functions over a `calibration_map`), `MAP_KINDS`, and
  `Verified::probabilities` / `Verified::confidence`. New Rust example `probabilities`.
- **The issuer fits `dr` maps**: `--map dr --recal-data … --prior …` (v1.2 only; the recalibration
  set must not share a case with the calibration cases).
- `docs/credit-approval.md`: a profile for automating part of a credit-approval decision. It is the
  v1.2 spec applied as is: the error target is chosen and the coverage measured, with the shift score
  as a drift alarm.
- **`fixtures/v1.2/`** gains seven map fixtures (`valid_dr_map`, `valid_other_map_kind`,
  `invalid_dr_*`, `invalid_temperature_*`); its earlier files are byte-unchanged.

## 0.3.0 — 2026-11-08 (tag `v0.3.0`)

Spec v1.1: frozen, verified, issued. Verifiers accept v1 and v1.1; v1 certificates and fixtures are
unchanged.

- **Spec v1.1 frozen** (2026-11-08): `spec/decision-certificate.v1.1.md` and its schema. The fields
  are v1's. One procedure change: each test starts the threshold grid at the best cut on its own
  temperature-split cases. Clarifications: the refusal floor, mix dependence, the label budget,
  monitoring without labels and its limits, and the v1 errata folded in. A `dr` map kind is left for
  v1.2.
- **Verifiers accept both specs.** The Rust crate and the Python verifier accept
  `decision-certificate.v1` and `decision-certificate.v1.1`; new constants `SPEC_V1_1` and `SPECS`
  (`SPEC` is still v1's id). The "not a valid" error now reads "certificate is not a valid decision
  certificate: …".
- **The issuer writes v1.1** with the per-test start; `spec="decision-certificate.v1"` (CLI
  `--spec`) issues by the v1 procedure. `stats.grid` is now `cuts_of` and `start`, and `grid` keeps
  its v1 meaning. The package carries both schemas.
- **`fixtures/v1.1/`**: the v1.1 conformance set and its own manifest, from
  `gen_positive_fixtures.py`. The v1 fixtures and `fixtures/FIXTURES.sha256` are byte-unchanged.
- `docs/certificates.md`: how many labelled cases (guidance table), segments and a changing mix,
  and monitoring without labels.

- `python/tools/study_shift.py` and `spec/drafts/o2-shift-study.md`: which shifts a label-free score
  can see; recommendation for O2 (no shift-score field; monitor the answered share against
  `coverage`; state what label-free monitoring cannot see). Not decided.
- `python/tools/study_mix.py` and `spec/drafts/o3-mix-study.md`: thresholds under a shift in the
  segment mix; recommendation for O3 (no new mechanism; v1 segments are conditional tests; state
  the remainder's mix dependence). Not decided.
- `python/tools/study_budget.py` and `spec/drafts/o4-budget-study.md`: how many labelled cases an
  `ltt` certificate needs, by model quality and alpha. Recommendations for O4 (no new field,
  guidance only) and O5 (defer to v1.2) in the v1.1 draft; not decided.
- v1.1 draft: O1 decided (per-test grid start, v1's cuts), with a decision log. v1.1 stays
  unfrozen until O2–O5 are settled or deferred to v1.2.
- `python/tools/study_grid.py` and `spec/drafts/o1-grid-study.md`: a deterministic simulation
  study of the threshold grid on small tests (v1.1 draft O1), reporting validity (violation rate,
  90th and 95th percentile error) alongside power. It suggests a per-test start and no coarse grid;
  nothing is decided.
- `spec/drafts/decision-certificate.v1.1.md`: a draft of v1.1 with every item open (threshold grid
  for small tests, shift score, segment-conditional thresholds, label budget, a `dr` map kind).
  Nothing is frozen; verifiers and the issuer are unchanged.
- Issuer regression tests pinning v1's grid behaviour: a set with no passing cut abstains on
  everything, and a failing start cut stops the sequence.
- `docs/drafts/method.md`: when nothing passes, abstaining is the result.

- `demo/bank-marketing/` and `demo/bank-marketing-crc/`: the first demo certificates on a public
  dataset (UCI Bank Marketing, CC BY 4.0), issued with the released 0.2.0 issuer and the demo key,
  each with the model's manifest; `python/tools/demo_bank_marketing.py` rebuilds the inputs. CI
  verifies every demo with `--now` inside its validity window and checks `manifest_hash` against
  `model.json`.

## 0.2.0 — 2026-11-07 (tag `v0.2.0`)

The reference issuer moves here. The verifiers, the spec and the fixtures are unchanged; the Rust
crate is republished at the same version for lockstep.

- **The reference issuer**, `decision_cert.issue`, as the optional extra `decision-cert[issue]`
  (numpy, scipy, jsonschema, PyYAML): `python -m decision_cert.issue keygen | certify | verify`, the
  Learn-then-Test and conformal-risk-control statistics, and the few-label `dr` recalibration
  functions (not part of spec v1). Certificates it issues name `{"tool": "decision-cert"}`.
- `python/tools/gen_positive_fixtures.py`: the reference fixtures, regenerated byte-identical; CI
  checks them.
- `demo/`: the demo signing key's public half, and `demo/example/`, the quickstart certificate (the
  conformance fixture `valid_basic`, split into certificate and keys).
- README: a one-line verify quickstart, run in CI.
- `docs/drafts/method.md`: a draft write-up of the method.

## 0.1.0 — 2026-11-07 (tag `v0.1.0`)

First release: the crate on crates.io and the Python verifier on PyPI, both as `decision-cert`.


- `decision-certificate.v1` spec and JSON Schema (frozen 2026-10-25).
- `decision-cert` Rust crate: `verify` (schema, trusted key, strict Ed25519 signature), `canonical`
  (RFC 8785), `certificate_id`, `key_id`, `Verified::threshold_for`, `Verified::is_expired`,
  `Verified::temperature`.
- Conformance fixtures: valid and invalid signed certificates with their canonical bytes, ids and
  verdicts, and a set of schema-invalid mutations every verifier must reject.
- Python verifier (`python/`, module `decision_cert`): a port of the crate's `verify`,
  `threshold_for`, `is_expired`, `canonical`, `certificate_id` and `key_id`, depending only on
  `rfc8785` and `cryptography`. Passes the same fixtures, and agrees with the crate on a few hundred
  edited, re-signed certificates in CI.
- Six negative fixtures (small-order key, small-order `R`, non-canonical `S`, timestamp with an
  offset, boolean as number, float as integer), their generator, and `fixtures/FIXTURES.sha256`.
- `decision-cert verify <cert.json> --keys <keys.json> [--now <ts>]`: a command-line verifier in
  Rust (feature `cli`) and Python (`python -m decision_cert verify`), same exit codes and output;
  `timestamp` is now public in the crate.
- `docs/conformance.md` (how another verifier proves agreement) and `spec/ERRATA.md` (dated
  clarifications; the frozen text is never edited).
- crates.io readiness: package metadata and a `cargo publish --dry-run` check in CI (not published).
- Repository docs: README for outside readers, `CONTRIBUTING.md`, `SECURITY.md`, this changelog, and
  a dated implementations note under the frozen spec.
