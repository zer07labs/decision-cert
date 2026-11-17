# Changelog

All notable changes to this repository. The spec (`decision-certificate.v1`, `v1.1`, `v1.2`, `v1.3`, `v1.4` and `v1.5`, all
frozen) is versioned separately; this log covers the crate, the verifiers, the fixtures and the docs.

## Unreleased

- **Inclusion v1 (draft), the Rust verifier** (plan `plans/transparency-log-2026-11.md`, Phase 2): a new
  module `decision_cert::inclusion`, additive, no new dependency, following the unfrozen draft
  [`spec/drafts/decision-cert-inclusion.v1.md`](spec/drafts/decision-cert-inclusion.v1.md). RFC 9162
  hashing and proofs (`hash_leaf_bytes`, `node_hash`, `root_hash`, `audit_path`, `consistency_path`,
  `verify_inclusion_path`, `verify_consistency_path`), leaf forms and the JCS leaf hash (`Leaf`,
  `leaf_hash`), C2SP checkpoints and `cosignature/v1` (`parse_checkpoint`, `c2sp_key_hash`,
  `cosignature_message`), the log trust configuration (`LogTrust::from_json`, `check_tenants`), the
  consumer's checks in §10's order with §14's error names (`verify_bundle`, `verify_consistency`,
  `ErrorName`, `InclusionError`), `t_proven` as the `m`-th earliest counted cosignature time, the policy
  (`apply_policy`), and an I-JSON reader that refuses repeated member names (`parse_ijson`). Tested on
  the RFC 6962 reference vectors and every index and size pair of trees of 1 to 9 leaves.
- The CLI gains `decision-cert verify-bundle <bundle> --trust <config>` and
  `decision-cert verify-consistency <doc> --trust <config>`: one JSON verdict line on stdout, exit 0
  accepted, 1 refused (with the error name), 2 unreadable or a malformed configuration. The existing API,
  `verify`, and every fixture are unchanged.

## 0.6.0 — unreleased (tag `v0.6.0` on the merge commit)

Spec v1.5: frozen, verified, issued. Verifiers accept v1 to v1.5; v1 to v1.4 certificates, fixtures and
verdicts are byte-identical, `verify(cert, keys)` keeps its meaning for them, and the issuer's default stays v1.2.

- **Spec v1.5 frozen** (2026-11-17, owner go, #55): the `tenant` and `signer` fields, the tenant-bound
  signature, `verify_for_tenant` with moded trusted keys in both verifiers, the issuer's `--tenant` and
  signer mode, and `fixtures/v1.5/`.
- **Evidence packs** and **`verify-pack`**, with the procedure re-run (`decision_cert.issue.recompute`).
  A pack carries no expected tenant, so `verify-pack` refuses v1.5 certificates for now.
- **Design records** (docs only): the owner's answers for the transparency log (#28) and the auditor
  attestation (#29) (#54). Nothing in them is built.
- The README, CLAUDE.md, roadmap and docs reference the frozen v1.5 spec and 0.6.0.

The entries below, from 0.5.0 to this release, give the detail.

- **Spec v1.5 frozen: tenant binding and a hosted signer** (2026-11-17, owner go,
  [`spec/decision-certificate.v1.5.md`](spec/decision-certificate.v1.5.md)). v1.4 plus `tenant` and
  `signer` (`{"mode": "operator"}` or `{"mode": "hosted", "host": <key id>}`). A v1.5 signature is over
  `"decision-cert/certificate.v1.5" 0x0A tenant 0x0A JCS(body)`, built with the tenant the verifier
  expects. `certificate_id` is unchanged.
  - Both verifiers: `verify_for_tenant(cert, tenant, keys)` with moded trusted keys
    (`tenant_keys_from_json`: a bare public key is an operator key, or `{"key", "mode", "host"}`),
    checks 1 to 4 (tenant, key in the tenant's set, key mode and host, signature), the errors
    `WrongTenant` and `KeyMode`, and `Verified::tenant` / `signer`. A v1 to v1.4 certificate under an
    expected tenant is accepted under an operator key only. `verify(cert, keys)` keeps its meaning for
    v1 to v1.4 and refuses a v1.5 certificate. Both CLIs take `--tenant`.
  - The issuer: `--spec decision-certificate.v1.5 --tenant <id> [--signer-mode hosted --host <key id>]`;
    the default stays v1.2.
  - `decision-certificate.v1.5.schema.json`, and `fixtures/v1.5/` (108 files and its mutations), with the
    tenant, key-mode and framing negatives. v1 to v1.4 fixtures and the v1 manifest are byte-identical.
- **Evidence packs** (`decision-evidence-pack.v1`, [`docs/evidence-pack.md`](docs/evidence-pack.md)): one
  tenant's certificates, the trusted keys, where the measured cases live (and optionally the cases, the
  members of `data_hash`), and a manifest with every file's sha256, as a directory or a tar. Versioned
  additively. `python -m decision_cert verify-pack` (and `decision_cert.verify_pack`) checks the layout,
  the manifest, the hashes, each certificate against the caller's or the pack's keys, the cases against
  `data_hash`, and, with the `issue` extra, re-runs the procedure on the cases and compares every
  measured figure (`decision_cert.issue.recompute`). Synthetic fixture packs in `python/tests/packs/`
  from `tools/gen_pack_fixtures.py` (`--check` in CI). The verifier bounds what it reads (1 GiB in all,
  256 MiB a member, 10,000 entries by default; `--max-total-bytes`, `--max-member-bytes`,
  `--max-members`), checked while reading; a pack over a limit, or truncated, corrupt or unreadable, is
  exit 2 with a message. A manifest that repeats a key is rejected. Without `--keys` the trusted-keys
  check reports `warn` and the verdict says the pack is consistent with its own keys only.
- **The method write-up is published** (#26, owner go 2026-11-16): `docs/drafts/method.md` moves to
  `docs/method.md`, without its DRAFT banner, and is brought up to date with the frozen v1.1 to v1.4
  specs: the per-test start, the refusal floor, segments and the mix, `cannot_tell`, the v1.3
  automated options, the v1.4 cost risk, expiry, the histogram's withholding rule, the frozen
  `certificate_id`, and the limits.

## 0.5.0 — 2026-11-12 (tag `v0.5.0`)

Specs v1.3 and v1.4: frozen, verified, issued. Verifiers accept v1 to v1.4; v1 to v1.2 certificates,
fixtures and verdicts are byte-identical, and the issuer's default stays v1.2.

- **Specs v1.3 and v1.4 frozen** (2026-11-12, founder go). Their status lines, the fixture notes and
  the docs no longer say "not frozen"; corrections now go in `spec/ERRATA.md`.
- **v1.4, the cost risk `selective_cost`** (#44): Hoeffding-Bentkus Learn-then-Test on the mean
  normalised cost of the answered cases; equal costs are byte-identical to the error test.
- **Whole-number costs and `loss_sum`** (#45, #46): exact integer checks replace float comparisons.
- **The exact coverage check** (#46): every v1.4 test's `coverage` must equal `answered / n` exactly,
  with `answered` recovered as the nearest whole number (n at most 2⁵³), so `realized_cost` is
  checked against `loss_sum` with no tolerance.
- **The HB statistics** (`stats.py`: `cost_start`, `cost_ltt`, the Hoeffding-Bentkus p-value) and the
  **cost study** (`spec/drafts/cost-study.md`, 648 cells, valid everywhere).
- The README, CLAUDE.md, roadmap and docs reference the frozen v1.3 and v1.4 specs and 0.5.0.
- **Release readback** (`release.yml`, job `readback`): after both publishes, a fresh install from PyPI
  and a fresh build from crates.io each check all 84 `fixtures/v1.4/` files against their verdicts.

The entries below, from 0.4.0 to this release, give the detail.

- **Spec v1.4 (not frozen): whole-number costs and `loss_sum`** (#45). Cost matrix entries and
  `c_max` are integers (`unit` names the scale; `c_max` at most 10⁶), and each test, segment and
  `automated` block states `loss_sum`, the exact sum of its answered cases' costs. `realized_cost` must
  be exactly `loss_sum / (c_max · answered)`, and with every option automated the `automated` sums
  must equal their test's as integers. Before, those equalities compared float sums whose last bit
  depended on summation order, so a correct issuer summing differently from ours would have written
  certificates every verifier refused (found when #44's first CI run caught our own issuer doing it).
  The statistics are unchanged. The v1.4 fixtures are regenerated with 14 new cases (84 files); v1
  to v1.3 are byte-identical.

- **Spec v1.4: the cost risk `selective_cost`, implemented, not frozen**
  (`spec/decision-certificate.v1.4.md`). Both verifiers accept `decision-certificate.v1.4`, and the
  issuer writes it with `--spec decision-certificate.v1.4`; the default stays v1.2.
  - `--cost DECISION=COSTS.json` certifies the mean normalised cost of the answered cases with
    Hoeffding-Bentkus Learn-then-Test. Equal off-diagonal costs give `selective_error`, byte-identical
    to the certificate issued without a cost (a required test).
  - New fields `cost`, `pvalue` and `realized_cost` (per test and per `automated` block), with
    their checks in both verifiers. Reader: `cost()`.
  - A new fixture set, `fixtures/v1.4/` (70 files and its mutations); v1 to v1.3 certificates,
    fixtures and verdicts are byte-identical. `joint_cost` and a betting p-value stay draft.
  - `spec/drafts/cost-study.md`: the label study (648 cells, valid everywhere), and
    `docs/certificates.md` guidance on when a cost matrix pays and on small-`n_cal` certificates.

- `python/tools/study_start.py` and `spec/drafts/s1-start-study.md`: where the `ltt` fixed sequence
  starts, on small tests (n 250–1,000, alpha = delta = 0.1). Four start rules across four synthetic
  worlds; all are valid, and the reference issuer's argmin-p start is the most powerful. It suggests
  keeping the start and adding `n_cal` guidance; nothing is decided and no spec or issuer changes.

- **Spec v1.3 (not frozen), follow-up.** §1.6 says outright that `automated.ucb` is not a bound and
  can exceed `alpha`. Both verifiers now refuse a certificate whose `automate_options` names every
  option but whose `automated` blocks differ from their tests' numbers (two new fixtures in
  `fixtures/v1.3/`). The issuer refuses a `cannot_tell` value that is not a number or null, under
  every spec; such input had no defined meaning before.

- **Spec v1.3: C1 and P1, implemented, not frozen** (`spec/decision-certificate.v1.3.md`). Both
  verifiers accept `decision-certificate.v1.3`, and the issuer writes it with `--spec
  decision-certificate.v1.3`; the default stays v1.2.
  - **C1:** `data_hash` also binds each case's `cannot_tell` value.
  - **P1:** `automate_options` (`--automate-options DECISION=OPTION[,OPTION]`, default every option) and, for each test,
    `automated`: the answered share and the error among the cases whose top option is automated.
    These numbers are descriptive; the bound at `alpha` still covers every answered case.
  - Readers: `automate_options()` and `automated_for(segment)`. A new fixture set,
    `fixtures/v1.3/` (41 files and its mutations).
  - v1, v1.1 and v1.2 certificates, fixtures and verdicts are byte-identical. F1, R1, K1, U1, S1
    and M1 stay draft.

- **Issuer: unlabelled rows under `--audit sample`** (#37). **Behaviour change:** a row scored for
  the decision that logs a propensity above 0 (the audit selected it) but has no label is refused,
  with the count, so inputs that log the rate on every row of the window, selected or not, now
  refuse: log it only on selected rows. Other scored rows without a label are skipped as before, now
  counted in the diagnostics (`n_skipped_unlabelled`) and reported on stderr. Certificates and
  fixtures are unchanged.

- **Docs: how many labelled cases** (`docs/certificates.md`): the arithmetic floor of an `ltt` and
  a `crc` test at `alpha` 0.05, 0.10 and 0.20 (`delta` 0.10), in labelled rows by coverage, with the
  issuer's half split counted.
- **Issuer: a label-budget warning.** `certify` warns when an `ltt` test has fewer threshold-split
  cases than the fewest that can pass with no errors (`budget_notes`). It never changes the method.
- **Docs: model validation** (`docs/model-risk.md`, new): certificate fields mapped to the headings
  of a model validation, and what a certificate does not give.
- **Docs: selective labels** (`docs/credit-approval.md`): an audit sample for credit, with the
  label source, how the sample is drawn, its size, and v1.2's uniform-propensity limit.

## 0.4.0 — 2026-11-09 (tag `v0.4.0`)

Spec v1.2: frozen, verified, issued. Verifiers accept v1, v1.1 and v1.2; v1 and v1.1 certificates
and fixtures are unchanged.

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
