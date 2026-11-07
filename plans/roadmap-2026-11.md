# decision-cert roadmap (2026-11)

Working names throughout; naming is not final. This repo holds the frozen `decision-certificate.v1`
spec and schema, the Rust verifier crate, and the cross-language conformance fixtures. A certificate
describes a measured process; it never guarantees an outcome.

## Scope

- **In scope:** the spec and schema (frozen, v1); the Rust crate (`rust/src/lib.rs`); the conformance
  fixtures (`fixtures/`); a Python verifier; later, the reference issuer and spec v1.1.
- **Not in scope:** models, data, servers, or any customer material.

## Public contract

1. Spec text and schema. v1 verifiers reject unknown fields.
2. Certificate id: `sha256:` + lowercase hex of the RFC 8785 (JCS) bytes of the whole signed object.
3. The crate API (`verify`, `verify_strict` semantics, `check`, `threshold_for`, `is_expired`,
   `canonical`, `certificate_id`, `key_id`). Semver from 0.1.0 once published; until then consumers
   pin a git rev.
4. The fixture set and verdicts: every verifier, in any language, must agree with the Rust crate on
   every file.

## Phase 1 — repo hygiene, Python verifier, publish readiness

1. `CONTRIBUTING.md` (merge commits, never squash), `SECURITY.md` (reporting; signing keys are
   replaced on loss, never recovered), `CHANGELOG.md` (`0.1.0 — unreleased`).
2. A dated *Implementations* note under the frozen spec text (frozen sentences and schema untouched).
3. crates.io readiness without publishing: a CI step that runs `cargo publish --dry-run` and
   `cargo package --list` on a temp copy with `publish = false` removed; `exclude = ["tests/**"]` so
   the package carries no test that reads `../fixtures`.
4. **Python verifier** in `python/` (module `decision_cert`; dependencies `rfc8785` and
   `cryptography` only). A port of the crate; the Rust crate is the oracle. It must match:
   - strict `YYYY-MM-DDTHH:MM:SSZ` timestamps only;
   - `verify_strict`: reject small-order public keys and `R`, and non-canonical `S`;
   - booleans are never numbers; integer fields reject floats, even `1.0`;
   - `NaN`/`Infinity` rejected; unknown fields rejected at every level; base64url without padding;
   - canonical numbers identical to `serde_jcs` on `valid_tricky_numbers.json`.
5. New negative fixtures (small-order key, small-order R, non-canonical S, timestamp offset, bool as
   number, float as integer), verdicts recorded by running the Rust crate; `fixtures/FIXTURES.sha256`.
6. CI: a Python job (ruff, mypy --strict, pytest over the same fixture loop) and a fixture-manifest
   check.

## Phase 2 — third-party verifiability

- A `decision-cert verify <cert.json> --keys <keys.json> [--now <ts>]` CLI in Rust (feature `cli`)
  and `python -m decision_cert verify`, same exit codes.
- `docs/conformance.md`: how a verifier in another language proves agreement.
- `spec/ERRATA.md`: dated entries only, never edits to frozen text.

## Phase 3 — publish 0.1.0

Tag `v0.1.0`, publish the crate to crates.io and the verifier to PyPI. Consumers then switch from git
revs to version pins.

## Phase 3b — distribution (after 0.1.0)

Make it easy for an outside reader to see a real certificate, check it in one line, and read how
the measurement works. Everything here is public material: no customer data, and a certificate
describes a measured process, never an outcome.

1. **Demo certificates on public datasets** under `demo/<name>/`: the signed certificate, its
   trusted-keys file, and a README that states the dataset (source, version, licence), the model
   that was measured, the split, `alpha` and `delta`, the result, and the "what this does not
   claim" list from spec §5.
   - Datasets are openly licensed and allow sharing derived aggregates. A certificate carries only
     hashes and aggregate numbers, never rows.
   - The certificates are issued by the reference issuer with a **demo signing key**. Its public
     key is published here, its private key stays outside the repository, and no live domain ever
     trusts it.
   - The demos are signed files and are treated like fixtures: never hand-edited, listed in a
     `demo/DEMOS.sha256` manifest, and checked in CI by both verifiers (the Rust and Python CLIs),
     with `--now` set inside each certificate's validity window.
2. **A one-line verify quickstart** in the README, using the published packages against a demo
   certificate (for example `uvx decision-cert verify …` or `cargo install decision-cert --features
   cli`). CI runs exactly the documented line.
3. **A draft method write-up** under `docs/drafts/`: what is measured, Learn-then-Test and
   conformal risk control as the spec uses them, why `ucb` and `realized_band` are descriptive, how
   expiry and the audit basis work, and the limits.
   - The draft stays in this repository and is never posted elsewhere until the owner says so.
   - It is held to the same wording rules as the spec (the CI `wording` job covers `docs/`).

**Acceptance.** Every demo verifies with both CLIs in CI. The quickstart line runs green in CI.
The draft is marked DRAFT at the top and passes the wording check.

## Phase 4 — the reference issuer and spec v1.1

The Python issuer (`issue` extra, so the base verifier stays two-dependency) and the fixture
generator move here. Spec v1.1 is drafted as a separate document; v1 fixtures are kept and verifiers
accept both.

## Risks

- Verifier divergence: the Rust crate as oracle, shared fixtures, a property test re-signing
  `valid_basic.json` with random keys and edits.
- Small-order check wrong in Python: a table test over all eight small-order encodings.
- Packaging surprises: caught by the Phase 1 dry-run step.
- Wording: a CI check that spec, docs and README never promise outcomes.
