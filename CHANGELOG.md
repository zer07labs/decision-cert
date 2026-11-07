# Changelog

All notable changes to this repository. The spec (`decision-certificate.v1`) is versioned
separately and is frozen; this log covers the crate, the verifiers, the fixtures and the docs.

## 0.1.0 — unreleased

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
- crates.io readiness: package metadata and a `cargo publish --dry-run` check in CI (not published).
- Repository docs: README for outside readers, `CONTRIBUTING.md`, `SECURITY.md`, this changelog, and
  a dated implementations note under the frozen spec.
