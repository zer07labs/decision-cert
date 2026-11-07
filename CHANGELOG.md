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
- Repository docs: README for outside readers, `CONTRIBUTING.md`, `SECURITY.md`, this changelog, and
  a dated implementations note under the frozen spec.
