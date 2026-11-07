# Security

## Reporting a vulnerability

**Do not open a public issue.**

- Preferred: a [private security advisory](https://github.com/zer07labs/decision-cert/security/advisories/new)
  on this repository (Security → Report a vulnerability).
- Or email **security@zer07labs.com** with a description, reproduction steps and impact.

We acknowledge within 3 business days, give an initial assessment within 7, and agree a disclosure
timeline with you before anything is made public.

**In scope:** a certificate that verifies when it should not (or fails when it should not) in the
Rust crate or any verifier here; canonicalisation differences between implementations; signature or
key-id handling; anything in the spec that lets two conforming verifiers disagree.
**Out of scope:** what a certificate's numbers mean. A certificate describes a measured process and
never promises an outcome (see `spec/decision-certificate.v1.md` §5).

## Signing keys

- **The signer is whoever runs the measurement**, in their own environment, with their own Ed25519
  key. This repository never holds a private key; fixtures carry public keys and deterministic test
  signatures only.
- **Verifiers trust keys explicitly**: a map of key id (`ed25519:` + 16 hex of SHA-256 of the raw
  public key) to the base64url raw public key. There is no key discovery and no default trust.
- **A lost or leaked signing key is replaced, never recovered.** Generate a new key, replace the
  trusted-keys map, and record the retired key id with the date. Certificates signed by the retired
  key then verify only against a key map that still lists it. A key suspected of leaking is removed
  from every trusted-keys map at once.

## Supported versions

Until 0.1.0 is published, only `main` is supported.
