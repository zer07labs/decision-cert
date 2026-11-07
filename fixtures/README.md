# Conformance fixtures

Every verifier of `decision-certificate.v1`, in any language, must agree with the Rust crate
(`rust/`) on every file here: the canonical bytes of the signed body (`body_jcs_b64`), the
certificate id, and the verdict (`valid`, and for an invalid certificate a substring of the error,
`error`). `mutations/schema_invalid.json` holds signed certificates the schema rejects; every one
must be rejected.

| Files | Produced by |
|---|---|
| `valid_*.json`, `invalid_missing_nullable_field.json`, `invalid_tampered.json`, `invalid_unknown_field.json`, `invalid_untrusted_key.json`, `mutations/` | the reference issuer, which is not in this repository yet; copied here unchanged |
| `invalid_small_order_key.json`, `invalid_small_order_r.json`, `invalid_noncanonical_s.json`, `invalid_timestamp_offset.json`, `invalid_bool_as_number.json`, `invalid_float_as_integer.json` | [`python/tools/gen_negative_fixtures.py`](../python/tools/gen_negative_fixtures.py), with each verdict recorded by running the Rust crate |

Two of the strict-signature cases (`invalid_small_order_key`, `invalid_small_order_r`) pass plain
RFC 8032 verification, as OpenSSL does it; a verifier must also reject a small-order public key or
`R`, and a non-canonical `S`, as ed25519-dalek's `verify_strict` does.

Fixtures are never edited by hand. Keys and signatures here are public test material only.

**Vendoring.** `FIXTURES.sha256` lists the SHA-256 of every fixture file (`sha256sum -c` format).
Consumers vendor this directory and `FIXTURES.sha256` together, record the upstream commit, and
check their copy with `sha256sum -c FIXTURES.sha256`.
