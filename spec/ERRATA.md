# decision-certificate.v1: errata and clarifications

These entries concern v1. [v1.1](decision-certificate.v1.1.md) (frozen 2026-11-08) folds the
clarifications below into its text; entries concerning v1.1 will name it.

The v1 text and schema are frozen (2026-10-25). Nothing in them is edited. A correction or
clarification is a dated entry here, newest last, and never changes the fields or their meaning:
that would be `decision-certificate.v2`. Each entry names the section it concerns and states what
the reference verifier (the Rust crate in `rust/`) does; conformance fixtures back it where they
can.

Format:

```
## YYYY-MM-DD: <short title>
Concerns: §<section> (and/or the schema path)
Kind: erratum (the text is wrong) | clarification (the text is ambiguous)
<what the text says, what the reference verifier does, and what a verifier must do>
Fixtures: <file names, or "none">
```

## 2026-11-07: reference implementation paths

Concerns: the header ("Reference implementations", "Conformance fixtures")
Kind: erratum
The header names the paths these files had where the spec was written. In this repository they are
`rust/` (Rust crate), `python/` (Python verifier) and `fixtures/`. See also the note at the end of
the spec text.
Fixtures: none

## 2026-11-07: the reference issuer

Concerns: §2 (`issuer`); the implementations note below §5
Kind: clarification
The reference issuer now lives in this repository as `python/src/decision_cert/issue/` (the
`decision-cert[issue]` extra). Certificates it issues carry `{"tool": "decision-cert", ...}` in
`issuer`; the field names the library and is not checked by verifiers. The fixtures keep the
`issuer` they were first issued with.
Fixtures: none (all unchanged)

## 2026-11-07: integers are written without a fraction or exponent

Concerns: §2 (every `integer` field), §3 (numbers); schema `type: integer`
Kind: clarification
JSON Schema 2020-12 counts `2500.0` as an integer. The reference verifier does not: an integer field
written with a fraction or exponent (`2500.0`, `25e2`), or as `-0`, is rejected. A verifier must
reject it too. Number fields accept integers (`"rate": 1`).
Fixtures: `invalid_float_as_integer.json`

## 2026-11-07: signatures are verified strictly

Concerns: §3 (signature)
Kind: clarification
§3 says Ed25519 (RFC 8032). The reference verifier uses ed25519-dalek's `verify_strict`: on top of
the RFC 8032 equation it rejects a small-order public key, a small-order `R`, and `S` at or above
the group order. A verifier must reject all three. Plain RFC 8032 verification, as OpenSSL does it,
accepts the first two.
Fixtures: `invalid_small_order_key.json`, `invalid_small_order_r.json`, `invalid_noncanonical_s.json`

## 2026-11-07: timestamps

Concerns: §2 ("Timestamps are RFC 3339 UTC, whole seconds, `Z` suffix"); schema timestamp pattern
Kind: clarification
The reference verifier accepts exactly `YYYY-MM-DDTHH:MM:SSZ` (uppercase `T` and `Z`, no offset, no
fraction) naming a real calendar date and time. As RFC 3339 allows, a leap second (`:60`) and the
year `0000` are accepted.
Fixtures: `invalid_timestamp_offset.json`

## 2026-11-07: integers at or above 2^53

Concerns: §3 ("Integers stay below 2^53")
Kind: clarification
Neither the schema nor the reference verifier rejects a larger integer; the reference canonicalises
every number through an IEEE-754 double, so `9007199254740993` canonicalises as
`9007199254740992`. Issuers must not write such integers. A verifier that canonicalises them
differently will compute a different id; the Python verifier follows the reference.
Fixtures: none
