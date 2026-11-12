# Conformance: proving a verifier agrees

A verifier of decision certificates (`decision-certificate.v1`, `v1.1` and `v1.2`) in any language
conforms when it agrees with the reference verifier, the Rust crate in [`rust/`](../rust/), on every
file in [`fixtures/`](../fixtures/), [`fixtures/v1.1/`](../fixtures/v1.1/) and
[`fixtures/v1.2/`](../fixtures/v1.2/). A verifier may support fewer specs: it then rejects the
others as unknown, and runs only their sets' files that name its specs. The
Python verifier in [`python/`](../python/) is held to the same test. Where a verifier and the crate
disagree, the verifier is wrong, unless an entry in [`spec/ERRATA.md`](../spec/ERRATA.md) says
otherwise.

## 1. Pin the fixtures

Copy `fixtures/` with `fixtures/FIXTURES.sha256` (and `v1.1/`, `v1.2/` with theirs) and record the
commit you copied from. Check the copy before every run:

```bash
cd fixtures && sha256sum --strict -c FIXTURES.sha256
(cd v1.1 && sha256sum --strict -c FIXTURES.sha256) && (cd v1.2 && sha256sum --strict -c FIXTURES.sha256)
```

The manifest is the anchor: two verifiers that pass the same manifest were tested on the same bytes.

## 2. Run every fixture

Each `fixtures/*.json` file is an object:

| Key | Meaning |
|---|---|
| `certificate` | the signed certificate, as a JSON value |
| `keys` | trusted keys: key id → base64url (no padding) raw Ed25519 public key |
| `body_jcs_b64` | standard base64 of the RFC 8785 bytes of `certificate` without `signature` |
| `certificate_id` | `sha256:` + lowercase hex SHA-256 of the RFC 8785 bytes of the whole `certificate` |
| `valid` | whether `certificate` verifies against `keys` |
| `error` | for an invalid certificate, a substring of the reference verifier's error, else null |

For every file, a conforming verifier must:

1. produce exactly `body_jcs_b64` from the parsed `certificate` without `signature`;
2. produce exactly `certificate_id`;
3. accept the certificate when `valid` is true and reject it when false. Matching the `error`
   substring is recommended, not required: it names the reason the reference verifier gives.

`fixtures/mutations/schema_invalid.json` is `{keys, cases}`, each case a signed certificate the
schema rejects with the `path` and `edit` that broke it. A conforming verifier rejects every case.

Parse the JSON as the reference does: no `NaN` or `Infinity`, no lone surrogates, and integer
fields written without a fraction or exponent (`2500`, never `2500.0`). Canonicalise the parsed
value, never a re-serialised typed struct.

## 3. What the fixtures test

| Fixture | What a verifier must get right |
|---|---|
| `valid_tricky_numbers` | RFC 8785 number formatting: `0.30000000000000004`, `1e-7`, `5e-324`, 2^53 − 1, an integer `1` in a number field |
| `valid_segments_unicode` | non-ASCII strings in the canonical bytes; segments; two trusted keys |
| `valid_crc_abstain_all` | `method: crc` with null `delta` and `ucb`; `abstain_below` 1.01 |
| `invalid_unknown_field` | unknown fields are rejected, never ignored |
| `invalid_missing_nullable_field` | a nullable field must be present, as `null` |
| `invalid_tampered`, `invalid_untrusted_key` | the signature, and explicit key trust |
| `invalid_small_order_key`, `invalid_small_order_r` | reject a small-order public key or `R`. **Both pass plain RFC 8032 verification** (OpenSSL accepts them) |
| `invalid_noncanonical_s` | reject `S` ≥ the group order |
| `invalid_timestamp_offset` | timestamps are exactly `YYYY-MM-DDTHH:MM:SSZ` |
| `invalid_bool_as_number` | a boolean is never a number |
| `invalid_float_as_integer` | an integer field rejects `2500.0` |
| `mutations/schema_invalid` | every schema constraint, one edit at a time |
| `v1.1/invalid_unknown_spec` | a `spec` the verifier does not know is refused (it names v1.2 with v1.1's fields; a v1.2 verifier refuses it as a spec it is not) |
| `v1.2/valid_*` | the v1.2 fields: `confidence_bins` and the histograms, one withheld (null) |
| `v1.2/invalid_missing_v1_2_field`, `v1.2/invalid_segment_missing_histogram`, `v1.2/invalid_v1_2_field_in_v1_1` | fields that belong to another `spec`, at the top level or in a segment |
| `v1.2/invalid_histogram_sum`, `v1.2/invalid_segment_histogram_sum`, `v1.2/invalid_histogram_bins`, `v1.2/invalid_bins_*` | the checks beyond the schema (spec v1.2 §2) |
| `v1.2/valid_dr_map`, `v1.2/valid_other_map_kind` | a `dr` calibration map, and a kind v1.2 does not define (verifies; a consumer that does not apply it refuses it) |
| `v1.2/invalid_dr_*`, `v1.2/invalid_temperature_*` | map parameters that do not fit their kind (spec v1.2 §2) |
| `v1.2/invalid_unknown_spec` | a later `spec` (v1.3) is refused |
| `v1.4/valid_cost_*` | `selective_cost` certificates over two and three options, with segments and an automated subset |
| `v1.4/invalid_cost_*`, `v1.4/invalid_hb_under_selective_error`, `v1.4/invalid_crc_pvalue` | the cost matrix, the equal-cost refusal and the `cost`/`pvalue`/`risk` pairing (spec v1.4 §2) |
| `v1.4/invalid_*realized_cost*` | `realized_cost` in [0, 1], and null for the error risks, an inherited segment and a test that answered no case |

## 4. Beyond the fixtures

The fixtures are the minimum. This repository also runs a differential test
([`python/tests/test_rust_oracle.py`](../python/tests/test_rust_oracle.py)): a few hundred edited,
re-signed certificates, where the Python verifier must give the crate's verdict and id on every
one, and the two must bin windows of confidences and compute the v1.2 shift score alike (to 1e-9
relative) and apply the v1.2 calibration maps alike (to 1e-12 relative). A verifier in another language can do the same against the crate's command-line
verifier:

```bash
cd rust && cargo run --features cli -- verify cert.json --keys keys.json --now 2026-11-07T00:00:00Z
```

Exit 0 means the certificate verifies and has not expired at `--now` (the id is printed); 1 means
it does not verify or has expired; 2 is a usage or file error. `python -m decision_cert verify`
behaves the same.

## 5. Reporting a disagreement

If your verifier and the crate disagree on a certificate and you believe the crate is wrong, open
an issue with the certificate and keys (public test material only). A disagreement that lets a
certificate verify when it should not is a security report: see [`SECURITY.md`](../SECURITY.md).
