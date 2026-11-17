# Conformance: proving a verifier agrees

A verifier of decision certificates (`decision-certificate.v1` to `v1.5`) in any language
conforms when it agrees with the reference verifier, the Rust crate in [`rust/`](../rust/), on every
file in [`fixtures/`](../fixtures/) and its per-version sets, [`fixtures/v1.1/`](../fixtures/v1.1/)
to [`fixtures/v1.5/`](../fixtures/v1.5/). A verifier may support fewer specs: it then rejects the
others as unknown, and runs only their sets' files that name its specs. The
Python verifier in [`python/`](../python/) is held to the same test. Where a verifier and the crate
disagree, the verifier is wrong, unless an entry in [`spec/ERRATA.md`](../spec/ERRATA.md) says
otherwise.

## 1. Pin the fixtures

Copy `fixtures/` with `fixtures/FIXTURES.sha256` (and `v1.1/` to `v1.5/` with theirs) and record the
commit you copied from. Check the copy before every run:

```bash
cd fixtures && sha256sum --strict -c FIXTURES.sha256
for v in v1.1 v1.2 v1.3 v1.4 v1.5; do (cd "$v" && sha256sum --strict -c FIXTURES.sha256) || exit 1; done
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
| `tenant` | v1.5 set only: the expected tenant the certificate is verified for |

For every file, a conforming verifier must:

1. produce exactly `body_jcs_b64` from the parsed `certificate` without `signature`;
2. produce exactly `certificate_id`;
3. accept the certificate when `valid` is true and reject it when false. Matching the `error`
   substring is recommended, not required: it names the reason the reference verifier gives.

A file with `tenant` (every file in `fixtures/v1.5/`) is verified for that expected tenant, as
spec v1.5 §4 says, and its `keys` are that tenant's moded trusted keys: key id → a bare public key
(an `operator` key) or `{"key", "mode": "operator"}` or `{"key", "mode": "hosted", "host"}`. The
reference API is `verify_for_tenant(cert, tenant, keys)`, with `tenant_keys_from_json` to read the
keys, in both the crate and the Python verifier. `verify(cert, keys)` keeps its meaning for v1 to
v1.4 and refuses a v1.5 certificate. In the v1.5 set, `valid_earlier_spec_under_operator_key` is a
v1.4 certificate with a flat key map, verified under an expected tenant.

`fixtures/mutations/schema_invalid.json` is `{keys, cases}` (in v1.5, `{tenant, keys, cases}`), each case a signed certificate the
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
| `v1.4/invalid_*realized_cost*`, `v1.4/invalid_*loss_sum*` | `loss_sum` and `realized_cost` null exactly for the error risks, an inherited segment and a test that answered no case; otherwise `realized_cost` exactly `loss_sum / (c_max · answered)`, and an all-automated block's `loss_sum` its test's |
| `v1.5/valid_operator`, `v1.5/valid_hosted`, `v1.5/valid_tenant_longest` | the tenant-bound signed bytes (spec v1.5 §3) in both signer modes, a hosted key entry with its `host`, and a 128-character tenant |
| `v1.5/valid_earlier_spec_under_operator_key`, `v1.5/invalid_earlier_spec_under_hosted_key` | a v1.4 certificate under an expected tenant: accepted under an operator key only |
| `v1.5/invalid_wrong_tenant`, `v1.5/invalid_key_not_in_tenant_set` | checks 1 and 2: the tenant field, and the key in the expected tenant's set |
| `v1.5/invalid_operator_key_on_hosted_cert`, `v1.5/invalid_hosted_key_on_operator_cert`, `v1.5/invalid_host_mismatch` | check 3: the key's mode, and a hosted entry's `host`, byte for byte |
| `v1.5/invalid_v1_5_signature_over_bare_jcs`, `v1.5/invalid_v1_4_signature_under_v1_5_framing`, `v1.5/invalid_prefix_for_another_tenant` | check 4: the signature is over the context string and the **expected** tenant, then the JCS bytes |
| `v1.5/invalid_missing_tenant`, `v1.5/invalid_missing_signer`, `v1.5/invalid_tenant_*`, `v1.5/invalid_*signer*`, `v1.5/invalid_*host*`, `v1.5/invalid_v1_5_fields_in_v1_4` | the `tenant` and `signer` forms (spec v1.5 §2), and the fields in an earlier spec |

## 4. Beyond the fixtures

The fixtures are the minimum. This repository also runs a differential test
([`python/tests/test_rust_oracle.py`](../python/tests/test_rust_oracle.py)): a few hundred edited,
re-signed certificates, where the Python verifier must give the crate's verdict and id on every
one (in v1.5, edits of `tenant`, `signer` and `spec`, re-signed for an expected tenant under
operator and hosted entries), and the two must bin windows of confidences and compute the v1.2 shift score alike (to 1e-9
relative) and apply the v1.2 calibration maps alike (to 1e-12 relative). A verifier in another language can do the same against the crate's command-line
verifier:

```bash
cd rust && cargo run --features cli -- verify cert.json --keys keys.json --now 2026-11-07T00:00:00Z
```

Exit 0 means the certificate verifies and has not expired at `--now` (the id is printed); 1 means
it does not verify or has expired; 2 is a usage or file error. `python -m decision_cert verify`
behaves the same. Add `--tenant <id>` to verify for an expected tenant (spec v1.5 §4), with
`--keys` then that tenant's moded keys; without it, a v1.5 certificate is refused (exit 1) and a
moded keys file is a usage error (exit 2).

## 5. Inclusion proofs

A verifier of the transparency-log sidecar
([`decision-cert-inclusion.v1`](../spec/decision-cert-inclusion.v1.md)) conforms when it agrees
with the crate's `decision_cert::inclusion` on every case of
[`fixtures/inclusion-v1/manifest.json`](../fixtures/inclusion-v1/manifest.json): the verdict, and
for a refusal the error name of the spec's §14. Pin the set as above, with its hash list:

```bash
cd fixtures/inclusion-v1 && sha256sum --strict -c INCLUSION.sha256
```

Each case names its `check` (`bundle`, `consistency`, `trust`, `tenants`, `policy`, `leaf_hash`, and the
RFC 9162 path vectors `rfc9162_inclusion` and `rfc9162_consistency`), the files it reads, and `expect`,
what a verifier must say about it. Both CLIs print a verdict as one JSON line:

```bash
cd rust && cargo run --features cli -- verify-bundle bundle.json --trust log-trust.json
cd rust && cargo run --features cli -- verify-consistency consistency.json --trust log-trust.json
```

Exit 0 is accepted, 1 refused (with the error name), 2 an unreadable file or a malformed
configuration. The checkpoints are C2SP signed notes; [`interop/c2sp/`](../interop/c2sp/) verifies
their log signatures and witness cosignatures with independent Go libraries (CI job `c2sp-interop`).

## 6. Reporting a disagreement

If your verifier and the crate disagree on a certificate and you believe the crate is wrong, open
an issue with the certificate and keys (public test material only). A disagreement that lets a
certificate verify when it should not is a security report: see [`SECURITY.md`](../SECURITY.md).
