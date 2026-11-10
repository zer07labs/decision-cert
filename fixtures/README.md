# Conformance fixtures

Every verifier of decision certificates, in any language, must agree with the Rust crate (`rust/`)
on every file here: the v1 set at the top level, the v1.1 set in [`v1.1/`](v1.1/), the v1.2 set
in [`v1.2/`](v1.2/) and the v1.3 set in [`v1.3/`](v1.3/). On each file
it must agree on the canonical bytes of the signed body (`body_jcs_b64`), the
certificate id, and the verdict (`valid`, and for an invalid certificate a substring of the error,
`error`). `mutations/schema_invalid.json` holds signed certificates the schema rejects; every one
must be rejected.

| Files | Produced by |
|---|---|
| `valid_*.json`, `invalid_missing_nullable_field.json`, `invalid_tampered.json`, `invalid_unknown_field.json`, `invalid_untrusted_key.json`, `mutations/` | [`python/tools/gen_positive_fixtures.py`](../python/tools/gen_positive_fixtures.py), signed by the reference issuer (`decision_cert.issue`); byte-identical to their first issue |
| `invalid_small_order_key.json`, `invalid_small_order_r.json`, `invalid_noncanonical_s.json`, `invalid_timestamp_offset.json`, `invalid_bool_as_number.json`, `invalid_float_as_integer.json` | [`python/tools/gen_negative_fixtures.py`](../python/tools/gen_negative_fixtures.py), with each verdict recorded by running the Rust crate |

Two of the strict-signature cases (`invalid_small_order_key`, `invalid_small_order_r`) pass plain
RFC 8032 verification, as OpenSSL does it; a verifier must also reject a small-order public key or
`R`, and a non-canonical `S`, as ed25519-dalek's `verify_strict` does.

Fixtures are never edited by hand. Keys and signatures here are public test material only.

**v1.1.** [`v1.1/`](v1.1/) holds the reference issuer's set again with `spec`
`decision-certificate.v1.1` (and the issuer's current name), its own `mutations/`, and
`invalid_unknown_spec.json`: a signed certificate naming a spec no verifier knows. These are the
v1 certificates with `spec` and `issuer` changed, not new runs of the v1.1 procedure: verifiers
check fields and signatures, and the fields are the same. The whole set comes
from `gen_positive_fixtures.py`, which also writes `v1.1/FIXTURES.sha256`. The signature, timestamp
and number cases above do not depend on `spec`, so they are not repeated.

**v1.2.** [`v1.2/`](v1.2/) holds the set again with `spec` `decision-certificate.v1.2`, the v1.2
fields (`confidence_bins`, and `confidence_histogram` at the top level and per segment, one of them
withheld as null) and the issuer version 0.4.0, its own `mutations/`, and the v1.2 cases:

- `valid_histogram_withheld`: the top-level histogram is null;
- `invalid_missing_v1_2_field`, `invalid_segment_missing_histogram` and
  `invalid_v1_2_field_in_v1_1`: fields that belong to another spec;
- `invalid_histogram_sum`, `invalid_segment_histogram_sum`, `invalid_histogram_bins`,
  `invalid_bins_not_rising` and `invalid_bins_not_ending_at_1`: histograms the schema accepts and
  the checks of spec v1.2 §2 refuse;
- `valid_dr_map`: a `dr` calibration map; `valid_other_map_kind`: a kind v1.2 does not define,
  which verifies (a consumer that does not apply it refuses it);
- `invalid_dr_missing_param`, `invalid_dr_slope_not_positive`, `invalid_dr_label_budget_null`,
  `invalid_temperature_not_positive` and `invalid_temperature_extra_param`: map parameters the
  checks of spec v1.2 §2 refuse;
- `invalid_unknown_spec`: a certificate naming `decision-certificate.v1.3`.

The v1.2 set is frozen with the spec: later changes add files and never change these.

**v1.3.** [`v1.3/`](v1.3/) holds the v1.2 set again with `spec` `decision-certificate.v1.3` and
the v1.3 fields: `automate_options` naming every option, so each `automated` block repeats its
test's `coverage`, `ucb` and `realized_band`. Its own `mutations/`, and the v1.3 cases:

- `valid_automated_subset`: approvals automated only (`automate_options` `["yes"]`), at the top
  level, in a certified segment and in an inherited one;
- `invalid_automate_options_unknown`, `_order`, `_repeated` and `_empty`: lists the checks of spec
  v1.3 §2 refuse;
- `invalid_automated_coverage_above_test`, `invalid_automated_ucb_null`,
  `invalid_automated_ucb_under_crc`, `invalid_automated_band_null`, `invalid_segment_automated_band`,
  `invalid_segment_automated_ucb_null`, `invalid_segment_automated_coverage_above_test` and
  `invalid_segment_automated_ucb_inherited`: `automated` blocks that
  disagree with their test;
- `invalid_automated_differs_from_test` and `invalid_segment_automated_differs_from_test`: every
  option automated, but an `automated` block that is not its test's own numbers;
- `invalid_missing_v1_3_field`, `invalid_segment_missing_automated` and
  `invalid_v1_3_field_in_v1_2`: fields that belong to another spec;
- `invalid_unknown_spec`: a certificate naming `decision-certificate.v1.4`.

v1.3 is not frozen yet, so this set may still change until it is; `v1.2/invalid_unknown_spec.json`
names v1.3 with v1.2's fields, and a v1.3 verifier refuses it with `spec is not` in its message.

The v1 and v1.1 sets do not change. `v1.1/invalid_unknown_spec.json` names v1.2 with v1.1's fields;
a v1.2 verifier still refuses it, because its fields are not v1.2's, and its message still contains
`spec is not`.

**Vendoring.** `FIXTURES.sha256` lists the SHA-256 of every v1 fixture file (`sha256sum -c` format);
`v1.1/FIXTURES.sha256`, `v1.2/FIXTURES.sha256` and `v1.3/FIXTURES.sha256` do the same for their sets.
Consumers vendor this directory and `FIXTURES.sha256` together, record the upstream commit, and
check their copy with `sha256sum -c FIXTURES.sha256`.
