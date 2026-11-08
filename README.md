# decision-cert

The open specification for **decision certificates** (`decision-certificate.v1.1`, and v1 before it), a Rust crate that
verifies and applies them, and the conformance fixtures every implementation must agree on.

## Try it in one line

Verify a signed example certificate with the published Python package
([`demo/`](demo/README.md) says what the example is):

<!-- quickstart -->
```bash
uvx decision-cert verify <(curl -sL https://raw.githubusercontent.com/zer07labs/decision-cert/main/demo/example/certificate.json) --keys <(curl -sL https://raw.githubusercontent.com/zer07labs/decision-cert/main/demo/example/trusted-keys.json)
```

It prints the certificate id (`sha256:d0547d97…`) and exits 0. CI runs this line.

## What a decision certificate is

A model answers a decision (approve or decline, route A or B) and gives each answer a confidence.
A decision certificate records how that model's answers were **measured** on labelled cases:

- which labelled cases were used (by hash, never the cases themselves);
- the confidence threshold below which the model abstains;
- the share of cases it answers at that threshold;
- an upper bound on the error rate of the answered cases, at a stated confidence level.

Whoever ran the measurement signs the certificate (Ed25519 over the RFC 8785 canonical JSON bytes),
and its id is `sha256:` of those bytes. Anyone holding the signer's public key can check that the
record is intact and who produced it.

**Certificates describe a measured process, never guarantee an outcome.** The bound holds only
while future cases are exchangeable with the calibration cases. It says nothing about any single
decision, about label quality or fairness, or about populations that were never sampled. That is
why certificates expire. [`docs/certificates.md`](docs/certificates.md) lists what a certificate
claims and what it does not.

## Verify one

```rust
use decision_cert::verify;

let cert: serde_json::Value = serde_json::from_str(&std::fs::read_to_string("cert.json")?)?;
let keys = serde_json::from_str(&std::fs::read_to_string("trusted-keys.json")?)?; // key id -> base64url public key
let v = verify(&cert, &keys)?;                       // schema, trusted key, signature
let threshold = v.threshold_for(Some("north"));      // segment threshold, else the top-level one
let expired = v.is_expired(chrono::Utc::now());      // re-measure after expires_at
```

`verify` rejects a certificate that does not match the schema (unknown fields included), is signed
by a key not in `keys`, or whose signature does not verify. It returns the certificate id, the typed
certificate and its expiry.

## Layout

| Path | What |
|---|---|
| [`spec/`](spec/) | [`decision-certificate.v1.1.md`](spec/decision-certificate.v1.1.md) (normative, **frozen** 2026-11-08), [`decision-certificate.v1.md`](spec/decision-certificate.v1.md) (**frozen** 2026-10-25), and a JSON Schema for each |
| [`rust/`](rust/) | the `decision-cert` crate: `verify`, `canonical`, `certificate_id`, `key_id`, segment thresholds, expiry |
| [`python/`](python/) | a pure-Python verifier (`decision_cert`), a port of the crate that passes the same fixtures |
| [`fixtures/`](fixtures/) | conformance fixtures: signed certificates with their canonical bytes, ids and expected verdicts, plus `mutations/schema_invalid.json`, schema-invalid certificates a verifier must reject; v1 at the top level, v1.1 in `fixtures/v1.1/` |
| [`docs/certificates.md`](docs/certificates.md) | how a certificate is issued, verified and applied |
| [`plans/`](plans/) | the public roadmap |

v1 and v1.1 are frozen, and verifiers accept both. They have the same fields; v1.1 changes one step
of the issuing procedure (each test starts the threshold grid on its own cases) and clarifies the
text. Any change to a field or its meaning is `decision-certificate.v2`, and verifiers reject unknown
fields. Corrections to frozen text go in [`spec/ERRATA.md`](spec/ERRATA.md), never in the text.

From the command line, in Rust or Python (exit 0 verified and unexpired, 1 rejected or expired,
2 usage or file error):

```bash
cargo install decision-cert --features cli
decision-cert verify cert.json --keys trusted-keys.json [--now 2026-11-07T00:00:00Z]

pip install decision-cert
python -m decision_cert verify cert.json --keys trusted-keys.json
```

Or in Python:

```python
from decision_cert import loads, verify
v = verify(loads(open("cert.json").read()), loads(open("trusted-keys.json").read()))
v.id, v.threshold_for("north"), v.is_expired(datetime.now(UTC))
```

## Install

```toml
# Cargo.toml
decision-cert = "0.1"
```

```bash
pip install decision-cert      # Python 3.12+, depends on rfc8785 and cryptography only
```

Releases are tagged `vX.Y.Z` on `main` and published from CI
([`.github/workflows/release.yml`](.github/workflows/release.yml)). A git pin still works for
unreleased commits:

```toml
decision-cert = { git = "https://github.com/zer07labs/decision-cert", rev = "<sha>" }
```

Working on this repository:

```bash
cd rust && cargo test --all-features     # unit tests + the conformance suite over ../fixtures
cd python && uv sync && uv run pytest     # the Python verifier, incl. agreement with the crate
```

## Writing another verifier

A verifier in any language must agree with the Rust crate on every file in `fixtures/`: the
canonical bytes, the certificate id and the verdict ([`fixtures/README.md`](fixtures/README.md)).
The Rust crate is the reference; where a
verifier disagrees with it, the verifier is wrong or the spec needs an erratum.
[`docs/conformance.md`](docs/conformance.md) is the procedure; [`spec/ERRATA.md`](spec/ERRATA.md)
holds dated clarifications of the frozen text.

## The issuer

The reference issuer (the tool that runs the measurement and signs the certificate) is
`decision_cert.issue`, an optional extra of the Python package, so the verifier keeps its two
dependencies:

```bash
pip install 'decision-cert[issue]'          # adds numpy, scipy, jsonschema, PyYAML
python -m decision_cert.issue keygen --out operator.pem
python -m decision_cert.issue certify --predictions preds.jsonl --data labelled.jsonl \
    --domain-dir my-domain --backend my-model --key operator.pem --audit full-label
```

[`docs/certificates.md`](docs/certificates.md) describes the inputs, the output and the refusals.
The issuer also generates the reference fixtures
([`python/tools/gen_positive_fixtures.py`](python/tools/gen_positive_fixtures.py)).

## Contributing and security

See [`CONTRIBUTING.md`](CONTRIBUTING.md), [`SECURITY.md`](SECURITY.md) and
[`CHANGELOG.md`](CHANGELOG.md).

## Licence

Apache-2.0, see [`LICENSE`](LICENSE).
