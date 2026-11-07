# decision-cert (Python verifier)

A pure-Python verifier for `decision-certificate.v1`, a port of the Rust crate in
[`rust/`](https://github.com/zer07labs/decision-cert/tree/main/rust). Dependencies: `rfc8785` and `cryptography`, nothing else. It verifies; it
does not issue.

```python
from decision_cert import loads, verify

cert = loads(open("cert.json").read())  # strict JSON, as the Rust crate parses it
keys = loads(open("trusted-keys.json").read())  # key id -> base64url raw Ed25519 public key
v = verify(cert, keys)  # raises Invalid, UntrustedKey, BadKey or BadSignature
v.id, v.threshold_for("north"), v.is_expired(datetime.now(UTC))
```

The Rust crate is the reference. This package passes the same conformance fixtures
([`fixtures/`](https://github.com/zer07labs/decision-cert/tree/main/fixtures)); where the two disagree, this package is wrong. A certificate
describes a measured process and never promises an outcome; see the
[spec](https://github.com/zer07labs/decision-cert/blob/main/spec/decision-certificate.v1.md).

```bash
pip install decision-cert
python -m decision_cert verify cert.json --keys trusted-keys.json   # exit 0 / 1 / 2
```

Development, from `python/` in the repository:

```bash
uv sync && uv run pytest && uv run ruff check && uv run mypy
```
