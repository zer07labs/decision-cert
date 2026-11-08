# decision-cert (Python verifier)

A pure-Python verifier for decision certificates (`decision-certificate.v1.2`, `v1.1` and `v1`), a port of the Rust crate in
[`rust/`](https://github.com/zer07labs/decision-cert/tree/main/rust). Dependencies: `rfc8785` and `cryptography`, nothing else. The reference issuer is
an optional extra, `pip install 'decision-cert[issue]'` (module `decision_cert.issue`); the verifier
never imports it.

```python
from decision_cert import Histogram, loads, shift_score, verify

cert = loads(open("cert.json").read())  # strict JSON, as the Rust crate parses it
keys = loads(open("trusted-keys.json").read())  # key id -> base64url raw Ed25519 public key
v = verify(cert, keys)  # raises Invalid, UntrustedKey, BadKey or BadSignature
v.id, v.threshold_for("north"), v.is_expired(datetime.now(UTC))

# v1.2: compare recent cases' confidences with the stored histogram;
# pass None for a case the rule abstains on whatever the threshold: unscored, or above cannot_tell_above
window = Histogram.of(v.confidence_bins(), recent_confidences)
shift_score(v.histogram_for("north"), window).p_value  # small: measure again; never a finding about the bound
```

The Rust crate is the reference. This package passes the same conformance fixtures
([`fixtures/`](https://github.com/zer07labs/decision-cert/tree/main/fixtures)); where the two disagree, this package is wrong. A certificate
describes a measured process and never promises an outcome; see the
[spec](https://github.com/zer07labs/decision-cert/blob/main/spec/decision-certificate.v1.2.md).

```bash
pip install decision-cert
python -m decision_cert verify cert.json --keys trusted-keys.json   # exit 0 / 1 / 2
```

Development, from `python/` in the repository:

```bash
uv sync && uv run pytest && uv run ruff check && uv run mypy
```
