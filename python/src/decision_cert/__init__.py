"""Verify and apply decision certificates: `decision-certificate.v1` and `decision-certificate.v1.1`
(spec/decision-certificate.v1.md, spec/decision-certificate.v1.1.md).

A port of the Rust crate in this repository's `rust/`, which is the reference: both must agree on
every conformance fixture. A certificate describes a measured process; it never promises an outcome.

    from decision_cert import loads, verify
    v = verify(loads(open("cert.json").read()), keys)   # keys: key id -> base64url public key
    v.id, v.threshold_for("north"), v.is_expired(now)
"""

from ._verify import (
    ABSTAIN_ALL,
    SPEC,
    SPEC_V1_1,
    SPECS,
    BadKey,
    BadSignature,
    CertError,
    Invalid,
    UntrustedKey,
    Verified,
    canonical,
    certificate_id,
    is_expired,
    key_id,
    loads,
    threshold_for,
    timestamp,
    verify,
)

__version__ = "0.3.0"

__all__ = [
    "ABSTAIN_ALL",
    "SPEC",
    "SPECS",
    "SPEC_V1_1",
    "BadKey",
    "BadSignature",
    "CertError",
    "Invalid",
    "UntrustedKey",
    "Verified",
    "__version__",
    "canonical",
    "certificate_id",
    "is_expired",
    "key_id",
    "loads",
    "threshold_for",
    "timestamp",
    "verify",
]
