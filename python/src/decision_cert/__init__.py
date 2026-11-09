"""Verify and apply decision certificates: `decision-certificate.v1`, `v1.1` and `v1.2`
(spec/decision-certificate.v1.md, spec/decision-certificate.v1.1.md, spec/decision-certificate.v1.2.md).

A port of the Rust crate in this repository's `rust/`, which is the reference: both must agree on
every conformance fixture. A certificate describes a measured process; it never promises an outcome.

    from decision_cert import loads, verify
    v = verify(loads(open("cert.json").read()), keys)   # keys: key id -> base64url public key
    v.id, v.threshold_for("north"), v.is_expired(now)

    # v1.2: monitor a window of use-time confidences without labels;
    # None for a case unscored or above `rule.cannot_tell_above`
    window = Histogram.of(v.confidence_bins(), confidences)
    shift_score(v.histogram_for("north"), window).p_value

    # apply the certificate's calibration map (v1.2 kinds: temperature, dr) to a case's raw scores
    v.confidence(raw_scores) >= v.threshold_for("north")
"""

from ._map import MAP_KINDS, confidence, probabilities
from ._monitor import Histogram, ShiftScore, bin_of, chi2_sf, shift_score
from ._verify import (
    ABSTAIN_ALL,
    SPEC,
    SPEC_V1_1,
    SPEC_V1_2,
    SPECS,
    V1_2_FIELDS,
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
    "MAP_KINDS",
    "SPEC",
    "SPECS",
    "SPEC_V1_1",
    "SPEC_V1_2",
    "V1_2_FIELDS",
    "BadKey",
    "BadSignature",
    "CertError",
    "Histogram",
    "Invalid",
    "ShiftScore",
    "UntrustedKey",
    "Verified",
    "__version__",
    "bin_of",
    "canonical",
    "certificate_id",
    "chi2_sf",
    "confidence",
    "is_expired",
    "key_id",
    "loads",
    "probabilities",
    "shift_score",
    "threshold_for",
    "timestamp",
    "verify",
]
