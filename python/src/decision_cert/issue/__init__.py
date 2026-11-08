"""The reference issuer for `decision-certificate.v1`: calibrate a model on labelled cases and issue
a signed certificate per decision. Install with `pip install 'decision-cert[issue]'`; the verifier
in `decision_cert` never needs it.

    python -m decision_cert.issue keygen --out operator.pem
    python -m decision_cert.issue certify --predictions … --data … --domain-dir … --backend … --key …
"""

from __future__ import annotations

from .certify import CertError, TooFewCases, certify_decision, issue, keygen, load_private_key, sign

__all__ = ["CertError", "TooFewCases", "certify_decision", "issue", "keygen", "load_private_key", "sign"]
