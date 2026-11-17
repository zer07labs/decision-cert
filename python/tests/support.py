"""Re-signing helpers for tests: a throwaway, public, deterministic key (seed [7] * 32)."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import decision_cert as dc
from decision_cert._verify import b64url_encode

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"
KEY = Ed25519PrivateKey.from_private_bytes(bytes([7] * 32))
PUB = KEY.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
KID = dc.key_id(PUB)
KEYS = {KID: b64url_encode(PUB)}
# the hosting service's key id that the v1.5 fixtures' hosted certificates name (its key, seed 64..95, as in
# tools/gen_positive_fixtures.py), for v1.5 hosted entries
HOST_ID = dc.key_id(
    Ed25519PrivateKey.from_private_bytes(bytes(range(64, 96)))
    .public_key()
    .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
)


def fixture(name: str) -> Any:
    return dc.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


def base(name: str = "valid_basic") -> dict[str, Any]:
    return copy.deepcopy(fixture(name)["certificate"])


def resign(cert: dict[str, Any]) -> dict[str, Any]:
    """`cert` signed by KEY. Values the canonicaliser refuses are signed as the crate would see them."""
    body = {k: v for k, v in cert.items() if k != "signature"}
    body["signer_key_id"] = KID
    return {**body, "signature": b64url_encode(KEY.sign(dc.canonical(body)))}


def resign_for(cert: dict[str, Any], tenant: str) -> dict[str, Any]:
    """`cert` signed by KEY as a v1.5 issuer for `tenant` signs it: over the tenant-bound bytes when its
    `spec` is v1.5, else over the bare JCS bytes."""
    body = {k: v for k, v in cert.items() if k != "signature"}
    body["signer_key_id"] = KID
    msg = dc.canonical(body)
    if body.get("spec") == dc.SPEC_V1_5:
        msg = dc.signed_bytes_v1_5(tenant, msg)
    return {**body, "signature": b64url_encode(KEY.sign(msg))}


def set_path(cert: dict[str, Any], path: str, value: Any) -> dict[str, Any]:
    """A copy of `cert` with `a.b.0.c` set to `value`."""
    out = copy.deepcopy(cert)
    *parents, last = path.split(".")
    node: Any = out
    for p in parents:
        node = node[int(p)] if isinstance(node, list) else node[p]
    if isinstance(node, list):
        node[int(last)] = value
    else:
        node[last] = value
    return out
