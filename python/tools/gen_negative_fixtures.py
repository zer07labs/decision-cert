"""Generate the negative conformance fixtures that this repository owns, and record each verdict by
running the Rust crate (the reference verifier).

    cd python && uv run python tools/gen_negative_fixtures.py          # write the fixtures
    cd python && uv run python tools/gen_negative_fixtures.py --check  # fail if any would change

Each fixture is `valid_basic.json`'s certificate, edited and re-signed with a throwaway key (seed
`[7] * 32`, public and deterministic). The positive fixtures and `mutations/` are generated
elsewhere and copied here unchanged; this script never touches them. It rewrites
`fixtures/FIXTURES.sha256` over every v1 fixture file (`fixtures/v1.1/` to `fixtures/v1.4/` have their
own manifests).
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from decision_cert import _ed25519 as ed
from decision_cert import canonical, certificate_id, key_id, loads
from decision_cert._verify import b64url_encode

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "fixtures"
SEED = bytes([7] * 32)


def raw_public(sk: Ed25519PrivateKey) -> bytes:
    return sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def secret_scalar(seed: bytes) -> int:
    h = bytearray(hashlib.sha512(seed).digest()[:32])
    h[0] &= 248
    h[31] &= 127
    h[31] |= 64
    return int.from_bytes(h, "little")


def body_of(cert: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in cert.items() if k != "signature"}


def signed(cert: dict[str, Any], kid: str, sign: Any) -> dict[str, Any]:
    body = body_of(cert)
    body["signer_key_id"] = kid
    return {**body, "signature": b64url_encode(sign(canonical(body)))}


def k_of(r: bytes, a: bytes, msg: bytes) -> int:
    return int.from_bytes(hashlib.sha512(r + a + msg).digest(), "little") % ed.L


def cases() -> dict[str, tuple[dict[str, Any], dict[str, str], str]]:
    """name -> (certificate, trusted keys, a substring the reference verifier's error must contain)."""
    base = loads((FIXTURES / "valid_basic.json").read_text(encoding="utf-8"))["certificate"]
    sk = Ed25519PrivateKey.from_private_bytes(SEED)
    pub = raw_public(sk)
    kid = key_id(pub)
    keys = {kid: b64url_encode(pub)}
    a = secret_scalar(SEED)
    assert ed.encode(ed.mul(a, ed.BASE)) == pub
    out: dict[str, tuple[dict[str, Any], dict[str, str], str]] = {}

    # A small-order public key (the identity). With A = O the plain RFC 8032 equation holds for
    # R = [s]B and any message, so only a strict verifier rejects it.
    o = ed.encode(ed.IDENTITY)
    s1 = 1
    out["invalid_small_order_key"] = (
        signed(base, key_id(o), lambda _m: ed.encode(ed.mul(s1, ed.BASE)) + s1.to_bytes(32, "little")),
        {key_id(o): b64url_encode(o)},
        "signature",
    )

    # A small-order R (the identity) with S = k·a: [S]B = R + [k]A holds, so again only a strict
    # verifier rejects it.
    def sign_identity_r(m: bytes) -> bytes:
        return o + (k_of(o, pub, m) * a % ed.L).to_bytes(32, "little")

    out["invalid_small_order_r"] = (signed(base, kid, sign_identity_r), keys, "signature")

    # A valid signature with S replaced by S + L: the same scalar mod L, but not canonical.
    def sign_noncanonical_s(m: bytes) -> bytes:
        sig = sk.sign(m)
        return sig[:32] + (int.from_bytes(sig[32:], "little") + ed.L).to_bytes(32, "little")

    out["invalid_noncanonical_s"] = (signed(base, kid, sign_noncanonical_s), keys, "signature")

    edits: list[tuple[str, str, Any, str]] = [
        ("invalid_timestamp_offset", "expires_at", "2027-01-23T12:00:00+00:00", "is not YYYY-MM-DDTHH:MM:SSZ"),
        ("invalid_bool_as_number", "coverage", True, "invalid type: boolean"),
        ("invalid_float_as_integer", "n_cal", 2500.0, "invalid type: floating point"),
    ]
    for name, field, value, error in edits:
        c = copy.deepcopy(base)
        c[field] = value
        out[name] = (signed(c, kid, sk.sign), keys, error)
    return out


def render(name: str, cert: dict[str, Any], keys: dict[str, str], error: str) -> str:
    f = {
        "name": name,
        "certificate": cert,
        "keys": keys,
        "body_jcs_b64": base64.b64encode(canonical(body_of(cert))).decode(),
        "certificate_id": certificate_id(cert),
        "valid": False,
        "error": error,
    }
    return json.dumps(f, indent=2, ensure_ascii=False) + "\n"


def rust_verdicts(paths: list[Path]) -> dict[str, dict[str, Any]]:
    run = subprocess.run(
        ["cargo", "run", "--quiet", "--locked", "--example", "verdict", "--", *map(str, paths)],
        cwd=ROOT / "rust",
        check=True,
        capture_output=True,
        text=True,
    )
    return {Path(v["file"]).stem: v for v in map(json.loads, run.stdout.splitlines())}


def manifest() -> str:
    files = sorted(
        p for p in FIXTURES.rglob("*.json") if not {"v1.1", "v1.2", "v1.3", "v1.4"} & set(p.relative_to(FIXTURES).parts)
    )
    lines = [f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(FIXTURES).as_posix()}" for p in files]
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="fail if a fixture or the manifest would change")
    args = ap.parse_args()

    stale = []
    rendered = {name: render(name, *c) for name, c in cases().items()}
    for name, text in rendered.items():
        path = FIXTURES / f"{name}.json"
        if not path.exists() or path.read_text(encoding="utf-8") != text:
            stale.append(path.name)
            if not args.check:
                path.write_text(text, encoding="utf-8")

    # The verdicts come from the reference verifier, never from this script.
    verdicts = rust_verdicts([FIXTURES / f"{n}.json" for n in rendered])
    for name, (_c, _k, error) in cases().items():
        v = verdicts[name]
        if v["valid"] or error not in v["error"]:
            print(f"{name}: the Rust crate says {v}, expected an error mentioning {error!r}", file=sys.stderr)
            return 1

    sha = FIXTURES / "FIXTURES.sha256"
    want = manifest()
    if not sha.exists() or sha.read_text(encoding="utf-8") != want:
        stale.append(sha.name)
        if not args.check:
            sha.write_text(want, encoding="utf-8")

    if stale and args.check:
        print(f"stale: {', '.join(stale)}; run tools/gen_negative_fixtures.py", file=sys.stderr)
        return 1
    print(f"{'checked' if args.check else 'wrote'} {len(rendered)} negative fixtures; Rust verdicts agree")
    return 0


if __name__ == "__main__":
    sys.exit(main())
