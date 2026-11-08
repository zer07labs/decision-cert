"""Generate the reference issuer's conformance fixtures: the positive (and first negative) fixtures
and `mutations/schema_invalid.json`, signed with the reference issuer's `sign`, for v1 (`fixtures/`)
and for v1.1 (`fixtures/v1.1/`, with its own `FIXTURES.sha256`).

    cd python && uv run python tools/gen_positive_fixtures.py          # write
    cd python && uv run python tools/gen_positive_fixtures.py --check  # fail if any byte would change

The keys are public and deterministic (seeds 0..31 and 32..63). The v1 files predate this script and
must stay byte-identical: a change to any of them is a change to the conformance suite, and every
vendored copy must follow. After writing, run `tools/gen_negative_fixtures.py` to refresh
`fixtures/FIXTURES.sha256`. The v1.1 set is the same certificates with `spec`
`decision-certificate.v1.1`, plus a certificate naming a spec no verifier knows; its manifest is
written here.
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import jsonschema
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from decision_cert.issue import certify as ct

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "fixtures"
V11 = FIXTURES / "v1.1"
KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
OTHER = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))


def keys(*ks: Ed25519PrivateKey) -> dict[str, str]:
    return {ct.key_id(k.public_key()): ct.b64url(ct.raw_public(k.public_key())) for k in ks}


def make_base(spec: str = ct.SPEC_V1) -> dict[str, Any]:
    out = _base_v1()
    if spec != ct.SPEC_V1:
        out["spec"] = spec
        out["issuer"] = {"tool": "decision-cert", "version": "0.3.0"}
    return out


def _base_v1() -> dict[str, Any]:
    band = {"level": 0.95, "low": 0.0011834410146505043, "high": 0.04314473389094683}
    return {
        "spec": "decision-certificate.v1",
        "domain": "hmda-approval",
        "decision": "approved",
        "options": ["yes", "no"],
        "model_id": "b1/lightgbm@lgbm-4.7.0-seed7",
        "manifest_hash": "sha256:" + "ab" * 32,
        "data_hash": "sha256:" + "0f" * 32,
        "n_cal": 2500,
        "n_temperature": 2500,
        "split": {"method": "seeded", "seed": 7},
        "calibration_map": {"kind": "temperature", "params": {"temperature": 1.3173913043478262}, "label_budget": None},
        "rule": {"cannot_tell_above": None, "unscored": "abstain"},
        "alpha": 0.05,
        "delta": 0.1,
        "method": "ltt",
        "risk": "selective_error",
        "n": 2500,
        "abstain_below": 0.8829170572757721,
        "coverage": 0.4116,
        "ucb": 0.032977066870911,
        "realized_band": band,
        "segments": [],
        "window": None,
        "fitted_at": "2026-10-25T12:00:00Z",
        "expires_at": "2027-01-23T12:00:00Z",
        "audit": {"mode": "full-label", "rate": 1, "n": 5000, "propensity_logged": False},
        "issuer": {"tool": "decisionkit-calib", "version": "0.1.0"},  # as first issued; kept for byte identity
    }


def fixtures(spec: str = ct.SPEC_V1) -> dict[str, dict[str, Any]]:
    def base() -> dict[str, Any]:
        return make_base(spec)

    out: dict[str, tuple[dict[str, Any], dict[str, str], bool, str | None]] = {}
    out["valid_basic"] = (ct.sign(base(), KEY), keys(KEY), True, None)

    tricky = base()
    tricky["calibration_map"] = {
        "kind": "temperature",
        "params": {"temperature": 0.30000000000000004},
        "label_budget": 200,
    }
    tricky.update(abstain_below=1e-7, coverage=0.1234567890123456789, ucb=5e-324, n_cal=9007199254740991)
    tricky["split"] = {"method": "seeded", "seed": -3}
    tricky["realized_band"] = {"level": 0.95, "low": 0.0, "high": 1.0}
    out["valid_tricky_numbers"] = (ct.sign(tricky, KEY), keys(KEY), True, None)

    crc = base()
    crc.update(method="crc", risk="joint_error", delta=None, ucb=None, abstain_below=1.01, coverage=0.0)
    out["valid_crc_abstain_all"] = (ct.sign(crc, KEY), keys(KEY), True, None)

    seg = base()
    seg["split"] = {"method": "time", "seed": None}
    seg["window"] = {"start": "2023-01-02T00:00:00Z", "end": "2023-12-29T23:59:59Z"}
    seg["rule"] = {"cannot_tell_above": 0.5, "unscored": "abstain"}
    seg["audit"] = {"mode": "sample", "rate": 0.05, "n": 5000, "propensity_logged": True}
    s = {
        "field": "region",
        "n": 600,
        "abstain_below": 0.9,
        "coverage": 0.25,
        "ucb": 0.04,
        "realized_band": seg["realized_band"],
    }
    seg["segments"] = [
        {**s, "value": "east", "inherited": False},
        {
            **s,
            "value": "zürich ☃",
            "inherited": True,
            "ucb": None,
            "realized_band": None,
            "abstain_below": 0.8829170572757721,
        },
    ]
    out["valid_segments_unicode"] = (ct.sign(seg, KEY), keys(KEY, OTHER), True, None)

    tampered = copy.deepcopy(out["valid_basic"][0])
    tampered["abstain_below"] = 0.5
    out["invalid_tampered"] = (tampered, keys(KEY), False, "signature")

    unknown = base()
    unknown["extra_claim"] = True  # signed, but v1 verifiers reject unknown fields
    out["invalid_unknown_field"] = (ct.sign(unknown, KEY), keys(KEY), False, "unknown field")
    out["invalid_untrusted_key"] = (ct.sign(base(), OTHER), keys(KEY), False, "not a trusted key")

    missing = ct.sign(base(), KEY)
    del missing["window"]
    out["invalid_missing_nullable_field"] = (missing, keys(KEY), False, "window")

    if spec != ct.SPEC_V1:
        later = base()
        later["spec"] = "decision-certificate.v1.2"  # signed, but no verifier knows this spec
        out["invalid_unknown_spec"] = (ct.sign(later, KEY), keys(KEY), False, "spec is not")

    result = {}
    for name, (cert, trusted, valid, error) in out.items():
        body = {k: v for k, v in cert.items() if k != "signature"}
        result[name] = {
            "name": name,
            "certificate": cert,
            "keys": trusted,
            "body_jcs_b64": base64.b64encode(ct.canonical(body)).decode(),
            "certificate_id": ct.certificate_id(cert),
            "valid": valid,
            "error": error,
        }
    return result


def _paths(v: Any, path: tuple[str | int, ...] = ()) -> Iterator[tuple[str | int, ...]]:
    """Every object key path in a certificate body, nested into the first segment."""
    if isinstance(v, dict):
        for k, x in v.items():
            yield (*path, k)
            yield from _paths(x, (*path, k))
    elif isinstance(v, list) and v and isinstance(v[0], dict):
        yield from _paths(v[0], (*path, 0))


def mutations(spec: str = ct.SPEC_V1) -> list[dict[str, Any]]:
    """Signed certificates that the schema rejects, one per field and edit: dropped, null, wrong
    type, empty string, a string with a newline. Every verifier must reject every one."""
    cert0 = fixtures(spec)["valid_segments_unicode"]["certificate"]
    body0 = {k: v for k, v in cert0.items() if k not in ("signature", "signer_key_id")}
    schema = ct.schema(spec)
    out = []
    for path in _paths(body0):
        for edit, value in [("drop", None), ("null", None), ("type", [1]), ("empty", ""), ("newline", "a\n")]:
            body = copy.deepcopy(body0)
            parent: Any = body
            for p in path[:-1]:
                parent = parent[p]
            if edit == "drop":
                del parent[path[-1]]
            else:
                parent[path[-1]] = value
            cert = ct.sign(body, KEY)
            try:
                jsonschema.validate(cert, schema)
            except jsonschema.ValidationError:
                out.append({"path": ".".join(map(str, path)), "edit": edit, "certificate": cert})
    return out


def _set(spec: str, root: Path) -> dict[Path, str]:
    files = {root / f"{n}.json": json.dumps(f, indent=2, ensure_ascii=False) + "\n" for n, f in fixtures(spec).items()}
    m = {"keys": keys(KEY), "cases": mutations(spec)}
    assert len(m["cases"]) > 150
    files[root / "mutations" / "schema_invalid.json"] = json.dumps(m, indent=1, ensure_ascii=False) + "\n"
    return files


def rendered() -> dict[Path, str]:
    files = _set(ct.SPEC_V1, FIXTURES)
    v11 = _set(ct.SPEC, V11)
    lines = sorted(f"{hashlib.sha256(t.encode()).hexdigest()}  {p.relative_to(V11).as_posix()}" for p, t in v11.items())
    v11[V11 / "FIXTURES.sha256"] = "\n".join(sorted(lines, key=lambda x: x.split("  ")[1])) + "\n"
    return {**files, **v11}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="fail if any fixture would change")
    args = ap.parse_args()
    stale = []
    for path, text in rendered().items():
        if not path.exists() or path.read_text(encoding="utf-8") != text:
            stale.append(path.relative_to(FIXTURES).as_posix())
            if not args.check:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text, encoding="utf-8")
    if stale and args.check:
        print(f"stale: {', '.join(stale)}; run tools/gen_positive_fixtures.py", file=sys.stderr)
        return 1
    print(f"{'checked' if args.check else 'wrote'} the reference issuer's fixtures ({len(stale)} changed)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
