"""The same fixture loop as rust/tests/conformance.rs: agree with the Rust crate on the canonical
bytes, the certificate id and the verdict of every fixture (v1 to v1.5), and reject every schema mutation. A
v1.5 file carries the expected `tenant` and moded `keys`, and is verified with `verify_for_tenant`."""

from __future__ import annotations

import base64
from pathlib import Path
from typing import Any

import pytest

import decision_cert as dc

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"
SETS = {
    "": 14,
    "v1.1": 9,
    "v1.2": 25,
    "v1.3": 43,
    "v1.4": 70,
    "v1.5": 100,
}  # each fixture set, and how many fixtures it has at least


def verdict(f: Any, cert: Any) -> dc.Verified:
    """A fixture's verdict: for its expected tenant when it has one (v1.5), else with `verify`."""
    if "tenant" in f:
        return dc.verify_for_tenant(cert, f["tenant"], dc.tenant_keys_from_json(f["keys"]))
    return dc.verify(cert, f["keys"])


def fixtures() -> list[tuple[str, Any]]:
    out = []
    for name, least in SETS.items():
        found = sorted(
            (f"{name}/{p.stem}".lstrip("/"), dc.loads(p.read_text(encoding="utf-8")))
            for p in (FIXTURES / name).glob("*.json")
        )
        assert len(found) >= least, f"expected the conformance fixtures in {name or '.'}, found {len(found)}"
        out += found
    return out


@pytest.mark.parametrize(("name", "f"), fixtures(), ids=lambda x: x if isinstance(x, str) else "")
def test_python_agrees_with_rust_on_every_fixture(name: str, f: Any) -> None:
    cert = f["certificate"]
    body = {k: v for k, v in cert.items() if k != "signature"}
    jcs = dc.canonical(body)
    assert base64.b64encode(jcs).decode() == f["body_jcs_b64"], f"{name}: JCS bytes differ:\n{jcs!r}"
    assert dc.certificate_id(cert) == f["certificate_id"], name
    if f["valid"]:
        v = verdict(f, cert)
        assert v.id == f["certificate_id"], name
    else:
        with pytest.raises(dc.CertError) as e:
            verdict(f, cert)
        assert f["error"] in str(e.value), f"{name}: error {e.value!s} does not mention {f['error']!r}"


@pytest.mark.parametrize("name", list(SETS))
def test_every_schema_invalid_mutation_is_rejected(name: str) -> None:
    f = dc.loads((FIXTURES / name / "mutations" / "schema_invalid.json").read_text(encoding="utf-8"))
    accepted = []
    for c in f["cases"]:
        try:
            verdict(f, c["certificate"])
            accepted.append(f"{c['path']} {c['edit']}")
        except dc.CertError:
            pass
    assert not accepted, f"accepted: {accepted}"
    assert len(f["cases"]) > 200


def test_costs_are_read_from_v1_4_cost_certificates_only() -> None:
    def read(name: str) -> Any:
        f = dc.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))
        return dc.verify(f["certificate"], f["keys"])

    for name in ("v1.3/valid_basic", "v1.4/valid_basic", "v1.4/valid_crc_abstain_all"):
        assert read(name).cost() is None, name
    assert read("v1.4/valid_cost_three_options").cost() == {
        "matrix": [[0, 2, 1], [16, 0, 4], [6, 3, 0]],
        "c_max": 16,
        "unit": None,
    }
    assert read("v1.4/valid_cost_basic").cost()["unit"] == "usd"


def test_every_v1_5_fixture_names_its_tenant() -> None:
    files = sorted((FIXTURES / "v1.5").glob("*.json"))
    assert files and all("tenant" in dc.loads(p.read_text(encoding="utf-8")) for p in files)


@pytest.mark.parametrize("name", ["valid_operator", "valid_hosted"])
def test_verify_refuses_a_v1_5_certificate_and_verify_for_tenant_reads_it(name: str) -> None:
    """`verify` keeps its meaning for v1 to v1.4 and refuses a v1.5 certificate, which binds a tenant."""
    f = dc.loads((FIXTURES / "v1.5" / f"{name}.json").read_text(encoding="utf-8"))
    flat = {k: e["key"] for k, e in f["keys"].items()}
    with pytest.raises(
        dc.Invalid, match=r"a v1\.5 certificate is verified with its expected tenant \(verify_for_tenant\)"
    ):
        dc.verify(f["certificate"], flat)
    v = verdict(f, f["certificate"])
    assert v.tenant() == f["tenant"] and v.signer() == f["certificate"]["signer"]
    keys = dc.tenant_keys_from_json(f["keys"])
    with pytest.raises(dc.WrongTenant):
        dc.verify_for_tenant(f["certificate"], "another-tenant", keys)
    with pytest.raises(dc.Invalid, match="expected tenant must be"):
        dc.verify_for_tenant(f["certificate"], "a b", keys)
    v14 = dc.loads((FIXTURES / "v1.4" / "valid_basic.json").read_text(encoding="utf-8"))
    assert dc.verify(v14["certificate"], v14["keys"]).tenant() is None


def test_tenant_keys_are_read_strictly() -> None:
    host = "ed25519:0123456789abcdef"
    ok = dc.tenant_keys_from_json(
        {
            "ed25519:aaaaaaaaaaaaaaaa": "AAAA",
            "ed25519:bbbbbbbbbbbbbbbb": {"key": "BBBB", "mode": "operator"},
            "ed25519:cccccccccccccccc": {"key": "CCCC", "mode": "hosted", "host": host},
        }
    )
    assert ok["ed25519:aaaaaaaaaaaaaaaa"] == dc.TrustedKey("AAAA")
    assert ok["ed25519:bbbbbbbbbbbbbbbb"] == dc.TrustedKey("BBBB", "operator")
    assert ok["ed25519:cccccccccccccccc"] == dc.TrustedKey("CCCC", "hosted", host)
    for bad in [
        {"key": "K", "mode": "operator", "host": host},
        {"key": "K", "mode": "hosted"},
        {"key": "K", "mode": "hosted", "host": "hosting.example"},
        {"key": "K", "mode": "hosted", "host": "ed25519:0123456789ABCDEF"},
        {"key": "K", "mode": "delegated"},
        {"key": "K", "mode": "operator", "extra": 1},
        {"mode": "operator"},
        7,
    ]:
        with pytest.raises(dc.BadKey):
            dc.tenant_keys_from_json({"ed25519:aaaaaaaaaaaaaaaa": bad})
    with pytest.raises(dc.CertError):
        dc.tenant_keys_from_json(["k"])
