"""The same fixture loop as rust/tests/conformance.rs: agree with the Rust crate on the canonical
bytes, the certificate id and the verdict of every fixture (v1, v1.1, v1.2 and v1.3), and reject every
schema mutation."""

from __future__ import annotations

import base64
from pathlib import Path
from typing import Any

import pytest

import decision_cert as dc

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"
SETS = {"": 14, "v1.1": 9, "v1.2": 25, "v1.3": 41}  # each fixture set, and how many fixtures it has at least


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
        v = dc.verify(cert, f["keys"])
        assert v.id == f["certificate_id"], name
    else:
        with pytest.raises(dc.CertError) as e:
            dc.verify(cert, f["keys"])
        assert f["error"] in str(e.value), f"{name}: error {e.value!s} does not mention {f['error']!r}"


@pytest.mark.parametrize("name", list(SETS))
def test_every_schema_invalid_mutation_is_rejected(name: str) -> None:
    f = dc.loads((FIXTURES / name / "mutations" / "schema_invalid.json").read_text(encoding="utf-8"))
    accepted = []
    for c in f["cases"]:
        try:
            dc.verify(c["certificate"], f["keys"])
            accepted.append(f"{c['path']} {c['edit']}")
        except dc.CertError:
            pass
    assert not accepted, f"accepted: {accepted}"
    assert len(f["cases"]) > 200
