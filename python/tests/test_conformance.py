"""The same fixture loop as rust/tests/conformance.rs: agree with the Rust crate on the canonical
bytes, the certificate id and the verdict of every fixture, and reject every schema mutation."""

from __future__ import annotations

import base64
from pathlib import Path
from typing import Any

import pytest

import decision_cert as dc

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"
MIN_FIXTURES = 14


def fixtures() -> list[tuple[str, Any]]:
    out = sorted((p.stem, dc.loads(p.read_text(encoding="utf-8"))) for p in FIXTURES.glob("*.json"))
    assert len(out) >= MIN_FIXTURES, f"expected the conformance fixtures, found {len(out)}"
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


def test_every_schema_invalid_mutation_is_rejected() -> None:
    f = dc.loads((FIXTURES / "mutations" / "schema_invalid.json").read_text(encoding="utf-8"))
    accepted = []
    for c in f["cases"]:
        try:
            dc.verify(c["certificate"], f["keys"])
            accepted.append(f"{c['path']} {c['edit']}")
        except dc.CertError:
            pass
    assert not accepted, f"accepted: {accepted}"
    assert len(f["cases"]) > 200
