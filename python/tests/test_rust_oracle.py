"""Differential test: Python and the Rust crate (the oracle) agree on hundreds of edited,
re-signed certificates. Runs the crate through `cargo run --example verdict`; skipped when cargo is
not on PATH (CI always has it)."""

from __future__ import annotations

import json
import random
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
from support import KEYS, base, resign, set_path

import decision_cert as dc

RUST = Path(__file__).resolve().parents[2] / "rust"

EDGE_VALUES: list[Any] = [
    None,
    True,
    False,
    0,
    1,
    -1,
    1.0,
    0.5,
    1.01,
    1.0100000000000002,
    2,
    2**53 + 1,
    2**63,
    2**64,
    -(2**63) - 1,
    5e-324,
    1e300,
    "",
    "x",
    "\n",
    [],
    {},
    ["a"],
    {"a": 1},
    "2027-01-23T12:00:00Z",
    "2026-12-31T23:59:60Z",
    "0000-01-01T00:00:00Z",
    "2023-02-29T00:00:00Z",
    "2024-02-29T00:00:00Z",
    "2027-01-23T12:00:00+00:00",
    "b/m@v",
    "b/@v",
    "b/m@?",
    "/m@v",
    "b/m@",
    "b/m\u2028@v",
    "sha256:" + "a" * 64,
    "sha256:" + "A" * 64,
    "time",
    "seeded",
    "ltt",
    "crc",
    "sample",
    "full-label",
    "abstain",
]

PATHS = [
    "spec",
    "domain",
    "decision",
    "options",
    "options.0",
    "model_id",
    "manifest_hash",
    "data_hash",
    "n_cal",
    "n_temperature",
    "split",
    "split.method",
    "split.seed",
    "calibration_map.kind",
    "calibration_map.params",
    "calibration_map.params.temperature",
    "calibration_map.label_budget",
    "rule.cannot_tell_above",
    "rule.unscored",
    "alpha",
    "delta",
    "method",
    "risk",
    "n",
    "abstain_below",
    "coverage",
    "ucb",
    "realized_band.level",
    "realized_band.low",
    "realized_band.high",
    "segments",
    "window",
    "fitted_at",
    "expires_at",
    "audit.mode",
    "audit.rate",
    "audit.n",
    "audit.propensity_logged",
    "issuer.tool",
    "issuer.version",
    "extra",
]

SEGMENT_PATHS = [
    f"segments.0.{k}"
    for k in ["field", "value", "n", "abstain_below", "coverage", "ucb", "realized_band", "inherited", "extra"]
]


def cases() -> list[tuple[str, str]]:
    """(name, fixture-file text). Most are a single edit, re-signed; some are raw JSON text."""
    rng = random.Random(20261107)
    out: list[tuple[str, str]] = []

    def add(name: str, cert: Any, keys: dict[str, str] = KEYS) -> None:
        out.append((name, json.dumps({"certificate": cert, "keys": keys}, ensure_ascii=False)))

    for i in range(300):
        seg = rng.random() < 0.3
        c = base("valid_segments_unicode" if seg else "valid_basic")
        path = rng.choice(PATHS + (SEGMENT_PATHS if seg else []))
        value = rng.choice(EDGE_VALUES)
        try:
            c = set_path(c, path, value)
        except (KeyError, IndexError, TypeError):
            continue
        try:
            add(f"edit{i}-{path}", resign(c))
        except dc.Invalid:
            add(f"unsigned{i}-{path}", c)  # not canonicalisable: both must refuse it unsigned
    for name, raw in [("minus-zero-int", '"n": -0'), ("float-int", '"n": 2500.0'), ("exp-int", '"n": 25e2')]:
        c = resign(base())
        text = json.dumps({"certificate": c, "keys": KEYS}).replace('"n": 2500', raw, 1)
        out.append((name, text))
    return out


def python_verdict(text: str) -> dict[str, Any]:
    try:
        f = dc.loads(text)
        v = dc.verify(f["certificate"], f["keys"])
        return {"valid": True, "id": v.id}
    except dc.CertError as e:
        return {"valid": False, "error": str(e)}


def kind(error: str) -> str:
    for k in ("not a valid", "not a trusted key", "trusted key", "signature does not verify"):
        if k in error:
            return k
    return error


@pytest.mark.skipif(shutil.which("cargo") is None, reason="cargo not on PATH")
def test_python_and_rust_agree(tmp_path: Path) -> None:
    files = []
    for i, (name, text) in enumerate(cases()):
        p = tmp_path / f"{i:04d}.json"
        p.write_text(text, encoding="utf-8")
        files.append((name, p, text))
    run = subprocess.run(
        ["cargo", "run", "--quiet", "--locked", "--example", "verdict", "--", *(str(p) for _, p, _ in files)],
        cwd=RUST,
        check=True,
        capture_output=True,
        text=True,
    )
    rust = [json.loads(line) for line in run.stdout.splitlines()]
    assert len(rust) == len(files)
    disagree = []
    valid = 0
    for (name, _, text), r in zip(files, rust, strict=True):
        py = python_verdict(text)
        valid += py["valid"]
        if (
            py["valid"] != r["valid"]
            or (r["valid"] and py["id"] != r["id"])
            or (not r["valid"] and kind(py["error"]) != kind(r["error"]))
        ):
            disagree.append(f"{name}: python {py} rust {r}")
    assert not disagree, "\n".join(disagree)
    assert valid >= 20, f"only {valid} accepted cases; the edits are not exercising the accept path"
