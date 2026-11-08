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
    "decision-certificate.v1.1",
    "decision-certificate.v1.2",
    0.0,
    0.99,
    [0, 1],
    [0, 0.5, 1],
    [0, 0.5, 0.5, 1],
    [1, 0.5, 0],
    {"counts": [2500], "unscored": 0},
    {"counts": [2450, 0], "unscored": 50},
    {"counts": [1, 2], "unscored": -1},
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

V12_PATHS = [
    "confidence_bins",
    "confidence_bins.0",
    "confidence_bins.1",
    "confidence_bins.9",
    "confidence_histogram",
    "confidence_histogram.counts",
    "confidence_histogram.counts.0",
    "confidence_histogram.counts.8",
    "confidence_histogram.unscored",
    "confidence_histogram.extra",
    "segments.0.confidence_histogram",
    "segments.0.confidence_histogram.counts.1",
    "segments.0.confidence_histogram.unscored",
    "segments.1.confidence_histogram",
    "n",
    "segments.0.n",
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
    for i in range(300):
        c = base("v1.2/valid_segments_unicode")
        path = rng.choice(V12_PATHS + PATHS)
        value = rng.choice(EDGE_VALUES)
        try:
            c = set_path(c, path, value)
        except (KeyError, IndexError, TypeError):
            continue
        try:
            add(f"v12-edit{i}-{path}", resign(c))
        except dc.Invalid:
            add(f"v12-unsigned{i}-{path}", c)
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


def monitor_cases() -> list[dict[str, Any]]:
    """Windows of confidences (None = unscored) on random bins, against random baselines."""
    rng = random.Random(20261112)
    out = []
    for _ in range(300):
        k = rng.randint(1, 30)
        inner = sorted({round(rng.random(), rng.choice([2, 4, 17])) for _ in range(k - 1)} - {0.0, 1.0})
        bins = [0.0, *inner, 1.0]
        b = len(bins) - 1
        counts = [rng.choice([0, rng.randint(0, 50), rng.randint(0, 5000)]) for _ in range(b)]
        baseline: dict[str, Any] = {"counts": counts, "unscored": rng.choice([0, rng.randint(0, 100)])}
        m = rng.choice([0, 1, 5, 300, 3000])
        conf: list[float | None] = []
        like = rng.random() < 0.6 and sum(counts) > 0  # drawn like the baseline, so p-values spread
        for _ in range(m):
            r = rng.random()
            if like:
                i = rng.choices(range(b), weights=counts)[0]
                conf.append(rng.uniform(bins[i], bins[i + 1]) if r > 0.02 else None)
            else:
                conf.append(None if r < 0.05 else rng.choice([0.0, 1.0, *bins]) if r < 0.15 else rng.random() ** 0.3)
        out.append({"bins": bins, "baseline": baseline, "confidences": conf})
    return out


@pytest.mark.skipif(shutil.which("cargo") is None, reason="cargo not on PATH")
def test_python_and_rust_bin_and_score_windows_alike(tmp_path: Path) -> None:
    cases = monitor_cases()
    p = tmp_path / "monitor.json"
    p.write_text(json.dumps(cases))
    run = subprocess.run(
        ["cargo", "run", "--quiet", "--locked", "--example", "monitor", "--", str(p)],
        cwd=RUST,
        check=True,
        capture_output=True,
        text=True,
    )
    rust = [json.loads(line) for line in run.stdout.splitlines()]
    assert len(rust) == len(cases)
    scored = 0
    for c, r in zip(cases, rust, strict=True):
        w = dc.Histogram.of(c["bins"], c["confidences"])
        assert r["window"] == {"counts": list(w.counts), "unscored": w.unscored}, c["bins"]
        s = dc.shift_score(dc.Histogram(tuple(c["baseline"]["counts"]), c["baseline"]["unscored"]), w)
        assert r["score"]["df"] == s.df
        assert r["score"]["statistic"] == pytest.approx(s.statistic, rel=1e-12, abs=1e-12)
        assert r["score"]["p_value"] == pytest.approx(s.p_value, rel=1e-9, abs=1e-15)
        scored += s.df > 0 and 1e-12 < s.p_value < 1
    assert scored >= 75, "too few cases exercise the chi-square tail"
