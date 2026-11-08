"""The reference issuer (`decision_cert.issue`): end to end on synthetic cases, its refusals, and
agreement with both verifiers. Every issued certificate is checked by the Python verifier and by the
Rust crate (the oracle; skipped when cargo is not on PATH, CI always has it)."""

from __future__ import annotations

import datetime as dt
import json
import shutil
import stat
import subprocess
from pathlib import Path
from typing import Any

import numpy as np
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import decision_cert as dc
from decision_cert.issue import certify as ct
from decision_cert.issue import recal
from decision_cert.issue import stats as cs

RUST = Path(__file__).resolve().parents[2] / "rust"
KEY = Ed25519PrivateKey.from_private_bytes(bytes([9] * 32))
NOW = dt.datetime(2026, 11, 7, 12, 0, tzinfo=dt.UTC)
OPTIONS = ["yes", "no"]


def trusted() -> dict[str, str]:
    return {ct.key_id(KEY.public_key()): ct.b64url(ct.raw_public(KEY.public_key()))}


def domain(tmp: Path, *, segments: dict[str, Any] | None = None, cannot_tell_above: float | None = None) -> Path:
    d = tmp / "domain"
    d.mkdir(exist_ok=True)
    lines = ["id: demo-approval", "decisions:", "  - id: approved", "    kind: noul", "    question: Approve?"]
    if cannot_tell_above is not None:
        lines.append(f"cannot_tell_above: {cannot_tell_above}")
    lines += ["certificate:", "  ttl_days: 30"]
    if segments:
        vals = ", ".join(f"'{v}'" for v in segments["values"])
        lines += [
            "  segments:",
            f"    field: {segments['field']}",
            f"    values: [{vals}]",
            f"    floor: {segments['floor']}",
        ]
    (d / "domain.yaml").write_text("\n".join(lines) + "\n")
    return d


def cases(
    n: int, seed: int = 0, *, timed: bool = False, regions: list[str] | None = None, unscored: int = 0
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """(predictions, labelled rows): a model whose margin tracks how likely it is to be right."""
    rng = np.random.default_rng(seed)
    preds, rows = [], []
    for i in range(n):
        margin = float(rng.normal(0, 2.5))
        truth = 0 if rng.random() < 1 / (1 + np.exp(-margin)) else 1
        cid = f"c{i:05d}"
        row: dict[str, Any] = {"case_id": cid, "case": {"region": regions[i % len(regions)]} if regions else {}}
        row["labels"] = {"approved": OPTIONS[truth]}
        if timed:
            row["decided_at"] = (dt.datetime(2026, 1, 1, tzinfo=dt.UTC) + dt.timedelta(minutes=i)).isoformat()
        rows.append(row)
        p: dict[str, Any] = {"case_id": cid, "decision": "approved", "model": "toy", "version": "1"}
        if i < unscored:
            p["status"] = "no_answer"
        else:
            p["raw_scores"] = [margin / 2, -margin / 2]
        preds.append(p)
    return preds, rows


def issue(tmp: Path, n: int = 2000, **kw: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    segs = kw.pop("segments", None)
    ct_above = kw.pop("cannot_tell_above", None)
    preds, rows = cases(
        n, timed=kw.pop("timed", False), regions=kw.pop("regions", None), unscored=kw.pop("unscored", 0)
    )
    cal, diags = ct.issue(
        preds, rows, domain(tmp, segments=segs, cannot_tell_above=ct_above), "toy-backend", KEY, now=NOW,
        audit=kw.pop("audit", "full-label"), **kw,
    )  # fmt: skip
    return cal["approved"], diags["approved"]


def rust_verdicts(tmp: Path, certs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    files = []
    for i, c in enumerate(certs):
        f = tmp / f"issued_{i}.json"
        f.write_text(json.dumps({"certificate": c, "keys": trusted()}))
        files.append(str(f))
    run = subprocess.run(
        ["cargo", "run", "--quiet", "--locked", "--example", "verdict", "--", *files],
        cwd=RUST, check=True, capture_output=True, text=True,
    )  # fmt: skip
    return [json.loads(line) for line in run.stdout.splitlines()]


def test_issued_certificate_verifies_and_claims_what_it_measured(tmp_path: Path) -> None:
    entry, diag = issue(tmp_path)
    cert = entry["certificate"]
    v = dc.verify(cert, trusted())
    assert v.id == diag["certificate_id"] == ct.certificate_id(cert)
    assert cert["issuer"] == {"tool": "decision-cert", "version": dc.__version__}
    assert cert["n_cal"] == 1000 and cert["n_temperature"] == 1000 and cert["split"] == {"method": "seeded", "seed": 0}
    assert cert["audit"] == {"mode": "full-label", "rate": 1, "n": 2000, "propensity_logged": False}
    assert cert["fitted_at"] == "2026-11-07T12:00:00Z" and cert["expires_at"] == "2026-12-07T12:00:00Z"
    assert cert["abstain_below"] < 1.0, "a well-separated toy model should certify"
    # The test's own counts: the answered errors are below alpha's bound, and ucb covers them.
    assert diag["answered"] > 0 and diag["errors"] / diag["answered"] <= cert["ucb"] <= 1
    assert cs.p_value(diag["answered"], diag["errors"], cert["alpha"]) <= cert["delta"]
    assert cert["coverage"] == diag["answered"] / cert["n"]
    assert entry["temperature"] == cert["calibration_map"]["params"]["temperature"]


def test_same_inputs_give_the_same_certificate_bytes(tmp_path: Path) -> None:
    a, _ = issue(tmp_path)
    b, _ = issue(tmp_path)
    assert ct.canonical(a["certificate"]) == ct.canonical(b["certificate"])


@pytest.mark.parametrize(
    "kw",
    [
        {},
        {"method": "crc"},
        {"timed": True},
        {
            "regions": ["east", "west", "zürich ☃"],
            "segments": {"field": "region", "values": ["east", "zürich ☃"], "floor": 300},
        },
        {"unscored": 150, "alpha": 0.1, "delta": 0.05},
        {"cannot_tell_above": 0.5},
    ],
    ids=["ltt", "crc", "time-split", "segments", "unscored", "cannot-tell"],
)
def test_rust_crate_accepts_every_issued_certificate(tmp_path: Path, kw: dict[str, Any]) -> None:
    entry, diag = issue(tmp_path, **kw)
    cert = entry["certificate"]
    assert dc.verify(cert, trusted()).id == diag["certificate_id"]
    if shutil.which("cargo") is None:
        pytest.skip("cargo not on PATH")
    [v] = rust_verdicts(tmp_path, [cert])
    assert v["valid"], v
    assert v["id"] == diag["certificate_id"]


def test_crc_is_a_joint_error_certificate_with_no_ucb(tmp_path: Path) -> None:
    cert = issue(tmp_path, method="crc")[0]["certificate"]
    assert cert["risk"] == "joint_error" and cert["delta"] is None and cert["ucb"] is None


def test_time_split_records_the_window_and_dates_expiry_from_its_end(tmp_path: Path) -> None:
    cert = issue(tmp_path, timed=True)[0]["certificate"]
    assert cert["split"] == {"method": "time", "seed": None}
    assert cert["window"] == {"start": "2026-01-01T00:00:00Z", "end": "2026-01-02T09:19:00Z"}
    assert cert["expires_at"] == "2026-02-01T09:19:00Z"


def test_segments_above_the_floor_are_certified_and_the_rest_inherit(tmp_path: Path) -> None:
    segs = {"field": "region", "values": ["east", "zürich ☃"], "floor": 300}
    entry, diag = issue(tmp_path, regions=["east", "west", "zürich ☃", "zürich ☃"], segments=segs)
    cert = entry["certificate"]
    by_value = {s["value"]: s for s in cert["segments"]}
    assert set(by_value) == {"east", "zürich ☃"}, "undeclared values are never segments"
    assert by_value["zürich ☃"]["inherited"] is False and by_value["east"]["inherited"] is True
    assert by_value["east"]["ucb"] is None and by_value["east"]["abstain_below"] == cert["abstain_below"]
    assert diag["test_level"] == pytest.approx(cert["delta"] / 2), "Bonferroni over 1 + 1 certified segment"
    v = dc.verify(cert, trusted())
    assert v.threshold_for("zürich ☃") == by_value["zürich ☃"]["abstain_below"] == ct.threshold_for(cert, "zürich ☃")
    assert v.threshold_for("east") == cert["abstain_below"]


def test_unscored_cases_count_as_abstentions(tmp_path: Path) -> None:
    entry, diag = issue(tmp_path, unscored=150)
    assert diag["n_unscored"] == 150
    assert diag["answered"] <= entry["certificate"]["n"] - sum(1 for c in diag["_cases"] if c["confidence"] < 0)


def test_too_few_cases_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ct.TooFewCases, match="n_cal 9 < 1/alpha - 1 = 19"):
        issue(tmp_path, n=18)


@pytest.mark.parametrize(
    ("kw", "error"),
    [
        ({"alpha": 0.0}, "alpha and delta must be in"),
        ({"audit": "sample"}, "logs a propensity > 0"),
    ],
)
def test_refusals(tmp_path: Path, kw: dict[str, Any], error: str) -> None:
    with pytest.raises(ct.CertError, match=error):
        issue(tmp_path, **kw)


def test_predictions_served_with_calibration_are_refused(tmp_path: Path) -> None:
    preds, rows = cases(100)
    preds[0]["calibrated"] = True
    with pytest.raises(ct.CertError, match="calibration applied"):
        ct.issue(preds, rows, domain(tmp_path), "toy-backend", KEY, now=NOW, audit="full-label")


def test_a_uniform_audit_sample_is_certified_with_its_rate(tmp_path: Path) -> None:
    preds, rows = cases(2000)
    for r in rows:
        r["propensity"] = 0.05
    cal, _ = ct.issue(preds, rows, domain(tmp_path), "toy-backend", KEY, now=NOW)
    assert cal["approved"]["certificate"]["audit"] == {
        "mode": "sample",
        "rate": 0.05,
        "n": 2000,
        "propensity_logged": True,
    }
    rows[0]["propensity"] = 0.06
    with pytest.raises(ct.CertError, match="uniform audit samples only"):
        ct.issue(preds, rows, domain(tmp_path), "toy-backend", KEY, now=NOW)


def test_segment_values_must_be_quoted_strings(tmp_path: Path) -> None:
    d = domain(tmp_path)
    (d / "domain.yaml").write_text(
        (d / "domain.yaml").read_text() + "  segments:\n    field: tier\n    values: [1.50]\n"
    )
    with pytest.raises(ct.CertError, match="must be non-empty strings"):
        ct.load_config(d)


def test_keygen_writes_a_private_key_only_its_owner_can_read(tmp_path: Path) -> None:
    out = tmp_path / "operator.pem"
    ct.keygen(out)
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    assert isinstance(ct.load_private_key(out), Ed25519PrivateKey)
    with pytest.raises(SystemExit, match="refusing to overwrite"):
        ct.keygen(out)


def test_command_line_certify_then_verify(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    preds, rows = cases(2000)
    (tmp_path / "preds.jsonl").write_text("".join(json.dumps(p) + "\n" for p in preds))
    (tmp_path / "rows.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
    ct.keygen(tmp_path / "op.pem")
    d = domain(tmp_path)
    ct.main(["certify", "--predictions", str(tmp_path / "preds.jsonl"), "--data", str(tmp_path / "rows.jsonl"),
             "--domain-dir", str(d), "--backend", "toy", "--key", str(tmp_path / "op.pem"), "--audit", "full-label",
             "--in-environment"])  # fmt: skip
    out = d / "calibration" / "toy.json"
    assert out.exists() and not out.with_suffix(".certify-cases.jsonl").exists(), (
        "--in-environment keeps case ids local"
    )
    report = json.loads(out.with_suffix(".certify.json").read_text())
    assert "_cases" not in report["decisions"]["approved"]
    key = ct.load_private_key(tmp_path / "op.pem")
    keys = {ct.key_id(key.public_key()): ct.b64url(ct.raw_public(key.public_key()))}
    (tmp_path / "keys.json").write_text(json.dumps(keys))
    with pytest.raises(SystemExit) as e:
        ct.main(["verify", "--calibration", str(out), "--keys", str(tmp_path / "keys.json")])
    assert e.value.code == 0
    assert "approved: OK sha256:" in capsys.readouterr().out
    with pytest.raises(SystemExit) as e:
        ct.main(["verify", "--calibration", str(out), "--keys", str(tmp_path / "keys.json").replace("keys", "nokeys")])
    assert e.value.code == 1


def test_command_line_exit_code_for_too_few_cases(tmp_path: Path) -> None:
    preds, rows = cases(10)
    (tmp_path / "p.jsonl").write_text("".join(json.dumps(p) + "\n" for p in preds))
    (tmp_path / "r.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
    ct.keygen(tmp_path / "op.pem")
    with pytest.raises(SystemExit) as e:
        ct.main(["certify", "--predictions", str(tmp_path / "p.jsonl"), "--data", str(tmp_path / "r.jsonl"),
                 "--domain-dir", str(domain(tmp_path)), "--backend", "toy", "--key", str(tmp_path / "op.pem"),
                 "--audit", "full-label"])  # fmt: skip
    assert e.value.code == ct.EXIT_TOO_FEW


# ---------- the statistics ----------


def test_ltt_stops_at_the_first_cut_that_is_not_rejected() -> None:
    conf = np.array([0.99, 0.98, 0.97, 0.6, 0.55, 0.52])
    err = np.array([False, False, False, True, True, False])
    # 0.9: 3 answered, 0 errors, p = 0.5^3 = 0.125 <= 0.2, rejected; 0.58: 4 answered, 1 error,
    # p = 5/16 > 0.2, so the sequence stops and 0.9 is the threshold.
    pt = cs.ltt(conf, err, np.array([0.9, 0.58, 0.0]), alpha=0.5, delta=0.2)
    assert pt.abstain_below == 0.9 and (pt.n, pt.e) == (3, 0)
    # A first cut answering one case has p = 0.5 > 0.2: nothing is rejected, so abstain on everything.
    assert cs.ltt(conf, err, np.array([0.985, 0.9, 0.0]), alpha=0.5, delta=0.2).abstain_below == cs.ABSTAIN_ALL


def test_clopper_pearson_edges() -> None:
    assert cs.ucb(0, 0, 0.1) == 1.0 and cs.ucb(5, 5, 0.1) == 1.0
    assert cs.band(0, 0, 0.95) == (0.0, 1.0)
    low, high = cs.band(100, 0, 0.95)
    assert low == 0.0 and 0 < high < 0.04
    assert cs.n_min(0.05, 0.1) == 45


# ---------- the dr map ----------


def test_dr_fit_recovers_a_known_temperature_and_shift() -> None:
    rng = np.random.default_rng(1)
    logits = rng.normal(0, 2, size=(20000, 3))
    logp = logits - np.log(np.exp(logits).sum(axis=1, keepdims=True))
    q = recal.apply(logp, 0.5, np.array([0.4, 0.0, -0.4]))
    y = np.array([rng.choice(3, p=row) for row in q])
    a, b = recal.fit(logp, y, recal.FLAT)
    assert a == pytest.approx(0.5, abs=0.05)
    assert (b - b.mean()) == pytest.approx(np.array([0.4, 0.0, -0.4]), abs=0.08)


def test_isotonic_fit_is_monotone() -> None:
    rng = np.random.default_rng(2)
    x = rng.random(500)
    y = (rng.random(500) < x).astype(float)
    model = recal.isotonic_fit(x, y)
    out = recal.isotonic_apply(model, np.linspace(0, 1, 50))
    assert np.all(np.diff(out) >= 0)
