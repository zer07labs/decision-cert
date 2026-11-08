"""The reference issuer (`decision_cert.issue`): end to end on synthetic cases, its refusals, and
agreement with both verifiers. Every issued certificate is checked by the Python verifier and by the
Rust crate (the oracle; skipped when cargo is not on PATH, CI always has it)."""

from __future__ import annotations

import datetime as dt
import itertools
import json
import shutil
import stat
import subprocess
from pathlib import Path
from typing import Any

import numpy as np
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from scipy.stats import binom

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
    assert cert["spec"] == "decision-certificate.v1.2" == ct.SPEC
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
        {"spec": "decision-certificate.v1.1"},
        {
            "regions": ["east", "west", "zürich ☃"],
            "segments": {"field": "region", "values": ["east", "zürich ☃"], "floor": 300},
            "spec": "decision-certificate.v1.1",
        },
    ],
    ids=["ltt", "crc", "time-split", "segments", "unscored", "cannot-tell", "v1.1", "v1.1-segments"],
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


# ---------- v1 behaviour pinned for the v1.1 study (spec/drafts/decision-certificate.v1.1.md, O1) ----------


def _hindsight_passes(conf: np.ndarray, err: np.ndarray, cuts: np.ndarray, alpha: float, d: float) -> int:
    """How many cuts would pass if one were picked after seeing the threshold split (for scale only;
    picking that way is not a valid test)."""
    n, e = cs.counts(conf, err, cuts)
    return int(np.sum((n > 0) & (binom.cdf(e, np.maximum(n, 1), alpha) <= d)))


def test_a_set_with_no_passing_cut_abstains_on_everything() -> None:
    """Errors at about 6% at every confidence: no cut passes at alpha 0.05, even with hindsight, so
    abstaining on everything is the correct result, not a defect."""
    rng = np.random.default_rng(11)
    conf_t, conf_a = rng.uniform(0.5, 1.0, 4000), rng.uniform(0.5, 1.0, 4000)
    err_t, err_a = rng.random(4000) < 0.06, rng.random(4000) < 0.06
    cuts = cs.grid(conf_t, err_t, 0.05)
    assert _hindsight_passes(conf_a, err_a, cuts, 0.05, 0.1) == 0
    assert cs.ltt(conf_a, err_a, cuts, 0.05, 0.1).abstain_below == cs.ABSTAIN_ALL


def test_v1_stops_at_a_failing_start_cut_even_when_a_looser_cut_would_pass() -> None:
    """A small set: the start cut is learned on the temperature split (200 correct cases above it),
    but on the threshold split 3 of the 20 cases above it are wrong, so the fixed sequence stops at
    once although the next cut (220 cases, 3 errors) would pass. v1 keeps this behaviour; any v1.1
    grid rule is measured against it."""
    conf_t = np.array([0.95] * 200 + [0.85] * 50)
    err_t = np.array([False] * 200 + [True] * 10 + [False] * 40)
    cuts = cs.grid(conf_t, err_t, 0.05)
    assert len(cuts) == 2 and 0.85 < cuts[0] < 0.95 and cuts[1] == 0.0
    conf_a = np.array([0.95] * 20 + [0.85] * 200)
    err_a = np.array([True] * 3 + [False] * 17 + [False] * 200)
    assert _hindsight_passes(conf_a, err_a, cuts, 0.05, 0.1) == 1
    assert cs.ltt(conf_a, err_a, cuts, 0.05, 0.1).abstain_below == cs.ABSTAIN_ALL


# ---------- v1.1: the per-test grid start (spec/decision-certificate.v1.1.md §1.1 step 3) ----------

# Two populations at three margins (high, mid, low). `west` is undeclared, so it is the remainder;
# `east` is a certified segment. Per split: (segment, margin, cases, errors).
_HIGH, _MID, _LOW = 4.0, 2.0, 0.5
_TEMPERATURE = [("west", _HIGH, 400, 0), ("west", _MID, 400, 40),
                ("east", _HIGH, 10, 2), ("east", _MID, 300, 0), ("east", _LOW, 50, 25)]  # fmt: skip
_THRESHOLD = [("west", _HIGH, 400, 0), ("west", _MID, 400, 40),
              ("east", _HIGH, 20, 3), ("east", _MID, 300, 0), ("east", _LOW, 40, 20)]  # fmt: skip


def _start_cases() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Timed cases: the temperature split is the older half. On the whole temperature split the
    best cut is the high one (west's 400 correct cases dominate), but east's own best cut is the mid
    one. On east's threshold split 3 of the 20 cases above the high cut are wrong, so a sequence
    starting there stops at once; starting at the mid cut, 3 errors in 320 cases pass."""
    preds: list[dict[str, Any]] = []
    rows: list[dict[str, Any]] = []
    t0 = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)
    for block in (_TEMPERATURE, _THRESHOLD):
        for region, z, n, errors in block:
            for j in range(n):
                i = len(rows)
                cid = f"c{i:05d}"
                truth = 1 if j < errors else 0  # the model always picks option 0, so truth 1 is an error
                at = (t0 + dt.timedelta(minutes=i)).isoformat()
                rows.append({"case_id": cid, "case": {"region": region}, "labels": {"approved": OPTIONS[truth]},
                             "decided_at": at})  # fmt: skip
                preds.append({"case_id": cid, "decision": "approved", "model": "toy", "version": "1",
                              "raw_scores": [z / 2, -z / 2]})  # fmt: skip
    return preds, rows


def _issue_start(tmp: Path, spec: str) -> dict[str, Any]:
    preds, rows = _start_cases()
    segs = {"field": "region", "values": ["east"], "floor": 100}
    cal, _ = ct.issue(preds, rows, domain(tmp, segments=segs), "toy-backend", KEY, now=NOW, audit="full-label",
                      spec=spec)  # fmt: skip
    cert: dict[str, Any] = cal["approved"]["certificate"]
    return cert


def test_v1_1_starts_each_test_on_its_own_cases_and_v1_does_not(tmp_path: Path) -> None:
    v1, v11 = _issue_start(tmp_path, ct.SPEC_V1), _issue_start(tmp_path, ct.SPEC_V1_1)
    assert v1["spec"] == "decision-certificate.v1" and v11["spec"] == "decision-certificate.v1.1"
    east1, east11 = v1["segments"][0], v11["segments"][0]
    assert east1["value"] == east11["value"] == "east" and not east1["inherited"] and not east11["inherited"]
    assert east1["abstain_below"] == cs.ABSTAIN_ALL, "v1: east's sequence starts at the pooled cut and stops"
    assert east11["abstain_below"] < 1.0 and east11["coverage"] == pytest.approx(320 / 360)
    # The remainder's own best cut is the pooled one, so its test is the same under both.
    for k in ("abstain_below", "coverage", "ucb", "n"):
        assert v1[k] == v11[k], k
    assert v11["coverage"] == pytest.approx(400 / 800)
    for c in (v1, v11):
        assert dc.verify(c, trusted()).id == ct.certificate_id(c)


@pytest.mark.skipif(shutil.which("cargo") is None, reason="needs cargo for the Rust oracle")
def test_every_spec_verifies_in_the_rust_oracle(tmp_path: Path) -> None:
    certs = [_issue_start(tmp_path, spec) for spec in ct.SPECS]
    for c, v in zip(certs, rust_verdicts(tmp_path, certs), strict=True):
        assert v["valid"] and v["id"] == ct.certificate_id(c), v


def test_an_unknown_spec_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ct.CertError, match="unknown spec"):
        _issue_start(tmp_path, "decision-certificate.v2")


def test_without_segments_v1_and_v1_1_issue_the_same_test(tmp_path: Path) -> None:
    a, _ = issue(tmp_path, spec=ct.SPEC_V1)
    b, _ = issue(tmp_path, spec=ct.SPEC_V1_1)
    ca, cb = a["certificate"], b["certificate"]
    assert {k: v for k, v in ca.items() if k not in ("spec", "signature")} == {
        k: v for k, v in cb.items() if k not in ("spec", "signature")
    }


# ---------- v1.2: the stored confidence histogram (spec/decision-certificate.v1.2.md §1.5) ----------


def _threshold_split(diag: dict[str, Any]) -> list[float | None]:
    return [None if c["confidence"] < 0 else c["confidence"] for c in diag["_cases"] if c["split"] == "threshold"]


def test_v1_2_stores_the_threshold_splits_histogram_on_bins_from_the_temperature_split(tmp_path: Path) -> None:
    entry, diag = issue(tmp_path, unscored=150)
    cert = entry["certificate"]
    bins = cert["confidence_bins"]
    assert bins[0] == 0.0 and bins[-1] == 1.0 and all(a < b for a, b in itertools.pairwise(bins))
    assert 2 < len(bins) <= ct.HISTOGRAM_BINS + 1
    temperature = [c["confidence"] for c in diag["_cases"] if c["split"] == "temperature"]
    assert bins == cs.bins_of(np.array(temperature), ct.HISTOGRAM_BINS), "bins come from the temperature split only"
    want = dc.Histogram.of(bins, _threshold_split(diag))
    assert cert["confidence_histogram"] == {"counts": list(want.counts), "unscored": want.unscored}
    assert want.unscored == sum(1 for c in _threshold_split(diag) if c is None) > 0
    assert want.total == cert["n"]
    v = dc.verify(cert, trusted())
    assert v.confidence_bins() == tuple(bins) and v.histogram_for(None) == want


def test_v1_2_issues_the_same_test_as_v1_1_and_only_adds_the_histogram(tmp_path: Path) -> None:
    segs = {"field": "region", "values": ["east", "zürich ☃"], "floor": 300}
    regions = ["east", "west", "zürich ☃", "zürich ☃"]
    a, _ = issue(tmp_path, spec=ct.SPEC_V1_1, regions=regions, segments=segs)
    b, _ = issue(tmp_path, spec=ct.SPEC_V1_2, regions=regions, segments=segs)
    ca, cb = a["certificate"], b["certificate"]
    assert "confidence_bins" not in ca and all("confidence_histogram" not in s for s in ca["segments"])
    strip = ("spec", "signature", "confidence_bins", "confidence_histogram")
    assert {k: v for k, v in ca.items() if k not in strip and k != "segments"} == {
        k: v for k, v in cb.items() if k not in strip and k != "segments"
    }
    assert [{k: v for k, v in s.items() if k not in strip} for s in cb["segments"]] == ca["segments"]
    for s in cb["segments"]:
        assert sum(s["confidence_histogram"]["counts"]) + s["confidence_histogram"]["unscored"] == s["n"]
    v = dc.verify(cb, trusted())
    zurich = next(s for s in cb["segments"] if s["value"] == "zürich ☃")
    assert v.histogram_for("zürich ☃") == dc.Histogram(tuple(zurich["confidence_histogram"]["counts"]), 0)
    assert v.histogram_for("east") == v.histogram_for(None), "an inherited segment is monitored with the remainder"


def test_small_tests_have_their_histogram_withheld(tmp_path: Path) -> None:
    segs = {"field": "region", "values": ["east", "tiny"], "floor": 300}
    regions = ["east"] * 49 + ["west"] * 50 + ["tiny"]
    cert = issue(tmp_path, regions=regions, segments=segs)[0]["certificate"]
    tiny = next(s for s in cert["segments"] if s["value"] == "tiny")
    assert tiny["n"] < 30 and tiny["confidence_histogram"] is None
    assert cert["confidence_histogram"] is not None
    assert dc.verify(cert, trusted()).histogram_for("tiny") == dc.verify(cert, trusted()).histogram_for(None)


def test_a_withheld_histogram_cannot_be_recovered_by_subtraction(tmp_path: Path) -> None:
    # Every remainder case is east or tiny: the remainder's histogram minus east's would be tiny's.
    segs = {"field": "region", "values": ["east", "tiny"], "floor": 10**6}
    cert = issue(tmp_path, regions=["east"] * 99 + ["tiny"], segments=segs)[0]["certificate"]
    by = {s["value"]: s for s in cert["segments"]}
    assert by["east"]["confidence_histogram"] is not None
    assert by["tiny"]["n"] < 30 and by["tiny"]["confidence_histogram"] is None
    assert cert["confidence_histogram"] is None


def test_histogram_min_n_is_configurable(tmp_path: Path) -> None:
    d = domain(tmp_path)
    (d / "domain.yaml").write_text((d / "domain.yaml").read_text() + "  histogram_min_n: 5000\n")
    preds, rows = cases(2000)
    cal, _ = ct.issue(preds, rows, d, "toy-backend", KEY, now=NOW, audit="full-label")
    assert cal["approved"]["certificate"]["confidence_histogram"] is None
    (d / "domain.yaml").write_text((d / "domain.yaml").read_text().replace("5000", "-1"))
    with pytest.raises(ct.CertError, match="histogram_min_n"):
        ct.issue(preds, rows, d, "toy-backend", KEY, now=NOW, audit="full-label")


def test_the_shift_score_flags_a_window_whose_confidences_moved(tmp_path: Path) -> None:
    entry, diag = issue(tmp_path)
    v = dc.verify(entry["certificate"], trusted())
    bins, base = v.confidence_bins(), v.histogram_for(None)
    assert bins is not None and base is not None
    same = [c for c in _threshold_split(diag) if c is not None]
    assert dc.shift_score(base, dc.Histogram.of(bins, same)).p_value == pytest.approx(1.0)
    rng = np.random.default_rng(3)
    fresh = rng.choice(np.array(same), 1500)
    assert dc.shift_score(base, dc.Histogram.of(bins, fresh.tolist())).p_value > 0.001
    lower = np.clip(fresh - 0.1, 0.5, 1.0)
    assert dc.shift_score(base, dc.Histogram.of(bins, lower.tolist())).p_value < 1e-6
