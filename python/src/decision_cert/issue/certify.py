"""Calibrate one model on labelled cases and issue a signed decision certificate per decision
(spec/decision-certificate.v1.md).

    python -m decision_cert.issue keygen --out operator.pem
    python -m decision_cert.issue certify --predictions calib.jsonl --data calib_split.jsonl \\
        --domain-dir <domain> --backend <name> --key operator.pem [--audit sample|full-label] [--in-environment]
    python -m decision_cert.issue verify --calibration <domain>/calibration/<backend>.json --keys keys.json

Input: the model's predictions on a calibration split, plus that split's labelled rows (labels,
`decided_at`, `propensity`). Output: <domain>/calibration/<backend>.json with the temperature, the
certified thresholds and a `certificate` per decision.

`--in-environment` is for running inside the environment that holds the cases: it reads local files
only, and writes only the calibration file and aggregate metrics (no case ids). The certificate is
always signed with the operator's own key (`--key`).

Exit codes: 3 when there are too few cases to certify (n_cal < 1/alpha - 1); 1 for other refusals.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import sys
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any, cast

import jsonschema
import numpy as np
import rfc8785
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .. import CertError as VerifyError
from .. import __version__
from .. import verify as verify_strict
from . import _support as sp
from . import stats as cs

SPEC = "decision-certificate.v1"
ISSUER = {"tool": "decision-cert", "version": __version__}
BAND_LEVEL = 0.95
UNSCORED = -1.0  # below every cut, so an unscored or cannot-tell case never counts as answered
EXIT_TOO_FEW = 3


class CertError(ValueError):
    """A refusal to certify, or a certificate that does not verify."""


class TooFewCases(CertError):
    pass


def schema() -> dict[str, Any]:
    text = resources.files("decision_cert.issue").joinpath(f"{SPEC}.schema.json").read_text(encoding="utf-8")
    return cast(dict[str, Any], json.loads(text))


# ---------- keys, canonical bytes, signatures ----------


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def raw_public(pub: Ed25519PublicKey) -> bytes:
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def key_id(pub: Ed25519PublicKey) -> str:
    return "ed25519:" + hashlib.sha256(raw_public(pub)).hexdigest()[:16]


def load_private_key(path: Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise CertError(f"{path}: not an Ed25519 private key")
    return key


def canonical(obj: Any) -> bytes:
    """RFC 8785 bytes. It refuses integers beyond ±(2^53 - 1), so the issuer never signs a number
    that canonicalises lossily."""
    return rfc8785.dumps(obj)


def sign(cert: dict[str, Any], key: Ed25519PrivateKey) -> dict[str, Any]:
    body = {k: v for k, v in cert.items() if k != "signature"}
    body["signer_key_id"] = key_id(key.public_key())
    return {**body, "signature": b64url(key.sign(canonical(body)))}


def certificate_id(cert: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonical(cert)).hexdigest()


def verify(cert: dict[str, Any], keys: dict[str, str]) -> str:
    """Verify with the package's strict verifier (the same rules as the Rust crate). Returns the id."""
    try:
        return verify_strict(cert, keys).id
    except VerifyError as e:
        raise CertError(str(e)) from None


# ---------- domain config ----------


@dataclass(frozen=True)
class Segments:
    field: str
    values: tuple[str, ...]
    floor: int


@dataclass(frozen=True)
class CertConfig:
    ttl_days: int = 90
    on_expired: str = "refer"
    segments: Segments | None = None
    keys: dict[str, str] | None = None


CONFIG_KEYS = {"ttl_days", "on_expired", "segments", "keys"}


def load_config(domain_dir: Path) -> tuple[dict[str, Any], CertConfig]:
    """The domain's raw YAML and its `certificate:` block (docs/certificates.md, "Domain config")."""
    raw = yaml.safe_load((domain_dir / "domain.yaml").read_text())
    if not isinstance(raw, dict) or not isinstance(raw.get("id"), str) or not raw["id"]:
        raise CertError(f"{domain_dir / 'domain.yaml'}: must be a mapping with a non-empty string `id`")
    block = raw.get("certificate") or {}
    where = f"{domain_dir / 'domain.yaml'}: certificate"
    if unknown := set(block) - CONFIG_KEYS:
        raise CertError(f"{where}: unknown keys {sorted(unknown)}")
    ttl = block.get("ttl_days", 90)
    if isinstance(ttl, bool) or not isinstance(ttl, int) or ttl < 1:
        raise CertError(f"{where}.ttl_days must be a positive integer")
    if (on := block.get("on_expired", "refer")) not in ("refer", "warn"):
        raise CertError(f"{where}.on_expired must be refer or warn")
    segs = None
    if (s := block.get("segments")) is not None:
        if (
            not isinstance(s, dict)
            or set(s) - {"field", "values", "floor"}
            or not isinstance(s.get("field"), str)
            or not isinstance(s.get("values"), list)  # a bare string would read as one value per character
            or not s["values"]
        ):
            raise CertError(f"{where}.segments needs `field` (a case field) and `values` (a non-empty list)")
        if not all(isinstance(v, str) and v for v in s["values"]):
            # YAML reads 1.50, 007 or yes as numbers or booleans, and a consumer reads them as text:
            # only quoted strings mean the same on both sides.
            raise CertError(f"{where}.segments.values must be non-empty strings (quote values like '1.50' or 'yes')")
        values = tuple(s["values"])
        if len(set(values)) != len(values):
            raise CertError(f"{where}.segments.values repeat")
        floor = s.get("floor", 200)
        if isinstance(floor, bool) or not isinstance(floor, int) or floor < 1:
            raise CertError(f"{where}.segments.floor must be a positive integer")
        segs = Segments(s["field"], values, floor)
    return raw, CertConfig(ttl, on, segs, block.get("keys"))


def segment_of(case: Any, segs: Segments | None) -> str | None:
    """The case field's value if it is a string and a declared value, else None (spec §1.3).
    Non-string values are never segments, so no rendering of numbers or objects has to agree
    between languages."""
    if segs is None or not isinstance(case, dict):
        return None
    v = case.get(segs.field)
    return v if isinstance(v, str) and v in segs.values else None


# ---------- certification ----------


def utc(ts: str) -> dt.datetime:
    t = dt.datetime.fromisoformat(ts)
    return (t if t.tzinfo else t.replace(tzinfo=dt.UTC)).astimezone(dt.UTC)


def stamp(t: dt.datetime) -> str:
    return t.astimezone(dt.UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Case:
    case_id: str
    label_index: int
    raw: list[float] | None  # None: unscored
    cannot_tell: float | None
    decided_at: str | None
    segment: str | None
    propensity: float | None


def score(case: Case, temperature: float, cannot_tell_above: float | None) -> tuple[float, bool]:
    """(confidence, error) of one case under the rule. A case the rule abstains on whatever the
    threshold (unscored, or cannot-tell above the domain's bound) gets UNSCORED, below every cut."""
    if case.raw is None or (
        cannot_tell_above is not None and case.cannot_tell is not None and case.cannot_tell > cannot_tell_above
    ):
        return UNSCORED, False
    p = sp.softmax(np.asarray(case.raw, float), temperature)
    return float(p.max()), bool(int(np.argmax(p)) != case.label_index)


def apply_rule(
    case: Case, temperature: float, abstain_below: float, cannot_tell_above: float | None
) -> tuple[bool, bool]:
    """(answered, error if answered) for one case: answered when confidence >= abstain_below, as a
    consumer reads it (stats.counts)."""
    conf, err = score(case, temperature, cannot_tell_above)
    answered = conf >= abstain_below
    return answered, answered and err


def threshold_for(cert: dict[str, Any], segment: str | None) -> float:
    """The threshold a certificate applies to a case in `segment`: its certified segment's own, else
    the top-level one (the same as `Verified.threshold_for`)."""
    own = [s["abstain_below"] for s in cert["segments"] if not s["inherited"] and s["value"] == segment]
    return float(own[0]) if segment is not None and own else float(cert["abstain_below"])


def _audit(cases: list[Case], mode: str, decision: str) -> dict[str, Any]:
    if mode == "full-label":
        return {"mode": mode, "rate": 1, "n": len(cases), "propensity_logged": False}
    props = [c.propensity for c in cases]
    if not cases or any(p is None or p <= 0 for p in props):
        raise CertError(
            f"decision '{decision}': --audit sample needs an audit sample whose every row logs a propensity > 0 "
            "(public sets where every row is labelled: --audit full-label)"
        )
    if len(set(props)) != 1:
        raise CertError(f"decision '{decision}': audit propensities differ; v1 certifies uniform audit samples only")
    return {"mode": mode, "rate": props[0], "n": len(cases), "propensity_logged": True}


def _test(conf: np.ndarray, err: np.ndarray, cuts: np.ndarray, alpha: float, d: float | None) -> dict[str, Any]:
    """One test (spec §1.1): ltt at level d, or crc when d is None."""
    pt = cs.ltt(conf, err, cuts, alpha, d) if d is not None else cs.crc(conf, err, cuts, alpha)
    low, high = cs.band(pt.n, pt.e, BAND_LEVEL)
    return {
        "n": len(conf),
        "abstain_below": pt.abstain_below,
        "coverage": pt.n / len(conf) if len(conf) else 0.0,
        "ucb": cs.ucb(pt.n, pt.e, d) if d is not None else None,
        "realized_band": {"level": BAND_LEVEL, "low": low, "high": high},
        "_answered": pt.n,
        "_errors": pt.e,
    }


def certify_decision(
    domain: str,
    decision: str,
    options: list[str],
    model_id: str,
    cases: list[Case],
    *,
    alpha: float,
    delta: float,
    method: str,
    audit: str,
    seed: int,
    cfg: CertConfig,
    cannot_tell_above: float | None,
    manifest_hash: str | None,
    now: dt.datetime,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """(unsigned certificate, aggregate diagnostics) for one decision. Spec §1.1."""
    audit_block = _audit(cases, audit, decision)
    timed = all(c.decided_at for c in cases)
    if timed:
        order = sorted(range(len(cases)), key=lambda i: (utc(cases[i].decided_at or ""), cases[i].case_id))
        half = len(cases) // 2
        t_idx, a_idx = np.array(order[:half], int), np.array(order[half:], int)
    else:
        t_idx, a_idx = sp.split_halves(len(cases), seed)
    n_cal = len(a_idx)
    if n_cal < 1 / alpha - 1:
        raise TooFewCases(f"decision '{decision}': n_cal {n_cal} < 1/alpha - 1 = {1 / alpha - 1:g}; add labelled cases")

    scored_t = [cases[i] for i in t_idx if cases[i].raw is not None]
    if not scored_t:
        raise CertError(f"decision '{decision}': the temperature split has no scored cases")
    temperature = float(sp.fit_temperature([c.raw or [] for c in scored_t], [c.label_index for c in scored_t]))

    def conf_err(idx: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        pairs = [score(cases[i], temperature, cannot_tell_above) for i in idx]
        return np.array([c for c, _ in pairs], float).reshape(-1), np.array([e for _, e in pairs], bool).reshape(-1)

    conf_t, err_t = conf_err(t_idx)
    cuts = cs.grid(conf_t, err_t, alpha)
    conf_a, err_a = conf_err(a_idx)
    per_case = [
        {"case_id": cases[i].case_id, "split": "temperature", "confidence": float(c), "error": bool(e)}
        for i, c, e in zip(t_idx, conf_t, err_t, strict=True)
    ]
    per_case += [
        {"case_id": cases[i].case_id, "split": "threshold", "confidence": float(c), "error": bool(e)}
        for i, c, e in zip(a_idx, conf_a, err_a, strict=True)
    ]
    seg_a = np.array([cases[i].segment or "" for i in a_idx], object)
    has_seg = np.array([cases[i].segment is not None for i in a_idx], bool)

    present = sorted({s for i in a_idx if (s := cases[i].segment) is not None}, key=lambda v: v.encode())
    floor = cfg.segments.floor if cfg.segments else 0
    certified = [v for v in present if int((has_seg & (seg_a == v)).sum()) >= floor]
    d = delta / (1 + len(certified)) if method == "ltt" else None

    rest = ~np.isin(seg_a, certified) | ~has_seg
    top = _test(conf_a[rest], err_a[rest], cuts, alpha, d)
    segments: list[dict[str, Any]] = []
    seg_diag: dict[str, dict[str, int]] = {}
    for v in present:
        m = has_seg & (seg_a == v)
        field = cfg.segments.field if cfg.segments else ""
        if v in certified:
            r = _test(conf_a[m], err_a[m], cuts, alpha, d)
        else:  # inherited: decided by the top-level threshold, no bound of its own
            hit = m & (conf_a >= top["abstain_below"])
            r = {
                "n": int(m.sum()),
                "abstain_below": top["abstain_below"],
                "coverage": int(hit.sum()) / int(m.sum()),
                "ucb": None,
                "realized_band": None,
                "_answered": int(hit.sum()),
                "_errors": int(err_a[hit].sum()),
            }
        segments.append(
            {"field": field, "value": v, "inherited": v not in certified, **{k: x for k, x in r.items() if k[0] != "_"}}
        )
        seg_diag[v] = {"answered": r["_answered"], "errors": r["_errors"]}

    hashed = [
        [c.case_id, c.label_index, c.raw, c.decided_at, c.segment, c.propensity]
        for c in sorted(cases, key=lambda c: c.case_id.encode())
    ]
    window = None
    if timed:
        ts = sorted(utc(c.decided_at or "") for c in cases)
        window = {"start": stamp(ts[0]), "end": stamp(ts[-1])}
    base = utc(window["end"]) if window else now
    cert = {
        "spec": SPEC,
        "domain": domain,
        "decision": decision,
        "options": options,
        "model_id": model_id,
        "manifest_hash": manifest_hash,
        "data_hash": "sha256:" + hashlib.sha256(canonical(hashed)).hexdigest(),
        "n_cal": n_cal,
        "n_temperature": len(t_idx),
        "split": {"method": "time" if timed else "seeded", "seed": None if timed else seed},
        "calibration_map": {"kind": "temperature", "params": {"temperature": temperature}, "label_budget": None},
        "rule": {"cannot_tell_above": cannot_tell_above, "unscored": "abstain"},
        "alpha": alpha,
        "delta": delta if method == "ltt" else None,
        "method": method,
        "risk": "selective_error" if method == "ltt" else "joint_error",
        **{k: v for k, v in top.items() if k[0] != "_"},
        "segments": segments,
        "window": window,
        "fitted_at": stamp(now),
        "expires_at": stamp(base + dt.timedelta(days=cfg.ttl_days)),
        "audit": audit_block,
        "issuer": ISSUER,
    }
    diag = {
        "n": len(cases),
        "n_unscored": sum(c.raw is None for c in cases),
        "grid_size": len(cuts),
        "test_level": d,
        "answered": top["_answered"],
        "errors": top["_errors"],
        "segments": seg_diag,
        "temperature_at_search_bound": temperature <= sp.T_MIN * 1.05 or temperature >= sp.T_MAX * 0.95,
        "_cases": per_case,
    }
    return cert, diag


def model_id_of(backend: str, preds: list[dict[str, Any]]) -> str:
    ids = {(p.get("model"), p.get("version")) for p in preds if p.get("status", "ok") == "ok"}
    if len(ids) != 1 or None in next(iter(ids)):
        raise CertError(f"predictions must name exactly one model and version; found {sorted(map(str, ids))}")
    model, version = next(iter(ids))
    return f"{backend}/{model}@{version}"


def collect(
    preds: list[dict[str, Any]],
    rows: list[dict[str, Any]],
    decision: str,
    options: list[str],
    segs: Segments | None,
    audit: str,
) -> list[Case]:
    """One Case per labelled row: its prediction joined on case_id (a no_answer is unscored)."""
    by_id = {p["case_id"]: p for p in preds if p["decision"] == decision}
    if audit == "full-label" and (missing := [r["case_id"] for r in rows if decision not in r.get("labels", {})]):
        raise CertError(
            f"decision '{decision}': --audit full-label but {len(missing)} rows lack a label (first: {missing[0]!r})"
        )
    out = []
    for r in rows:
        if decision not in r.get("labels", {}):
            continue
        label = r["labels"][decision]
        if label not in options:
            raise CertError(f"decision '{decision}': case {r['case_id']!r} has label {label!r}, not one of {options}")
        p = by_id.get(r["case_id"])
        if p is None:
            raise CertError(
                f"decision '{decision}': case {r['case_id']!r} has a label but no prediction; score it first"
            )
        scored = p.get("status", "ok") == "ok"
        if scored and p.get("options", options) != options:
            raise CertError(f"decision '{decision}': predictions list options {p['options']}, the domain {options}")
        if scored and len(p["raw_scores"]) != len(options):
            raise CertError(
                f"decision '{decision}': case {r['case_id']!r} has {len(p['raw_scores'])} scores "
                f"for {len(options)} options"
            )
        decided = r.get("decided_at")
        out.append(
            Case(
                r["case_id"],
                options.index(label),
                [float(x) for x in p["raw_scores"]] if scored else None,
                p.get("cannot_tell"),
                stamp(utc(decided)) if decided else None,
                segment_of(r["case"], segs),
                r.get("propensity"),
            )
        )
    return out


def issue(
    preds: list[dict[str, Any]],
    rows: list[dict[str, Any]],
    domain_dir: Path,
    backend: str,
    key: Ed25519PrivateKey,
    *,
    alpha: float = 0.05,
    delta: float = 0.1,
    method: str = "ltt",
    audit: str = "sample",
    seed: int = 0,
    manifest: Path | None = None,
    now: dt.datetime | None = None,
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    """(calibration file contents, aggregate diagnostics per decision)."""
    if not 0 < alpha < 1 or not 0 < delta < 1:
        raise CertError("alpha and delta must be in (0, 1)")
    if any(p.get("calibrated") for p in preds):
        raise CertError("predictions were served with calibration applied; score the cases again without it")
    raw, cfg = load_config(domain_dir)
    dom = sp.load_domain(domain_dir)
    model_id = model_id_of(backend, preds)
    manifest_hash = "sha256:" + hashlib.sha256(manifest.read_bytes()).hexdigest() if manifest else None
    now = now or dt.datetime.now(dt.UTC)
    wanted = sorted({p["decision"] for p in preds})
    if unknown := [d for d in wanted if d not in {x.id for x in dom.decisions}]:
        raise CertError(f"predictions are for decisions the domain doesn't have: {unknown}")
    cal, diags = {}, {}
    for dec_id in wanted:
        options = dom.decision(dec_id).option_ids()
        cases = collect(preds, rows, dec_id, options, cfg.segments, audit)
        cert, diag = certify_decision(
            raw["id"],
            dec_id,
            options,
            model_id,
            cases,
            alpha=alpha,
            delta=delta,
            method=method,
            audit=audit,
            seed=seed,
            cfg=cfg,
            cannot_tell_above=dom.cannot_tell_above,
            manifest_hash=manifest_hash,
            now=now,
        )
        signed = sign(cert, key)
        jsonschema.validate(signed, schema())
        cal[dec_id] = {
            "temperature": cert["calibration_map"]["params"]["temperature"],
            "abstain_below": cert["abstain_below"],
            "_fit": {
                "n": diag["n"],
                "method": method,
                "alpha": alpha,
                "delta": cert["delta"],
                "coverage": cert["coverage"],
                "ucb": cert["ucb"],
                "certified": cert["abstain_below"] <= 1.0,
            },
            "certificate": signed,
        }
        diags[dec_id] = {**diag, "certificate_id": certificate_id(signed)}
    return cal, diags


def per_case_rows(diags: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Pop the per-case diagnostics (case ids, confidences) out of `diags`, leaving only aggregates."""
    return [{"decision": dec, **c} for dec, d in diags.items() for c in d.pop("_cases")]


# ---------- CLI ----------


def ct_expired(cert: dict[str, Any], now: dt.datetime | None = None) -> bool:
    return utc(cert["expires_at"]) <= (now or dt.datetime.now(dt.UTC))


def keygen(out: Path) -> None:
    if out.exists():
        raise SystemExit(f"{out} exists; refusing to overwrite a signing key")
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
    pub = b64url(raw_public(key.public_key()))
    print(
        f"wrote {out} (keep it in your environment). Trust it in domain.yaml:\n"
        f'certificate:\n  keys:\n    "{key_id(key.public_key())}": {pub}'
    )


def load_keys(path: Path) -> dict[str, str]:
    """A trusted-keys file: `{key_id: base64url raw Ed25519 public key}` (as committed beside a certificate)."""
    try:
        keys = json.loads(path.read_text())
    except (OSError, ValueError) as e:
        raise CertError(f"{path}: {e}") from None
    if not isinstance(keys, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in keys.items()):
        raise CertError(f"{path}: expected {{key_id: public_key}} strings")
    return keys


def verify_file(calibration: Path, domain_dir: Path | None = None, keys: dict[str, str] | None = None) -> int:
    """Verify every certificate in a calibration file against the domain's `certificate.keys`, or
    against an explicit trusted-keys map."""
    if keys is None:
        if domain_dir is None:
            raise CertError("verify needs a domain dir or a trusted-keys file")
        keys = load_config(domain_dir)[1].keys or {}
    cal = json.loads(calibration.read_text())
    bad = 0
    for dec, entry in sorted(cal.items()):
        if "certificate" not in entry:
            print(f"{dec}: no certificate")
            continue
        try:
            cid = verify(entry["certificate"], keys)
            c = entry["certificate"]
            print(
                f"{dec}: OK {cid} abstain<{c['abstain_below']:.4g} coverage {c['coverage']:.1%} "
                f"expires {c['expires_at']}"
            )
        except CertError as e:
            bad += 1
            print(f"{dec}: FAILED {e}")
    return 1 if bad else 0


PROG = "python -m decision_cert.issue"


def main(argv: list[str] | None = None) -> None:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["keygen"]:
        ap = argparse.ArgumentParser(
            prog=f"{PROG} keygen", description="Write a new Ed25519 signing key (PEM, mode 0600)."
        )
        ap.add_argument("--out", required=True, type=Path)
        keygen(ap.parse_args(argv[1:]).out)
        return
    if argv[:1] == ["verify"]:
        ap = argparse.ArgumentParser(
            prog=f"{PROG} verify", description="Verify the certificates in a calibration file."
        )
        ap.add_argument("--calibration", required=True, type=Path)
        trust = ap.add_mutually_exclusive_group(required=True)
        trust.add_argument("--domain-dir", type=Path, help="a domain directory: its certificate.keys are trusted")
        trust.add_argument("--keys", type=Path, help="a trusted-keys JSON file {key_id: base64url public key}")
        v = ap.parse_args(argv[1:])
        try:
            raise SystemExit(verify_file(v.calibration, v.domain_dir, load_keys(v.keys) if v.keys else None))
        except CertError as e:
            print(f"{PROG} verify: {e}", file=sys.stderr)
            raise SystemExit(1) from None
    if argv[:1] == ["certify"]:
        argv = argv[1:]

    ap = argparse.ArgumentParser(
        prog=f"{PROG} certify", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--predictions", required=True, type=Path, help="the model's predictions on the calibration split")
    ap.add_argument("--data", required=True, type=Path, help="the calibration split's labelled rows")
    ap.add_argument("--domain-dir", required=True, type=Path)
    ap.add_argument("--backend", required=True)
    ap.add_argument("--key", required=True, type=Path, help="the operator's Ed25519 private key (keygen)")
    ap.add_argument("--alpha", type=float, default=0.05, help="target error rate")
    ap.add_argument("--delta", type=float, default=0.1, help="failure probability (ltt)")
    ap.add_argument("--method", choices=["ltt", "crc"], default="ltt")
    ap.add_argument(
        "--audit",
        choices=["sample", "full-label"],
        default="sample",
        help="sample: an audit sample with logged propensities; full-label: every row is labelled",
    )
    ap.add_argument("--seed", type=int, default=0, help="split seed when cases have no decided_at")
    ap.add_argument("--manifest", type=Path, help="the model's provenance manifest (omit when there is none)")
    ap.add_argument(
        "--in-environment", action="store_true", help="write only the calibration file and aggregate metrics"
    )
    ap.add_argument("--out", type=Path, help="calibration file (default <domain-dir>/calibration/<backend>.json)")
    a = ap.parse_args(argv)

    try:
        cal, diags = issue(
            sp.read_jsonl(a.predictions),
            sp.read_cases(a.data),
            a.domain_dir,
            a.backend,
            load_private_key(a.key),
            alpha=a.alpha,
            delta=a.delta,
            method=a.method,
            audit=a.audit,
            seed=a.seed,
            manifest=a.manifest,
        )
    except TooFewCases as e:
        print(f"{PROG} certify: {e}", file=sys.stderr)
        raise SystemExit(EXIT_TOO_FEW) from e
    except (CertError, sp.DataError) as e:
        raise SystemExit(f"{PROG} certify: {e}") from e
    out = a.out or a.domain_dir / "calibration" / f"{a.backend}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(cal, indent=2) + "\n")
    cases = per_case_rows(diags)
    if not a.in_environment:  # case ids stay inside the environment that holds the cases
        sp.write_jsonl(out.with_suffix(".certify-cases.jsonl"), cases)
    report = out.with_suffix(".certify.json")
    report.write_text(json.dumps({"backend": a.backend, "decisions": diags}, indent=2) + "\n")
    for dec, c in cal.items():
        cert = c["certificate"]
        if ct_expired(cert):
            print(
                f"warning: {dec}: certificate already expired at {cert['expires_at']} (window end + ttl_days); "
                "with on_expired: refer a consumer abstains on every case",
                file=sys.stderr,
            )
        state = "certified" if cert["abstain_below"] <= 1.0 else "NOT certified: abstains on everything"
        ucb = cert["ucb"] if cert["ucb"] is None else round(cert["ucb"], 4)
        print(
            f"{dec}: {state}; abstain<{cert['abstain_below']:.4g} coverage {cert['coverage']:.1%} "
            f"ucb {ucb} n_cal {cert['n_cal']} expires {cert['expires_at']}"
        )
    print(f"wrote {out} and {report}")
