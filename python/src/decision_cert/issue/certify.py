"""Calibrate one model on labelled cases and issue a signed decision certificate per decision
(spec/decision-certificate.v1.2.md; `spec="decision-certificate.v1.1"` writes a v1.1 certificate,
without the confidence histogram, and `spec="decision-certificate.v1"` issues by the v1 procedure).

    python -m decision_cert.issue keygen --out operator.pem
    python -m decision_cert.issue certify --predictions calib.jsonl --data calib_split.jsonl \\
        --domain-dir <domain> --backend <name> --key operator.pem [--audit sample|full-label] [--in-environment]
    python -m decision_cert.issue verify --calibration <domain>/calibration/<backend>.json --keys keys.json

`--spec decision-certificate.v1.3` adds the automated options (`--automate-options approved=yes`,
once per decision, default every option) and, per test, the share and error of the answered cases
whose answer is one of them; its `data_hash` also covers each case's `cannot_tell` value (spec v1.3).

`--spec decision-certificate.v1.4` adds a cost risk (`--cost approved=costs.json`, once per decision): the file is
`{"matrix": [[...]], "unit": "usd_cents" | null}`, whole-number costs (in `unit`; c_max at most 10^6), row = label,
column = answered option, in the options' order. The
certificate then bounds the mean normalised cost of the answered cases (`risk: selective_cost`, Hoeffding-Bentkus
p-values). With every off-diagonal cost equal it writes `selective_error` with v1's binomial test instead, the same
certificate as without `--cost` (spec v1.4 §1).

`--map dr --recal-data recal.jsonl --prior prior.json` (v1.2 or later) fits a `dr` calibration map on a
recalibration set of labelled target cases, disjoint from the calibration cases, instead of the
temperature (spec v1.2 §1.1 step 2). The predictions file covers those cases too. The prior is
`{"mu_a", "sigma_a", "sigma_b"}`, learned from earlier shifts (`decision_cert.issue.recal.meta_prior`).

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
import math
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
from .. import Histogram, __version__
from .. import probabilities as map_probabilities
from .. import verify as verify_strict
from . import _support as sp
from . import recal as rc
from . import stats as cs

SPEC_V1 = "decision-certificate.v1"
SPEC_V1_1 = "decision-certificate.v1.1"
SPEC_V1_2 = "decision-certificate.v1.2"
SPEC_V1_3 = "decision-certificate.v1.3"  # v1.2 + the automated options (P1) and cannot_tell hashed (C1)
SPEC_V1_4 = "decision-certificate.v1.4"  # v1.3 + the cost risk `selective_cost` (Hoeffding-Bentkus)
SPEC = SPEC_V1_2  # what this issuer writes by default
SPECS = (SPEC_V1, SPEC_V1_1, SPEC_V1_2, SPEC_V1_3, SPEC_V1_4)
V1_3_ON = (SPEC_V1_3, SPEC_V1_4)  # the specs with v1.3's fields
V1_2_ON = (SPEC_V1_2, *V1_3_ON)  # the specs with v1.2's fields
HISTOGRAM_BINS = 20  # v1.2: bins at the 20-quantiles of the temperature split's confidences
ISSUER = {"tool": "decision-cert", "version": __version__}
BAND_LEVEL = 0.95
UNSCORED = -1.0  # below every cut, so an unscored or cannot-tell case never counts as answered
EXIT_TOO_FEW = 3


class CertError(ValueError):
    """A refusal to certify, or a certificate that does not verify."""


class TooFewCases(CertError):
    pass


def schema(spec: str = SPEC) -> dict[str, Any]:
    if spec not in SPECS:
        raise CertError(f"unknown spec {spec!r}; this issuer writes {' or '.join(SPECS)}")
    text = resources.files("decision_cert.issue").joinpath(f"{spec}.schema.json").read_text(encoding="utf-8")
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
    histogram_min_n: int = 30


CONFIG_KEYS = {"ttl_days", "on_expired", "segments", "keys", "histogram_min_n"}


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
    hmin = block.get("histogram_min_n", 30)
    if isinstance(hmin, bool) or not isinstance(hmin, int) or hmin < 0:
        raise CertError(f"{where}.histogram_min_n must be a non-negative integer")
    return raw, CertConfig(ttl, on, segs, block.get("keys"), hmin)


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


CalMap = dict[str, Any]  # a certificate's calibration_map: {kind, params, label_budget}


def temperature_map(temperature: float) -> CalMap:
    return {"kind": "temperature", "params": {"temperature": temperature}, "label_budget": None}


def score(case: Case, cmap: CalMap | float, cannot_tell_above: float | None) -> tuple[float, bool]:
    """(confidence, error) of one case under the rule and the calibration map (a float is a
    temperature). A case the rule abstains on whatever the threshold (unscored, or cannot-tell above
    the domain's bound) gets UNSCORED, below every cut."""
    conf, err, _ = scored(case, cmap, cannot_tell_above)
    return conf, err


def scored(case: Case, cmap: CalMap | float, cannot_tell_above: float | None) -> tuple[float, bool, int]:
    """`score`, and the index of the case's top option (-1 when the rule abstains on it whatever the
    threshold)."""
    if case.raw is None or (
        cannot_tell_above is not None and case.cannot_tell is not None and case.cannot_tell > cannot_tell_above
    ):
        return UNSCORED, False, -1
    m = temperature_map(cmap) if isinstance(cmap, (int, float)) else cmap
    if m["kind"] == "temperature":
        p = sp.softmax(np.asarray(case.raw, float), m["params"]["temperature"])
    else:  # as a consumer applies it (decision_cert.probabilities)
        q = map_probabilities(m, case.raw)
        if q is None:
            raise CertError(f"case {case.case_id!r}: the {m['kind']} map gives no probabilities for its scores")
        p = np.asarray(q, float)
    top = int(np.argmax(p))
    return float(p.max()), bool(top != case.label_index), top


def apply_rule(
    case: Case, cmap: CalMap | float, abstain_below: float, cannot_tell_above: float | None
) -> tuple[bool, bool]:
    """(answered, error if answered) for one case: answered when confidence >= abstain_below, as a
    consumer reads it (stats.counts)."""
    conf, err = score(case, cmap, cannot_tell_above)
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
        raise CertError(f"decision '{decision}': audit propensities differ; only uniform audit samples are certified")
    return {"mode": mode, "rate": props[0], "n": len(cases), "propensity_logged": True}


def _histogram(bins: list[float], conf: np.ndarray, min_n: int) -> dict[str, Any] | None:
    """v1.2: one test's threshold-split cases per bin, and those the rule abstains on whatever the
    threshold (UNSCORED); None (withheld) when the test has fewer than `min_n` cases, so that a few
    cases' confidences are not published one by one."""
    if len(conf) < min_n:
        return None
    h = Histogram.of(bins, [None if c < 0 else float(c) for c in conf])
    return {"counts": list(h.counts), "unscored": h.unscored}


def _automated(
    conf: np.ndarray,
    err: np.ndarray,
    auto: np.ndarray,
    abstain_below: float,
    d: float | None,
    bounded: bool,
    loss: np.ndarray | None = None,
    c_max: int = 1,
) -> dict[str, Any]:
    """v1.3 (P1): one test's answered cases whose answer is an automated option. Their share of the
    test's cases, and `ucb` (ltt only) and `realized_band` of their error, computed as the test's own
    are (descriptive, spec v1.2 §1.2); both null for an inherited segment, which has no test. With
    `loss` (v1.4 `selective_cost`, whole costs), `loss_sum` is their exact cost sum, `ucb` the
    Hoeffding-Bentkus bound on their mean normalised loss and `realized_cost` that mean, loss_sum /
    (c_max · answered); all null when none is answered, and descriptive."""
    hit = (conf >= abstain_below) & auto
    k, e = int(hit.sum()), int(err[hit].sum())
    out: dict[str, Any] = {"coverage": k / len(conf) if len(conf) else 0.0, "ucb": None, "realized_band": None}
    if loss is not None:
        out.update(NO_COST)
    if bounded:
        low, high = cs.band(k, e, BAND_LEVEL)
        if loss is not None:
            # whole costs: the sum is exact in any order, so with every option automated it is the test's
            # (spec v1.4 §2), and so are ucb and realized_cost, computed from it as the test's are
            raw = int(cs.loss_sums(conf, np.where(auto, loss, 0.0), np.array([abstain_below]))[1][0]) if k else 0
            out["ucb"] = cs.hb_ucb(k, raw / c_max, d) if d is not None else None
            if k:
                out.update(loss_sum=raw, realized_cost=raw / (c_max * k))
        else:
            out["ucb"] = cs.ucb(k, e, d) if d is not None else None
        out["realized_band"] = {"level": BAND_LEVEL, "low": low, "high": high}
    return {**out, "_answered": k, "_errors": e}


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


def _cost_test(
    conf: np.ndarray, err: np.ndarray, loss: np.ndarray, cuts: np.ndarray, alpha: float, d: float, c_max: int
) -> dict[str, Any]:
    """One `selective_cost` test (spec v1.4 §1): ltt at level d on the mean normalised loss, with
    Hoeffding-Bentkus p-values. `ucb` is that bound at the chosen threshold, `realized_band` stays the
    Clopper-Pearson band on the answered cases' error count, `loss_sum` their exact sum of whole costs, and
    `realized_cost` their mean normalised loss, loss_sum / (c_max · answered), one exact division."""
    pt = cs.cost_ltt(conf, loss, cuts, alpha, d, c_max)
    raw = int(pt.raw_sum)
    e = int(err[conf >= pt.abstain_below].sum()) if pt.n else 0
    low, high = cs.band(pt.n, e, BAND_LEVEL)
    return {
        "n": len(conf),
        "abstain_below": pt.abstain_below,
        "coverage": pt.n / len(conf) if len(conf) else 0.0,
        "ucb": cs.hb_ucb(pt.n, pt.loss_sum, d),
        "realized_band": {"level": BAND_LEVEL, "low": low, "high": high},
        "loss_sum": raw if pt.n else None,
        "realized_cost": raw / (c_max * pt.n) if pt.n else None,
        "_answered": pt.n,
        "_errors": e,
        "_loss": pt.loss_sum,
    }


NO_COST = {"loss_sum": None, "realized_cost": None}  # v1.4's cost fields where there is no cost
MAX_C = 10**6  # the largest c_max (spec v1.4 §1.7): whole costs up to a million, in the consumer's `unit`


def check_cost(cost: dict[str, Any], options: list[str], decision: str) -> tuple[np.ndarray, int, bool]:
    """(matrix, c_max, equal) for a v1.4 cost input: options x options, diagonal 0, whole-number entries
    >= 0 (spec v1.4 §1.7: integer costs, so every loss sum is exact), largest > 0 and at most MAX_C.
    `equal` is True when every off-diagonal entry is the same, the case v1.4 writes as `selective_error`."""
    unknown = sorted(set(cost) - {"matrix", "unit"})
    if unknown or "matrix" not in cost:
        raise CertError(f"decision '{decision}': a cost is {{matrix, unit}}; got {sorted(cost)}")
    unit = cost.get("unit")
    if unit is not None and (not isinstance(unit, str) or not unit):
        raise CertError(f"decision '{decision}': cost.unit is a non-empty string or null")
    k = len(options)
    m = cost["matrix"]
    ok = isinstance(m, list) and len(m) == k and all(isinstance(r, list) and len(r) == k for r in m)
    ok = ok and all(isinstance(x, int) and not isinstance(x, bool) and 0 <= x <= MAX_C for r in m for x in r)
    a = np.array(m, float) if ok else np.zeros((0, 0))
    if not ok or any(a[i, i] != 0 for i in range(k)) or a.max() <= 0:
        raise CertError(
            f"decision '{decision}': cost.matrix must be {k} x {k} (row = label, column = answered option), "
            f"with a zero diagonal and whole-number entries from 0 to {MAX_C}, the largest above 0"
        )
    off = [float(a[i, j]) for i in range(k) for j in range(k) if i != j]
    return a, int(a.max()), len(set(off)) == 1


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
    spec: str = SPEC,
    recal: list[Case] | None = None,
    prior: rc.Prior | None = None,
    automate_options: list[str] | None = None,
    cost: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """(unsigned certificate, aggregate diagnostics) for one decision. Spec §1.1. Under v1.1 and
    v1.2 each test starts at the best cut on its own temperature-split cases; under v1, every test
    starts at the best cut on the whole temperature split. v1.2 adds each test's confidence
    histogram, on bins learned from the temperature split.

    With `recal` (v1.2 only), the map is `dr`, fitted by MAP under `prior` on those labelled target
    cases, which must be disjoint from `cases`; the temperature split then only builds the grid and
    the bins."""
    if spec not in SPECS:
        raise CertError(f"unknown spec {spec!r}; this issuer writes {' or '.join(SPECS)}")
    if recal is not None and spec not in V1_2_ON:
        raise CertError(f"decision '{decision}': the dr calibration map needs {SPEC_V1_2} or later")
    v13 = spec in V1_3_ON
    v14 = spec == SPEC_V1_4
    if automate_options is not None and not v13:
        raise CertError(f"decision '{decision}': automate_options needs {SPEC_V1_3} or later")
    matrix: np.ndarray | None = None  # set only for a selective_cost certificate
    c_max = 0
    if cost is not None:
        if not v14:
            raise CertError(f"decision '{decision}': a cost needs {SPEC_V1_4}")
        if method != "ltt":
            raise CertError(f"decision '{decision}': a cost risk is certified with ltt, not {method}")
        m, c_max, equal = check_cost(cost, options, decision)
        if not equal:  # equal costs: v1's exact binomial test, the same certificate as without a cost
            matrix = m
    auto = list(options) if automate_options is None else [o for o in options if o in automate_options]
    if automate_options is not None and (not automate_options or len(automate_options) != len(auto)):
        raise CertError(
            f"decision '{decision}': automate_options {automate_options} must name one or more of {options}, once each"
        )
    auto_idx = [options.index(o) for o in auto]
    audit_block = _audit(cases, audit, decision)
    timed = all(c.decided_at for c in cases)
    if timed:
        order = sorted(range(len(cases)), key=lambda i: (utc(cases[i].decided_at or ""), cases[i].case_id))
        half = len(cases) // 2
        t_idx, a_idx = np.array(order[:half], int), np.array(order[half:], int)
    else:
        t_idx, a_idx = sp.split_halves(len(cases), seed)
    n_cal = len(a_idx)
    if c_max * len(cases) > 2**53:  # every loss sum and c_max · answered stay exact integers (spec v1.4 §1.7)
        raise CertError(f"decision '{decision}': c_max {c_max} x {len(cases)} cases is above 2^53; use a coarser unit")
    if n_cal < 1 / alpha - 1:
        raise TooFewCases(f"decision '{decision}': n_cal {n_cal} < 1/alpha - 1 = {1 / alpha - 1:g}; add labelled cases")

    scored_t = [cases[i] for i in t_idx if cases[i].raw is not None]
    if not scored_t:
        raise CertError(f"decision '{decision}': the temperature split has no scored cases")
    temperature: float | None = None
    if recal is None:
        t = float(sp.fit_temperature([c.raw or [] for c in scored_t], [c.label_index for c in scored_t]))
        temperature, cmap = t, temperature_map(t)
    else:
        cmap = fit_dr(decision, recal, cases, prior)

    def conf_err(idx: np.ndarray) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
        s3 = [scored(cases[i], cmap, cannot_tell_above) for i in idx]
        return (
            np.array([c for c, _, _ in s3], float).reshape(-1),
            np.array([e for _, e, _ in s3], bool).reshape(-1),
            np.array([t for _, _, t in s3], int).reshape(-1),
        )

    def losses(idx: np.ndarray, conf: np.ndarray, top: np.ndarray) -> np.ndarray:
        """Each case's cost C[label][answer], a whole number (normalised by c_max only after summing, so that
        every sum is exact in any order, spec v1.4 §1.7); 0 where the rule abstains whatever the cut."""
        assert matrix is not None
        lab = np.array([cases[i].label_index for i in idx], int).reshape(-1)
        return np.where(conf >= 0, matrix[lab, np.maximum(top, 0)], 0.0) if len(idx) else np.zeros(0)

    conf_t, err_t, top_t = conf_err(t_idx)
    loss_t = losses(t_idx, conf_t, top_t) if matrix is not None else None
    all_cuts = cs.cuts_of(conf_t)
    pooled_start = cs.start(all_cuts, conf_t, err_t, alpha)
    conf_a, err_a, top_a = conf_err(a_idx)
    loss_a = losses(a_idx, conf_a, top_a) if matrix is not None else None
    automated_a = np.isin(top_a, auto_idx)  # threshold-split cases whose answer would be automated
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
    seg_t = np.array([cases[i].segment or "" for i in t_idx], object)
    has_seg_t = np.array([cases[i].segment is not None for i in t_idx], bool)

    present = sorted({s for i in a_idx if (s := cases[i].segment) is not None}, key=lambda v: v.encode())
    floor = cfg.segments.floor if cfg.segments else 0
    certified = [v for v in present if int((has_seg & (seg_a == v)).sum()) >= floor]
    d = delta / (1 + len(certified)) if method == "ltt" else None

    def cuts_for(mask_t: np.ndarray) -> np.ndarray:
        """The grid for one test: v1 starts every test at the pooled start; v1.1 starts each on its
        own temperature-split cases, falling back to the pooled start when it has none."""
        if spec == SPEC_V1 or not mask_t.any():
            return all_cuts[pooled_start:]
        if loss_t is not None:  # v1.4 selective_cost: the start by the Hoeffding-Bentkus p-value on the losses
            return all_cuts[cs.cost_start(all_cuts, conf_t[mask_t], loss_t[mask_t], alpha, c_max) :]
        return all_cuts[cs.start(all_cuts, conf_t[mask_t], err_t[mask_t], alpha) :]

    def run(m: np.ndarray, mask_t: np.ndarray) -> dict[str, Any]:
        """The test of the threshold-split cases `m` on their grid: v1's, or v1.4's cost test."""
        if loss_a is not None and d is not None:
            return _cost_test(conf_a[m], err_a[m], loss_a[m], cuts_for(mask_t), alpha, d, c_max)
        r = _test(conf_a[m], err_a[m], cuts_for(mask_t), alpha, d)
        return {**r, **NO_COST} if v14 else r

    def auto_of(m: np.ndarray, abstain_below: float, bounded: bool) -> dict[str, Any]:
        lo = None if loss_a is None else loss_a[m]
        a = _automated(conf_a[m], err_a[m], automated_a[m], abstain_below, d, bounded, lo, c_max)
        return {**a, **NO_COST} if v14 and lo is None else a

    v12 = spec in V1_2_ON
    bins = cs.bins_of(conf_t, HISTOGRAM_BINS) if v12 else []
    rest = ~np.isin(seg_a, certified) | ~has_seg
    rest_t = ~np.isin(seg_t, certified) | ~has_seg_t
    cuts = cuts_for(rest_t)
    top = run(rest, rest_t)
    top_auto = auto_of(rest, top["abstain_below"], True)
    segments: list[dict[str, Any]] = []
    seg_diag: dict[str, dict[str, Any]] = {}
    hidden = rest.copy()  # remainder cases no published inherited histogram counts (spec §6)
    for v in present:
        m = has_seg & (seg_a == v)
        field = cfg.segments.field if cfg.segments else ""
        if v in certified:
            r = run(m, has_seg_t & (seg_t == v))
        else:  # inherited: decided by the top-level threshold, no bound of its own
            hit = m & (conf_a >= top["abstain_below"])
            r = {
                "n": int(m.sum()),
                "abstain_below": top["abstain_below"],
                "coverage": int(hit.sum()) / int(m.sum()),
                "ucb": None,
                "realized_band": None,
                **(NO_COST if v14 else {}),
                "_answered": int(hit.sum()),
                "_errors": int(err_a[hit].sum()),
            }
        public = {k: x for k, x in r.items() if k[0] != "_"}
        entry = {"field": field, "value": v, "inherited": v not in certified, **public}
        if v12:
            entry["confidence_histogram"] = _histogram(bins, conf_a[m], cfg.histogram_min_n)
            if v not in certified and entry["confidence_histogram"] is not None:
                hidden &= ~m
        seg_diag[v] = {"answered": r["_answered"], "errors": r["_errors"]}
        if v13:
            a = auto_of(m, r["abstain_below"], v in certified)
            entry["automated"] = {k: x for k, x in a.items() if k[0] != "_"}
            seg_diag[v]["automated"] = {"answered": a["_answered"], "errors": a["_errors"]}
        segments.append(entry)

    hashed = [  # every labelled case used: both splits, and a dr map's recalibration cases
        [c.case_id, c.label_index, c.raw, c.decided_at, c.segment, c.propensity]
        + ([c.cannot_tell] if v13 else [])  # v1.3 (C1): the value that decides a cannot-tell abstention
        for c in sorted([*cases, *(recal or [])], key=lambda c: c.case_id.encode())
    ]
    window = None
    if timed:
        ts = sorted(utc(c.decided_at or "") for c in cases)
        window = {"start": stamp(ts[0]), "end": stamp(ts[-1])}
    base = utc(window["end"]) if window else now
    cert = {
        "spec": spec,
        "domain": domain,
        "decision": decision,
        "options": options,
        "model_id": model_id,
        "manifest_hash": manifest_hash,
        "data_hash": "sha256:" + hashlib.sha256(canonical(hashed)).hexdigest(),
        "n_cal": n_cal,
        "n_temperature": len(t_idx),
        "split": {"method": "time" if timed else "seeded", "seed": None if timed else seed},
        "calibration_map": cmap,
        "rule": {"cannot_tell_above": cannot_tell_above, "unscored": "abstain"},
        "alpha": alpha,
        "delta": delta if method == "ltt" else None,
        "method": method,
        "risk": ("selective_cost" if matrix is not None else "selective_error") if method == "ltt" else "joint_error",
        **{k: v for k, v in top.items() if k[0] != "_"},
        "segments": segments,
        "window": window,
        "fitted_at": stamp(now),
        "expires_at": stamp(base + dt.timedelta(days=cfg.ttl_days)),
        "audit": audit_block,
        "issuer": ISSUER,
    }
    if v12:
        cert["confidence_bins"] = bins
        # The remainder's histogram minus the published inherited ones is the histogram of the other
        # remainder cases (withheld segments, cases without a segment): withhold it when they are few.
        few = 0 < int(hidden.sum()) < cfg.histogram_min_n
        cert["confidence_histogram"] = None if few else _histogram(bins, conf_a[rest], cfg.histogram_min_n)
    if v13:
        cert["automate_options"] = auto
        cert["automated"] = {k: x for k, x in top_auto.items() if k[0] != "_"}
    if v14:
        cert["cost"] = (
            None
            if matrix is None or cost is None
            else {"matrix": [[int(x) for x in row] for row in matrix], "c_max": c_max, "unit": cost.get("unit")}
        )
        cert["pvalue"] = ("hoeffding_bentkus" if matrix is not None else "binomial") if method == "ltt" else None
    diag = {
        "n": len(cases),
        "n_unscored": sum(c.raw is None for c in cases),
        "grid_size": len(cuts),
        "test_level": d,
        "answered": top["_answered"],
        "errors": top["_errors"],
        "segments": seg_diag,
        **({"automated": {"answered": top_auto["_answered"], "errors": top_auto["_errors"]}} if v13 else {}),
        **({"loss_sum": top["_loss"]} if "_loss" in top else {}),
        "temperature_at_search_bound": temperature is not None
        and (temperature <= sp.T_MIN * 1.05 or temperature >= sp.T_MAX * 0.95),
        "_cases": per_case,
    }
    return cert, diag


def fit_dr(decision: str, recal: list[Case], cases: list[Case], prior: rc.Prior | None) -> CalMap:
    """A `dr` map (spec v1.2 §1.1 step 2), softmax(a · scores + b), fitted by MAP under `prior` on the
    scored recalibration cases. Refuses a recalibration set that shares a case with the calibration
    cases, has no scored case, or gives a slope `a` that is not above 0."""
    if prior is None:
        raise CertError(f"decision '{decision}': the dr calibration map needs a prior")
    if shared := sorted({c.case_id for c in recal} & {c.case_id for c in cases}):
        raise CertError(
            f"decision '{decision}': {len(shared)} recalibration cases are also calibration cases "
            f"(first: {shared[0]!r}); the sets must be disjoint"
        )
    scored = [c for c in recal if c.raw is not None]
    if not scored:
        raise CertError(f"decision '{decision}': the recalibration set has no scored labelled cases")
    raw = np.array([c.raw for c in scored], float)
    logp = raw - raw.max(axis=1, keepdims=True)
    logp = logp - np.log(np.exp(logp).sum(axis=1, keepdims=True))
    a, b = rc.fit(logp, np.array([c.label_index for c in scored], int), prior)
    if not (np.isfinite(a) and a > 0 and np.isfinite(b).all()):
        raise CertError(f"decision '{decision}': the dr fit gave a = {a:g}; the map needs a > 0")
    # softmax(a · log softmax(s) + b) = softmax(a · s + b): the log-normaliser is the same for every option
    params = {"a": float(a), **{f"b{i}": float(x) for i, x in enumerate(b)}}
    return {"kind": "dr", "params": params, "label_budget": len(scored)}  # the cases it was fitted on


def load_prior(path: Path) -> rc.Prior:
    """A prior file: `{"mu_a": number, "sigma_a": number > 0, "sigma_b": number > 0}`."""
    try:
        raw = json.loads(path.read_text())
    except (OSError, ValueError) as e:
        raise CertError(f"{path}: {e}") from None
    keys = ("mu_a", "sigma_a", "sigma_b")
    if (
        not isinstance(raw, dict)
        or set(raw) != set(keys)
        or not all(isinstance(raw[k], (int, float)) and not isinstance(raw[k], bool) for k in keys)
        or not all(abs(raw[k]) < 1e300 for k in keys)
        or not (raw["sigma_a"] > 0 and raw["sigma_b"] > 0)
    ):
        raise CertError(f"{path}: expected {{mu_a, sigma_a > 0, sigma_b > 0}} as finite numbers")
    return rc.Prior(float(raw["mu_a"]), float(raw["sigma_a"]), float(raw["sigma_b"]))


def model_id_of(backend: str, preds: list[dict[str, Any]]) -> str:
    ids = {(p.get("model"), p.get("version")) for p in preds if p.get("status", "ok") == "ok"}
    if len(ids) != 1 or None in next(iter(ids)):
        raise CertError(f"predictions must name exactly one model and version; found {sorted(map(str, ids))}")
    model, version = next(iter(ids))
    return f"{backend}/{model}@{version}"


def _selected(r: dict[str, Any]) -> bool:
    """A row the audit selected: it logs a propensity above 0 (spec §1.4)."""
    p = r.get("propensity")
    return isinstance(p, (int, float)) and not isinstance(p, bool) and p > 0


def unlabelled_rows(preds: list[dict[str, Any]], rows: list[dict[str, Any]], decision: str, audit: str) -> int:
    """How many rows of `--data` scored for `decision` have no label for it, which `collect` skips
    under `--audit sample`. Refuses when one of them was selected by the audit (it logs a propensity
    above 0): a selected case left unlabelled makes the sample other than the uniform one the
    certificate states (spec §1.4). Rows with no prediction for `decision` are not its cases."""
    scored = {p["case_id"] for p in preds if p["decision"] == decision}
    missing = [r for r in rows if r["case_id"] in scored and decision not in r.get("labels", {})]
    if audit == "sample" and (selected := [r["case_id"] for r in missing if _selected(r)]):
        raise CertError(
            f"decision '{decision}': {len(selected)} row(s) the audit selected (propensity above 0) have no "
            f"label (first: {selected[0]!r}). Every case the audit selected needs its label, or the sample "
            "is not the uniform sample the certificate would state; log a propensity only on rows the "
            "audit selected"
        )
    return len(missing)


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
        ct_value = p.get("cannot_tell")
        if ct_value is not None and (
            isinstance(ct_value, bool) or not isinstance(ct_value, (int, float)) or not math.isfinite(ct_value)
        ):
            raise CertError(
                f"decision '{decision}': case {r['case_id']!r} has cannot_tell {ct_value!r}; "
                "it must be a number or null"
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
    spec: str = SPEC,
    recal_rows: list[dict[str, Any]] | None = None,
    prior: rc.Prior | None = None,
    automate_options: dict[str, list[str]] | None = None,
    costs: dict[str, dict[str, Any]] | None = None,
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    """(calibration file contents, aggregate diagnostics per decision). `spec` picks what is written:
    v1.2 by default, v1.3 (v1.2 plus the automated options in `automate_options`, keyed by decision
    id, default every option, and `cannot_tell` in `data_hash`), v1.1 (the same procedure, no
    confidence histogram), or v1
    (`decision-certificate.v1`) to reproduce a v1 certificate. With `recal_rows` and `prior` (v1.2),
    each decision's map is `dr`, fitted on those rows' labelled cases (`certify_decision`); `preds`
    covers them too."""
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
    if automate_options and (stray := sorted(set(automate_options) - set(wanted))):
        raise CertError(f"automate_options names decisions with no predictions: {stray}")
    if costs and (stray := sorted(set(costs) - set(wanted))):
        raise CertError(f"costs names decisions with no predictions: {stray}")
    cal, diags = {}, {}
    for dec_id in wanted:
        options = dom.decision(dec_id).option_ids()
        skipped = unlabelled_rows(preds, rows, dec_id, audit)  # under full-label, collect refuses them
        cases = collect(preds, rows, dec_id, options, cfg.segments, audit)
        recal = None if recal_rows is None else collect(preds, recal_rows, dec_id, options, cfg.segments, "sample")
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
            spec=spec,
            recal=recal,
            prior=prior,
            automate_options=None if automate_options is None else automate_options.get(dec_id),
            cost=None if costs is None else costs.get(dec_id),
        )
        signed = sign(cert, key)
        jsonschema.validate(signed, schema(spec))
        cal[dec_id] = {
            "temperature": cert["calibration_map"]["params"].get("temperature"),  # None for a dr map
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
        diags[dec_id] = {**diag, "n_skipped_unlabelled": skipped, "certificate_id": certificate_id(signed)}
    return cal, diags


def budget_notes(cert: dict[str, Any]) -> list[str]:
    """The label-budget check: for an `ltt` certificate, one note per test (the top level, each
    certified segment) whose threshold-split cases are fewer than the fewest answered cases that can
    pass at its level with no errors (`stats.n_min`). Such a test abstains on everything whatever the
    model. A note never changes the method: `crc` makes a weaker claim and is the issuer's choice."""
    if cert["method"] != "ltt":
        return []
    certified = [s for s in cert["segments"] if not s["inherited"]]
    alpha, d = cert["alpha"], cert["delta"] / (1 + len(certified))
    need = cs.n_min(alpha, d)
    tests = [("top-level test", cert["n"])] + [(f"segment {s['value']!r}", s["n"]) for s in certified]
    return [
        f"{cert['decision']}: the {where} has {n} threshold-split cases, and ltt at alpha {alpha:g} "
        f"(test level {d:.3g}) needs at least {need} answered cases with no errors, so it abstains on "
        f"everything. The threshold split is half the labelled cases: give the test about {2 * need} "
        "labelled cases at least (more when it answers fewer than all of them or makes errors), "
        "or choose a larger alpha; --method crc makes a weaker claim (an average), and is not chosen for you"
        for where, n in tests
        if 0 < n < need  # a remainder with no cases decides none
    ]


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
    ap.add_argument(
        "--spec", choices=SPECS, default=SPEC, help="the procedure and spec id to issue under (default %(default)s)"
    )
    ap.add_argument(
        "--map",
        choices=["temperature", "dr"],
        default="temperature",
        help="the calibration map: a temperature fitted on the temperature split, or dr (v1.2) fitted on --recal-data",
    )
    ap.add_argument("--recal-data", type=Path, help="--map dr: labelled target cases, disjoint from --data")
    ap.add_argument("--prior", type=Path, help="--map dr: the prior {mu_a, sigma_a, sigma_b}")
    ap.add_argument(
        "--automate-options",
        action="append",
        metavar="DECISION=OPTION[,OPTION]",
        help=f"the options the consumer decides automatically for one decision ({SPEC_V1_3} or later; repeat "
        "per decision; default every option)",
    )
    ap.add_argument(
        "--cost",
        action="append",
        metavar="DECISION=COSTS.json",
        help=f"a cost matrix for one decision ({SPEC_V1_4}; repeat per decision): the file is "
        '{"matrix": [[...]], "unit": "USD" | null}, row = label, column = answered option',
    )
    a = ap.parse_args(argv)
    if a.map == "dr" and (a.recal_data is None or a.prior is None or a.spec not in V1_2_ON):
        ap.error(f"--map dr needs --recal-data, --prior and --spec {SPEC_V1_2} or later")
    if a.automate_options is not None and a.spec not in V1_3_ON:
        ap.error(f"--automate-options needs --spec {SPEC_V1_3} or later")
    if a.cost is not None and a.spec != SPEC_V1_4:
        ap.error(f"--cost needs --spec {SPEC_V1_4}")
    costs: dict[str, dict[str, Any]] | None = None
    if a.cost is not None:
        costs = {}
        for item in a.cost:
            dec, sep, path = item.partition("=")
            if not sep or not dec or not path or dec in costs:
                ap.error("--cost takes DECISION=COSTS.json, once per decision")
            try:
                costs[dec] = json.loads(Path(path).read_text())
            except (OSError, ValueError) as e:
                ap.error(f"--cost {dec}: {e}")
    automate: dict[str, list[str]] | None = None
    if a.automate_options is not None:
        automate = {}
        for item in a.automate_options:
            dec, sep, opts = item.partition("=")
            if not sep or not dec or dec in automate:
                ap.error("--automate-options takes DECISION=OPTION[,OPTION], once per decision")
            automate[dec] = opts.split(",") if opts else []
    if a.map != "dr" and (a.recal_data is not None or a.prior is not None):
        ap.error("--recal-data and --prior go with --map dr")

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
            spec=a.spec,
            recal_rows=sp.read_cases(a.recal_data) if a.recal_data else None,
            prior=load_prior(a.prior) if a.prior else None,
            automate_options=automate,
            costs=costs,
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
        if skipped := diags[dec]["n_skipped_unlabelled"]:
            print(
                f"warning: {dec}: skipped {skipped} row(s) in --data scored for this decision without a label "
                "for it (not selected by the audit: no propensity above 0)",
                file=sys.stderr,
            )
        for note in budget_notes(cert):
            print(f"warning: {note}", file=sys.stderr)
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
