"""Re-run the reference issuer's procedure on a certificate's measured cases and compare the result
with the certificate (docs/evidence-pack.md, "The recompute").

The certificate fixes everything the procedure reads except four issuer inputs it does not record:
the domain's `ttl_days`, `histogram_min_n` and segment `floor`, and a `dr` map's prior. An evidence
pack's manifest gives those as `procedure`. The cases come in the order the issuer passed them, since
a `seeded` split permutes that order. Signatures and the issuer's name and version are not compared.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from typing import Any

from .._verify import SPEC_V1_3, SPEC_V1_4, SPEC_V1_5, timestamp
from . import recal as rc
from .certify import Case, CertConfig, Segments, certify_decision

#: Fields that are not measured figures: the signature, and the issuer's tool and version.
NOT_COMPARED = frozenset({"signature", "signer_key_id", "issuer"})
#: Numbers agree up to this relative (or absolute, near 0) difference, as the reference
#: implementations agree on the shift score (spec v1.2 §4).
TOLERANCE = 1e-9


def _case(r: Mapping[str, Any]) -> Case:
    raw = r["raw_scores"]
    return Case(
        r["case_id"],
        int(r["label_index"]),
        None if raw is None else [float(x) for x in raw],
        r["cannot_tell"],
        r["decided_at"],
        r["segment"],
        r["propensity"],
    )


def recompute(cert: Mapping[str, Any], cases: Sequence[Mapping[str, Any]], procedure: Mapping[str, Any]) -> list[str]:
    """The paths at which the procedure, re-run on `cases` with `procedure`, gives other values than
    `cert` (empty: every measured figure is reproduced). Raises the issuer's `CertError` when the
    procedure refuses the cases."""
    spec = cert["spec"]
    seg_field = cert["segments"][0]["field"] if cert["segments"] else ""
    floor = procedure["segment_floor"]
    cfg = CertConfig(
        ttl_days=int(procedure["ttl_days"]),
        segments=None if floor is None else Segments(seg_field, (), int(floor)),
        histogram_min_n=int(procedure["histogram_min_n"]),
    )
    prior = procedure["dr_prior"]
    cost = cert.get("cost") if spec in (SPEC_V1_4, SPEC_V1_5) else None
    calibration = [_case(r) for r in cases if r["set"] == "calibration"]
    recal = [_case(r) for r in cases if r["set"] == "recalibration"]
    got, _ = certify_decision(
        cert["domain"],
        cert["decision"],
        list(cert["options"]),
        cert["model_id"],
        calibration,
        alpha=float(cert["alpha"]),
        delta=0.1 if cert["delta"] is None else float(cert["delta"]),  # crc reads no delta
        method=cert["method"],
        audit=cert["audit"]["mode"],
        seed=0 if cert["split"]["seed"] is None else int(cert["split"]["seed"]),
        cfg=cfg,
        cannot_tell_above=cert["rule"]["cannot_tell_above"],
        manifest_hash=cert["manifest_hash"],
        now=timestamp(cert["fitted_at"]),
        spec=spec,
        recal=recal if cert["calibration_map"]["kind"] == "dr" else None,
        prior=None
        if prior is None
        else rc.Prior(float(prior["mu_a"]), float(prior["sigma_a"]), float(prior["sigma_b"])),
        automate_options=list(cert["automate_options"]) if spec in (SPEC_V1_3, SPEC_V1_4, SPEC_V1_5) else None,
        cost=None if cost is None else {"matrix": cost["matrix"], "unit": cost["unit"]},
        tenant=cert["tenant"] if spec == SPEC_V1_5 else None,
        signer=dict(cert["signer"]) if spec == SPEC_V1_5 else None,
    )
    want = {k: v for k, v in cert.items() if k not in NOT_COMPARED}
    have = {k: v for k, v in got.items() if k not in NOT_COMPARED}
    return differences(want, have)


def _same_number(a: float, b: float) -> bool:
    return a == b or math.isclose(a, b, rel_tol=TOLERANCE, abs_tol=TOLERANCE)


def differences(want: Any, have: Any, path: str = "") -> list[str]:
    """The paths (`segments.0.ucb`) where `have` differs from `want`: numbers up to `TOLERANCE`, booleans
    and everything else exactly."""
    num = (int, float)
    if isinstance(want, bool) or isinstance(have, bool):
        return [] if want is have else [path or "."]
    if isinstance(want, num) and isinstance(have, num):
        return [] if _same_number(float(want), float(have)) else [path or "."]
    if isinstance(want, dict) and isinstance(have, dict):
        out: list[str] = []
        for k in sorted(set(want) | set(have)):
            sub = f"{path}.{k}" if path else str(k)
            out += [sub] if k not in want or k not in have else differences(want[k], have[k], sub)
        return out
    if isinstance(want, list) and isinstance(have, list):
        if len(want) != len(have):
            return [path or "."]
        out = []
        for i, (a, b) in enumerate(zip(want, have, strict=True)):
            out += differences(a, b, f"{path}.{i}" if path else str(i))
        return out
    return [] if want == have else [path or "."]
