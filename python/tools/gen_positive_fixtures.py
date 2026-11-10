"""Generate the reference issuer's conformance fixtures: the positive (and first negative) fixtures
and `mutations/schema_invalid.json`, signed with the reference issuer's `sign`, for v1 (`fixtures/`)
for v1.1 (`fixtures/v1.1/`), for v1.2 (`fixtures/v1.2/`) and for v1.3 (`fixtures/v1.3/`), each later
set with its own `FIXTURES.sha256`.

    cd python && uv run python tools/gen_positive_fixtures.py          # write
    cd python && uv run python tools/gen_positive_fixtures.py --check  # fail if any byte would change

The keys are public and deterministic (seeds 0..31 and 32..63). The v1 files predate this script and
must stay byte-identical: a change to any of them is a change to the conformance suite, and every
vendored copy must follow. After writing, run `tools/gen_negative_fixtures.py` to refresh
`fixtures/FIXTURES.sha256`. The v1.1 set is the same certificates with `spec`
`decision-certificate.v1.1`, plus a certificate naming a spec no verifier knows; its manifest is
written here. The v1.2 set is the same again with `spec` `decision-certificate.v1.2` and the v1.2
fields (the confidence histograms), plus the v1.2 cases: a withheld histogram, fields that belong to
another spec, histograms the schema accepts but a verifier must refuse, a `dr` calibration map, a
map kind v1.2 does not define, and map parameters a v1.2 verifier must refuse. The v1.3 set is the
v1.2 set with `spec` `decision-certificate.v1.3` and the v1.3 fields (every option automated, so each
`automated` block repeats its test's numbers), plus the v1.3 cases: a subset of options automated,
`automate_options` a verifier must refuse, `automated` blocks that disagree with their test, and
fields that belong to another spec.
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import jsonschema
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from decision_cert.issue import certify as ct

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "fixtures"
V11 = FIXTURES / "v1.1"
V12 = FIXTURES / "v1.2"
V13 = FIXTURES / "v1.3"
FROM_V1_2 = (ct.SPEC_V1_2, ct.SPEC_V1_3)  # the specs with the v1.2 fields
BINS = [0, 0.5, 0.6, 0.7, 0.8, 0.85, 0.9, 0.95, 0.99, 1]
HISTOGRAM = {"counts": [0, 310, 320, 330, 280, 300, 340, 420, 150], "unscored": 50}  # n 2500
KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
OTHER = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))


def keys(*ks: Ed25519PrivateKey) -> dict[str, str]:
    return {ct.key_id(k.public_key()): ct.b64url(ct.raw_public(k.public_key())) for k in ks}


def make_base(spec: str = ct.SPEC_V1) -> dict[str, Any]:
    out = _base_v1()
    if spec != ct.SPEC_V1:
        out["spec"] = spec
        out["issuer"] = {"tool": "decision-cert", "version": "0.3.0"}
    if spec in FROM_V1_2:
        out["issuer"] = {"tool": "decision-cert", "version": "0.4.0"}
        out["confidence_bins"] = list(BINS)
        out["confidence_histogram"] = copy.deepcopy(HISTOGRAM)
    if spec == ct.SPEC_V1_3:
        out["automate_options"] = list(out["options"])
        sync(out)
    return out


def _same_as(test: dict[str, Any]) -> dict[str, Any]:
    return {"coverage": test["coverage"], "ucb": test["ucb"], "realized_band": copy.deepcopy(test["realized_band"])}


def sync(cert: dict[str, Any]) -> dict[str, Any]:
    """v1.3, every option automated: each test's `automated` block is the test's own numbers."""
    if cert["spec"] == ct.SPEC_V1_3:
        cert["automated"] = _same_as(cert)
        for s in cert["segments"]:
            s["automated"] = _same_as(s)
    return cert


def _base_v1() -> dict[str, Any]:
    band = {"level": 0.95, "low": 0.0011834410146505043, "high": 0.04314473389094683}
    return {
        "spec": "decision-certificate.v1",
        "domain": "hmda-approval",
        "decision": "approved",
        "options": ["yes", "no"],
        "model_id": "b1/lightgbm@lgbm-4.7.0-seed7",
        "manifest_hash": "sha256:" + "ab" * 32,
        "data_hash": "sha256:" + "0f" * 32,
        "n_cal": 2500,
        "n_temperature": 2500,
        "split": {"method": "seeded", "seed": 7},
        "calibration_map": {"kind": "temperature", "params": {"temperature": 1.3173913043478262}, "label_budget": None},
        "rule": {"cannot_tell_above": None, "unscored": "abstain"},
        "alpha": 0.05,
        "delta": 0.1,
        "method": "ltt",
        "risk": "selective_error",
        "n": 2500,
        "abstain_below": 0.8829170572757721,
        "coverage": 0.4116,
        "ucb": 0.032977066870911,
        "realized_band": band,
        "segments": [],
        "window": None,
        "fitted_at": "2026-10-25T12:00:00Z",
        "expires_at": "2027-01-23T12:00:00Z",
        "audit": {"mode": "full-label", "rate": 1, "n": 5000, "propensity_logged": False},
        "issuer": {"tool": "decisionkit-calib", "version": "0.1.0"},  # as first issued; kept for byte identity
    }


def fixtures(spec: str = ct.SPEC_V1) -> dict[str, dict[str, Any]]:
    def base() -> dict[str, Any]:
        return make_base(spec)

    out: dict[str, tuple[dict[str, Any], dict[str, str], bool, str | None]] = {}
    out["valid_basic"] = (ct.sign(base(), KEY), keys(KEY), True, None)

    tricky = base()
    tricky["calibration_map"] = {
        "kind": "temperature",
        "params": {"temperature": 0.30000000000000004},
        "label_budget": 200,
    }
    tricky.update(abstain_below=1e-7, coverage=0.1234567890123456789, ucb=5e-324, n_cal=9007199254740991)
    tricky["split"] = {"method": "seeded", "seed": -3}
    tricky["realized_band"] = {"level": 0.95, "low": 0.0, "high": 1.0}
    if spec in FROM_V1_2:
        tricky["confidence_bins"] = [0, 1e-7, 0.30000000000000004, 0.5, 0.9999999999999999, 1.0]
        tricky["confidence_histogram"] = {"counts": [0, 0, 1250, 1249, 1], "unscored": 0}
    out["valid_tricky_numbers"] = (ct.sign(sync(tricky), KEY), keys(KEY), True, None)

    crc = base()
    crc.update(method="crc", risk="joint_error", delta=None, ucb=None, abstain_below=1.01, coverage=0.0)
    out["valid_crc_abstain_all"] = (ct.sign(sync(crc), KEY), keys(KEY), True, None)

    seg = base()
    seg["split"] = {"method": "time", "seed": None}
    seg["window"] = {"start": "2023-01-02T00:00:00Z", "end": "2023-12-29T23:59:59Z"}
    seg["rule"] = {"cannot_tell_above": 0.5, "unscored": "abstain"}
    seg["audit"] = {"mode": "sample", "rate": 0.05, "n": 5000, "propensity_logged": True}
    s = {
        "field": "region",
        "n": 600,
        "abstain_below": 0.9,
        "coverage": 0.25,
        "ucb": 0.04,
        "realized_band": seg["realized_band"],
    }
    seg["segments"] = [
        {**s, "value": "east", "inherited": False},
        {
            **s,
            "value": "zürich ☃",
            "inherited": True,
            "ucb": None,
            "realized_band": None,
            "abstain_below": 0.8829170572757721,
        },
    ]
    if spec in FROM_V1_2:
        seg["segments"][0]["confidence_histogram"] = {"counts": [0, 60, 70, 80, 70, 80, 90, 100, 40], "unscored": 10}
        seg["segments"][1]["confidence_histogram"] = None  # withheld
    out["valid_segments_unicode"] = (ct.sign(sync(seg), KEY), keys(KEY, OTHER), True, None)

    tampered = copy.deepcopy(out["valid_basic"][0])
    tampered["abstain_below"] = 0.5
    out["invalid_tampered"] = (tampered, keys(KEY), False, "signature")

    unknown = base()
    unknown["extra_claim"] = True  # signed, but v1 verifiers reject unknown fields
    out["invalid_unknown_field"] = (ct.sign(unknown, KEY), keys(KEY), False, "unknown field")
    out["invalid_untrusted_key"] = (ct.sign(base(), OTHER), keys(KEY), False, "not a trusted key")

    missing = ct.sign(base(), KEY)
    del missing["window"]
    out["invalid_missing_nullable_field"] = (missing, keys(KEY), False, "window")

    if spec != ct.SPEC_V1:
        later = base()
        # signed, but no verifier knows this spec (v1.2 was unknown when the v1.1 set was made, v1.3 when
        # the v1.2 set was; a later verifier refuses those files because their fields are not that
        # spec's, with the same message)
        later["spec"] = {
            ct.SPEC_V1_1: "decision-certificate.v1.2",
            ct.SPEC_V1_2: "decision-certificate.v1.3",
        }.get(spec, "decision-certificate.v1.4")
        out["invalid_unknown_spec"] = (ct.sign(later, KEY), keys(KEY), False, "spec is not")

    if spec in FROM_V1_2:
        withheld = base()
        withheld["confidence_histogram"] = None
        out["valid_histogram_withheld"] = (ct.sign(withheld, KEY), keys(KEY), True, None)

        no_bins = base()
        del no_bins["confidence_bins"]  # a v1.2 certificate without a v1.2 field
        out["invalid_missing_v1_2_field"] = (ct.sign(no_bins, KEY), keys(KEY), False, "spec is not consistent")

        in_v11 = make_base(ct.SPEC_V1_1)
        in_v11["confidence_bins"] = list(BINS)  # a v1.1 certificate with a v1.2 field
        in_v11["confidence_histogram"] = copy.deepcopy(HISTOGRAM)
        out["invalid_v1_2_field_in_v1_1"] = (ct.sign(in_v11, KEY), keys(KEY), False, "unknown field")

        off = base()
        off["confidence_histogram"] = {"counts": [0, 310, 320, 330, 280, 300, 340, 420, 151], "unscored": 50}
        out["invalid_histogram_sum"] = (ct.sign(off, KEY), keys(KEY), False, "confidence_histogram needs")

        short = base()
        short["confidence_histogram"] = {"counts": [310, 320, 330, 280, 300, 340, 420, 150], "unscored": 50}
        out["invalid_histogram_bins"] = (ct.sign(short, KEY), keys(KEY), False, "confidence_histogram needs")

        flat = base()
        flat["confidence_bins"] = [0, 0.5, 0.6, 0.7, 0.8, 0.85, 0.9, 0.9, 0.99, 1]
        out["invalid_bins_not_rising"] = (ct.sign(flat, KEY), keys(KEY), False, "confidence_bins must rise")

        open_end = base()
        open_end["confidence_bins"] = [0, 0.5, 0.6, 0.7, 0.8, 0.85, 0.9, 0.95, 0.99, 0.999]
        out["invalid_bins_not_ending_at_1"] = (ct.sign(open_end, KEY), keys(KEY), False, "confidence_bins must rise")

        def segmented() -> dict[str, Any]:
            cert = copy.deepcopy(out["valid_segments_unicode"][0])
            del cert["signature"]
            return cert

        seg_off = segmented()
        seg_off["segments"][0]["confidence_histogram"]["unscored"] = 9  # sums to 599, the segment's n is 600
        out["invalid_segment_histogram_sum"] = (
            ct.sign(seg_off, KEY),
            keys(KEY, OTHER),
            False,
            "confidence_histogram needs",
        )

        seg_none = segmented()
        del seg_none["segments"][1]["confidence_histogram"]  # a v1.2 segment without its v1.2 field
        out["invalid_segment_missing_histogram"] = (
            ct.sign(seg_none, KEY),
            keys(KEY, OTHER),
            False,
            "spec is not consistent",
        )

        def mapped(m: dict[str, Any]) -> dict[str, Any]:
            cert = base()
            cert["calibration_map"] = m
            return cert

        dr: dict[str, Any] = {"kind": "dr", "params": {"a": 0.8125, "b0": 0.375, "b1": -0.375}, "label_budget": 200}
        out["valid_dr_map"] = (ct.sign(mapped(dr), KEY), keys(KEY), True, None)
        bad_maps: dict[str, dict[str, Any]] = {
            "invalid_dr_missing_param": {**dr, "params": {"a": 0.8125, "b0": 0.375}},  # no b1 for option 2
            "invalid_dr_slope_not_positive": {**dr, "params": {**dr["params"], "a": 0}},
            "invalid_dr_label_budget_null": {**dr, "label_budget": None},
            "invalid_temperature_not_positive": {
                "kind": "temperature",
                "params": {"temperature": 0},
                "label_budget": None,
            },
            "invalid_temperature_extra_param": {
                "kind": "temperature",
                "params": {"temperature": 1.3173913043478262, "shift": 0.5},
                "label_budget": None,
            },
        }
        for name, m in bad_maps.items():
            out[name] = (ct.sign(mapped(m), KEY), keys(KEY), False, "calibration_map needs")
        # a kind v1.2 does not define still verifies; a consumer that does not apply it refuses it
        other = {"kind": "platt", "params": {"slope": 1.5, "intercept": -0.25}, "label_budget": None}
        out["valid_other_map_kind"] = (ct.sign(mapped(other), KEY), keys(KEY), True, None)

    if spec == ct.SPEC_V1_3:
        band = {"level": 0.95, "low": 0.0019, "high": 0.0571}
        sub = segmented()
        sub["automate_options"] = ["yes"]  # approvals automated; a "no" answer goes to a person
        sub["automated"] = {"coverage": 0.3, "ucb": 0.0447, "realized_band": band}
        sub["segments"][0]["automated"] = {"coverage": 0.2, "ucb": 0.0513, "realized_band": band}
        sub["segments"][1]["automated"] = {"coverage": 0.15, "ucb": None, "realized_band": None}  # inherited
        out["valid_automated_subset"] = (ct.sign(sub, KEY), keys(KEY, OTHER), True, None)

        for name, auto in [
            ("invalid_automate_options_unknown", ["yes", "maybe"]),
            ("invalid_automate_options_order", ["no", "yes"]),
            ("invalid_automate_options_repeated", ["yes", "yes"]),
            ("invalid_automate_options_empty", []),
        ]:
            cert = base()
            cert["automate_options"] = auto
            out[name] = (ct.sign(cert, KEY), keys(KEY), False, "automate_options must name")

        above = base()
        above["automated"]["coverage"] = 0.5  # the test answers 0.4116 of its cases
        out["invalid_automated_coverage_above_test"] = (ct.sign(above, KEY), keys(KEY), False, "automated must agree")
        no_ucb = base()
        no_ucb["automated"]["ucb"] = None  # the test has a ucb
        out["invalid_automated_ucb_null"] = (ct.sign(no_ucb, KEY), keys(KEY), False, "automated must agree")
        crc_ucb = copy.deepcopy(out["valid_crc_abstain_all"][0])
        del crc_ucb["signature"]
        crc_ucb["automated"]["ucb"] = 0.01  # crc has no ucb
        out["invalid_automated_ucb_under_crc"] = (ct.sign(crc_ucb, KEY), keys(KEY), False, "automated must agree")
        inherited = segmented()
        inherited["segments"][1]["automated"]["realized_band"] = band  # an inherited segment has no test
        out["invalid_segment_automated_band"] = (
            ct.sign(inherited, KEY),
            keys(KEY, OTHER),
            False,
            "automated must agree",
        )

        no_auto = base()
        del no_auto["automated"]  # a v1.3 certificate without a v1.3 field
        out["invalid_missing_v1_3_field"] = (ct.sign(no_auto, KEY), keys(KEY), False, "spec is not consistent")
        seg_no_auto = segmented()
        del seg_no_auto["segments"][0]["automated"]
        out["invalid_segment_missing_automated"] = (
            ct.sign(seg_no_auto, KEY),
            keys(KEY, OTHER),
            False,
            "spec is not consistent",
        )
        in_v12 = make_base(ct.SPEC_V1_2)
        in_v12["automate_options"] = ["yes", "no"]  # a v1.2 certificate with a v1.3 field
        out["invalid_v1_3_field_in_v1_2"] = (ct.sign(in_v12, KEY), keys(KEY), False, "unknown field")

    result = {}
    for name, (cert, trusted, valid, error) in out.items():
        body = {k: v for k, v in cert.items() if k != "signature"}
        result[name] = {
            "name": name,
            "certificate": cert,
            "keys": trusted,
            "body_jcs_b64": base64.b64encode(ct.canonical(body)).decode(),
            "certificate_id": ct.certificate_id(cert),
            "valid": valid,
            "error": error,
        }
    return result


def _paths(v: Any, path: tuple[str | int, ...] = ()) -> Iterator[tuple[str | int, ...]]:
    """Every object key path in a certificate body, nested into the first segment."""
    if isinstance(v, dict):
        for k, x in v.items():
            yield (*path, k)
            yield from _paths(x, (*path, k))
    elif isinstance(v, list) and v and isinstance(v[0], dict):
        yield from _paths(v[0], (*path, 0))


def mutations(spec: str = ct.SPEC_V1) -> list[dict[str, Any]]:
    """Signed certificates that the schema rejects, one per field and edit: dropped, null, wrong
    type, empty string, a string with a newline. Every verifier must reject every one."""
    cert0 = fixtures(spec)["valid_segments_unicode"]["certificate"]
    body0 = {k: v for k, v in cert0.items() if k not in ("signature", "signer_key_id")}
    schema = ct.schema(spec)
    out = []
    for path in _paths(body0):
        for edit, value in [("drop", None), ("null", None), ("type", [1]), ("empty", ""), ("newline", "a\n")]:
            body = copy.deepcopy(body0)
            parent: Any = body
            for p in path[:-1]:
                parent = parent[p]
            if edit == "drop":
                del parent[path[-1]]
            else:
                parent[path[-1]] = value
            cert = ct.sign(body, KEY)
            try:
                jsonschema.validate(cert, schema)
            except jsonschema.ValidationError:
                out.append({"path": ".".join(map(str, path)), "edit": edit, "certificate": cert})
    return out


def _set(spec: str, root: Path) -> dict[Path, str]:
    files = {root / f"{n}.json": json.dumps(f, indent=2, ensure_ascii=False) + "\n" for n, f in fixtures(spec).items()}
    m = {"keys": keys(KEY), "cases": mutations(spec)}
    assert len(m["cases"]) > 150
    files[root / "mutations" / "schema_invalid.json"] = json.dumps(m, indent=1, ensure_ascii=False) + "\n"
    return files


def _with_manifest(files: dict[Path, str], root: Path) -> dict[Path, str]:
    lines = [f"{hashlib.sha256(t.encode()).hexdigest()}  {p.relative_to(root).as_posix()}" for p, t in files.items()]
    return {**files, root / "FIXTURES.sha256": "\n".join(sorted(lines, key=lambda x: x.split("  ")[1])) + "\n"}


def rendered() -> dict[Path, str]:
    files = _set(ct.SPEC_V1, FIXTURES)
    v11 = _with_manifest(_set(ct.SPEC_V1_1, V11), V11)
    v12 = _with_manifest(_set(ct.SPEC_V1_2, V12), V12)
    v13 = _with_manifest(_set(ct.SPEC_V1_3, V13), V13)
    return {**files, **v11, **v12, **v13}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="fail if any fixture would change")
    args = ap.parse_args()
    stale = []
    for path, text in rendered().items():
        if not path.exists() or path.read_text(encoding="utf-8") != text:
            stale.append(path.relative_to(FIXTURES).as_posix())
            if not args.check:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text, encoding="utf-8")
    if stale and args.check:
        print(f"stale: {', '.join(stale)}; run tools/gen_positive_fixtures.py", file=sys.stderr)
        return 1
    print(f"{'checked' if args.check else 'wrote'} the reference issuer's fixtures ({len(stale)} changed)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
