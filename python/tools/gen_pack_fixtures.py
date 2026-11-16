"""Generate the evidence-pack fixtures in `python/tests/packs/` (docs/evidence-pack.md): synthetic
measured cases, certificates issued on them by the reference issuer, packs built from those, and
mutations a pack verifier must reject. Everything is synthetic and seeded; never hand-edit the output.

    cd python && uv run python tools/gen_pack_fixtures.py          # write
    cd python && uv run python tools/gen_pack_fixtures.py --check  # fail if any byte would change
    cd python && uv run python tools/gen_pack_fixtures.py --issue  # re-issue the certificates, then write

The certificates are issued once and kept in `issued/`, as signed demo certificates are: their last
float bits depend on the platform's maths library, so `--check` builds the packs from the committed
certificates and the regenerated cases (seeded, identical on every platform) instead of re-issuing.
It still checks that each certificate's `data_hash` is the hash of its cases, and the tests re-run the
procedure on them (to 1e-9). Re-issue with `--issue` only when the cases or the issuer change.

`expected.json` names each pack's verdict and, for a rejected pack, the first check that fails.
`PACKS.sha256` lists every file. The keys are public test keys (seeds 64..95 and 96..127).
"""

from __future__ import annotations

import argparse
import copy
import datetime as dt
import hashlib
import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import numpy as np
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from decision_cert._pack import CASE_FIELDS, MANIFEST, manifest_bytes, measured_cases_hash, tar_bytes
from decision_cert.issue import certify as ct

ROOT = Path(__file__).resolve().parents[1] / "tests" / "packs"
ISSUED = ROOT / "issued"
KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(64, 96)))
OTHER = Ed25519PrivateKey.from_private_bytes(bytes(range(96, 128)))
FITTED_AT = dt.datetime(2026, 11, 1, tzinfo=dt.UTC)
CREATED_AT = "2026-11-16T00:00:00Z"
TENANT = "tenant-synthetic"
ASSEMBLED_BY = {"tool": "decision-cert/tools/gen_pack_fixtures.py", "version": "1"}
DOMAIN = "synthetic-lending"
TTL_DAYS, HISTOGRAM_MIN_N, SEGMENT_FLOOR = 90, 30, 60
PROCEDURE = {"ttl_days": TTL_DAYS, "histogram_min_n": HISTOGRAM_MIN_N, "segment_floor": SEGMENT_FLOOR, "dr_prior": None}


def keys(*ks: Ed25519PrivateKey) -> dict[str, str]:
    return {ct.key_id(k.public_key()): ct.b64url(ct.raw_public(k.public_key())) for k in ks}


def synthetic_rows(seed: int, n: int, k: int, *, segments: bool, timed: bool) -> list[dict[str, Any]]:
    """`n` synthetic measured cases over `k` options: a label, raw scores whose signal for the label
    varies by case (so confidences spread), 2% unscored, and a region (none for a quarter of the
    cases, which fall to the remainder) or a decision time."""
    rng = np.random.default_rng(seed)
    start = dt.datetime(2026, 9, 1, tzinfo=dt.UTC)
    rows = []
    for i in range(n):
        label = int(rng.integers(k))
        raw = rng.normal(0.0, 1.0, k)
        raw[label] += rng.uniform(0.0, 5.0)
        scored = rng.uniform() >= 0.02
        region = str(rng.choice(["north", "south", ""], p=[0.4, 0.35, 0.25]))
        rows.append(
            {
                "case_id": f"syn-{seed}-{i:04d}",
                "set": "calibration",
                "label_index": label,
                "raw_scores": [round(float(x), 4) for x in raw] if scored else None,
                "decided_at": ct.stamp(start + dt.timedelta(minutes=37 * i)) if timed else None,
                "segment": region if segments and region else None,
                "propensity": None,
                "cannot_tell": None,
            }
        )
    return rows


def issue(rows: list[dict[str, Any]], decision: str, options: list[str], spec: str, **kw: Any) -> dict[str, Any]:
    cases = [
        ct.Case(r["case_id"], r["label_index"], r["raw_scores"], r["cannot_tell"], r["decided_at"], r["segment"], None)
        for r in rows
    ]
    seg = ct.Segments("region", ("north", "south"), SEGMENT_FLOOR)
    cfg = ct.CertConfig(ttl_days=TTL_DAYS, segments=seg, histogram_min_n=HISTOGRAM_MIN_N)
    cert, _ = ct.certify_decision(
        DOMAIN,
        decision,
        options,
        "synthetic/logit-sim@1",
        cases,
        alpha=kw.pop("alpha"),
        delta=0.1,
        method="ltt",
        audit="full-label",
        seed=kw.pop("seed", 0),
        cfg=cfg,
        cannot_tell_above=None,
        manifest_hash=None,
        now=FITTED_AT,
        spec=spec,
        **kw,
    )
    cert["issuer"] = {"tool": "decision-cert", "version": "0.5.0"}  # signed: fixed so a release bump changes nothing
    return ct.sign(cert, KEY)


def jsonl(rows: list[dict[str, Any]]) -> bytes:
    line = [json.dumps({k: r[k] for k in CASE_FIELDS}, ensure_ascii=False, separators=(",", ":")) for r in rows]
    return "".join(x + "\n" for x in line).encode()


def pretty(v: Any) -> bytes:
    return (json.dumps(v, indent=2, ensure_ascii=False) + "\n").encode()


class Pack:
    """A pack's files and manifest entries, rebuilt into members on demand."""

    def __init__(self) -> None:
        self.files: dict[str, bytes] = {"trusted-keys.json": pretty(keys(KEY))}
        self.entries: list[dict[str, Any]] = []
        self.format_override: str | None = None

    def add(self, name: str, cert: dict[str, Any], rows: list[dict[str, Any]] | None, location: str | None) -> None:
        path = f"certificates/{name}.json"
        self.files[path] = pretty(cert)
        cases = None
        if rows is not None:
            cases = f"cases/{name}.jsonl"
            self.files[cases] = jsonl(rows)
        self.entries.append(
            {
                "path": path,
                "certificate_id": ct.certificate_id(cert),
                "measurement": {
                    "data_hash": cert["data_hash"],
                    "location": location,
                    "cases": cases,
                    "procedure": None if rows is None else dict(PROCEDURE),
                },
            }
        )

    def members(self) -> dict[str, bytes]:
        m = manifest_bytes(
            files=self.files,
            certificates=self.entries,
            trusted_keys="trusted-keys.json",
            tenant=TENANT,
            created_at=CREATED_AT,
            assembled_by=ASSEMBLED_BY,
        )
        if self.format_override is not None:
            raw = json.loads(m)
            raw["format"] = self.format_override
            m = pretty(raw)
        return {**self.files, MANIFEST: m}

    def copy(self) -> Pack:
        return copy.deepcopy(self)


def issued(name: str, reissue: bool, make: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    """The committed certificate `issued/<name>.json`, or a fresh one from `make` with `reissue`."""
    path = ISSUED / f"{name}.json"
    if reissue or not path.exists():
        return make()
    cert: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return cert


def packs(
    reissue: bool,
) -> tuple[dict[str, dict[str, bytes]], dict[str, bytes], dict[str, Any], dict[str, dict[str, Any]]]:
    """(pack directories by name, tar files by name, expected verdicts, issued certificates by name)."""
    approved_rows = synthetic_rows(1, 600, 2, segments=True, timed=False)
    route_rows = synthetic_rows(2, 300, 3, segments=False, timed=True)
    approved = issued(
        "approved",
        reissue,
        lambda: issue(
            approved_rows, "approved", ["yes", "no"], ct.SPEC_V1_3, alpha=0.1, seed=7, automate_options=["yes"]
        ),
    )
    route = issued(
        "route", reissue, lambda: issue(route_rows, "route", ["fast", "standard", "manual"], ct.SPEC_V1_2, alpha=0.1)
    )
    if approved["data_hash"] != measured_cases_hash(approved_rows, approved["spec"]):
        raise SystemExit("issued/approved.json was not measured on these cases; re-issue with --issue")
    if route["data_hash"] != measured_cases_hash(route_rows, route["spec"]):
        raise SystemExit("issued/route.json was not measured on these cases; re-issue with --issue")
    loc = "example://tenant-synthetic/calibration/{}.jsonl"

    valid = Pack()
    valid.add("approved", approved, approved_rows, loc.format("approved"))
    valid.add("route", route, route_rows, loc.format("route"))

    location_only = Pack()
    location_only.add("approved", approved, None, loc.format("approved"))

    dirs: dict[str, dict[str, bytes]] = {"valid": valid.members(), "valid_location_only": location_only.members()}
    expected: dict[str, Any] = {
        "valid": {"verdict": "verified", "first_failure": None, "recomputed": 2},
        "valid.tar": {"verdict": "verified", "first_failure": None, "recomputed": 2},
        "valid_location_only": {"verdict": "verified", "first_failure": None, "recomputed": 0},
    }

    def rejected(name: str, members: dict[str, bytes], check: str) -> None:
        dirs[name] = members
        expected[name] = {"verdict": "rejected", "first_failure": check, "recomputed": None}

    # The mutations start from a pack of the route certificate alone, to keep the fixtures small.
    base = Pack()
    base.add("route", route, route_rows, loc.format("route"))

    # The file's bytes change but not the certificate it parses to: only the manifest's sha256 sees it.
    m = base.members()
    m["certificates/route.json"] = m["certificates/route.json"].replace(b"\n}", b"\n }")
    rejected("invalid_tampered_file", m, "files")

    m = base.members()
    m["NOTES.txt"] = b"a file the manifest does not list\n"
    rejected("invalid_unlisted_file", m, "files")

    m = base.members()
    del m["cases/route.jsonl"]
    rejected("invalid_missing_file", m, "files")

    p = base.copy()
    p.format_override = "decision-evidence-pack.v2"
    rejected("invalid_format", p.members(), "manifest")

    p = base.copy()
    p.entries[0]["certificate_id"] = "sha256:" + "0" * 64
    rejected("invalid_certificate_id", p.members(), "certificate certificates/route.json")

    p = Pack()  # signed by a key the pack does not list
    p.add("route", ct.sign({k: v for k, v in route.items() if k != "signature"}, OTHER), route_rows, None)
    rejected("invalid_untrusted_key", p.members(), "certificate certificates/route.json")

    flipped = copy.deepcopy(route_rows)  # one label changed: the cases no longer hash to data_hash
    flipped[0]["label_index"] = (flipped[0]["label_index"] + 1) % 3
    p = Pack()
    p.add("route", route, flipped, loc.format("route"))
    rejected("invalid_cases_hash", p.members(), "cases certificates/route.json")

    # Signed by the trusted key and measured on these cases, but its coverage is not what they give.
    off = {k: v for k, v in route.items() if k != "signature"}
    off["coverage"] = round(off["coverage"] / 2, 6)
    p = Pack()
    p.add("route", ct.sign(off, KEY), route_rows, loc.format("route"))
    rejected("invalid_recompute", p.members(), "recompute certificates/route.json")

    tars = {"valid.tar": tar_bytes(valid.members())}
    escaping = {**base.members(), "../outside.json": b"{}\n"}
    tars["invalid_traversal.tar"] = tar_bytes(escaping)  # tar_bytes writes any name; the verifier refuses it
    expected["invalid_traversal.tar"] = {"verdict": "rejected", "first_failure": "layout", "recomputed": None}
    return dirs, tars, expected, {"approved": approved, "route": route}


def rendered(reissue: bool = False) -> dict[Path, bytes]:
    dirs, tars, expected, certs = packs(reissue)
    out: dict[Path, bytes] = {ISSUED / f"{name}.json": pretty(c) for name, c in certs.items()}
    for name, members in dirs.items():
        for p, data in members.items():
            out[ROOT / name / p] = data
    for name, data in tars.items():
        out[ROOT / name] = data
    out[ROOT / "expected.json"] = pretty(dict(sorted(expected.items())))
    lines = sorted(f"{hashlib.sha256(d).hexdigest()}  {p.relative_to(ROOT).as_posix()}" for p, d in out.items())
    out[ROOT / "PACKS.sha256"] = ("\n".join(sorted(lines, key=lambda x: x.split("  ")[1])) + "\n").encode()
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="fail if any fixture would change")
    mode.add_argument("--issue", action="store_true", help="re-issue the certificates in issued/, then write")
    args = ap.parse_args()
    files = rendered(reissue=args.issue)
    stale = [p for p, d in files.items() if not p.exists() or p.read_bytes() != d]
    extra = sorted(p for p in ROOT.rglob("*") if p.is_file() and p not in files) if ROOT.exists() else []
    if args.check:
        for p in [*stale, *extra]:
            print(f"stale: {p.relative_to(ROOT).as_posix()}", file=sys.stderr)
        print(f"checked the pack fixtures ({len(stale)} changed, {len(extra)} not generated)")
        return 1 if stale or extra else 0
    for p in extra:
        p.unlink()
    for p in stale:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(files[p])
    print(f"wrote the pack fixtures ({len(stale)} changed, {len(extra)} removed)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
