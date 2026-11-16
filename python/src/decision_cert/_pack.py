"""Evidence packs (`decision-evidence-pack.v1`, docs/evidence-pack.md): one tenant's certificates with
what an auditor needs to check them, and the verifier that checks a pack.

A pack is a directory, or a tar of one: `pack.json` (the manifest), the trusted keys, the
certificates as issued, and optionally the measured cases each certificate was computed from. The
verifier checks, in order: the layout, the manifest, every file's sha256, the trusted keys, each
certificate (schema, signature, id, `data_hash`), each included set of measured cases against the
certificate's `data_hash`, and, when the reference issuer is installed (`decision-cert[issue]`), that
re-running the procedure on those cases gives the certificate's figures.

A verified pack shows that its files are intact, that its certificates are signed by the keys it was
checked against, and, where cases are included, that the certificate was measured on them. It
describes a measured process; it never guarantees an outcome.
"""

from __future__ import annotations

import datetime as dt
import gzip
import hashlib
import io
import json
import lzma
import os
import re
import stat
import tarfile
import zlib
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Any, Literal

from ._verify import (
    SPEC,
    SPEC_V1_1,
    SPEC_V1_2,
    CertError,
    Invalid,
    canonical,
    loads,
    timestamp,
    verify,
)

#: The `format` of a v1 pack manifest.
PACK_FORMAT = "decision-evidence-pack.v1"
#: The manifest's path in a pack. It is the only file the manifest does not list.
MANIFEST = "pack.json"

#: A member path: relative, `/`-separated, each part starting with a letter or digit.
_PATH = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*)*")
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}")
#: Before v1.3 a measured case's `data_hash` entry has six members; from v1.3 a seventh, `cannot_tell`.
_SIX_MEMBERS = (SPEC, SPEC_V1_1, SPEC_V1_2)
#: The fields of one measured case, a line of a `cases` file (docs/evidence-pack.md, "Measured cases").
CASE_FIELDS = (
    "case_id",
    "set",
    "label_index",
    "raw_scores",
    "decided_at",
    "segment",
    "propensity",
    "cannot_tell",
)
SETS = ("calibration", "recalibration")
PROCEDURE_FIELDS = ("ttl_days", "histogram_min_n", "segment_floor", "dr_prior")

Status = Literal["ok", "warn", "fail", "skipped"]

#: The verdict line's qualifier when the certificates were checked against the pack's own keys.
UNPINNED = "consistent with its own keys only; pin keys with --keys"


class PackError(Exception):
    """The pack could not be read at all: a missing path, neither a directory nor a tar, a truncated or
    corrupt archive, a read error, or a read limit reached (`Limits`)."""


@dataclass(frozen=True)
class Limits:
    """What a verifier reads before refusing a pack (`PackError`), enforced while reading: no member
    larger than `member_bytes`, no more than `total_bytes` of member content in all, and no more than
    `members` entries (files, and in a tar also directories). Sizes are uncompressed."""

    total_bytes: int = 1 << 30
    member_bytes: int = 256 << 20
    members: int = 10_000

    def __post_init__(self) -> None:
        if min(self.total_bytes, self.member_bytes, self.members) < 1:
            raise ValueError("every read limit must be at least 1")


DEFAULT_LIMITS = Limits()
#: The errors reading a pack's bytes can raise: the file system, and a truncated or corrupt archive.
_READ_ERRORS = (OSError, EOFError, zlib.error, gzip.BadGzipFile, lzma.LZMAError, tarfile.TarError)


@dataclass(frozen=True)
class Check:
    """One step of the verification: its name (e.g. `certificate certificates/approved.json`), its
    status and a one-line detail."""

    name: str
    status: Status
    detail: str


@dataclass
class PackReport:
    """Every check run on a pack, in order. `ok` is True when none failed."""

    checks: list[Check] = field(default_factory=list)
    #: The verified certificates' ids, in manifest order.
    certificate_ids: list[str] = field(default_factory=list)
    #: False when the certificates were checked against the pack's own trusted keys, not the caller's.
    keys_pinned: bool = True

    @property
    def ok(self) -> bool:
        return all(c.status != "fail" for c in self.checks)

    def skipped(self, prefix: str) -> list[Check]:
        return [c for c in self.checks if c.status == "skipped" and c.name.startswith(prefix)]

    def first_failure(self) -> Check | None:
        return next((c for c in self.checks if c.status == "fail"), None)

    def add(self, name: str, status: Status, detail: str) -> bool:
        self.checks.append(Check(name, status, detail))
        return status != "fail"


# ---------- reading a pack ----------


def _member_ok(name: str) -> bool:
    return bool(_PATH.fullmatch(name)) and all(p not in (".", "..") for p in name.split("/"))


def read_members(path: Path, limits: Limits = DEFAULT_LIMITS) -> dict[str, bytes]:
    """The pack's files by member path. A directory is walked without following links; a tar
    (optionally compressed) is read in memory, never extracted. Refuses links, special files,
    duplicate names and paths outside the pack (`Invalid`). `PackError` when `path` is neither, cannot
    be read, is truncated or corrupt, or reaches a read limit, which is checked before each member is
    read and bounds each read."""
    reader: Callable[[Path, _Budget], dict[str, bytes]]
    if path.is_dir():
        reader = _read_dir
    elif path.is_file():
        reader = _read_tar
    else:
        raise PackError(f"{path}: no such directory or file")
    try:
        return reader(path, _Budget(limits))
    except tarfile.ReadError as e:
        raise PackError(f"{path}: not a directory or a readable tar archive ({e})") from None
    except _READ_ERRORS as e:
        raise PackError(f"{path}: cannot be read ({type(e).__name__}: {e})") from None


class _Budget:
    """The read limits, counted down while a pack is read."""

    def __init__(self, limits: Limits) -> None:
        self.limits = limits
        self.members = 0
        self.total = 0

    def entry(self, name: str) -> None:
        self.members += 1
        if self.members > self.limits.members:
            raise PackError(f"more than {self.limits.members} members (at {name!r}); raise --max-members to read it")

    def file(self, name: str, size: int) -> int:
        """Admit a file of `size` bytes; returns how many bytes to read at most (one more than allowed,
        so a file that grows while read is caught)."""
        if size > self.limits.member_bytes:
            raise PackError(
                f"{name!r} is {size} bytes, over the {self.limits.member_bytes}-byte member limit;"
                " raise --max-member-bytes to read it"
            )
        if self.total + size > self.limits.total_bytes:
            raise PackError(
                f"the members reach more than {self.limits.total_bytes} bytes in all (at {name!r});"
                " raise --max-total-bytes to read it"
            )
        self.total += size
        return size + 1

    def read(self, name: str, f: IO[bytes], size: int) -> bytes:
        data = f.read(self.file(name, size))
        if len(data) != size:
            raise PackError(f"{name!r}: read {len(data)} bytes, expected {size} (changed or truncated while read)")
        return bytes(data)


def _raise(e: OSError) -> None:
    raise e


def _read_dir(root: Path, budget: _Budget) -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False, onerror=_raise):
        for name in [*dirnames, *filenames]:
            full = Path(dirpath) / name
            rel = full.relative_to(root).as_posix()
            st = full.lstat()
            if stat.S_ISLNK(st.st_mode):
                raise Invalid(f"{rel}: a link; a pack holds regular files only")
            if stat.S_ISDIR(st.st_mode):
                continue
            if not stat.S_ISREG(st.st_mode):
                raise Invalid(f"{rel}: not a regular file")
            if not _member_ok(rel):
                raise Invalid(f"{rel!r}: not a valid member path")
            budget.entry(rel)
            with full.open("rb") as f:
                out[rel] = budget.read(rel, f, st.st_size)
    return out


def _read_tar(path: Path, budget: _Budget) -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    with tarfile.open(path, "r:*") as tar:
        # Iterate, not getmembers(): each header is checked against the limits before the next is read.
        for m in tar:
            name = m.name[2:] if m.name.startswith("./") else m.name
            if m.isdir() and name.rstrip("/") in ("", "."):
                continue
            budget.entry(m.name)
            if m.issym() or m.islnk():
                raise Invalid(f"{m.name!r}: a link; a pack holds regular files only")
            if m.isdir():
                if not _member_ok(name.rstrip("/")):
                    raise Invalid(f"{m.name!r}: not a valid member path")
                continue
            if not m.isreg():
                raise Invalid(f"{m.name!r}: not a regular file")
            if not _member_ok(name):
                raise Invalid(f"{m.name!r}: not a valid member path (relative, no '..', letters, digits, . _ -)")
            if name in out:
                raise Invalid(f"{name!r}: appears twice in the archive")
            f = tar.extractfile(m)  # reads nothing yet; budget.read admits the size first
            if f is None:
                raise Invalid(f"{m.name!r}: unreadable")
            out[name] = budget.read(name, f, m.size)
    return out


def sha256_of(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


# ---------- the manifest ----------


def _refuse_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise Invalid(f"the key {k!r} appears twice in one object; a pack manifest names each key once")
        out[k] = v
    return out


def load_manifest(data: bytes) -> Any:
    """Parse `pack.json`: strictly, as `loads` parses a certificate, and refusing a key repeated in any
    object (a certificate keeps the last, as serde_json does; a manifest has no such legacy)."""
    m = loads(data)
    try:
        json.loads(data, object_pairs_hook=_refuse_duplicates)
    except ValueError as e:
        raise Invalid(str(e)) from None
    return m


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _is_num(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _check_manifest(m: Any) -> list[str]:
    """The manifest's v1 fields (docs/evidence-pack.md, "The manifest"). Returns its unknown fields,
    which a v1 verifier ignores and reports; raises `Invalid` on a known field it cannot read."""
    if not isinstance(m, dict):
        raise Invalid("pack.json is not a JSON object")
    if m.get("format") != PACK_FORMAT:
        raise Invalid(f"format {m.get('format')!r} is not {PACK_FORMAT!r}; this verifier reads {PACK_FORMAT} only")
    required = ("format", "created_at", "tenant", "assembled_by", "trusted_keys", "certificates", "files")
    if missing := [k for k in required if k not in m]:
        raise Invalid(f"pack.json lacks {', '.join(missing)}")
    if not isinstance(m["created_at"], str):
        raise Invalid("created_at is not a timestamp")
    timestamp(m["created_at"])
    if m["tenant"] is not None and (not isinstance(m["tenant"], str) or not m["tenant"]):
        raise Invalid("tenant must be a non-empty string or null")
    a = m["assembled_by"]
    if not isinstance(a, dict) or not isinstance(a.get("tool"), str) or not isinstance(a.get("version"), str):
        raise Invalid("assembled_by must be {tool, version}, both strings")
    if not isinstance(m["trusted_keys"], str) or not _member_ok(m["trusted_keys"]):
        raise Invalid("trusted_keys must be a member path")
    files = m["files"]
    if not isinstance(files, dict) or not files:
        raise Invalid("files must be a non-empty object of member path -> sha256")
    for p, h in files.items():
        if not _member_ok(p) or p == MANIFEST:
            raise Invalid(f"files: {p!r} is not a member path the manifest may list")
        if not isinstance(h, str) or not _SHA256.fullmatch(h):
            raise Invalid(f"files: {p!r} has {h!r}, not sha256:<64 lowercase hex>")
    certs = m["certificates"]
    if not isinstance(certs, list) or not certs:
        raise Invalid("certificates must be a non-empty list")
    unknown = sorted(set(m) - set(required))
    seen: set[str] = set()
    for i, e in enumerate(certs):
        where = f"certificates[{i}]"
        if not isinstance(e, dict):
            raise Invalid(f"{where} is not an object")
        for k in ("path", "certificate_id", "measurement"):
            if k not in e:
                raise Invalid(f"{where} lacks {k}")
        unknown += [f"{where}.{k}" for k in sorted(set(e) - {"path", "certificate_id", "measurement"})]
        if not isinstance(e["path"], str) or not _member_ok(e["path"]):
            raise Invalid(f"{where}.path is not a member path")
        if e["path"] in seen:
            raise Invalid(f"{where}.path {e['path']!r} is listed twice")
        seen.add(e["path"])
        if not isinstance(e["certificate_id"], str) or not _SHA256.fullmatch(e["certificate_id"]):
            raise Invalid(f"{where}.certificate_id is not sha256:<64 lowercase hex>")
        unknown += _check_measurement(e["measurement"], f"{where}.measurement")
    return unknown


def _check_measurement(ms: Any, where: str) -> list[str]:
    known = ("data_hash", "location", "cases", "procedure")
    if not isinstance(ms, dict) or any(k not in ms for k in known):
        raise Invalid(f"{where} must be {{data_hash, location, cases, procedure}}")
    if not isinstance(ms["data_hash"], str) or not _SHA256.fullmatch(ms["data_hash"]):
        raise Invalid(f"{where}.data_hash is not sha256:<64 lowercase hex>")
    if ms["location"] is not None and (not isinstance(ms["location"], str) or not ms["location"]):
        raise Invalid(f"{where}.location must be a non-empty string or null")
    if ms["cases"] is not None and (not isinstance(ms["cases"], str) or not _member_ok(ms["cases"])):
        raise Invalid(f"{where}.cases must be a member path or null")
    if ms["location"] is None and ms["cases"] is None:
        raise Invalid(f"{where}: location and cases are both null; a pack names where the measured cases are")
    p = ms["procedure"]
    if p is not None:
        if not isinstance(p, dict) or set(p) != set(PROCEDURE_FIELDS):
            raise Invalid(f"{where}.procedure must be {{{', '.join(PROCEDURE_FIELDS)}}} or null")
        if not _is_int(p["ttl_days"]) or p["ttl_days"] < 1:
            raise Invalid(f"{where}.procedure.ttl_days must be an integer >= 1")
        if not _is_int(p["histogram_min_n"]) or p["histogram_min_n"] < 0:
            raise Invalid(f"{where}.procedure.histogram_min_n must be an integer >= 0")
        if p["segment_floor"] is not None and (not _is_int(p["segment_floor"]) or p["segment_floor"] < 0):
            raise Invalid(f"{where}.procedure.segment_floor must be an integer >= 0 or null")
        prior = p["dr_prior"]
        if prior is not None and (
            not isinstance(prior, dict)
            or set(prior) != {"mu_a", "sigma_a", "sigma_b"}
            or not all(_is_num(prior[k]) for k in prior)
            or not (prior["sigma_a"] > 0 and prior["sigma_b"] > 0)
        ):
            raise Invalid(f"{where}.procedure.dr_prior must be {{mu_a, sigma_a > 0, sigma_b > 0}} or null")
    return [f"{where}.{k}" for k in sorted(set(ms) - set(known))]


# ---------- measured cases ----------


def read_cases(data: bytes, n_options: int) -> list[dict[str, Any]]:
    """A `cases` file: JSON Lines, one measured case per line, in the order the issuer passed them to
    the procedure. Raises `Invalid` on a line that is not one."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as e:
        raise Invalid(f"not UTF-8: {e}") from None
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for i, line in enumerate(lines, 1):
        r = loads(line)
        if not isinstance(r, dict) or set(r) != set(CASE_FIELDS):
            raise Invalid(f"line {i}: a measured case has exactly the fields {', '.join(CASE_FIELDS)}")
        cid = r["case_id"]
        if not isinstance(cid, str) or not cid:
            raise Invalid(f"line {i}: case_id must be a non-empty string")
        if cid in seen:
            raise Invalid(f"line {i}: case_id {cid!r} appears twice")
        seen.add(cid)
        if r["set"] not in SETS:
            raise Invalid(f"line {i}: set must be one of {', '.join(SETS)}")
        if not _is_int(r["label_index"]) or not 0 <= r["label_index"] < n_options:
            raise Invalid(f"line {i}: label_index must be an integer in [0, {n_options})")
        raw = r["raw_scores"]
        if raw is not None and (not isinstance(raw, list) or len(raw) != n_options or not all(map(_is_num, raw))):
            raise Invalid(f"line {i}: raw_scores must be null or {n_options} numbers")
        if r["decided_at"] is not None:
            if not isinstance(r["decided_at"], str):
                raise Invalid(f"line {i}: decided_at must be a timestamp or null")
            timestamp(r["decided_at"])
        if r["segment"] is not None and not isinstance(r["segment"], str):
            raise Invalid(f"line {i}: segment must be a string or null")
        for k in ("propensity", "cannot_tell"):
            if r[k] is not None and not _is_num(r[k]):
                raise Invalid(f"line {i}: {k} must be a number or null")
        out.append(r)
    if not out:
        raise Invalid("no measured cases")
    return out


def measured_cases_hash(cases: Sequence[Mapping[str, Any]], spec: str) -> str:
    """The `data_hash` of measured cases under the certificate's `spec` (spec v1.2 §2, v1.3 §2): JCS of
    one entry per case, both sets, sorted bytewise by UTF-8 `case_id`."""
    six = spec in _SIX_MEMBERS
    entries = [
        [c["case_id"], c["label_index"], c["raw_scores"], c["decided_at"], c["segment"], c["propensity"]]
        + ([] if six else [c["cannot_tell"]])
        for c in sorted(cases, key=lambda c: str(c["case_id"]).encode("utf-8"))
    ]
    return sha256_of(canonical(entries))


# ---------- the recompute ----------

#: (certificate, cases, procedure) -> the fields that differ from the certificate; raises on a refusal.
Recompute = Callable[[Mapping[str, Any], Sequence[Mapping[str, Any]], Mapping[str, Any]], list[str]]


def _load_recompute() -> Recompute | None:
    """The reference issuer's recompute, or None without the `issue` extra (numpy, scipy)."""
    try:
        from .issue.recompute import recompute
    except ImportError:
        return None
    return recompute


# ---------- verify ----------


def verify_pack(
    path: Path,
    keys: Mapping[str, str] | None = None,
    *,
    now: dt.datetime | None = None,
    recompute: bool = True,
    limits: Limits = DEFAULT_LIMITS,
    _recompute: Recompute | None = None,
) -> PackReport:
    """Verify the pack at `path` (docs/evidence-pack.md, "Verifying a pack"). With `keys`, the
    certificates are verified against those (key id -> base64url public key, obtained out of band);
    without, against the pack's own trusted keys, which shows only that the pack is consistent. `now`
    is the time expiry is reported at (default: the current time); an expired certificate is reported,
    not failed. `limits` bounds what is read. Raises `PackError` only when `path` cannot be read as a
    pack at all, or reaches a read limit."""
    report = PackReport()
    now = now or dt.datetime.now(dt.UTC)

    # 1. layout
    try:
        members = read_members(path, limits)
    except Invalid as e:
        report.add("layout", "fail", str(e))
        return report
    if MANIFEST not in members:
        report.add("layout", "fail", f"no {MANIFEST} at the top of the pack")
        return report
    report.add("layout", "ok", f"{len(members)} regular files, {MANIFEST} at the top")

    # 2. manifest
    try:
        m = load_manifest(members[MANIFEST])
        unknown = _check_manifest(m)
    except Invalid as e:
        report.add("manifest", "fail", str(e))
        return report
    tenant = "no tenant named" if m["tenant"] is None else f"tenant {m['tenant']!r}"
    extra = f"; fields this verifier does not read, not checked: {', '.join(unknown)}" if unknown else ""
    report.add("manifest", "ok", f"{PACK_FORMAT}, {tenant}, {len(m['certificates'])} certificate(s){extra}")

    # 3. files
    listed, present = set(m["files"]), set(members) - {MANIFEST}
    if missing := sorted(listed - present):
        report.add("files", "fail", f"listed but not in the pack: {', '.join(missing)}")
        return report
    if unlisted := sorted(present - listed):
        report.add("files", "fail", f"in the pack but not listed: {', '.join(unlisted)}")
        return report
    if bad := sorted(p for p in listed if sha256_of(members[p]) != m["files"][p]):
        report.add("files", "fail", f"sha256 does not match the manifest: {', '.join(bad)}")
        return report
    refs = [m["trusted_keys"]] + [e["path"] for e in m["certificates"]]
    refs += [e["measurement"]["cases"] for e in m["certificates"] if e["measurement"]["cases"] is not None]
    if dangling := sorted({r for r in refs if r not in listed}):
        report.add("files", "fail", f"named by the manifest but not listed in files: {', '.join(dangling)}")
        return report
    report.add("files", "ok", f"{len(listed)} files listed, every sha256 matches, nothing unlisted")

    # 4. trusted keys
    try:
        pack_keys = loads(members[m["trusted_keys"]])
    except Invalid as e:
        report.add("trusted-keys", "fail", f"{m['trusted_keys']}: {e}")
        return report
    if not isinstance(pack_keys, dict) or not all(isinstance(v, str) for v in pack_keys.values()):
        report.add("trusted-keys", "fail", f"{m['trusted_keys']}: not a JSON object of key id -> public key")
        return report
    if keys is None:
        keys = pack_keys
        report.keys_pinned = False
        report.add(
            "trusted-keys",
            "warn",
            f"{len(pack_keys)} key(s) from the pack itself: {UNPINNED} (obtained out of band) to check who signed",
        )
    else:
        same = "the same as" if dict(keys) == pack_keys else "different from"
        report.add("trusted-keys", "ok", f"{len(keys)} key(s) given by the caller, {same} the pack's own")

    # 5-7. each certificate, its measured cases, the recompute
    run = _recompute or (_load_recompute() if recompute else None)
    for entry in m["certificates"]:
        _verify_entry(report, entry, members, keys, now, recompute, run)
    return report


def _verify_entry(
    report: PackReport,
    e: Mapping[str, Any],
    members: Mapping[str, bytes],
    keys: Mapping[str, str],
    now: dt.datetime,
    recompute: bool,
    run: Recompute | None,
) -> None:
    p, ms = e["path"], e["measurement"]

    def fail(check: str, detail: str) -> None:
        report.add(f"{check} {p}", "fail", detail)
        later = ("certificate", "cases", "recompute")
        for c in later[later.index(check) + 1 :]:
            report.add(f"{c} {p}", "skipped", f"the {check} check failed")

    try:
        cert = loads(members[p])
        v = verify(cert, keys)
    except CertError as err:
        return fail("certificate", str(err))
    if v.id != e["certificate_id"]:
        return fail("certificate", f"its id is {v.id}, the manifest says {e['certificate_id']}")
    if cert["data_hash"] != ms["data_hash"]:
        return fail("certificate", f"its data_hash is {cert['data_hash']}, the manifest says {ms['data_hash']}")
    expiry = "expired" if v.is_expired(now) else "unexpired"
    report.certificate_ids.append(v.id)
    report.add(
        f"certificate {p}",
        "ok",
        f"{v.id}, {cert['spec']}, {cert['domain']}/{cert['decision']}, signed by {cert['signer_key_id']}, "
        f"{expiry} at the check time (expires_at {cert['expires_at']})",
    )

    where = "" if ms["location"] is None else f"; measured cases at {ms['location']}"
    if ms["cases"] is None:
        report.add(f"cases {p}", "skipped", f"not included in the pack{where} (never fetched)")
        report.add(f"recompute {p}", "skipped", "no measured cases in the pack")
        return
    try:
        cases = read_cases(members[ms["cases"]], len(cert["options"]))
    except Invalid as err:
        return fail("cases", f"{ms['cases']}: {err}")
    got = measured_cases_hash(cases, cert["spec"])
    if got != cert["data_hash"]:
        return fail("cases", f"{ms['cases']} hashes to {got}, the certificate's data_hash is {cert['data_hash']}")
    n_cal = sum(c["set"] == "calibration" for c in cases)
    if n_cal != cert["n_cal"] + cert["n_temperature"]:
        want = cert["n_cal"] + cert["n_temperature"]
        return fail("cases", f"{n_cal} calibration cases; the certificate's n_cal + n_temperature is {want}")
    cmap = cert["calibration_map"]
    recal = [c for c in cases if c["set"] == "recalibration"]
    if cmap["kind"] != "dr" and recal:
        return fail("cases", f"{len(recal)} recalibration cases, but the calibration map is {cmap['kind']}")
    scored_recal = sum(c["raw_scores"] is not None for c in recal)
    if cmap["kind"] == "dr" and scored_recal != cmap["label_budget"]:
        return fail("cases", f"{scored_recal} scored recalibration cases, label_budget is {cmap['label_budget']}")
    report.add(f"cases {p}", "ok", f"{len(cases)} cases ({ms['cases']}) hash to the certificate's data_hash{where}")

    unbound = ""
    if cert["spec"] in _SIX_MEMBERS and cert["rule"]["cannot_tell_above"] is not None:
        unbound = "; before v1.3 the cases' cannot_tell values are not bound by data_hash"
    if not recompute:
        report.add(f"recompute {p}", "skipped", "not asked for")
    elif ms["procedure"] is None:
        report.add(f"recompute {p}", "skipped", "the manifest gives no procedure inputs")
    elif run is None:
        report.add(f"recompute {p}", "skipped", "needs the reference issuer: pip install 'decision-cert[issue]'")
    elif cmap["kind"] == "dr" and ms["procedure"]["dr_prior"] is None:
        report.add(f"recompute {p}", "skipped", "a dr map needs procedure.dr_prior")
    else:
        try:
            diff = run(cert, cases, ms["procedure"])
        except Exception as err:  # noqa: BLE001 - any refusal of the issuer is a failed recompute
            return fail("recompute", f"the procedure refused the measured cases: {err}")
        if diff:
            return fail("recompute", f"the recomputed certificate differs at {', '.join(diff)}")
        report.add(f"recompute {p}", "ok", f"re-running the procedure gives every measured figure{unbound}")


def render(report: PackReport) -> str:
    """The report as text: one line per check, then the verdict, which says when the keys were the
    pack's own."""
    lines = [f"{c.status:<8}{c.name}: {c.detail}" for c in report.checks]
    n = len(report.certificate_ids)
    if not report.ok:
        lines.append("pack rejected")
    elif report.keys_pinned:
        lines.append(f"pack verified: {n} certificate(s)")
    else:
        lines.append(f"pack verified: {n} certificate(s); {UNPINNED}")
    return "\n".join(lines) + "\n"


def manifest_bytes(
    *,
    files: Mapping[str, bytes],
    certificates: Sequence[Mapping[str, Any]],
    trusted_keys: str,
    tenant: str | None,
    created_at: str,
    assembled_by: Mapping[str, str],
) -> bytes:
    """A v1 manifest for `files`, two-space indented with a trailing newline."""
    m = {
        "format": PACK_FORMAT,
        "created_at": created_at,
        "tenant": tenant,
        "assembled_by": dict(assembled_by),
        "trusted_keys": trusted_keys,
        "certificates": [dict(c) for c in certificates],
        "files": {p: sha256_of(files[p]) for p in sorted(files)},
    }
    return (json.dumps(m, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def tar_bytes(members: Mapping[str, bytes]) -> bytes:
    """A deterministic ustar archive of `members` (sorted, mtime 0, owner 0, mode 0644), the
    transport form of a pack directory."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for name in sorted(members):
            info = tarfile.TarInfo(name)
            info.size = len(members[name])
            info.mtime = 0
            info.mode = 0o644
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            tar.addfile(info, io.BytesIO(members[name]))
    return buf.getvalue()
