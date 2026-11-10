"""A port of the Rust crate's `verify` (rust/src/lib.rs). The Rust crate is the oracle: where the two
disagree on a certificate, this module is wrong.

The typed read mirrors serde's: every field is required, nullable fields must be present (as null),
unknown fields are rejected at every level, booleans are never numbers, and integer fields reject
floats even when integral. `check` then mirrors the crate's `check`, the schema constraints a typed
read does not enforce.
"""

from __future__ import annotations

import base64
import binascii
import datetime as dt
import hashlib
import itertools
import json
import math
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import _ed25519, _map
from ._monitor import Histogram

#: The `spec` of a certificate produced by the v1 procedure.
SPEC = "decision-certificate.v1"
#: The `spec` of a certificate produced by the v1.1 procedure (the per-test grid start).
SPEC_V1_1 = "decision-certificate.v1.1"
#: The `spec` of a v1.2 certificate: v1.1's procedure, plus the stored confidence histogram.
SPEC_V1_2 = "decision-certificate.v1.2"
#: The `spec` of a v1.3 certificate: v1.2, plus the automated options and their answered share and
#: error per test.
SPEC_V1_3 = "decision-certificate.v1.3"
#: Every `spec` this verifier accepts. v1 and v1.1 have the same fields; v1.2 adds some
#: (`V1_2_FIELDS`), v1.3 more (`V1_3_FIELDS`).
SPECS = (SPEC, SPEC_V1_1, SPEC_V1_2, SPEC_V1_3)
#: The fields a v1.2 or v1.3 certificate has and a v1 or v1.1 certificate must not: top level, and
#: per segment.
V1_2_FIELDS = (("confidence_bins", "confidence_histogram"), ("confidence_histogram",))
#: The fields a v1.3 certificate has and an earlier one must not: top level, and per segment.
V1_3_FIELDS = (("automate_options", "automated"), ("automated",))
#: Most bins a `confidence_bins` may define.
MAX_BINS = 100
#: `abstain_below` that abstains on every case.
ABSTAIN_ALL = 1.01

_U64_MAX = 2**64 - 1
_I64 = (-(2**63), 2**63 - 1)
_SAFE_INT = 2**53 - 1


class CertError(Exception):
    """A certificate that does not verify. The message matches the Rust crate's `CertError`."""


class Invalid(CertError):
    def __init__(self, reason: str) -> None:
        super().__init__(f"certificate is not a valid decision certificate: {reason}")


class UntrustedKey(CertError):
    def __init__(self, key_id: str) -> None:
        super().__init__(f"certificate signed by {key_id}, which is not a trusted key")


class BadKey(CertError):
    def __init__(self, key_id: str) -> None:
        super().__init__(f"trusted key {key_id} is malformed or does not hash to its id")


class BadSignature(CertError):
    def __init__(self) -> None:
        super().__init__("certificate signature does not verify")


class _TypeError(Exception):
    """A serde-style typed-read error; becomes `Invalid`."""


# ---------- typed read (serde's semantics) ----------


def _unexpected(v: Any) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return f"boolean `{'true' if v else 'false'}`"
    if isinstance(v, int):
        return f"integer `{v}`"
    if isinstance(v, float):
        return f"floating point `{v!r}`"
    if isinstance(v, str):
        return f"string {json.dumps(v, ensure_ascii=False)}"
    if isinstance(v, list):
        return "sequence"
    if isinstance(v, Mapping):
        return "map"
    return type(v).__name__


def _bad_type(v: Any, expected: str) -> _TypeError:
    return _TypeError(f"invalid type: {_unexpected(v)}, expected {expected}")


Reader = Callable[[Any], Any]


def _string(v: Any) -> str:
    if not isinstance(v, str):
        raise _bad_type(v, "a string")
    return v


def _boolean(v: Any) -> bool:
    if not isinstance(v, bool):
        raise _bad_type(v, "a boolean")
    return v


def _f64(v: Any) -> float:
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        raise _bad_type(v, "f64")
    try:
        x = float(v)
    except OverflowError:
        raise _TypeError(f"invalid value: {_unexpected(v)}, expected f64") from None
    if not math.isfinite(x):
        raise _TypeError(f"invalid value: {_unexpected(v)}, expected a finite f64")
    return x


def _integer(lo: int, hi: int, name: str) -> Reader:
    def read(v: Any) -> int:
        if isinstance(v, bool) or not isinstance(v, int):
            raise _bad_type(v, name)
        if not lo <= v <= hi:
            raise _TypeError(f"invalid value: {_unexpected(v)}, expected {name}")
        return v

    return read


_u64 = _integer(0, _U64_MAX, "u64")
_i64 = _integer(*_I64, "i64")


def _nullable(inner: Reader) -> Reader:
    return lambda v: None if v is None else inner(v)


def _seq(inner: Reader) -> Reader:
    def read(v: Any) -> list[Any]:
        if not isinstance(v, list):
            raise _bad_type(v, "a sequence")
        return [inner(x) for x in v]

    return read


def _map_of(inner: Reader) -> Reader:
    def read(v: Any) -> dict[str, Any]:
        if not isinstance(v, Mapping):
            raise _bad_type(v, "a map")
        return {_string(k): inner(x) for k, x in sorted(v.items())}

    return read


def _struct(name: str, fields: dict[str, Reader], optional: tuple[str, ...] = ()) -> Reader:
    """A `#[serde(deny_unknown_fields)]` struct with no defaults. Keys are read in sorted order (as
    serde_json's map holds them), and missing fields are reported after the present ones. A field in
    `optional` may be absent (`#[serde(default)]`); it is then left out of the result, so `check` can
    tell absent from null."""

    def read(v: Any) -> dict[str, Any]:
        if not isinstance(v, Mapping):
            raise _bad_type(v, f"struct {name}")
        out: dict[str, Any] = {}
        for k in sorted(v):
            if not isinstance(k, str):
                raise _bad_type(k, "a string")
            if k not in fields:
                raise _TypeError(f"unknown field `{k}`, expected one of {', '.join(f'`{f}`' for f in fields)}")
            out[k] = fields[k](v[k])
        for f in fields:
            if f not in out and f not in optional:
                raise _TypeError(f"missing field `{f}`")
        return out

    return read


_band = _struct("Band", {"level": _f64, "low": _f64, "high": _f64})
_histogram = _nullable(_struct("Histogram", {"counts": _seq(_u64), "unscored": _u64}))
_automated = _struct("Automated", {"coverage": _f64, "ucb": _nullable(_f64), "realized_band": _nullable(_band)})
_segment = _struct(
    "Segment",
    {
        "field": _string,
        "value": _string,
        "n": _u64,
        "abstain_below": _f64,
        "coverage": _f64,
        "ucb": _nullable(_f64),
        "realized_band": _nullable(_band),
        "inherited": _boolean,
        "confidence_histogram": _histogram,
        "automated": _automated,
    },
    optional=V1_2_FIELDS[1] + V1_3_FIELDS[1],
)
_certificate = _struct(
    "Certificate",
    {
        "spec": _string,
        "domain": _string,
        "decision": _string,
        "options": _seq(_string),
        "model_id": _string,
        "manifest_hash": _nullable(_string),
        "data_hash": _string,
        "n_cal": _u64,
        "n_temperature": _u64,
        "split": _struct("Split", {"method": _string, "seed": _nullable(_i64)}),
        "calibration_map": _struct(
            "CalibrationMap", {"kind": _string, "params": _map_of(_f64), "label_budget": _nullable(_u64)}
        ),
        "rule": _struct("Rule", {"cannot_tell_above": _nullable(_f64), "unscored": _string}),
        "alpha": _f64,
        "delta": _nullable(_f64),
        "method": _string,
        "risk": _string,
        "n": _u64,
        "abstain_below": _f64,
        "coverage": _f64,
        "ucb": _nullable(_f64),
        "realized_band": _band,
        "segments": _seq(_segment),
        "window": _nullable(_struct("Window", {"start": _string, "end": _string})),
        "fitted_at": _string,
        "expires_at": _string,
        "audit": _struct("Audit", {"mode": _string, "rate": _f64, "n": _u64, "propensity_logged": _boolean}),
        "issuer": _struct("Issuer", {"tool": _string, "version": _string}),
        "signer_key_id": _string,
        "signature": _string,
        "confidence_bins": _seq(_f64),
        "confidence_histogram": _histogram,
        "automate_options": _seq(_string),
        "automated": _automated,
    },
    optional=V1_2_FIELDS[0] + V1_3_FIELDS[0],
)


# ---------- check (the schema constraints a typed read doesn't enforce) ----------


def _unit(x: float) -> bool:
    return 0.0 <= x <= 1.0


def _open(x: float) -> bool:
    return 0.0 < x < 1.0


def _threshold(x: float) -> bool:
    return 0.0 <= x <= ABSTAIN_ALL


def _band_ok(b: Mapping[str, float]) -> bool:
    return _open(b["level"]) and _unit(b["low"]) and _unit(b["high"])


def _lower_hex(s: str) -> bool:
    return all(c in "0123456789abcdef" for c in s)


def _sha256_ok(h: str) -> bool:
    return h.startswith("sha256:") and len(h) == 71 and _lower_hex(h[7:])


def _model_id_ok(m: str) -> bool:
    """`^[^/]+/.+@.+$`, and not ending in `@?`. The pattern's `.` matches no line terminator."""
    if any(c in "\n\r\u2028\u2029" for c in m):
        return False
    backend, slash, rest = m.partition("/")
    if not slash or not backend:
        return False
    at = any(ch == "@" and i + 1 < len(rest) for i, ch in enumerate(rest) if i >= 1)
    return at and not m.endswith("@?")


_B64URL = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


def _check(c: Mapping[str, Any]) -> None:
    def bad(m: str) -> Invalid:
        return Invalid(m)

    if c["spec"] not in SPECS:
        raise bad(
            "spec is not decision-certificate.v1, decision-certificate.v1.1, decision-certificate.v1.2 "
            "or decision-certificate.v1.3"
        )
    _check_fields_for_spec(c)
    opts = c["options"]
    if len(opts) < 2 or not all(o for o in opts) or len(set(opts)) != len(opts):
        raise bad("options needs at least 2 distinct non-empty ids")
    if not all((c["domain"], c["decision"], c["calibration_map"]["kind"], c["issuer"]["tool"], c["issuer"]["version"])):
        raise bad("domain, decision, calibration_map.kind and issuer must be non-empty")
    method, risk, delta, ucb = c["method"], c["risk"], c["delta"], c["ucb"]
    if not (
        (method == "ltt" and risk == "selective_error" and delta is not None and _open(delta))
        or (method == "crc" and risk == "joint_error" and delta is None and ucb is None)
    ):
        raise bad("method, risk, delta and ucb disagree")
    if not _open(c["alpha"]) or not _threshold(c["abstain_below"]) or not _unit(c["coverage"]):
        raise bad("alpha, abstain_below or coverage out of range")
    if (ucb is not None and not _unit(ucb)) or not _band_ok(c["realized_band"]):
        raise bad("ucb or realized_band out of range")
    for s in c["segments"]:
        if (
            not s["field"]
            or not _threshold(s["abstain_below"])
            or not _unit(s["coverage"])
            or (s["ucb"] is not None and not _unit(s["ucb"]))
            or (s["realized_band"] is not None and not _band_ok(s["realized_band"]))
        ):
            raise bad("a segment is out of range")
    split = c["split"]
    if not (
        (split["method"] == "time" and split["seed"] is None)
        or (split["method"] == "seeded" and split["seed"] is not None)
    ):
        raise bad("split.method and split.seed disagree")
    rule = c["rule"]
    if rule["unscored"] != "abstain" or (
        rule["cannot_tell_above"] is not None and not _unit(rule["cannot_tell_above"])
    ):
        raise bad("rule out of range")
    audit = c["audit"]
    if audit["mode"] not in ("sample", "full-label") or not 0.0 < audit["rate"] <= 1.0:
        raise bad("audit out of range")
    if not _model_id_ok(c["model_id"]):
        raise bad("model_id must be <backend>/<model>@<version>")
    if not _sha256_ok(c["data_hash"]) or (c["manifest_hash"] is not None and not _sha256_ok(c["manifest_hash"])):
        raise bad("data_hash and manifest_hash must be sha256:<64 hex>")
    kid = c["signer_key_id"]
    if not (kid.startswith("ed25519:") and len(kid) == 24 and _lower_hex(kid[8:])):
        raise bad("signer_key_id must be ed25519:<16 hex>")
    sig = c["signature"]
    if len(sig) != 86 or not set(sig) <= _B64URL:
        raise bad("signature must be 86 base64url characters")
    timestamp(c["fitted_at"])
    timestamp(c["expires_at"])
    if c["window"] is not None:
        timestamp(c["window"]["start"])
        timestamp(c["window"]["end"])
    if c["spec"] in (SPEC_V1_2, SPEC_V1_3):
        _check_histograms(c)
        if (msg := _map.check(c["calibration_map"], len(opts))) is not None:
            raise Invalid(msg)
    if c["spec"] == SPEC_V1_3:
        _check_automated(c)


def _check_fields_for_spec(c: Mapping[str, Any]) -> None:
    """A v1.2 certificate has every v1.2 field, a v1.3 certificate every v1.2 and v1.3 field, and an
    earlier certificate none of them, at the top level and in every segment. A certificate whose
    fields belong to another spec is refused as a spec it is not, so a v1.1-shaped certificate naming
    v1.2, or a v1.2-shaped one naming v1.3, is still refused as an unknown spec."""
    v13 = c["spec"] == SPEC_V1_3
    v12 = c["spec"] == SPEC_V1_2 or v13
    top = [(f, v12) for f in V1_2_FIELDS[0]] + [(f, v13) for f in V1_3_FIELDS[0]]
    per_segment = [(f, v12) for f in V1_2_FIELDS[1]] + [(f, v13) for f in V1_3_FIELDS[1]]
    for where, obj, names in [("", c, top), *(("segments[]", s, per_segment) for s in c["segments"])]:
        for f, required in names:
            name = f"{where}.{f}" if where else f
            if required and f not in obj:
                raise Invalid(f"spec is not consistent with the fields: {c['spec']} requires `{name}`")
            if not required and f in obj:
                raise Invalid(f"unknown field `{name}` in a {c['spec']} certificate")


def _check_automated(c: Mapping[str, Any]) -> None:
    """v1.3's checks beyond the schema: `automate_options` names options of the certificate, once
    each and in their order; each test's `automated` share is at most its `coverage`, its numbers
    are in range, and its `ucb` and `realized_band` are null exactly where the test's are."""
    auto, opts = c["automate_options"], iter(c["options"])
    if not auto or not all(any(x == o for x in opts) for o in auto):
        raise Invalid("automate_options must name one or more of the options, once each and in their order")
    tests = [(c["automated"], c["coverage"], c["ucb"] is not None, True)]
    tests += [
        (s["automated"], s["coverage"], s["ucb"] is not None, s["realized_band"] is not None) for s in c["segments"]
    ]
    for a, coverage, ucb, band in tests:
        if (
            not _unit(a["coverage"])
            or a["coverage"] > coverage
            or (a["ucb"] is not None and not _unit(a["ucb"]))
            or (a["realized_band"] is not None and not _band_ok(a["realized_band"]))
            or (a["ucb"] is not None) != ucb
            or (a["realized_band"] is not None) != band
        ):
            raise Invalid(
                "automated must agree with its test: coverage at most the test's, and ucb and realized_band "
                "null exactly where the test's are"
            )


def _check_histograms(c: Mapping[str, Any]) -> None:
    """v1.2's checks beyond the schema: the bins rise strictly from 0 to 1, and each histogram has
    one count per bin and counts exactly its test's `n` cases."""
    bins = c["confidence_bins"]
    if not (
        2 <= len(bins) <= MAX_BINS + 1
        and bins[0] == 0.0
        and bins[-1] == 1.0
        and all(a < b for a, b in itertools.pairwise(bins))
    ):
        raise Invalid(f"confidence_bins must rise strictly from 0 to 1, with 1 to {MAX_BINS} bins")
    for h, n in [(c["confidence_histogram"], c["n"]), *((s["confidence_histogram"], s["n"]) for s in c["segments"])]:
        if h is not None and (len(h["counts"]) != len(bins) - 1 or sum(h["counts"]) + h["unscored"] != n):
            raise Invalid("a confidence_histogram needs one count per bin, and its counts and unscored must sum to n")


# ---------- timestamps ----------


def _days_in_month(year: int, month: int) -> int:
    if month == 2:
        return 29 if year % 4 == 0 and (year % 100 != 0 or year % 400 == 0) else 28
    return 30 if month in (4, 6, 9, 11) else 31


def timestamp(s: str) -> dt.datetime:
    """Parse the spec's timestamp form, `YYYY-MM-DDTHH:MM:SSZ`, exactly as the Rust crate does.

    Like the crate (chrono), a leap second (`:60`) and year 0000 are accepted. Python's datetime can
    hold neither, so `:60` reads as `:59.999999` and year 0000 as `datetime.min`; both keep
    `is_expired` correct at microsecond resolution.
    """
    digits = "0123456789"
    shape = len(s) == 20 and all(
        (ch == "-")
        if i in (4, 7)
        else (ch == "T")
        if i == 10
        else (ch == ":")
        if i in (13, 16)
        else (ch == "Z")
        if i == 19
        else (ch in digits)
        for i, ch in enumerate(s)
    )
    if shape:
        y, mo, d, h, mi, se = (int(s[a:b]) for a, b in ((0, 4), (5, 7), (8, 10), (11, 13), (14, 16), (17, 19)))
        if 1 <= mo <= 12 and 1 <= d <= _days_in_month(y, mo) and h <= 23 and mi <= 59 and se <= 60:
            if y == 0:
                return dt.datetime.min.replace(tzinfo=dt.UTC)
            if se == 60:
                return dt.datetime(y, mo, d, h, mi, 59, 999999, tzinfo=dt.UTC)
            return dt.datetime(y, mo, d, h, mi, se, tzinfo=dt.UTC)
    raise Invalid(f"timestamp {json.dumps(s, ensure_ascii=False)} is not YYYY-MM-DDTHH:MM:SSZ")


# ---------- canonical bytes, ids, keys ----------


def _as_serde_number(v: Any) -> Any:
    """serde_jcs writes every number through f64, so an integer beyond 2^53 loses precision there;
    rfc8785 refuses it instead. Convert such integers the way the crate does."""
    if isinstance(v, bool) or v is None or isinstance(v, (str, float)):
        return v
    if isinstance(v, int):
        return float(v) if abs(v) > _SAFE_INT else v
    if isinstance(v, Mapping):
        return {k: _as_serde_number(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_as_serde_number(x) for x in v]
    return v


def canonical(v: Any) -> bytes:
    """The RFC 8785 (JCS) bytes of a JSON value, identical to the crate's `canonical`."""
    try:
        return rfc8785.dumps(_as_serde_number(v))
    except Exception as e:  # noqa: BLE001 - rfc8785 raises several unrelated types
        raise Invalid(f"not canonicalisable: {e}") from None


def certificate_id(v: Any) -> str:
    """`sha256:` + hex SHA-256 of the signed certificate's canonical bytes."""
    return "sha256:" + hashlib.sha256(canonical(v)).hexdigest()


def key_id(raw_public_key: bytes) -> str:
    """`ed25519:` + the first 16 hex chars of SHA-256 of the raw 32-byte public key."""
    return "ed25519:" + hashlib.sha256(raw_public_key).hexdigest()[:16]


def b64url_decode(s: str) -> bytes | None:
    """Strict base64url without padding, as the crate's `URL_SAFE_NO_PAD`: no `=`, no characters
    outside the alphabet, no non-zero trailing bits. None when `s` is not such a string."""
    if not isinstance(s, str) or not set(s) <= _B64URL or len(s) % 4 == 1:
        return None
    try:
        b = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except (binascii.Error, ValueError):
        return None
    return b if b64url_encode(b) == s else None


def b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _verify_strict(raw_key: bytes, sig: bytes, msg: bytes) -> bool:
    """ed25519-dalek's `verify_strict`: canonical S, neither A nor R of small order, then RFC 8032."""
    if int.from_bytes(sig[32:], "little") >= _ed25519.L:
        return False
    a = _ed25519.decode(raw_key)
    r = _ed25519.decode(sig[:32])
    if a is None or r is None or _ed25519.is_small_order(a) or _ed25519.is_small_order(r):
        return False
    try:
        Ed25519PublicKey.from_public_bytes(raw_key).verify(sig, msg)
    except (InvalidSignature, ValueError):
        return False
    return True


# ---------- verify ----------


@dataclass(frozen=True)
class Verified:
    """A certificate whose signature verified against a trusted key."""

    #: `sha256:<hex>` of the signed certificate's canonical bytes.
    id: str
    #: The certificate as received.
    cert: Mapping[str, Any]
    expires_at: dt.datetime
    _typed: Mapping[str, Any] = field(repr=False, compare=False)

    def threshold_for(self, segment: str | None) -> float:
        """The threshold for a case in `segment`: a certified segment's own, else the top-level one."""
        if segment is not None:
            for s in self._typed["segments"]:
                if not s["inherited"] and s["value"] == segment:
                    return float(s["abstain_below"])
        return float(self._typed["abstain_below"])

    def is_expired(self, now: dt.datetime) -> bool:
        """True from `expires_at` on. `now` must be timezone-aware."""
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("now must be timezone-aware")
        return now >= self.expires_at

    def confidence_bins(self) -> tuple[float, ...] | None:
        """The bin edges of a v1.2 certificate's confidence histograms; None before v1.2."""
        bins = self._typed.get("confidence_bins")
        return None if bins is None else tuple(float(x) for x in bins)

    def histogram_for(self, segment: str | None) -> Histogram | None:
        """The stored confidence histogram of the cases decided by the same threshold as a case in
        `segment`: a certified segment's own, else the top level's. None before v1.2, or when the
        issuer withheld it."""
        h = self._typed.get("confidence_histogram")
        if segment is not None:
            for s in self._typed["segments"]:
                if not s["inherited"] and s["value"] == segment:
                    h = s.get("confidence_histogram")
                    break
        return None if h is None else Histogram(tuple(h["counts"]), h["unscored"])

    def automate_options(self) -> tuple[str, ...] | None:
        """The options a v1.3 certificate's consumer automates; None before v1.3. A consumer refuses a
        certificate whose list differs from the options it automates (spec v1.3 §4)."""
        auto = self._typed.get("automate_options")
        return None if auto is None else tuple(auto)

    def automated_for(self, segment: str | None) -> Mapping[str, Any] | None:
        """The automated cases of the test that decides a case in `segment` (a certified segment's
        own, else the top level's): `coverage`, `ucb` and `realized_band`. None before v1.3."""
        a = self._typed.get("automated")
        if segment is not None:
            for s in self._typed["segments"]:
                if not s["inherited"] and s["value"] == segment:
                    a = s.get("automated")
                    break
        return a

    def probabilities(self, scores: Sequence[float]) -> tuple[float, ...] | None:
        """The probabilities the certificate's calibration map gives a case's raw scores, one per
        option (spec v1.2 §1, `decision_cert.probabilities`). None when the map's kind is not one
        this package applies (`MAP_KINDS`), its params do not fit that kind, or `scores` does not
        have one score per option, or the map is `dr` in a certificate before v1.2, which did not
        define it. A consumer refuses a certificate whose map it does not apply (spec v1.2 §4)."""
        m = self._typed["calibration_map"]
        if m["kind"] != "temperature" and self._typed["spec"] not in (SPEC_V1_2, SPEC_V1_3):
            return None
        if len(scores) != len(self._typed["options"]):
            return None
        return _map.probabilities(self._typed["calibration_map"], scores)

    def confidence(self, scores: Sequence[float]) -> float | None:
        """A case's confidence: the largest of its `probabilities`. A case is answered when this is
        at least `threshold_for` its segment (and the rule does not abstain on it)."""
        p = self.probabilities(scores)
        return None if p is None else max(p)

    def temperature(self) -> float | None:
        """The temperature of a `kind: temperature` calibration map; None for other kinds."""
        m = self._typed["calibration_map"]
        if m["kind"] != "temperature":
            return None
        t = m["params"].get("temperature")
        return None if t is None else float(t)


def verify(v: Any, keys: Mapping[str, str]) -> Verified:
    """Verify `v` (a parsed JSON value) against `keys` (key id → base64url raw public key) and read it.

    Raises `Invalid`, `UntrustedKey`, `BadKey` or `BadSignature`, in that order of checking.
    """
    if not isinstance(v, Mapping):
        raise Invalid("not a JSON object")
    try:
        typed = _certificate(v)
    except _TypeError as e:
        raise Invalid(str(e)) from None
    _check(typed)

    kid = typed["signer_key_id"]
    if kid not in keys:
        raise UntrustedKey(kid)
    raw = b64url_decode(keys[kid])
    if raw is None or len(raw) != 32 or _ed25519.decode(raw) is None or key_id(raw) != kid:
        raise BadKey(kid)
    sig = b64url_decode(typed["signature"])
    if sig is None or len(sig) != 64:
        raise BadSignature()
    body = {k: x for k, x in v.items() if k != "signature"}
    if not _verify_strict(raw, sig, canonical(body)):
        raise BadSignature()

    return Verified(id=certificate_id(v), cert=v, expires_at=timestamp(typed["expires_at"]), _typed=typed)


def is_expired(cert: Verified, now: dt.datetime) -> bool:
    """Module-level form of `Verified.is_expired`."""
    return cert.is_expired(now)


def threshold_for(cert: Verified, segment: str | None) -> float:
    """Module-level form of `Verified.threshold_for`."""
    return cert.threshold_for(segment)


def _reject_constant(name: str) -> Any:
    raise Invalid(f"{name} is not a JSON number")


def _parse_int(s: str) -> int | float:
    # serde_json reads `-0` as the float -0.0, so an integer field rejects it.
    return -0.0 if s == "-0" else int(s)


def _parse_float(s: str) -> float:
    x = float(s)
    if not math.isfinite(x):
        raise Invalid(f"number {s} is out of range")
    return x


def _no_surrogates(v: Any) -> None:
    if isinstance(v, str):
        if any(0xD800 <= ord(c) <= 0xDFFF for c in v):
            raise Invalid("string contains a lone surrogate")
    elif isinstance(v, Mapping):
        for k, x in v.items():
            _no_surrogates(k)
            _no_surrogates(x)
    elif isinstance(v, list):
        for x in v:
            _no_surrogates(x)


def loads(text: str | bytes) -> Any:
    """Parse JSON as the crate's serde_json does: no NaN or Infinity, no out-of-range numbers, no lone
    surrogates, `-0` read as a float. A duplicate key keeps its last value, as in serde_json."""
    try:
        v = json.loads(text, parse_constant=_reject_constant, parse_int=_parse_int, parse_float=_parse_float)
    except (ValueError, RecursionError) as e:
        raise Invalid(f"not JSON: {e}") from None
    _no_surrogates(v)
    return v
