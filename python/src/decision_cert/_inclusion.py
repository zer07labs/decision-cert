"""`decision-cert-inclusion.v1` (draft): a tenant's transparency log, checked offline
(spec/drafts/decision-cert-inclusion.v1.md).

A port of the Rust crate's `decision_cert::inclusion`, which is the reference: both give every file of
`fixtures/inclusion-v1/` the same verdict, the same verdict JSON and the same error name.

A log is an RFC 9162 Merkle tree over JCS-encoded leaves (`Leaf`, `leaf_hash`). Its checkpoints are
C2SP signed notes (`parse_checkpoint`) signed by the log's Ed25519 key and cosigned by witnesses
(`cosignature/v1`). A bundle carries a leaf, its audit path and a cosigned checkpoint, and a consumer
checks it against its log trust configuration (`LogTrust`) with `verify_bundle`, in the order of the
draft's §10, refusing at the first failure with that check's error name (`ErrorName`).
`verify_consistency` checks a consistency proof document between two checkpoints of one log, and
`apply_policy` applies the configuration's `policy` to a certificate with or without a bundle.

The draft is not frozen: this module follows it as it stands, and may change with it. A bundle does
not replace the certificate's own verification: for a certificate leaf, verify the bundle's
certificate with `verify_for_tenant` (or `verify`) as well.

The functions here take parsed JSON. A document's I-JSON rule (no member named twice) cannot be
checked once it is parsed into a dict, so read documents from text with `parse_ijson`.
"""

from __future__ import annotations

import base64
import binascii
import datetime as dt
import hashlib
import json
import unicodedata
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Literal

from . import _ed25519
from ._verify import (
    SPEC_V1_5,
    SPECS,
    Invalid,
    _key_id_form,
    _lower_hex,
    _no_surrogates,
    _parse_float,
    _parse_int,
    _reject_constant,
    _tenant_ok,
    _verify_strict,
    b64url_decode,
    canonical,
    certificate_id,
    key_id,
    timestamp,
)

#: The `spec` of a bundle (§8).
SPEC_BUNDLE = "decision-cert-inclusion.v1"
#: The `spec` of a consistency proof document (§7.2).
SPEC_CONSISTENCY = "decision-cert-consistency.v1"
#: The `spec` of a log trust configuration (§9).
SPEC_LOG_TRUST = "decision-cert-log-trust.v1"
#: The five leaf kinds of v1 (§3.2).
LEAF_KINDS = ("certificate", "ledger_entry", "keyset", "attestation", "audit_head")
#: The C2SP signed-note signature type of an Ed25519 log signature (§5.2).
SIG_TYPE_ED25519 = 0x01
#: The C2SP signed-note signature type of an Ed25519 `cosignature/v1` (§5.3).
SIG_TYPE_COSIGNATURE_V1 = 0x04
#: The latest cosignature timestamp v1 accepts, 9999-12-31T23:59:59Z (§5.3).
MAX_COSIGNATURE_TIME = 253_402_300_799
#: The most signature lines a checkpoint may carry (§5.1).
MAX_SIGNATURE_LINES = 100
#: The most node hashes an audit or consistency path may carry (§6, §7).
MAX_PATH = 64
#: The largest integer a document may carry, 2^53 - 1 (§0).
MAX_INT = 2**53 - 1
_MAX_U64 = 2**64 - 1


# ---------- errors ----------


class ErrorName(StrEnum):
    """The draft's error names (§14), one per check."""

    TRUST_FORM = "trust_form"
    TRUST_CROSS_TENANT = "trust_cross_tenant"
    BUNDLE_FORM = "bundle_form"
    LEAF_FORM = "leaf_form"
    LEAF_MISMATCH = "leaf_mismatch"
    TENANT_MISMATCH = "tenant_mismatch"
    UNKNOWN_LOG = "unknown_log"
    CHECKPOINT_FORM = "checkpoint_form"
    ORIGIN_MISMATCH = "origin_mismatch"
    BAD_PROOF = "bad_proof"
    LOG_SIGNATURE_MISSING = "log_signature_missing"
    BAD_LOG_SIGNATURE = "bad_log_signature"
    BAD_COSIGNATURE = "bad_cosignature"
    TOO_FEW_COSIGNATURES = "too_few_cosignatures"
    CONSISTENCY_FORM = "consistency_form"
    SIZE_REGRESSION = "size_regression"
    SPLIT_VIEW = "split_view"
    BAD_CONSISTENCY_PROOF = "bad_consistency_proof"
    INCLUSION_MISSING = "inclusion_missing"


class InclusionError(Exception):
    """A refusal: the failing check's error name (§14) and a message for people. `str(e)` is
    `"<name>: <detail>"`, as the crate's `InclusionError` displays."""

    def __init__(self, name: ErrorName, detail: str) -> None:
        super().__init__(f"{name}: {detail}")
        self.name = ErrorName(name)
        self.detail = detail

    def __eq__(self, other: object) -> bool:
        return isinstance(other, InclusionError) and (self.name, self.detail) == (other.name, other.detail)

    def __hash__(self) -> int:
        return hash((self.name, self.detail))


def _debug(s: str) -> str:
    """A string as Rust's `{:?}` writes it (for the ASCII and control characters a detail can carry)."""
    out = []
    for c in s:
        if c in '"\\':
            out.append("\\" + c)
        elif c == "\n":
            out.append("\\n")
        elif c == "\r":
            out.append("\\r")
        elif c == "\t":
            out.append("\\t")
        elif c == "\0":
            out.append("\\0")
        elif unicodedata.category(c) == "Cc":
            out.append(f"\\u{{{ord(c):x}}}")
        else:
            out.append(c)
    return '"' + "".join(out) + '"'


# ---------- I-JSON ----------


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise ValueError(f"member {_debug(k)} appears twice in one object (not I-JSON)")
        out[k] = v
    return out


def parse_ijson(text: str) -> Any:
    """Parse JSON text as I-JSON (§0), as the crate's `parse_ijson`: the crate's JSON reading (no NaN or
    Infinity, no lone surrogates, no out-of-range numbers, `-0` a float), refusing also an object with two
    members of one name. Raises `ValueError` with the reason."""
    try:
        v = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_constant=_reject_constant,
            parse_int=_parse_int,
            parse_float=_parse_float,
        )
    except Invalid as e:  # NaN, Infinity, a number out of range
        raise ValueError(str(e).removeprefix("certificate is not a valid decision certificate: ")) from None
    except (ValueError, RecursionError) as e:
        raise ValueError(str(e)) from None
    try:
        _no_surrogates(v)
    except Invalid:
        raise ValueError("a string contains a lone surrogate") from None
    return v


# ---------- the tree (§4, §6, §7.1): RFC 9162 §2.1 ----------


def hash_leaf_bytes(data: bytes) -> bytes:
    """RFC 9162 §2.1.1's leaf hash of raw leaf bytes: SHA-256(0x00 || data)."""
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    """An inner node: SHA-256(0x01 || left || right)."""
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split_point(n: int) -> int:
    k = 1
    while k << 1 < n:
        k <<= 1
    return k


def root_hash(leaf_hashes: Sequence[bytes]) -> bytes | None:
    """RFC 9162 §2.1.1's MTH over leaf hashes; None for no leaves (the draft defines no empty tree)."""
    n = len(leaf_hashes)
    if n == 0:
        return None
    if n == 1:
        return leaf_hashes[0]
    k = _split_point(n)
    left, right = root_hash(leaf_hashes[:k]), root_hash(leaf_hashes[k:])
    assert left is not None and right is not None
    return node_hash(left, right)


def audit_path(leaf_hashes: Sequence[bytes], index: int) -> list[bytes] | None:
    """RFC 9162 §2.1.3.1's audit path for the leaf at `index`, from its sibling upward; None when
    `index` is out of range."""
    n = len(leaf_hashes)
    if not 0 <= index < n:
        return None
    if n == 1:
        return []
    k = _split_point(n)
    if index < k:
        path, other = audit_path(leaf_hashes[:k], index), root_hash(leaf_hashes[k:])
    else:
        path, other = audit_path(leaf_hashes[k:], index - k), root_hash(leaf_hashes[:k])
    assert path is not None and other is not None
    return [*path, other]


def consistency_path(leaf_hashes: Sequence[bytes], older: int) -> list[bytes] | None:
    """RFC 9162 §2.1.4.1's consistency path from the tree of the first `older` leaves to the tree over
    all of `leaf_hashes`; None unless 1 ≤ `older` ≤ the number of leaves."""

    def sub(m: int, d: Sequence[bytes], whole: bool) -> list[bytes]:
        n = len(d)
        if m == n:
            r = root_hash(d)
            assert r is not None
            return [] if whole else [r]
        k = _split_point(n)
        if m <= k:
            path, other = sub(m, d[:k], whole), root_hash(d[k:])
        else:
            path, other = sub(m - k, d[k:], False), root_hash(d[:k])
        assert other is not None
        return [*path, other]

    if older < 1 or older > len(leaf_hashes):
        return None
    return sub(older, leaf_hashes, True)


def verify_inclusion_path(index: int, size: int, leaf_hash: bytes, path: Sequence[bytes], root: bytes) -> bool:
    """RFC 9162 §2.1.3.2 (the draft's §6): does `path` lead from `leaf_hash` at `index` to `root` in a
    tree of `size` leaves?"""
    if index >= size:
        return False
    fn, sn, r = index, size - 1, leaf_hash
    for p in path:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def verify_consistency_path(
    older: int, newer: int, older_root: bytes, newer_root: bytes, path: Sequence[bytes]
) -> bool:
    """RFC 9162 §2.1.4.2 (the draft's §7.1): is the tree of `older` leaves with `older_root` a prefix of
    the tree of `newer` leaves with `newer_root`, by `path`? For `older` = `newer`, only an empty path
    between equal roots; `older` = 0 or `older` > `newer` never."""
    if older == 0 or older > newer:
        return False
    if older == newer:
        return len(path) == 0 and older_root == newer_root
    if len(path) == 0:
        return False
    nodes = [older_root, *path] if older & (older - 1) == 0 else list(path)
    fn, sn = older - 1, newer - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = nodes[0]
    for c in nodes[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return fr == older_root and sr == newer_root and sn == 0


# ---------- leaves (§3) ----------


def _uint(v: Any) -> int | None:
    """An integer written as one, 0 to 2^53 - 1 (§0)."""
    return v if isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= MAX_INT else None


def _str_is(v: Any, f: Callable[[str], bool]) -> bool:
    return isinstance(v, str) and f(v)


def _prefixed_hex(s: str, prefix: str, n: int) -> bool:
    return s.startswith(prefix) and len(s) == len(prefix) + n and _lower_hex(s[len(prefix) :])


def _doc_hash_ok(s: str) -> bool:
    return _prefixed_hex(s, "sha256:", 64)


def _time_ok(s: str) -> bool:
    """§0's time: `YYYY-MM-DDTHH:MM:SSZ` naming a real date, seconds 00 to 59."""
    try:
        timestamp(s)
    except Invalid:
        return False
    return s[17:19] <= "59"


def _time_of(secs: int) -> str:
    """§0's time of POSIX seconds."""
    t = dt.datetime(1970, 1, 1, tzinfo=dt.UTC) + dt.timedelta(seconds=secs)
    return f"{t.year:04d}-{t.month:02d}-{t.day:02d}T{t.hour:02d}:{t.minute:02d}:{t.second:02d}Z"


_Check = Callable[[Any], bool]
_MEMBERS: dict[str, tuple[tuple[str, _Check], ...]] = {
    "certificate": (
        ("certificate_id", lambda v: _str_is(v, _doc_hash_ok)),
        ("signer_key_id", lambda v: _str_is(v, _key_id_form)),
        ("spec", lambda v: _str_is(v, lambda s: s in SPECS)),
        ("fitted_at", lambda v: _str_is(v, _time_ok)),
        ("tenant", _tenant_ok),
    ),
    "ledger_entry": (
        ("ledger_id", lambda v: _str_is(v, lambda s: _prefixed_hex(s, "ledger:", 32))),
        ("seq", lambda v: _uint(v) is not None),
        ("entry", lambda v: _str_is(v, _doc_hash_ok)),
    ),
    "keyset": (
        ("keyset_id", lambda v: _str_is(v, lambda s: _prefixed_hex(s, "keyset:", 32))),
        ("seq", lambda v: _uint(v) is not None),
        ("keyset", lambda v: _str_is(v, _doc_hash_ok)),
    ),
    "attestation": (
        ("attestation", lambda v: _str_is(v, _doc_hash_ok)),
        ("certificate_id", lambda v: _str_is(v, _doc_hash_ok)),
    ),
    "audit_head": (
        ("tenant", _tenant_ok),
        ("chain", _tenant_ok),
        ("seq", lambda v: (n := _uint(v)) is not None and n >= 1),
        ("digest", lambda v: _str_is(v, _doc_hash_ok)),
        ("observed_at", lambda v: _str_is(v, _time_ok)),
    ),
}


class Leaf:
    """A leaf (§3) whose form has been checked: one of `LEAF_KINDS` with exactly its members, each in its
    form. Build one with `Leaf.from_json`."""

    __slots__ = ("_obj",)

    def __init__(self, obj: Mapping[str, Any]) -> None:
        self._obj = dict(obj)

    @classmethod
    def from_json(cls, v: Any) -> Leaf:
        """Check a leaf's form (§3), refusing it as `leaf_form`."""

        def bad(m: str) -> InclusionError:
            return InclusionError(ErrorName.LEAF_FORM, m)

        if not isinstance(v, Mapping):
            raise bad("a leaf is a JSON object")
        kind = v.get("kind")
        if not isinstance(kind, str):
            raise bad("a leaf needs a string kind")
        members = _MEMBERS.get(kind)
        if members is None:
            raise bad(f"unknown leaf kind {_debug(kind)}")
        # `tenant` is a certificate leaf's member exactly for a v1.5 certificate (§3.2).
        v15 = kind == "certificate" and v.get("spec") == SPEC_V1_5 and isinstance(v.get("spec"), str)

        def required(name: str) -> bool:
            return not (kind == "certificate" and name == "tenant") or v15

        names = {m for m, _ in members}
        for k in sorted(v):
            if k != "kind" and k not in names:
                raise bad(f"unknown member {_debug(k)} in a {kind} leaf")
        for name, ok in members:
            if name not in v:
                if required(name):
                    raise bad(f"a {kind} leaf needs {_debug(name)}")
            elif not required(name):
                raise bad(f"a certificate leaf carries tenant only for a {SPEC_V1_5} certificate")
            elif not ok(v[name]):
                raise bad(f"{_debug(name)} of a {kind} leaf is out of its form")
        return cls(v)

    @property
    def kind(self) -> str:
        """The leaf's kind, one of `LEAF_KINDS`."""
        k: str = self._obj["kind"]
        return k

    def get_str(self, member: str) -> str | None:
        """A member's string value (None for an absent or non-string member)."""
        x = self._obj.get(member)
        return x if isinstance(x, str) else None

    def to_json(self) -> dict[str, Any]:
        return dict(self._obj)

    def canonical(self) -> bytes:
        """The leaf's canonical bytes, its JCS bytes (§3.1)."""
        return canonical(self._obj)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Leaf) and self._obj == other._obj

    def __hash__(self) -> int:
        return hash(self.canonical())

    def __repr__(self) -> str:
        return f"Leaf({self._obj!r})"


def leaf_hash(leaf: Leaf) -> bytes:
    """The leaf hash of a leaf (§4): SHA-256(0x00 || JCS(leaf))."""
    return hash_leaf_bytes(leaf.canonical())


# ---------- checkpoints (§5) ----------


@dataclass(frozen=True)
class SignatureLine:
    """One signature line of a signed note: the key name, the 4-byte C2SP key ID, and the bytes after the
    key ID (a log signature, or a cosignature's timestamp and signature)."""

    key_name: str
    key_hash: bytes
    value: bytes


@dataclass(frozen=True)
class Checkpoint:
    """A checkpoint parsed from its signed note (§5.1). Nothing in it is trusted yet."""

    origin: str
    tree_size: int
    root_hash: bytes
    #: The note text: the three lines, each with its newline. The log signs these bytes.
    note_text: str
    signatures: tuple[SignatureLine, ...]


def _key_name_ok(s: str) -> bool:
    """A C2SP key name or cosigner name: 1 to 255 printable ASCII characters other than `+` (§5.1)."""
    return 1 <= len(s) <= 255 and all(0x21 <= ord(c) <= 0x7E and c != "+" for c in s)


def _b64(s: str) -> bytes | None:
    """Canonical standard base64 (RFC 4648 §4 with padding, §3.5): decodes and re-encodes to itself."""
    try:
        b = base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        return None
    return b if base64.b64encode(b).decode("ascii") == s else None


def _b64_hash(s: Any) -> bytes | None:
    b = _b64(s) if isinstance(s, str) else None
    return b if b is not None and len(b) == 32 else None


def parse_checkpoint(note: str) -> Checkpoint:
    """Parse a checkpoint's full signed-note text (§5.1), without trusting it: refused as
    `checkpoint_form` when it breaks any rule of §5.1, two signature lines from one key included."""

    def bad(m: str) -> InclusionError:
        return InclusionError(ErrorName.CHECKPOINT_FORM, m)

    if any(c != "\n" and unicodedata.category(c) == "Cc" for c in note):
        raise bad("a checkpoint has no control character other than a newline")
    if not note.endswith("\n"):
        raise bad("a checkpoint ends with a newline")
    lines = note[:-1].split("\n")
    if len(lines) < 5 or lines[3] != "":
        raise bad("a checkpoint is three text lines, an empty line, then one or more signature lines")
    origin, size, root = lines[0], lines[1], lines[2]
    if origin == "":
        raise bad("the origin line is empty")
    tree_size = None
    if len(size) <= 20 and all(c in "0123456789" for c in size) and not size.startswith("0") and size:
        n = int(size)
        if 1 <= n <= _MAX_U64:
            tree_size = n
    if tree_size is None:
        raise bad("the tree size is 1 to 2^64 − 1 in decimal, without leading zeros")  # noqa: RUF001 - the crate's text
    root_bytes = _b64_hash(root)
    if root_bytes is None:
        raise bad("the root hash is 32 bytes in canonical base64")
    sig_lines = lines[4:]
    if len(sig_lines) > MAX_SIGNATURE_LINES:
        raise bad("a checkpoint has at most 100 signature lines")
    signatures = []
    seen: set[tuple[str, bytes]] = set()
    for line in sig_lines:
        rest = line[2:] if line.startswith("— ") else None
        if rest is None or " " not in rest:
            raise bad("a signature line is an em dash, a space, a key name, a space and a base64 value")
        name, value = rest.split(" ", 1)
        if not _key_name_ok(name):
            raise bad("a key name is 1 to 255 printable ASCII characters other than +")
        raw = _b64(value)
        if raw is None or len(raw) < 5:
            raise bad("a signature value is canonical base64 of at least 5 bytes")
        key_hash = raw[:4]
        if (name, key_hash) in seen:
            raise bad("two signature lines from one key (the same key name and key ID)")
        seen.add((name, key_hash))
        signatures.append(SignatureLine(key_name=name, key_hash=key_hash, value=raw[4:]))
    return Checkpoint(
        origin=origin,
        tree_size=tree_size,
        root_hash=root_bytes,
        note_text=f"{origin}\n{size}\n{root}\n",
        signatures=tuple(signatures),
    )


def c2sp_key_hash(key_name: str, sig_type: int, raw_key: bytes) -> bytes:
    """The C2SP key ID (§5.2, §5.3): the first 4 bytes of SHA-256(key name || 0x0A || type || public key)."""
    return hashlib.sha256(key_name.encode() + bytes([0x0A, sig_type]) + raw_key).digest()[:4]


def cosignature_message(note_text: str, timestamp: int) -> bytes:
    """The message a `cosignature/v1` signs (§5.3): `"cosignature/v1\\ntime <timestamp>\\n"` then the
    checkpoint's note text."""
    return f"cosignature/v1\ntime {timestamp}\n{note_text}".encode()


def _verify_sig(raw_key: bytes, msg: bytes, sig: bytes) -> bool:
    return len(sig) == 64 and _verify_strict(raw_key, sig, msg)


# ---------- the log trust configuration (§9) ----------


class Policy(StrEnum):
    """The consumer's `policy` for a certificate without a bundle (§11)."""

    OFF = "off"
    WARN = "warn"
    REFUSE = "refuse"


@dataclass(frozen=True)
class TrustedLog:
    """A trusted log: its id, its C2SP key name, its key id (`ed25519:<16 hex>`) and its raw key."""

    log_id: str
    key_name: str
    key_id: str
    key: bytes


@dataclass(frozen=True)
class TrustedWitness:
    """A trusted witness: its C2SP cosigner name, its key id and its raw key."""

    name: str
    key_id: str
    key: bytes


def _only(obj: Mapping[str, Any], required: Sequence[str], optional: Sequence[str] = ()) -> bool:
    return all(k in obj for k in required) and all(k in required or k in optional for k in obj)


def _trusted_key(e: Mapping[str, Any]) -> tuple[str, bytes]:
    """An entry's `key` (base64url, a valid Ed25519 key under strict verification) and its `key_id`,
    which must be the key's id."""
    s = e["key"]
    raw = b64url_decode(s) if isinstance(s, str) else None
    point = _ed25519.decode(raw) if raw is not None and len(raw) == 32 else None
    if raw is None or point is None or _ed25519.is_small_order(point):
        raise InclusionError(
            ErrorName.TRUST_FORM,
            "a key is a valid Ed25519 public key in base64url (43 characters), not of small order",
        )
    kid = key_id(raw)
    if e["key_id"] != kid or not isinstance(e["key_id"], str):
        raise InclusionError(ErrorName.TRUST_FORM, f"key_id is not the key id of its key ({kid})")
    return kid, raw


class LogTrust:
    """One tenant's log trust configuration (§9), checked as a whole by `LogTrust.from_json`."""

    __slots__ = ("_logs", "_m", "_policy", "_tenant", "_witnesses")

    def __init__(
        self,
        tenant: str,
        logs: Sequence[TrustedLog],
        witnesses: Sequence[TrustedWitness],
        m: int,
        policy: Policy,
    ) -> None:
        self._tenant = tenant
        self._logs = tuple(logs)
        self._witnesses = tuple(witnesses)
        self._m = m
        self._policy = policy

    @classmethod
    def from_json(cls, v: Any) -> LogTrust:
        """Read and check a log trust configuration (§9), refusing it as `trust_form`."""

        def bad(m: str) -> InclusionError:
            return InclusionError(ErrorName.TRUST_FORM, m)

        if not isinstance(v, Mapping):
            raise bad("the log trust configuration is a JSON object")
        if not _only(v, ("spec", "tenant", "logs", "witnesses"), ("m", "policy")):
            raise bad(
                "the log trust configuration has exactly spec, tenant, logs, witnesses and optionally m and policy"
            )
        if v["spec"] != SPEC_LOG_TRUST or not isinstance(v["spec"], str):
            raise bad("spec is not decision-cert-log-trust.v1")
        tenant = v["tenant"]
        if not _tenant_ok(tenant):
            raise bad("tenant is 1 to 128 characters of A-Z a-z 0-9 . _ : -")
        logs_in, witnesses_in = v["logs"], v["witnesses"]
        if not isinstance(logs_in, list) or not isinstance(witnesses_in, list):
            raise bad("logs and witnesses are arrays")
        if not logs_in or not witnesses_in:
            raise bad("logs and witnesses each have at least one entry")
        logs = []
        for e in logs_in:
            if not isinstance(e, Mapping) or not _only(e, ("log_id", "key_name", "key_id", "key")):
                raise bad("a log entry has exactly log_id, key_name, key_id and key")
            log_id = e["log_id"]
            if not _str_is(log_id, lambda s: _prefixed_hex(s, "log:", 32)):
                raise bad("a log_id is log: and 32 lowercase hex characters")
            key_name = e["key_name"]
            if not _str_is(key_name, _key_name_ok):
                raise bad("a key_name is 1 to 255 printable ASCII characters other than +")
            kid, raw = _trusted_key(e)
            logs.append(TrustedLog(log_id=log_id, key_name=key_name, key_id=kid, key=raw))
        witnesses = []
        for e in witnesses_in:
            if not isinstance(e, Mapping) or not _only(e, ("name", "key_id", "key")):
                raise bad("a witness entry has exactly name, key_id and key")
            name = e["name"]
            if not _str_is(name, _key_name_ok):
                raise bad("a witness name is 1 to 255 printable ASCII characters other than +")
            kid, raw = _trusted_key(e)
            witnesses.append(TrustedWitness(name=name, key_id=kid, key=raw))
        m = 1
        if "m" in v:
            n = _uint(v["m"])
            if n is None or not 1 <= n <= len(witnesses):
                raise bad("m is an integer from 1 to the number of witnesses")
            m = n
        policy = Policy.WARN
        if "policy" in v:
            p = v["policy"]
            if not isinstance(p, str) or p not in ("off", "warn", "refuse"):
                raise bad("policy is off, warn or refuse")
            policy = Policy(p)

        def distinct(xs: list[Any]) -> bool:
            return len(set(xs)) == len(xs)

        if not distinct([x.log_id for x in logs]) or not distinct([x.key for x in logs]):
            raise bad("two logs share a log_id or a key")
        if not distinct([w.name for w in witnesses]) or not distinct([w.key for w in witnesses]):
            raise bad("two witnesses share a name or a key")
        if any(w.key == x.key for w in witnesses for x in logs):
            raise bad("a witness's key is also a log's key")
        return cls(tenant, logs, witnesses, m, policy)

    @property
    def tenant(self) -> str:
        """The expected tenant."""
        return self._tenant

    @property
    def logs(self) -> tuple[TrustedLog, ...]:
        return self._logs

    @property
    def witnesses(self) -> tuple[TrustedWitness, ...]:
        return self._witnesses

    @property
    def m(self) -> int:
        """The number of distinct trusted witnesses a checkpoint needs (default 1)."""
        return self._m

    @property
    def policy(self) -> Policy:
        """The policy for a certificate without a bundle (default `warn`)."""
        return self._policy

    def log(self, log_id: str) -> TrustedLog:
        for x in self._logs:
            if x.log_id == log_id:
                return x
        raise InclusionError(ErrorName.UNKNOWN_LOG, f"{log_id} is not one of tenant {self._tenant}'s logs")


def check_tenants(configs: Sequence[LogTrust]) -> None:
    """Several tenants' configurations held together (§2, §9): refused as `trust_cross_tenant` when one
    `log_id`, or one log key, appears under two tenants. Witnesses may serve several tenants."""
    ids: dict[str, str] = {}
    keys: dict[bytes, str] = {}
    for c in configs:
        for x in c.logs:
            for owner in (ids.setdefault(x.log_id, c.tenant), keys.setdefault(x.key, c.tenant)):
                if owner != c.tenant:
                    raise InclusionError(
                        ErrorName.TRUST_CROSS_TENANT,
                        f"log {x.log_id} (or its key) appears under tenants {owner} and {c.tenant}",
                    )


# ---------- the bundle (§8) and the consumer's checks (§10) ----------


@dataclass(frozen=True)
class CountedWitness:
    """A witness counted for a checkpoint: a trusted witness whose cosignature verified."""

    name: str
    key_id: str
    #: The cosignature time, POSIX seconds.
    time: int


@dataclass(frozen=True)
class InclusionVerdict:
    """What a verified bundle shows (§10, "The verdict")."""

    log_id: str
    tree_size: int
    root_hash: bytes
    leaf_index: int
    kind: str
    #: For a certificate leaf, the certificate's id.
    certificate_id: str | None
    #: The counted witnesses, by cosignature time, then name.
    witnesses: tuple[CountedWitness, ...]
    #: The `m`-th earliest counted cosignature time, POSIX seconds.
    t_proven: int

    def t_proven_time(self) -> str:
        """`t_proven` as a time (§0)."""
        return _time_of(self.t_proven)

    def to_json(self) -> dict[str, Any]:
        """The verdict as JSON, as the crate writes it: hashes in base64, times in §0's form."""
        out: dict[str, Any] = {
            "log_id": self.log_id,
            "tree_size": self.tree_size,
            "root_hash": base64.b64encode(self.root_hash).decode("ascii"),
            "leaf_index": self.leaf_index,
            "kind": self.kind,
            "witnesses": [{"name": w.name, "key_id": w.key_id, "time": _time_of(w.time)} for w in self.witnesses],
            "t_proven": self.t_proven_time(),
        }
        if self.certificate_id is not None:
            out["certificate_id"] = self.certificate_id
        return out


def _path_of(v: Any) -> list[bytes] | None:
    """A JSON array of at most 64 canonical base64 32-byte hashes."""
    if not isinstance(v, list) or len(v) > MAX_PATH:
        return None
    out = []
    for h in v:
        b = _b64_hash(h)
        if b is None:
            return None
        out.append(b)
    return out


def _same(a: Mapping[str, Any], b: Mapping[str, Any], m: str) -> bool:
    """`a[m]` and `b[m]` are the same JSON value, or both absent."""
    if (m in a) != (m in b):
        return False
    return m not in a or json.dumps(a[m], sort_keys=True) == json.dumps(b[m], sort_keys=True)


def verify_bundle(bundle: Any, trust: LogTrust) -> InclusionVerdict:
    """Check a bundle against the expected tenant's configuration, in §10's order (checks 2 to 12; check
    1 is `LogTrust.from_json`), refusing at the first failure with that check's error name.

    For a certificate leaf this does not verify the certificate itself: verify it under its own spec as
    well (`verify_for_tenant` with `trust.tenant`)."""

    def bad(m: str) -> InclusionError:
        return InclusionError(ErrorName.BUNDLE_FORM, m)

    # 2. the bundle's form
    if not isinstance(bundle, Mapping):
        raise bad("a bundle is a JSON object")
    if not _only(bundle, ("spec", "log_id", "leaf_index", "leaf", "proof", "checkpoint"), ("certificate",)):
        raise bad(
            "a bundle has exactly spec, log_id, leaf_index, leaf, proof, checkpoint, and certificate for a "
            "certificate leaf"
        )
    if bundle["spec"] != SPEC_BUNDLE or not isinstance(bundle["spec"], str):
        raise bad("spec is not decision-cert-inclusion.v1")
    log_id = bundle["log_id"]
    if not _str_is(log_id, lambda s: _prefixed_hex(s, "log:", 32)):
        raise bad("log_id is log: and 32 lowercase hex characters")
    leaf_index = _uint(bundle["leaf_index"])
    if leaf_index is None:
        raise bad("leaf_index is an integer from 0 to 2^53 − 1")  # noqa: RUF001 - the crate's text
    leaf_value = bundle["leaf"]
    if not isinstance(leaf_value, Mapping):
        raise bad("leaf is a JSON object")
    proof = _path_of(bundle["proof"])
    if proof is None:
        raise bad("proof is an array of at most 64 base64 32-byte hashes")
    checkpoint_text = bundle["checkpoint"]
    if not isinstance(checkpoint_text, str):
        raise bad("checkpoint is a string, the checkpoint's signed note")
    is_cert = leaf_value.get("kind") == "certificate"
    cert = bundle.get("certificate")
    if not ((is_cert and isinstance(cert, Mapping)) or (not is_cert and "certificate" not in bundle)):
        raise bad("certificate is a JSON object, present if and only if leaf.kind is certificate")

    # 3. the leaf's form
    leaf = Leaf.from_json(leaf_value)

    # 4. a certificate leaf matches its certificate
    cid = None
    if is_cert:
        assert isinstance(cert, Mapping)
        try:
            cid = certificate_id(cert)
        except Invalid as e:
            raise InclusionError(ErrorName.LEAF_MISMATCH, str(e)) from None
        if leaf.get_str("certificate_id") != cid:
            raise InclusionError(
                ErrorName.LEAF_MISMATCH, f"the leaf's certificate_id is not the certificate's id {cid}"
            )
        obj = leaf.to_json()
        for m in ("signer_key_id", "spec", "fitted_at", "tenant"):
            if not _same(obj, cert, m):
                raise InclusionError(ErrorName.LEAF_MISMATCH, f"the leaf's {m} is not the certificate's")

    # 5. the leaf's tenant (a v1.5 certificate leaf's, an audit_head's) is the expected tenant
    t = leaf.get_str("tenant")
    if t is not None and t != trust.tenant:
        raise InclusionError(ErrorName.TENANT_MISMATCH, f"the leaf is for tenant {t}, not {trust.tenant}")

    # 6. a log of the expected tenant
    log = trust.log(log_id)

    # 7, 8. the checkpoint's form and origin
    cp = parse_checkpoint(checkpoint_text)
    if cp.origin != log_id:
        raise InclusionError(ErrorName.ORIGIN_MISMATCH, f"the checkpoint's origin is not {log_id}")

    # 9. the audit path
    if not verify_inclusion_path(leaf_index, cp.tree_size, leaf_hash(leaf), proof, cp.root_hash):
        raise InclusionError(
            ErrorName.BAD_PROOF,
            f"the audit path does not lead from the leaf at {leaf_index} to the root of the tree of "
            f"{cp.tree_size} leaves",
        )

    # 10. the log's signature
    _check_log_signature(cp, log)

    # 11, 12. the witnesses' cosignatures
    witnesses = _cosigners(cp, trust)
    if len(witnesses) < trust.m:
        raise InclusionError(
            ErrorName.TOO_FEW_COSIGNATURES,
            f"{len(witnesses)} trusted witnesses cosigned, the configuration needs {trust.m}",
        )
    return InclusionVerdict(
        log_id=log_id,
        tree_size=cp.tree_size,
        root_hash=cp.root_hash,
        leaf_index=leaf_index,
        kind=leaf.kind,
        certificate_id=cid,
        witnesses=tuple(witnesses),
        t_proven=witnesses[trust.m - 1].time,
    )


def _check_log_signature(cp: Checkpoint, log: TrustedLog) -> None:
    """Check 10 (§5.2, §5.4): a line matches the log's key, and it verifies."""
    want = c2sp_key_hash(log.key_name, SIG_TYPE_ED25519, log.key)
    matched = False
    for s in cp.signatures:
        if s.key_name == log.key_name and s.key_hash == want:
            matched = True
            if not _verify_sig(log.key, cp.note_text.encode(), s.value):
                raise InclusionError(ErrorName.BAD_LOG_SIGNATURE, f"the log signature of {log.log_id} does not verify")
    if not matched:
        raise InclusionError(ErrorName.LOG_SIGNATURE_MISSING, f"no signature line matches the key of log {log.log_id}")


def _cosigners(cp: Checkpoint, trust: LogTrust) -> list[CountedWitness]:
    """Checks 11 and 12 (§5.3, §5.4): every line matching a trusted witness verifies, with a timestamp at
    most `MAX_COSIGNATURE_TIME`. The counted witnesses, by time then name."""
    out = []
    for w in trust.witnesses:
        want = c2sp_key_hash(w.name, SIG_TYPE_COSIGNATURE_V1, w.key)
        for s in cp.signatures:
            if s.key_name != w.name or s.key_hash != want:
                continue
            time = int.from_bytes(s.value[:8], "big") if len(s.value) == 72 else None
            if (
                time is None
                or time > MAX_COSIGNATURE_TIME
                or not _verify_sig(w.key, cosignature_message(cp.note_text, time), s.value[8:])
            ):
                raise InclusionError(
                    ErrorName.BAD_COSIGNATURE,
                    f"the cosignature of witness {w.name} does not verify, or its time is out of range",
                )
            out.append(CountedWitness(name=w.name, key_id=w.key_id, time=time))
    out.sort(key=lambda c: (c.time, c.name.encode()))
    return out


# ---------- the consistency proof document (§7) ----------


@dataclass(frozen=True)
class ConsistencyVerdict:
    """What a verified consistency proof document shows (§7.2)."""

    log_id: str
    older_size: int
    newer_size: int

    def to_json(self) -> dict[str, Any]:
        return {"log_id": self.log_id, "older_size": self.older_size, "newer_size": self.newer_size}


def verify_consistency(doc: Any, trust: LogTrust) -> ConsistencyVerdict:
    """Check a consistency proof document against the expected tenant's configuration, in §7.2's order:
    its form, its log, each checkpoint's form and origin, each checkpoint's log signature, then the sizes
    and the path. Cosignatures are not required, and witness lines are not checked."""

    def bad(m: str) -> InclusionError:
        return InclusionError(ErrorName.CONSISTENCY_FORM, m)

    if not isinstance(doc, Mapping):
        raise bad("a consistency proof document is a JSON object")
    if not _only(doc, ("spec", "log_id", "older", "newer", "proof")):
        raise bad("a consistency proof document has exactly spec, log_id, older, newer and proof")
    if doc["spec"] != SPEC_CONSISTENCY or not isinstance(doc["spec"], str):
        raise bad("spec is not decision-cert-consistency.v1")
    log_id = doc["log_id"]
    if not _str_is(log_id, lambda s: _prefixed_hex(s, "log:", 32)):
        raise bad("log_id is log: and 32 lowercase hex characters")
    older_text, newer_text = doc["older"], doc["newer"]
    if not isinstance(older_text, str) or not isinstance(newer_text, str):
        raise bad("older and newer are strings, checkpoints' signed notes")
    proof = _path_of(doc["proof"])
    if proof is None:
        raise bad("proof is an array of at most 64 base64 32-byte hashes")
    log = trust.log(log_id)
    cps = []
    for text in (older_text, newer_text):
        cp = parse_checkpoint(text)
        if cp.origin != log_id:
            raise InclusionError(ErrorName.ORIGIN_MISMATCH, f"a checkpoint's origin is not {log_id}")
        cps.append(cp)
    for cp in cps:
        _check_log_signature(cp, log)
    older, newer = cps
    if newer.tree_size < older.tree_size:
        raise InclusionError(
            ErrorName.SIZE_REGRESSION,
            f"the newer checkpoint ({newer.tree_size}) is smaller than the older ({older.tree_size})",
        )
    if newer.tree_size == older.tree_size and newer.root_hash != older.root_hash:
        raise InclusionError(
            ErrorName.SPLIT_VIEW,
            f"two checkpoints of log {log_id} with size {older.tree_size} and different roots",
        )
    if not verify_consistency_path(older.tree_size, newer.tree_size, older.root_hash, newer.root_hash, proof):
        raise InclusionError(
            ErrorName.BAD_CONSISTENCY_PROOF,
            f"the consistency path does not connect sizes {older.tree_size} and {newer.tree_size}",
        )
    return ConsistencyVerdict(log_id=log_id, older_size=older.tree_size, newer_size=newer.tree_size)


# ---------- policy (§11) ----------


@dataclass(frozen=True)
class PolicyOutcome:
    """What a consumer does with a certificate, under its policy (§11). The certificate must pass its own
    verification in every case.

    - `load`: load it; `verdict` is the bundle's verdict when one was checked (`warn` and `refuse`),
      None under `off`;
    - `load_with_warning`: load it, with the warning `error` (`inclusion_missing`; `warn`, no bundle);
    - `refuse`: refuse it, with `error`: `inclusion_missing` under `refuse`, or the failing check's error.
    """

    action: Literal["load", "load_with_warning", "refuse"]
    verdict: InclusionVerdict | None = None
    error: InclusionError | None = None


def apply_policy(result: InclusionVerdict | InclusionError | None, policy: Policy | str) -> PolicyOutcome:
    """Apply `policy` to a certificate's bundle check: None when it has no bundle, else what
    `verify_bundle` returned or raised. `warn` softens only a missing bundle; a bundle that fails is
    refused under `warn` and `refuse` alike. Under `off` nothing is checked and any result is ignored."""
    policy = Policy(policy)
    if policy is Policy.OFF:
        return PolicyOutcome("load")
    if result is None:
        missing = InclusionError(ErrorName.INCLUSION_MISSING, "the certificate has no inclusion bundle")
        return PolicyOutcome("load_with_warning" if policy is Policy.WARN else "refuse", error=missing)
    if isinstance(result, InclusionError):
        return PolicyOutcome("refuse", error=result)
    return PolicyOutcome("load", verdict=result)
