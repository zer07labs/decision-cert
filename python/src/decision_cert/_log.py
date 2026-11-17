"""The reference log and the reference witness of `decision-cert-inclusion.v1`
(spec/decision-cert-inclusion.v1.md; plan Phase 5): file-based, one log per directory, one tenant
per log, no server and no network.

**The log** (`FileLog`) keeps a tenant's leaves as a Merkle tree (§4) in the C2SP `tlog-tiles` layout
(c2sp.org/tlog-tiles, tile height 8):

    <dir>/checkpoint                   the latest checkpoint the log signed (§5.1), log signature only
    <dir>/tile/<L>/<N>[.p/<W>]         hash tiles: level L holds the hashes of the full subtrees of 256^L
                                       leaves, 256 to a full tile; a partial tile holds the first W
    <dir>/tile/entries/<N>[.p/<W>]     entry bundles: each entry is a leaf's JCS bytes (§3.1) after its
                                       length as a 2-byte big-endian integer; its leaf hash is
                                       SHA-256(0x00 || entry) (§4)
    <dir>/log.json                     the log's configuration: tenant, log_id, the log key's public part,
                                       key name and key id, cadence, started_at
    <dir>/records.jsonl                append-side metadata, one line per leaf: its index, leaf hash,
                                       certificate_id, `backfilled`, and when it was appended
    <dir>/checkpointed.json            the size and time of the latest checkpoint, for the cadence

`<N>` is the tile index in 3-digit groups, every group but the last prefixed `x` (1234067 is
`x001/x234/067`). A partial tile is kept once written, so a proof for an older checkpoint can still be
built from the tiles, and removed when its full tile is written. Only the tiles and the checkpoint are
the log; `log.json`, `records.jsonl` and `checkpointed.json` are this tool's own files, and the
`backfilled` mark (§12) lives only there, never in a leaf or a tile.

The log never holds a private key: `checkpoint` takes the log key from a file the operator gives, each
time. The tree's hashes are computed from the tiles, independently of the verifier's own tree code
(`_inclusion`), which checks every proof built here.

**The witness** (`FileWitness`) keeps one log's last cosigned checkpoint in its state file, and cosigns a
new checkpoint (§5.3) only after checking the log's signature and that the new one extends the last
(§7.1): it refuses a smaller tree (`size_regression`), another root at the same size (`split_view`) and a
consistency path that does not connect them (`bad_consistency_proof`), so it never cosigns two histories.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import os
import secrets
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ._inclusion import (
    MAX_COSIGNATURE_TIME,
    SIG_TYPE_COSIGNATURE_V1,
    SIG_TYPE_ED25519,
    SPEC_CONSISTENCY,
    Checkpoint,
    ErrorName,
    InclusionError,
    Leaf,
    TrustedLog,
    _check_log_signature,
    _key_name_ok,
    _path_of,
    _time_ok,
    c2sp_key_hash,
    cosignature_message,
    parse_checkpoint,
    verify_consistency_path,
)
from ._verify import _tenant_ok, b64url_decode, b64url_encode, key_id

#: The default checkpoint cadence, one hour (plan, "Checkpoint cadence").
DEFAULT_CADENCE_SECONDS = 3600
#: tlog-tiles' tile height: 2^8 = 256 hashes to a full tile.
TILE_WIDTH = 256
_HEIGHT = 8
_MAX_ENTRY = 0xFFFF


class LogError(Exception):
    """A refusal of the reference log or witness. `name` is the spec's error name where one applies
    (`leaf_form`, `tenant_mismatch`, `checkpoint_form`, `origin_mismatch`, `bad_log_signature`,
    `size_regression`, `split_view`, `bad_consistency_proof`, ...) and otherwise this tool's own
    (`record_form`, `duplicate_leaf`, `backfill_order`, `not_this_log`, `empty_log`, `key`, `state`)."""

    def __init__(self, name: str, detail: str) -> None:
        super().__init__(f"{name}: {detail}")
        self.name = name
        self.detail = detail


class NotIncludedYet(LogError):
    """The checkpoint's tree does not include the leaf yet: prove it against a later checkpoint."""

    def __init__(self, leaf_index: int, tree_size: int) -> None:
        super().__init__(
            "bad_proof",
            f"the checkpoint's tree of {tree_size} leaves does not include leaf {leaf_index} yet: prove it against "
            "a later checkpoint",
        )
        self.leaf_index = leaf_index
        self.tree_size = tree_size


# ---------- keys, times, lines ----------


def load_private_key(path: Path) -> Ed25519PrivateKey:
    """An Ed25519 private key from a PEM file (PKCS#8, unencrypted), as `openssl genpkey -algorithm
    ed25519` writes it. The key file is the operator's; nothing here writes one."""
    try:
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    except (OSError, ValueError, TypeError) as e:
        raise LogError("key", f"{path}: not a readable unencrypted PEM private key: {e}") from None
    if not isinstance(key, Ed25519PrivateKey):
        raise LogError("key", f"{path}: not an Ed25519 private key")
    return key


def raw_public(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def time_of(secs: int) -> str:
    """POSIX seconds as a time in §0's form."""
    return (dt.datetime(1970, 1, 1, tzinfo=dt.UTC) + dt.timedelta(seconds=secs)).strftime("%Y-%m-%dT%H:%M:%SZ")


def seconds_of(time: str) -> int:
    """A time in §0's form as POSIX seconds; ValueError for anything else."""
    if not _time_ok(time):
        raise ValueError(f"{time!r} is not a time YYYY-MM-DDTHH:MM:SSZ")
    t = dt.datetime.strptime(time, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.UTC)
    return int(t.timestamp())


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def note_text(origin: str, size: int, root: bytes) -> str:
    """A checkpoint's note text (§5.1): origin, size and root, each line with its newline."""
    return f"{origin}\n{size}\n{b64(root)}\n"


def log_signature_line(text: str, key_name: str, key: Ed25519PrivateKey) -> str:
    """The log's signature line on a note text (§5.2): base64(key ID || Ed25519 signature)."""
    value = c2sp_key_hash(key_name, SIG_TYPE_ED25519, raw_public(key)) + key.sign(text.encode())
    return f"— {key_name} {b64(value)}\n"


def cosignature_line(text: str, name: str, key: Ed25519PrivateKey, time: int) -> str:
    """A witness's `cosignature/v1` line on a note text (§5.3): base64(key ID || timestamp || signature)."""
    if not 0 <= time <= MAX_COSIGNATURE_TIME:
        raise LogError("time", f"a cosignature time is 0 to {MAX_COSIGNATURE_TIME}")
    sig = key.sign(cosignature_message(text, time))
    value = c2sp_key_hash(name, SIG_TYPE_COSIGNATURE_V1, raw_public(key)) + time.to_bytes(8, "big") + sig
    return f"— {name} {b64(value)}\n"


# ---------- the tree over tiles (§4, tlog-tiles) ----------


def _leaf_hash(entry: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + entry).digest()


def _node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def tile_path(level: int | str, index: int, width: int = TILE_WIDTH) -> str:
    """The path of a tile in the tlog-tiles layout, relative to the log's directory."""
    digits = f"{index:03d}"
    digits = "0" * (-len(digits) % 3) + digits
    groups = [digits[i : i + 3] for i in range(0, len(digits), 3)]
    n = "/".join([*(f"x{g}" for g in groups[:-1]), groups[-1]])
    return f"tile/{level}/{n}" + ("" if width == TILE_WIDTH else f".p/{width}")


def _split(n: int) -> int:
    """The largest power of two smaller than n (n > 1)."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)


def _json_line(v: Any) -> str:
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


@dataclass(frozen=True)
class LogConfig:
    """`log.json`: the tenant, the log's id, its key's public part, the cadence, and `started_at` (the
    time of the first entry, once there is one)."""

    tenant: str
    log_id: str
    key_name: str
    key_id: str
    key: str
    cadence_seconds: int
    started_at: str | None

    def to_json(self) -> dict[str, Any]:
        return {
            "tenant": self.tenant,
            "log_id": self.log_id,
            "key_name": self.key_name,
            "key_id": self.key_id,
            "key": self.key,
            "cadence_seconds": self.cadence_seconds,
            "started_at": self.started_at,
        }

    def trust_entry(self) -> dict[str, Any]:
        """The log's entry for a log trust configuration's `logs` (§9), with `started_at` once known."""
        out = {"log_id": self.log_id, "key_name": self.key_name, "key_id": self.key_id, "key": self.key}
        if self.started_at is not None:
            out["started_at"] = self.started_at
        return out

    def trusted(self) -> TrustedLog:
        raw = b64url_decode(self.key)
        assert raw is not None  # checked when the log was created
        return TrustedLog(log_id=self.log_id, key_name=self.key_name, key_id=self.key_id, key=raw)


class FileLog:
    """A tenant's reference log in a directory (see the module's docstring for the layout)."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        try:
            v = json.loads((self.path / "log.json").read_text(encoding="utf-8"))
            self.config = LogConfig(**v)
        except (OSError, ValueError, TypeError) as e:
            raise LogError("state", f"{self.path}: not a reference log (log.json: {e})") from None
        self._records: list[dict[str, Any]] | None = None
        self._cache: dict[tuple[int, int], bytes] = {}

    # ----- creating -----

    @classmethod
    def init(
        cls,
        path: Path,
        tenant: str,
        public_key: bytes,
        *,
        key_name: str | None = None,
        cadence_seconds: int = DEFAULT_CADENCE_SECONDS,
        log_id: str | None = None,
    ) -> FileLog:
        """Create an empty log for `tenant` in `path` (a directory that is empty or absent). Its `log_id`
        is `log:` + 32 hex characters from a cryptographically secure source (§2); `log_id` is for
        reproducible test trees only. The key name defaults to the `log_id` (§5.2)."""
        path = Path(path)
        if path.exists() and any(path.iterdir()):
            raise LogError("state", f"{path} is not empty: one log per directory")
        if not _tenant_ok(tenant):
            raise LogError("tenant", f"tenant {tenant!r} is not 1 to 128 of A-Z a-z 0-9 . _ : -")
        if cadence_seconds < 1:
            raise LogError("cadence", "the cadence is at least one second")
        if log_id is None:
            log_id = "log:" + secrets.token_hex(16)
        name = log_id if key_name is None else key_name
        if not _key_name_ok(name):
            raise LogError("key", "a key name is 1 to 255 printable ASCII characters other than +")
        if len(public_key) != 32:
            raise LogError("key", "an Ed25519 public key is 32 bytes")
        config = LogConfig(
            tenant=tenant,
            log_id=log_id,
            key_name=name,
            key_id=key_id(public_key),
            key=b64url_encode(public_key),
            cadence_seconds=cadence_seconds,
            started_at=None,
        )
        path.mkdir(parents=True, exist_ok=True)
        _atomic_write(path / "log.json", (json.dumps(config.to_json(), indent=2) + "\n").encode())
        (path / "records.jsonl").write_bytes(b"")
        return cls(path)

    # ----- reading -----

    def records(self) -> list[dict[str, Any]]:
        """The append-side metadata, one record per leaf in index order."""
        if self._records is None:
            text = (self.path / "records.jsonl").read_text(encoding="utf-8")
            self._records = [json.loads(line) for line in text.splitlines() if line]
        return self._records

    @property
    def size(self) -> int:
        return len(self.records())

    def _tile(self, level: int | str, index: int) -> bytes:
        """The widest tile at (level, index) on disk: the full one, or the widest partial."""
        full = self.path / tile_path(level, index)
        if full.exists():
            return full.read_bytes()
        parent = full.parent / (full.name + ".p")
        widths = sorted(int(p.name) for p in parent.iterdir()) if parent.exists() else []
        if not widths:
            raise LogError("state", f"tile {level}/{index} is missing")
        return (parent / str(widths[-1])).read_bytes()

    def entry(self, index: int) -> bytes:
        """The entry at `index`: the leaf's JCS bytes."""
        if not 0 <= index < self.size:
            raise LogError("index", f"no leaf {index} in a log of {self.size}")
        data, pos = self._tile("entries", index // TILE_WIDTH), 0
        for _ in range(index % TILE_WIDTH):
            pos += 2 + int.from_bytes(data[pos : pos + 2], "big")
        n = int.from_bytes(data[pos : pos + 2], "big")
        return data[pos + 2 : pos + 2 + n]

    def leaf(self, index: int) -> dict[str, Any]:
        v: dict[str, Any] = json.loads(self.entry(index))
        return v

    def _full_node(self, height: int, index: int) -> bytes:
        """The hash of the full subtree of 2^height leaves starting at leaf index * 2^height, from the tiles:
        a stored hash when height is a multiple of 8, else combined from the stored hashes below it."""
        key = (height, index)
        if key in self._cache:
            return self._cache[key]
        level, rest = divmod(height, _HEIGHT)
        if rest == 0:
            tile = self._tile(level, index // TILE_WIDTH)
            pos = (index % TILE_WIDTH) * 32
            h = tile[pos : pos + 32]
            if len(h) != 32:
                raise LogError("state", f"hash {index} at level {level} is not in its tile")
        else:
            h = _node(self._full_node(height - 1, 2 * index), self._full_node(height - 1, 2 * index + 1))
        self._cache[key] = h
        return h

    def _hash(self, start: int, n: int) -> bytes:
        """MTH of the n leaves from `start` (RFC 9162 §2.1.1), where the recursion only ever asks for a
        range that is a full aligned subtree or splits into one."""
        if n & (n - 1) == 0 and start % n == 0:
            return self._full_node(n.bit_length() - 1, start // n)
        k = _split(n)
        return _node(self._hash(start, k), self._hash(start + k, n - k))

    def root(self, size: int) -> bytes:
        """The root hash of the tree of the first `size` leaves (§4), 1 <= size <= the log's size."""
        if not 1 <= size <= self.size:
            raise LogError("index", f"a tree size is 1 to {self.size}")
        return self._hash(0, size)

    def inclusion_proof(self, index: int, size: int) -> list[bytes]:
        """The audit path of leaf `index` in the tree of `size` leaves (§6, RFC 9162 §2.1.3.1)."""
        if not 0 <= index < size <= self.size:
            raise LogError("index", f"leaf {index} is not in a tree of {size} leaves")

        def path(m: int, start: int, n: int) -> list[bytes]:
            if n == 1:
                return []
            k = _split(n)
            if m < k:
                return [*path(m, start, k), self._hash(start + k, n - k)]
            return [*path(m - k, start + k, n - k), self._hash(start, k)]

        return path(index, 0, size)

    def consistency_proof(self, older: int, newer: int) -> list[bytes]:
        """The consistency path from the tree of `older` leaves to that of `newer` (§7.1, RFC 9162
        §2.1.4.1); empty when they are equal."""
        if not 1 <= older <= newer <= self.size:
            raise LogError("index", f"no consistency path from {older} to {newer} in a log of {self.size}")

        def sub(m: int, start: int, n: int, whole: bool) -> list[bytes]:
            if m == n:
                return [] if whole else [self._hash(start, n)]
            k = _split(n)
            if m <= k:
                return [*sub(m, start, k, whole), self._hash(start + k, n - k)]
            return [*sub(m - k, start + k, n - k, False), self._hash(start, k)]

        return [] if older == newer else sub(older, 0, newer, True)

    def find(self, certificate_id: str) -> int:
        """The index of a certificate's leaf."""
        for r in self.records():
            if r.get("certificate_id") == certificate_id:
                return int(r["leaf_index"])
        raise LogError("index", f"certificate {certificate_id} is not in this log")

    def leaf_record(self, index: int) -> dict[str, Any]:
        """The leaf record of the leaf at `index`, as `certify --leaf-out` and `log backfill` write it:
        `{"certificate_id", "leaf", "leaf_hash"}` for a certificate leaf (`{"leaf", "leaf_hash"}` for the
        other kinds), with `"backfilled": true` when it was appended as backfilled."""
        r = self.records()[index] if 0 <= index < self.size else None
        if r is None:
            raise LogError("index", f"no leaf {index} in a log of {self.size}")
        out: dict[str, Any] = {"leaf": self.leaf(index), "leaf_hash": r["leaf_hash"]}
        if "certificate_id" in r:
            out["certificate_id"] = r["certificate_id"]
        if r.get("backfilled") is True:
            out["backfilled"] = True
        return out

    # ----- appending -----

    def append(self, records: Iterable[Any], now: int) -> list[dict[str, Any]]:
        """Append leaf records (`{"leaf", optional "certificate_id", "leaf_hash", "backfilled"}`, as
        `certify --leaf-out` and `log backfill` write them) in order, all or none. Refused, with nothing
        appended: a record out of form (`record_form`) or a leaf out of form (`leaf_form`); a leaf for
        another tenant, a v1.5 certificate's or an `audit_head` (`tenant_mismatch`, §2); a leaf already in
        the log (`duplicate_leaf`); a backfilled record after a leaf that was not backfilled
        (`backfill_order`, §12). Each record's `backfilled` is kept in `records.jsonl`, never in the leaf
        or a tile. The first append sets `started_at` to `now`. Returns each appended leaf's
        `{"leaf_index", "leaf_hash", "certificate_id"?, "backfilled"?}`."""
        cfg = self.config
        existing = {r["leaf_hash"] for r in self.records()}
        only_backfilled = all(r.get("backfilled") is True for r in self.records())
        new: list[tuple[bytes, dict[str, Any]]] = []
        for i, rec in enumerate(records):
            where = f"record {i + 1}"
            if not isinstance(rec, Mapping) or "leaf" not in rec:
                raise LogError("record_form", f"{where} is a JSON object with a leaf")
            if not set(rec) <= {"leaf", "certificate_id", "leaf_hash", "backfilled"}:
                raise LogError("record_form", f"{where} has leaf, and optionally certificate_id, leaf_hash, backfilled")
            try:
                leaf = Leaf.from_json(rec["leaf"])
            except InclusionError as e:
                raise LogError(str(e.name), f"{where}: {e.detail}") from None
            entry = leaf.canonical()
            if len(entry) > _MAX_ENTRY:
                raise LogError("leaf_form", f"{where}: a leaf is at most {_MAX_ENTRY} bytes")
            h = b64(_leaf_hash(entry))
            if "leaf_hash" in rec and rec["leaf_hash"] != h:
                raise LogError("record_form", f"{where}: leaf_hash is not its leaf's hash {h}")
            cid = leaf.get_str("certificate_id") if leaf.kind == "certificate" else None
            if "certificate_id" in rec and rec["certificate_id"] != cid:
                raise LogError("record_form", f"{where}: certificate_id is not its certificate leaf's")
            backfilled = rec.get("backfilled") is True
            if "backfilled" in rec and (not backfilled or leaf.kind != "certificate"):
                raise LogError("record_form", f"{where}: backfilled is true, and only for a certificate leaf")
            t = leaf.get_str("tenant")
            if t is not None and t != cfg.tenant:
                raise LogError("tenant_mismatch", f"{where}: the leaf is for tenant {t}; this is {cfg.tenant}'s log")
            if h in existing:
                raise LogError("duplicate_leaf", f"{where}: the leaf is already in the log")
            existing.add(h)
            if backfilled and not only_backfilled:
                raise LogError(
                    "backfill_order",
                    f"{where}: a backfilled leaf goes before any new leaf (§12); this log has new ones",
                )
            only_backfilled = only_backfilled and backfilled
            meta: dict[str, Any] = {"leaf_hash": h, "appended_at": time_of(now)}
            if cid is not None:
                meta["certificate_id"] = cid
            if backfilled:
                meta["backfilled"] = True
            new.append((entry, meta))
        if not new:
            return []
        start = self.size
        for j, (_, meta) in enumerate(new):
            meta["leaf_index"] = start + j
        self._write_tiles(start, [e for e, _ in new])
        with (self.path / "records.jsonl").open("a", encoding="utf-8") as f:
            for _, meta in new:
                f.write(_json_line(meta) + "\n")
        self._records = None
        if cfg.started_at is None:
            self.config = LogConfig(**{**cfg.to_json(), "started_at": time_of(now)})
            _atomic_write(self.path / "log.json", (json.dumps(self.config.to_json(), indent=2) + "\n").encode())
        return [
            {k: m[k] for k in ("leaf_index", "leaf_hash", "certificate_id", "backfilled") if k in m} for _, m in new
        ]

    def _write_tiles(self, start: int, entries: Sequence[bytes]) -> None:
        """Write the entry bundles and hash tiles touched by appending `entries` at `start`."""
        size = start + len(entries)
        # entries: the touched bundles, from the partial bundle on disk and the new entries
        first = start // TILE_WIDTH
        old = self._bundle_entries(self._tile("entries", first)) if start % TILE_WIDTH else []
        all_entries = old[: start % TILE_WIDTH] + list(entries)
        for t in range(first, (size - 1) // TILE_WIDTH + 1):
            lo = (t - first) * TILE_WIDTH
            chunk = all_entries[lo : lo + TILE_WIDTH]
            self._put_tile("entries", t, b"".join(len(e).to_bytes(2, "big") + e for e in chunk), len(chunk))
        # hashes: level 0 holds leaf hashes; level L the hashes of full subtrees of 256^L leaves
        level, lo, hashes = 0, start, [_leaf_hash(e) for e in entries]
        while True:
            t0 = lo // TILE_WIDTH
            have = self._tile(level, t0)[: (lo % TILE_WIDTH) * 32] if lo % TILE_WIDTH else b""
            flat = have + b"".join(hashes)
            n_total = lo - t0 * TILE_WIDTH + len(hashes)
            for t in range(t0, t0 + (n_total + TILE_WIDTH - 1) // TILE_WIDTH):
                part = flat[(t - t0) * TILE_WIDTH * 32 : (t - t0 + 1) * TILE_WIDTH * 32]
                self._put_tile(level, t, part, len(part) // 32)
            # the next level: hashes of the full tiles completed by this append
            full_before, full_after = lo // TILE_WIDTH, (lo + len(hashes)) // TILE_WIDTH
            if full_after == full_before:
                break
            ups = []
            for t in range(full_before, full_after):
                tile = self._tile(level, t)
                nodes = [tile[i : i + 32] for i in range(0, TILE_WIDTH * 32, 32)]
                while len(nodes) > 1:
                    nodes = [_node(nodes[i], nodes[i + 1]) for i in range(0, len(nodes), 2)]
                ups.append(nodes[0])
            level, lo, hashes = level + 1, full_before, ups
        self._cache.clear()

    @staticmethod
    def _bundle_entries(data: bytes) -> list[bytes]:
        out, pos = [], 0
        while pos < len(data):
            n = int.from_bytes(data[pos : pos + 2], "big")
            out.append(data[pos + 2 : pos + 2 + n])
            pos += 2 + n
        return out

    def _put_tile(self, level: int | str, index: int, data: bytes, width: int) -> None:
        p = self.path / tile_path(level, index, width)
        _atomic_write(p, data)
        if width == TILE_WIDTH:
            partials = p.parent / (p.name + ".p")
            if partials.exists():
                for q in partials.iterdir():
                    q.unlink()
                partials.rmdir()

    # ----- checkpoints -----

    def checkpointed(self) -> dict[str, Any] | None:
        """`{"tree_size", "at"}` of the latest checkpoint the log signed, or None."""
        p = self.path / "checkpointed.json"
        if not p.exists():
            return None
        v: dict[str, Any] = json.loads(p.read_text(encoding="utf-8"))
        return v

    def due(self, now: int) -> int | None:
        """When the next checkpoint is due (POSIX seconds) if that is after `now`, else None."""
        last = self.checkpointed()
        if last is None:
            return None
        due = seconds_of(last["at"]) + self.config.cadence_seconds
        return due if due > now else None

    def checkpoint(self, key: Ed25519PrivateKey, now: int, *, force: bool = False) -> str | None:
        """Sign a checkpoint of the log at its current size with the log key (§5.1, §5.2), write it to
        `<dir>/checkpoint` and return it; None when the cadence says the next one is not due yet (unless
        `force`). Refused for an empty log (a checkpoint's size is at least 1) and a key that is not the
        log's."""
        cfg = self.config
        if raw_public(key) != cfg.trusted().key:
            raise LogError("key", f"the key is not log {cfg.log_id}'s key {cfg.key_id}")
        if self.size == 0:
            raise LogError("empty_log", "an empty log has no checkpoint: a checkpoint's tree size is at least 1")
        if not force and self.due(now) is not None:
            return None
        text = note_text(cfg.log_id, self.size, self.root(self.size))
        note = text + "\n" + log_signature_line(text, cfg.key_name, key)
        _atomic_write(self.path / "checkpoint", note.encode())
        _atomic_write(
            self.path / "checkpointed.json", (_json_line({"tree_size": self.size, "at": time_of(now)}) + "\n").encode()
        )
        return note

    def check_checkpoint(self, note: str) -> Checkpoint:
        """A checkpoint of this log, its signature checked against the log key, its tree no larger than the
        log and its root the log's root at its size (else `not_this_log`: another log's, or another
        history)."""
        try:
            cp = parse_checkpoint(note)
            if cp.origin != self.config.log_id:
                raise InclusionError(ErrorName.ORIGIN_MISMATCH, f"the checkpoint's origin is not {self.config.log_id}")
            _check_log_signature(cp, self.config.trusted())
        except InclusionError as e:
            raise LogError(str(e.name), e.detail) from None
        if cp.tree_size > self.size or self.root(cp.tree_size) != cp.root_hash:
            raise LogError("not_this_log", f"the checkpoint of size {cp.tree_size} is not of this log's history")
        return cp

    def prove(self, note: str, index: int) -> list[str]:
        """The inclusion proof (§6) of leaf `index` against the checkpoint `note`, as `bundle` takes it: a
        list of base64 node hashes. `NotIncludedYet` when the checkpoint's tree does not reach the leaf."""
        cp = self.check_checkpoint(note)
        if not 0 <= index < self.size:
            raise LogError("index", f"no leaf {index} in a log of {self.size}")
        if index >= cp.tree_size:
            raise NotIncludedYet(index, cp.tree_size)
        return [b64(h) for h in self.inclusion_proof(index, cp.tree_size)]

    def consistency(self, older: str, newer: str) -> dict[str, Any]:
        """The consistency proof document (§7.2) from checkpoint `older` to checkpoint `newer`."""
        a, b = self.check_checkpoint(older), self.check_checkpoint(newer)
        if b.tree_size < a.tree_size:
            raise LogError("size_regression", "the newer checkpoint is smaller than the older")
        return {
            "spec": SPEC_CONSISTENCY,
            "log_id": self.config.log_id,
            "older": older,
            "newer": newer,
            "proof": [b64(h) for h in self.consistency_proof(a.tree_size, b.tree_size)],
        }


# ---------- the witness ----------


class FileWitness:
    """A reference witness for one log: its state file holds its name, its public key's id, the log's
    trust entry (§9) and the note text of the last checkpoint it cosigned, with the time."""

    def __init__(self, state_path: Path) -> None:
        self.path = Path(state_path)
        try:
            self.state: dict[str, Any] = json.loads(self.path.read_text(encoding="utf-8"))
            log = self.state["log"]
            raw = b64url_decode(log["key"])
            if raw is None or len(raw) != 32 or key_id(raw) != log["key_id"]:
                raise ValueError("the log's key is not a base64url Ed25519 key matching its key_id")
            self.log = TrustedLog(log_id=log["log_id"], key_name=log["key_name"], key_id=log["key_id"], key=raw)
        except (OSError, ValueError, KeyError, TypeError) as e:
            raise LogError("state", f"{self.path}: not a witness state file: {e}") from None

    @classmethod
    def init(cls, state_path: Path, name: str, public_key: bytes, log_entry: Mapping[str, Any]) -> FileWitness:
        """A new state file for witness `name` (its C2SP cosigner name, §5.3) of the log `log_entry` (a log
        trust configuration's `logs` entry, as `log info` prints it). Refused when the file exists."""
        path = Path(state_path)
        if path.exists():
            raise LogError("state", f"{path} exists: a witness keeps one state per log")
        if not _key_name_ok(name):
            raise LogError("key", "a witness name is 1 to 255 printable ASCII characters other than +")
        log = {k: log_entry.get(k) for k in ("log_id", "key_name", "key_id", "key")}
        raw = b64url_decode(log["key"]) if isinstance(log["key"], str) else None
        if (
            not isinstance(log["log_id"], str)
            or not isinstance(log["key_name"], str)
            or not _key_name_ok(log["key_name"])
            or raw is None
            or len(raw) != 32
            or key_id(raw) != log["key_id"]
        ):
            raise LogError("state", "the log entry has log_id, key_name, and key with its key_id, as `log info` prints")
        state = {
            "name": name,
            "key_id": key_id(public_key),
            "key": b64url_encode(public_key),
            "log": log,
            "checkpoint": None,
            "cosigned_at": None,
        }
        _atomic_write(path, (json.dumps(state, indent=2) + "\n").encode())
        return cls(path)

    def cosign(
        self, note: str, consistency: Mapping[str, Any] | None, key: Ed25519PrivateKey, now: int
    ) -> tuple[str, Checkpoint]:
        """Cosign checkpoint `note` at time `now` and record it as the last cosigned checkpoint. Checked
        first: its form, origin and log signature; then, against the last checkpoint this witness
        cosigned, that it extends it: a smaller tree is `size_regression`, another root at the same size
        `split_view`, and a larger tree needs `consistency`, a consistency proof document (§7.2) from the
        last cosigned checkpoint to this one, whose path must verify (`bad_consistency_proof`). The first
        checkpoint a witness sees is cosigned on its own. Returns the checkpoint with this witness's line
        added (any earlier line of its key replaced)."""
        name = self.state["name"]
        if key_id(raw_public(key)) != self.state["key_id"]:
            raise LogError("key", f"the key is not witness {name}'s key {self.state['key_id']}")
        try:
            cp = parse_checkpoint(note)
            if cp.origin != self.log.log_id:
                raise InclusionError(ErrorName.ORIGIN_MISMATCH, f"the checkpoint's origin is not {self.log.log_id}")
            _check_log_signature(cp, self.log)
        except InclusionError as e:
            raise LogError(str(e.name), e.detail) from None
        last = self.last()
        if last is not None:
            size, root = last
            if cp.tree_size < size:
                raise LogError("size_regression", f"the checkpoint's tree of {cp.tree_size} is smaller than {size}")
            if cp.tree_size == size and cp.root_hash != root:
                raise LogError("split_view", f"another root for the tree of {size} leaves this witness cosigned")
            if cp.tree_size > size:
                self._check_consistency(consistency, last, cp)
        if now < (self.state["cosigned_at"] or 0):
            raise LogError("time", "the cosignature time is before this witness's last one")
        mine = c2sp_key_hash(name, SIG_TYPE_COSIGNATURE_V1, raw_public(key))
        lines = note[len(cp.note_text) + 1 :].splitlines(keepends=True)
        kept = [
            line
            for line, s in zip(lines, cp.signatures, strict=True)
            if not (s.key_name == name and s.key_hash == mine)
        ]
        out = cp.note_text + "\n" + "".join(kept) + cosignature_line(cp.note_text, name, key, now)
        self.state = {**self.state, "checkpoint": cp.note_text, "cosigned_at": now}
        _atomic_write(self.path, (json.dumps(self.state, indent=2) + "\n").encode())
        return out, cp

    def trust_entry(self) -> dict[str, Any]:
        """The witness's entry for a log trust configuration's `witnesses` (§9)."""
        return {"name": self.state["name"], "key_id": self.state["key_id"], "key": self.state["key"]}

    def last(self) -> tuple[int, bytes] | None:
        """The tree size and root of the last checkpoint this witness cosigned, or None."""
        text = self.state["checkpoint"]
        if text is None:
            return None
        _, size, root = text.split("\n")[:3]
        return int(size), base64.b64decode(root)

    def _check_consistency(self, doc: Mapping[str, Any] | None, last: tuple[int, bytes], cp: Checkpoint) -> None:
        if doc is None:
            raise LogError(
                "bad_consistency_proof",
                f"a consistency proof from the tree of {last[0]} this witness last cosigned is needed",
            )
        if not isinstance(doc, Mapping) or doc.get("spec") != SPEC_CONSISTENCY or doc.get("log_id") != self.log.log_id:
            raise LogError("consistency_form", f"not a {SPEC_CONSISTENCY} document of log {self.log.log_id}")
        path = _path_of(doc.get("proof"))
        if path is None:
            raise LogError("consistency_form", "proof is an array of at most 64 base64 32-byte hashes")
        if not verify_consistency_path(last[0], cp.tree_size, last[1], cp.root_hash, path):
            raise LogError(
                "bad_consistency_proof",
                f"the path does not connect the tree of {last[0]} this witness cosigned to the tree of {cp.tree_size}",
            )


def trust_config(
    tenant: str, logs: Sequence[Mapping[str, Any]], witnesses: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    """A log trust configuration (§9) from `log info`'s entries and witnesses' `{"name", "key_id", "key"}`."""
    return {"spec": "decision-cert-log-trust.v1", "tenant": tenant, "logs": list(logs), "witnesses": list(witnesses)}
