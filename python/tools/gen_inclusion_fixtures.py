"""Generate `fixtures/inclusion-v1/`: the conformance set of the inclusion draft
(spec/drafts/decision-cert-inclusion.v1.md), with its manifest `manifest.json` and its hash list
`INCLUSION.sha256`.

    cd python && uv run python tools/gen_inclusion_fixtures.py          # write
    cd python && uv run python tools/gen_inclusion_fixtures.py --check  # fail if any byte would change

Everything is built here from fixed seeds: the log and witness keys (public keys and deterministic
Ed25519 signatures only), the trees, the checkpoints and cosignatures, the bundles, the consistency proof
documents and the log trust configurations. The certificates in certificate leaves are read from the
frozen sets (`fixtures/v1.2/valid_basic.json`, and `fixtures/v1.5/valid_operator.json`, `valid_hosted.json`
and `valid_cost_basic.json`, all for tenant `acme-bank`).

Every case's expected verdict comes from how the case is built: an accepted verdict is assembled from the
tree, the checkpoint and the cosignatures written into the case, and a refusal names the one check the
case is built to fail (§10, §7.2, §9, §11, §14). This script does not use the verifier's checks; its
certificate leaves and their backfill order are the issuer's (`decision_cert.certificate_leaf`,
`backfill_order`), which the verifiers check against each certificate. Both verifiers
are then checked against the manifest: `rust/tests/inclusion_fixtures.rs` and
`python/tests/test_inclusion.py`, which also runs the two command-line verifiers on every file and
compares their output lines.

The manifest lists one case per entry, by `check`:

- `bundle` (`doc`, `trust`): `verify-bundle`'s verdict line, without `detail`;
- `consistency` (`doc`, `trust`): `verify-consistency`'s verdict line, without `detail`;
- `trust` (`trust`): the configuration read alone, accepted with its `tenant`, `m` and `policy`, or
  refused as `trust_form`;
- `tenants` (`trusts`): several tenants' configurations held together (`trust_cross_tenant`);
- `policy` (`trust`, `doc` or null): §11's outcome for a certificate with that bundle, or none;
- `leaf_hash` (`leaf`): the leaf's hash (§4), base64;
- `rfc9162_inclusion` and `rfc9162_consistency`: the RFC 6962 / RFC 9162 reference vectors on raw leaf
  inputs (hex), and altered copies of them, with the boolean result of §6's and §7.1's algorithms.
"""

from __future__ import annotations

import argparse
import base64
import copy
import datetime as dt
import hashlib
import json
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from decision_cert import backfill_order, certificate_leaf
from decision_cert.issue import certify as ct

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "fixtures"
OUT = FIXTURES / "inclusion-v1"

SPEC_BUNDLE = "decision-cert-inclusion.v1"
SPEC_CONSISTENCY = "decision-cert-consistency.v1"
SPEC_LOG_TRUST = "decision-cert-log-trust.v1"
ERROR_NAMES = (
    "trust_form",
    "trust_cross_tenant",
    "bundle_form",
    "leaf_form",
    "leaf_mismatch",
    "tenant_mismatch",
    "unknown_log",
    "checkpoint_form",
    "origin_mismatch",
    "bad_proof",
    "log_signature_missing",
    "bad_log_signature",
    "bad_cosignature",
    "too_few_cosignatures",
    "consistency_form",
    "size_regression",
    "split_view",
    "bad_consistency_proof",
    "inclusion_missing",
)
TENANT = "acme-bank"  # the tenant of the v1.5 certificates in fixtures/v1.5/
OTHER_TENANT = "globex"
T0 = 1_800_000_000  # 2027-01-15T08:00:00Z: cosignature times are T0 plus a few seconds
MAX_COSIGNATURE_TIME = 253_402_300_799
EM = "—"


# ---------- keys from fixed seeds ----------


def seeded(name: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(f"inclusion-v1 fixtures: {name}".encode()).digest())


def hex_id(name: str, n: int = 32) -> str:
    return hashlib.sha256(f"inclusion-v1 fixtures: {name}".encode()).hexdigest()[:n]


def raw(k: Ed25519PrivateKey) -> bytes:
    return ct.raw_public(k.public_key())


def kid(k: Ed25519PrivateKey) -> str:
    return ct.key_id(k.public_key())


LOG_A = "log:" + hex_id("log a")  # acme-bank's log
LOG_G = "log:" + hex_id("log g")  # globex's log
LOG_A_KEY = seeded("log a key")
LOG_G_KEY = seeded("log g key")
ROGUE_LOG_KEY = seeded("rogue log key")  # a log key no configuration trusts
W = {name: seeded(f"witness {name}") for name in ("witness.example/w1", "witness.example/w2", "witness.example/w3")}
W1, W2, W3 = W
ROGUE_W = "witness.example/rogue"
ROGUE_W_KEY = seeded("rogue witness key")


# ---------- the tree (RFC 9162 §2.1), written here independently of the verifier ----------


def h_leaf(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def h_node(a: bytes, b: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + a + b).digest()


def split(n: int) -> int:
    k = 1
    while 2 * k < n:
        k *= 2
    return k


def mth(d: Sequence[bytes]) -> bytes:
    if len(d) == 1:
        return d[0]
    k = split(len(d))
    return h_node(mth(d[:k]), mth(d[k:]))


def path(d: Sequence[bytes], i: int) -> list[bytes]:
    """RFC 9162 §2.1.3.1's PATH(m, D[n])."""
    if len(d) == 1:
        return []
    k = split(len(d))
    return [*path(d[:k], i), mth(d[k:])] if i < k else [*path(d[k:], i - k), mth(d[:k])]


def proof(m: int, d: Sequence[bytes]) -> list[bytes]:
    """RFC 9162 §2.1.4.1's PROOF(m, D[n])."""

    def sub(m: int, d: Sequence[bytes], b: bool) -> list[bytes]:
        if m == len(d):
            return [] if b else [mth(d)]
        k = split(len(d))
        return [*sub(m, d[:k], b), mth(d[k:])] if m <= k else [*sub(m - k, d[k:], False), mth(d[:k])]

    return sub(m, d, True)


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def noncanonical(s: str) -> str:
    """Padded base64 with non-zero trailing bits in its last character (RFC 4648 §3.5): it decodes to the
    same bytes under a lenient decoder, and a verifier refuses it."""
    body = s.rstrip("=")
    assert len(body) < len(s), "padded base64 has trailing bits"
    i = B64_ALPHABET.index(body[-1])
    return body[:-1] + B64_ALPHABET[i + 1] + s[len(body) :]


def raw_key_id(raw_key: bytes) -> str:
    return "ed25519:" + hashlib.sha256(raw_key).hexdigest()[:16]


def jcs_leaf_hash(leaf: dict[str, Any]) -> bytes:
    return h_leaf(ct.canonical(leaf))


# The RFC 6962 / RFC 9162 reference test data, from transparency-dev/merkle at tag v0.0.2 (commit
# 036047b5d2f7faf3b1ee643d391e60fe5b1defcf): testonly/constants.go and proof/verify_test.go, the values
# the Rust crate's unit tests also carry. Leaf indices are 0-based.
RFC_INPUTS = ["", "00", "10", "2021", "3031", "40414243", "5051525354555657", "606162636465666768696a6b6c6d6e6f"]
RFC_ROOTS = [
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
    "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
    "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
    "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
    "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
    "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
    "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
]
RFC_INCLUSION: list[tuple[int, int, list[str]]] = [
    (0, 1, []),
    (
        0,
        8,
        [
            "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
            "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
            "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
        ],
    ),
    (
        5,
        8,
        [
            "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
            "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
            "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
        ],
    ),
    (2, 3, ["fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125"]),
    (
        1,
        5,
        [
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
            "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
            "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
        ],
    ),
]
RFC_CONSISTENCY: list[tuple[int, int, list[str]]] = [
    (1, 1, []),
    (
        1,
        8,
        [
            "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
            "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
            "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
        ],
    ),
    (
        6,
        8,
        [
            "0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a",
            "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
            "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
        ],
    ),
    (
        2,
        5,
        [
            "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
            "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
        ],
    ),
    (
        6,
        7,
        [
            "0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a",
            "b08693ec2e721597130641e8211e7eedccb4c26413963eee6c1e2ed16ffb1a5f",
            "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
        ],
    ),
]


def flip(h: str) -> str:
    """A hex hash with its first byte changed."""
    return f"{int(h[:2], 16) ^ 1:02x}" + h[2:]


def rfc_cases() -> list[dict[str, Any]]:
    leaves = [h_leaf(bytes.fromhex(x)) for x in RFC_INPUTS]
    for n, want in enumerate(RFC_ROOTS, 1):
        assert mth(leaves[:n]).hex() == want, f"this script's MTH disagrees with RFC 9162 at size {n}"
    out: list[dict[str, Any]] = []

    def inc(name: str, i: int, n: int, p: list[str], root: str, expect: bool) -> None:
        out.append(
            {
                "name": name,
                "check": "rfc9162_inclusion",
                "leaf_input": RFC_INPUTS[i] if i < len(RFC_INPUTS) else "",
                "leaf_index": i,
                "tree_size": n,
                "path": p,
                "root": root,
                "expect": expect,
            }
        )

    for i, n, p in RFC_INCLUSION:
        assert [x.hex() for x in path(leaves[:n], i)] == p, f"this script's PATH disagrees at {i} in {n}"
        root = RFC_ROOTS[n - 1]
        tag = f"rfc9162_inclusion_{i}_in_{n}"
        inc(tag, i, n, p, root, True)
        if p:
            inc(f"{tag}_altered", i, n, [flip(p[0]), *p[1:]], root, False)
            inc(f"{tag}_short", i, n, p[:-1], root, False)
        inc(f"{tag}_long", i, n, [*p, root], root, False)
        inc(f"{tag}_other_root", i, n, p, flip(root), False)
        if i > 0:
            inc(f"{tag}_index_is_size", i, i, p, root, False)
    # §6: a path checks a size and root only together; the leftmost leaf's path in a tree of 3 leaves
    # also leads to that root at size 4, the draft's own example.
    inc(
        "rfc9162_inclusion_0_in_3_as_size_4_same_root", 0, 4, [x.hex() for x in path(leaves[:3], 0)], RFC_ROOTS[2], True
    )

    def con(name: str, m: int, n: int, p: list[str], r1: str, r2: str, expect: bool) -> None:
        out.append(
            {
                "name": name,
                "check": "rfc9162_consistency",
                "older": m,
                "newer": n,
                "older_root": r1,
                "newer_root": r2,
                "path": p,
                "expect": expect,
            }
        )

    for m, n, p in RFC_CONSISTENCY:
        assert [x.hex() for x in proof(m, leaves[:n])] == p, f"this script's PROOF disagrees at {m} -> {n}"
        r1, r2 = RFC_ROOTS[m - 1], RFC_ROOTS[n - 1]
        tag = f"rfc9162_consistency_{m}_to_{n}"
        con(tag, m, n, p, r1, r2, True)
        if p:
            con(f"{tag}_altered", m, n, [flip(p[0]), *p[1:]], r1, r2, False)
            con(f"{tag}_short", m, n, p[:-1], r1, r2, False)
        con(f"{tag}_long", m, n, [*p, r2], r1, r2, False)
        con(f"{tag}_wrong_older_root", m, n, p, flip(r1), r2, False)
        con(f"{tag}_wrong_newer_root", m, n, p, r1, flip(r2), False)
        if m < n:
            con(f"{tag}_reversed", n, m, p, r2, r1, False)
    con("rfc9162_consistency_0_to_1", 0, 1, [], RFC_ROOTS[0], RFC_ROOTS[0], False)
    return out


# ---------- leaves ----------


def doc_hash(name: str) -> str:
    return "sha256:" + hashlib.sha256(f"inclusion-v1 fixtures: {name}".encode()).hexdigest()


def time_of(secs: int) -> str:
    t = dt.datetime(1970, 1, 1, tzinfo=dt.UTC) + dt.timedelta(seconds=secs)
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def load_cert(rel: str) -> dict[str, Any]:
    c: dict[str, Any] = json.loads((FIXTURES / rel).read_text(encoding="utf-8"))["certificate"]
    return c


CERT_V12 = load_cert("v1.2/valid_basic.json")
CERT_OPERATOR = load_cert("v1.5/valid_operator.json")
CERT_HOSTED = load_cert("v1.5/valid_hosted.json")
CERT_COST = load_cert("v1.5/valid_cost_basic.json")
FITTED_AT = CERT_V12["fitted_at"]  # every certificate here was fitted at this time
assert all(c["fitted_at"] == FITTED_AT for c in (CERT_OPERATOR, CERT_HOSTED, CERT_COST))
STARTED_AFTER = "2026-11-01T00:00:00Z"  # a log started after the certificates were fitted: they are marked
STARTED_BEFORE = "2026-10-01T00:00:00Z"  # a log started before: they are not
assert STARTED_BEFORE < FITTED_AT < STARTED_AFTER


def cert_leaf(c: dict[str, Any]) -> dict[str, Any]:
    """A certificate's leaf as the issuer builds it (`decision_cert.certificate_leaf`, §3.2)."""
    return certificate_leaf(c).to_json()


def keyset_leaf(i: int) -> dict[str, Any]:
    return {"kind": "keyset", "keyset_id": "keyset:" + hex_id("keyset"), "seq": i, "keyset": doc_hash(f"keyset {i}")}


def ledger_leaf(i: int) -> dict[str, Any]:
    return {
        "kind": "ledger_entry",
        "ledger_id": "ledger:" + hex_id("ledger"),
        "seq": i,
        "entry": doc_hash(f"entry {i}"),
    }


def attestation_leaf(i: int) -> dict[str, Any]:
    return {
        "kind": "attestation",
        "attestation": doc_hash(f"attestation {i}"),
        "certificate_id": ct.certificate_id(CERT_OPERATOR),
    }


def audit_head_leaf(i: int, tenant: str = TENANT) -> dict[str, Any]:
    return {
        "kind": "audit_head",
        "tenant": tenant,
        "chain": "console-audit",
        "seq": i,
        "digest": doc_hash(f"audit head {i}"),
        "observed_at": time_of(T0 - 86_400 + 60 * i),
    }


def log_a_leaves() -> list[dict[str, Any]]:
    """acme-bank's log: three certificates backfilled when the log started (§12: by fitted_at, then
    certificate_id), then every other kind in turn, with one more certificate at 150; 300 leaves."""
    out = [cert_leaf(c) for c in backfill_order((CERT_V12, CERT_OPERATOR, CERT_HOSTED))]
    kinds: list[Callable[[int], dict[str, Any]]] = [keyset_leaf, ledger_leaf, attestation_leaf, audit_head_leaf]
    for i in range(3, 300):
        out.append(cert_leaf(CERT_COST) if i == 150 else kinds[i % 4](i))
    return out


A_LEAVES = log_a_leaves()
A_HASHES = [jcs_leaf_hash(x) for x in A_LEAVES]
CERT_AT = {ct.certificate_id(c): c for c in (CERT_V12, CERT_OPERATOR, CERT_HOSTED, CERT_COST)}
# globex's log: the v1.2 certificate, then key sets
G_LEAVES = [cert_leaf(CERT_V12), *(keyset_leaf(i) for i in range(1, 4))]
G_HASHES = [jcs_leaf_hash(x) for x in G_LEAVES]


# ---------- checkpoints and cosignatures (§5) ----------


def c2sp_id(name: str, sig_type: int, k: Ed25519PrivateKey) -> bytes:
    return hashlib.sha256(name.encode() + b"\n" + bytes([sig_type]) + raw(k)).digest()[:4]


def note_text(origin: str, size: int | str, root: bytes | str) -> str:
    return f"{origin}\n{size}\n{root if isinstance(root, str) else b64(root)}\n"


def log_line(text: str, k: Ed25519PrivateKey = LOG_A_KEY, name: str = LOG_A, sig: bytes | None = None) -> str:
    value = c2sp_id(name, 0x01, k) + (k.sign(text.encode()) if sig is None else sig)
    return f"{EM} {name} {b64(value)}\n"


def cosig_line(
    text: str, name: str, t: int, k: Ed25519PrivateKey | None = None, *, sign_time: int | None = None
) -> str:
    k = W[name] if k is None else k
    signed = f"cosignature/v1\ntime {t if sign_time is None else sign_time}\n{text}".encode()
    value = c2sp_id(name, 0x04, k) + t.to_bytes(8, "big") + k.sign(signed)
    return f"{EM} {name} {b64(value)}\n"


def checkpoint(text: str, lines: Sequence[str]) -> str:
    return text + "\n" + "".join(lines)


def a_note(size: int) -> str:
    return note_text(LOG_A, size, mth(A_HASHES[:size]))


def a_checkpoint(size: int, cosigners: Sequence[tuple[str, int]] | None = None) -> str:
    """A checkpoint of acme-bank's log at `size`, signed by the log and cosigned by `cosigners` (by
    default witness w1 at T0 + size)."""
    text = a_note(size)
    cos = [(W1, T0 + size)] if cosigners is None else cosigners
    return checkpoint(text, [log_line(text), *(cosig_line(text, n, t) for n, t in cos)])


# ---------- documents ----------


def bundle(index: int, size: int, cp: str | None = None, leaves: Sequence[dict[str, Any]] = A_LEAVES) -> dict[str, Any]:
    """acme-bank's log's bundle for the leaf at `index`, against the checkpoint at `size`."""
    leaf = leaves[index]
    hashes = [jcs_leaf_hash(x) for x in leaves[:size]]
    out: dict[str, Any] = {
        "spec": SPEC_BUNDLE,
        "log_id": LOG_A,
        "leaf_index": index,
        "leaf": copy.deepcopy(leaf),
        "proof": [b64(x) for x in path(hashes, index)],
        "checkpoint": a_checkpoint(size) if cp is None else cp,
    }
    if leaf["kind"] == "certificate":
        out["certificate"] = copy.deepcopy(CERT_AT[leaf["certificate_id"]])
    return out


def consistency(older: int, newer: int, older_cp: str | None = None, newer_cp: str | None = None) -> dict[str, Any]:
    return {
        "spec": SPEC_CONSISTENCY,
        "log_id": LOG_A,
        "older": a_checkpoint(older) if older_cp is None else older_cp,
        "newer": a_checkpoint(newer) if newer_cp is None else newer_cp,
        "proof": [b64(x) for x in proof(older, A_HASHES[:newer])] if older <= newer else [],
    }


def log_entry(
    log_id: str, k: Ed25519PrivateKey, key_name: str | None = None, started_at: str | None = None
) -> dict[str, Any]:
    out = {
        "log_id": log_id,
        "key_name": log_id if key_name is None else key_name,
        "key_id": kid(k),
        "key": ct.b64url(raw(k)),
    }
    if started_at is not None:
        out["started_at"] = started_at
    return out


def witness_entry(name: str, k: Ed25519PrivateKey | None = None) -> dict[str, Any]:
    k = W[name] if k is None else k
    return {"name": name, "key_id": kid(k), "key": ct.b64url(raw(k))}


def trust(
    tenant: str = TENANT,
    logs: Sequence[dict[str, Any]] | None = None,
    witnesses: Sequence[str] = (W1,),
    **extra: Any,
) -> dict[str, Any]:
    return {
        "spec": SPEC_LOG_TRUST,
        "tenant": tenant,
        "logs": [log_entry(LOG_A, LOG_A_KEY)] if logs is None else list(logs),
        "witnesses": [witness_entry(w) for w in witnesses],
        **extra,
    }


# ---------- expectations, from construction ----------


def accepted(
    b: dict[str, Any],
    size: int,
    root: bytes,
    cosigners: Sequence[tuple[str, int]],
    trusted: Sequence[str],
    m: int,
    backfilled_by: Sequence[str] = (),
) -> dict[str, Any]:
    """The verdict a bundle built here must get: its tree, the checkpoint's size and root, and the
    cosignatures of the trusted witnesses written into it, by time then name; `t_proven` the m-th. For a
    certificate leaf, the backfilled mark the case is built to get (`backfilled_by`: "bundle" for a bundle
    built with `backfilled`, "started_at" for a configuration whose `started_at` is after the certificate's
    `fitted_at`, in that order; none by default)."""
    counted = sorted(((t, n) for n, t in cosigners if n in trusted), key=lambda x: (x[0], x[1].encode()))
    assert len(counted) >= m
    out = {
        "verdict": "accepted",
        "log_id": b["log_id"],
        "tree_size": size,
        "root_hash": b64(root),
        "leaf_index": b["leaf_index"],
        "kind": b["leaf"]["kind"],
        "witnesses": [{"key_id": kid(W[n]), "name": n, "time": time_of(t)} for t, n in counted],
        "t_proven": time_of(counted[m - 1][0]),
    }
    if b["leaf"]["kind"] == "certificate":
        out["certificate_id"] = ct.certificate_id(b["certificate"])
        assert list(backfilled_by) in ([], ["bundle"], ["started_at"], ["bundle", "started_at"]), backfilled_by
        out["backfilled"] = bool(backfilled_by)
        out["backfilled_by"] = list(backfilled_by)
    else:
        assert not backfilled_by
    return out


def refused(error: str) -> dict[str, Any]:
    assert error in ERROR_NAMES, error
    return {"verdict": "refused", "error": error}


# ---------- the set ----------


@dataclass
class FixtureSet:
    files: dict[str, str] = field(default_factory=dict)
    cases: list[dict[str, Any]] = field(default_factory=list)

    def put(self, rel: str, v: Any) -> str:
        assert rel not in self.files, rel
        self.files[rel] = v if isinstance(v, str) else json.dumps(v, indent=2, ensure_ascii=False) + "\n"
        return rel

    def trust(self, name: str, v: Any) -> str:
        return self.put(f"trust/{name}.json", v)

    def bundle(self, name: str, v: Any, trust_file: str, expect: dict[str, Any]) -> None:
        doc = self.put(f"bundles/{name}.json", v)
        self.cases.append(
            {"name": f"bundle_{name}", "check": "bundle", "doc": doc, "trust": trust_file, "expect": expect}
        )

    def consistency(self, name: str, v: Any, trust_file: str, expect: dict[str, Any]) -> None:
        doc = self.put(f"consistency/{name}.json", v)
        self.cases.append(
            {"name": f"consistency_{name}", "check": "consistency", "doc": doc, "trust": trust_file, "expect": expect}
        )


def build() -> FixtureSet:
    fs = FixtureSet()
    fs.cases.extend(rfc_cases())

    # trust configurations
    t_a = fs.trust("acme-bank", trust())
    three = (W1, W2, W3)
    t_m2 = fs.trust("acme-bank-m2", trust(witnesses=three, m=2))
    t_m3 = fs.trust("acme-bank-m3", trust(witnesses=three, m=3))
    t_three_m1 = fs.trust("acme-bank-three-witnesses", trust(witnesses=three))
    policies = {p: fs.trust(f"acme-bank-policy-{p}", trust(policy=p)) for p in ("off", "warn", "refuse")}
    t_g = fs.trust("globex", trust(OTHER_TENANT, [log_entry(LOG_G, LOG_G_KEY)]))
    t_g_log_a = fs.trust("globex-holding-log-a", trust(OTHER_TENANT, [log_entry(LOG_A, LOG_A_KEY)]))
    t_g_key_a = fs.trust("globex-log-g-with-log-a-key", trust(OTHER_TENANT, [log_entry(LOG_G, LOG_A_KEY)]))
    t_two_logs = fs.trust(
        "acme-bank-two-logs", trust(logs=[log_entry(LOG_A, LOG_A_KEY), log_entry(LOG_G, LOG_G_KEY)], witnesses=three)
    )
    # the log's started_at (§9): after, at, and before the certificates' fitted_at
    started = {
        when: fs.trust(f"acme-bank-started-{when}", trust(logs=[log_entry(LOG_A, LOG_A_KEY, started_at=at)]))
        for when, at in (("after", STARTED_AFTER), ("at", FITTED_AT), ("before", STARTED_BEFORE))
    }
    for name, f, m, pol in (
        ("acme-bank", t_a, 1, "warn"),
        ("acme-bank-m2", t_m2, 2, "warn"),
        ("acme-bank-m3", t_m3, 3, "warn"),
        ("acme-bank-three-witnesses", t_three_m1, 1, "warn"),
        *((f"acme-bank-policy-{p}", policies[p], 1, p) for p in ("off", "warn", "refuse")),
        ("globex", t_g, 1, "warn"),
        ("acme-bank-two-logs", t_two_logs, 1, "warn"),
        *((f"acme-bank-started-{w}", started[w], 1, "warn") for w in ("after", "at", "before")),
        ("globex-holding-log-a", t_g_log_a, 1, "warn"),
        ("globex-log-g-with-log-a-key", t_g_key_a, 1, "warn"),
    ):
        tenant = OTHER_TENANT if name.startswith("globex") else TENANT
        fs.cases.append(
            {
                "name": f"trust_{name}",
                "check": "trust",
                "trust": f,
                "expect": {"verdict": "accepted", "tenant": tenant, "m": m, "policy": pol},
            }
        )
    trust_form_cases(fs)

    # several tenants' configurations (§2, §9)
    for name, files, expect in (
        ("tenants_acme_bank_and_globex", [t_a, t_g], {"verdict": "accepted"}),
        ("tenants_one_log_id_under_two_tenants", [t_a, t_g_log_a], refused("trust_cross_tenant")),
        ("tenants_one_log_key_under_two_tenants", [t_a, t_g_key_a], refused("trust_cross_tenant")),
        ("tenants_same_tenant_twice", [t_a, t_m2], {"verdict": "accepted"}),
    ):
        fs.cases.append({"name": name, "check": "tenants", "trusts": files, "expect": expect})

    # leaf hashes (§4)
    for name, leaf in (
        ("certificate_v1_2", cert_leaf(CERT_V12)),
        ("certificate_v1_5", cert_leaf(CERT_OPERATOR)),
        ("ledger_entry", ledger_leaf(5)),
        ("keyset", keyset_leaf(4)),
        ("attestation", attestation_leaf(6)),
        ("audit_head", audit_head_leaf(7)),
    ):
        f = fs.put(f"leaves/{name}.json", leaf)
        fs.cases.append(
            {
                "name": f"leaf_hash_{name}",
                "check": "leaf_hash",
                "leaf": f,
                "expect": {"leaf_hash": b64(jcs_leaf_hash(leaf))},
            }
        )

    positive_bundles(fs, t_a, t_m2, t_m3, t_three_m1, t_g)
    backfilled_bundles(fs, t_a, started)
    negative_bundles(fs, t_a, t_m2, t_g, t_g_log_a)
    consistency_cases(fs, t_a, t_two_logs)
    policy_cases(fs, policies)

    names = [c["name"] for c in fs.cases]
    assert len(names) == len(set(names)), [n for n in names if names.count(n) > 1]
    seen = {c["expect"].get("error") for c in fs.cases if isinstance(c["expect"], dict)}
    assert set(ERROR_NAMES) <= seen, f"error names without a case: {set(ERROR_NAMES) - seen}"
    fs.put(
        "manifest.json", {"spec": SPEC_BUNDLE, "draft": "spec/drafts/decision-cert-inclusion.v1.md", "cases": fs.cases}
    )
    return fs


def trust_form_cases(fs: FixtureSet) -> None:
    small_order = ct.b64url(bytes([1]) + bytes(31))  # the identity point: of small order
    base = trust(witnesses=(W1, W2))
    edits: list[tuple[str, Callable[[dict[str, Any]], Any]]] = [
        ("wrong_spec", lambda t: t.update(spec="decision-cert-log-trust.v2")),
        ("bundle_spec", lambda t: t.update(spec=SPEC_BUNDLE)),
        ("missing_witnesses", lambda t: t.pop("witnesses")),
        ("unknown_member", lambda t: t.update(note="x")),
        ("tenant_bad_charset", lambda t: t.update(tenant="acme bank")),
        ("tenant_too_long", lambda t: t.update(tenant="a" * 129)),
        ("logs_empty", lambda t: t.update(logs=[])),
        ("witnesses_not_array", lambda t: t.update(witnesses={})),
        ("log_id_uppercase", lambda t: t["logs"][0].update(log_id=LOG_A.upper().replace("LOG:", "log:"))),
        ("log_entry_unknown_member", lambda t: t["logs"][0].update(url="https://log.example")),
        ("log_key_name_with_plus", lambda t: t["logs"][0].update(key_name="log+a")),
        ("key_id_not_of_key", lambda t: t["logs"][0].update(key_id=kid(LOG_G_KEY))),
        ("key_small_order", lambda t: t["logs"][0].update(key=small_order, key_id=raw_key_id(bytes([1]) + bytes(31)))),
        ("key_padded_base64url", lambda t: t["witnesses"][0].update(key=t["witnesses"][0]["key"] + "=")),
        ("key_31_bytes", lambda t: t["witnesses"][0].update(key=ct.b64url(raw(W[W1])[:31]))),
        ("witness_name_with_space", lambda t: t["witnesses"][0].update(name="witness w1")),
        ("witness_name_empty", lambda t: t["witnesses"][0].update(name="")),
        ("m_zero", lambda t: t.update(m=0)),
        ("m_above_witnesses", lambda t: t.update(m=3)),
        ("m_float", lambda t: t.update(m=1.0)),
        ("m_null", lambda t: t.update(m=None)),
        ("policy_unknown", lambda t: t.update(policy="strict")),
        ("policy_null", lambda t: t.update(policy=None)),
        ("two_logs_one_log_id", lambda t: t["logs"].append(log_entry(LOG_A, LOG_G_KEY))),
        ("two_logs_one_key", lambda t: t["logs"].append(log_entry(LOG_G, LOG_A_KEY))),
        ("two_witnesses_one_name", lambda t: t["witnesses"].append(witness_entry(W1, W[W3]))),
        ("two_witnesses_one_key", lambda t: t["witnesses"].append(witness_entry(W3, W[W1]))),
        ("witness_key_is_log_key", lambda t: t["witnesses"].append(witness_entry(W3, LOG_A_KEY))),
        ("started_at_date_only", lambda t: t["logs"][0].update(started_at="2026-11-01")),
        ("started_at_leap_second", lambda t: t["logs"][0].update(started_at="2026-12-31T23:59:60Z")),
        ("started_at_offset", lambda t: t["logs"][0].update(started_at="2026-11-01T00:00:00+00:00")),
        ("started_at_null", lambda t: t["logs"][0].update(started_at=None)),
        ("started_at_number", lambda t: t["logs"][0].update(started_at=1_800_000_000)),
        ("started_at_at_top_level", lambda t: t.update(started_at=STARTED_AFTER)),
    ]
    for name, edit in edits:
        t = copy.deepcopy(base)
        edit(t)
        f = fs.trust(f"invalid_{name}", t)
        fs.cases.append(
            {"name": f"trust_invalid_{name}", "check": "trust", "trust": f, "expect": refused("trust_form")}
        )
    text = json.dumps(base, indent=2).replace('"spec": ', '"tenant": "acme-bank",\n  "spec": ', 1)
    f = fs.trust("invalid_member_named_twice", text + "\n")
    fs.cases.append(
        {"name": "trust_invalid_member_named_twice", "check": "trust", "trust": f, "expect": refused("trust_form")}
    )
    f = fs.trust("invalid_not_an_object", [base])
    fs.cases.append(
        {"name": "trust_invalid_not_an_object", "check": "trust", "trust": f, "expect": refused("trust_form")}
    )


def positive_bundles(fs: FixtureSet, t_a: str, t_m2: str, t_m3: str, t_three_m1: str, t_g: str) -> None:
    def ok(
        name: str,
        index: int,
        size: int,
        cos: Sequence[tuple[str, int]] | None = None,
        tf: str = t_a,
        trusted: Sequence[str] = (W1,),
        m: int = 1,
    ) -> None:
        cos = [(W1, T0 + size)] if cos is None else cos
        b = bundle(index, size, a_checkpoint(size, cos))
        fs.bundle(name, b, tf, accepted(b, size, mth(A_HASHES[:size]), cos, trusted, m))

    # tree sizes 1, 2, 3, 7, 8 and 300, at the first, a middle and the last index
    for size, indices in (
        (1, (0,)),
        (2, (0, 1)),
        (3, (0, 1, 2)),
        (7, (0, 3, 6)),
        (8, (0, 4, 5, 7)),
        (300, (0, 150, 299)),
    ):
        for i in indices:
            ok(f"valid_size_{size}_index_{i}_{A_LEAVES[i]['kind']}", i, size)
    # the certificate leaves: v1.2, v1.5 operator, v1.5 hosted, all three backfilled (§12), at a later checkpoint
    for i in range(3):
        c = CERT_AT[A_LEAVES[i]["certificate_id"]]
        tag = "v1_2" if c["spec"] != "decision-certificate.v1.5" else c["signer"]["mode"]
        ok(f"valid_certificate_{tag}_backfilled", i, 37)
    # m = 2 of three witnesses, two of them cosigning; m = 2 and m = 3 with all three, two at one time
    # (listed by time, then name); untrusted and other-key lines ignored
    ok("valid_m2_two_of_three_cosign", 20, 64, [(W1, T0 + 30), (W3, T0 + 10)], t_m2, (W1, W2, W3), 2)
    ok(
        "valid_m2_three_cosign_ties_by_name",
        20,
        64,
        [(W3, T0 + 20), (W1, T0 + 20), (W2, T0 + 5)],
        t_m2,
        (W1, W2, W3),
        2,
    )
    ok("valid_m3_three_cosign", 20, 64, [(W2, T0 + 40), (W1, T0 + 5), (W3, T0 + 20)], t_m3, (W1, W2, W3), 3)
    ok(
        "valid_m1_three_witnesses_earliest",
        20,
        64,
        [(W2, T0 + 40), (W1, T0 + 5), (W3, T0 + 20)],
        t_three_m1,
        (W1, W2, W3),
        1,
    )
    ok("valid_m1_untrusted_witnesses_ignored", 9, 12, [(W2, T0 + 1), (W1, T0 + 9), (W3, T0 + 2)], t_a, (W1,), 1)
    size = 12
    text = a_note(size)
    cos = [(W1, T0 + 50)]
    lines = [
        cosig_line(text, ROGUE_W, T0 + 1, ROGUE_W_KEY),
        log_line(text),
        cosig_line(text, W1, T0 + 50),
        cosig_line(text, W1, T0 + 2, ROGUE_W_KEY),  # w1's name, another key: another key ID, ignored
        log_line(text, ROGUE_LOG_KEY),  # the log's name, another key: ignored
    ]
    b = bundle(10, size, checkpoint(text, lines))
    fs.bundle("valid_lines_of_other_keys_ignored", b, t_a, accepted(b, size, mth(A_HASHES[:size]), cos, (W1,), 1))
    # a cosignature time at the top of v1's range
    ok("valid_cosignature_time_9999", 11, 12, [(W1, MAX_COSIGNATURE_TIME)])
    # §6: the leftmost leaf's path in a tree of 3 leaves leads to that tree's root at size 4 as well; a
    # checkpoint the log signs with size 4 and that root accepts it (the size and root are signed together)
    text = note_text(LOG_A, 4, mth(A_HASHES[:3]))
    b = bundle(0, 3, checkpoint(text, [log_line(text), cosig_line(text, W1, T0)]))
    fs.bundle(
        "valid_path_for_size_3_under_size_4_with_its_root",
        b,
        t_a,
        accepted(b, 4, mth(A_HASHES[:3]), [(W1, T0)], (W1,), 1),
    )
    # a v1.2 certificate in globex's log, checked against globex's configuration
    text = note_text(LOG_G, 4, mth(G_HASHES))
    gb = {
        "spec": SPEC_BUNDLE,
        "log_id": LOG_G,
        "leaf_index": 0,
        "leaf": G_LEAVES[0],
        "proof": [b64(x) for x in path(G_HASHES, 0)],
        "checkpoint": checkpoint(text, [log_line(text, LOG_G_KEY, LOG_G), cosig_line(text, W1, T0 + 3)]),
        "certificate": CERT_V12,
    }
    fs.bundle("valid_globex_v1_2_certificate", gb, t_g, accepted(gb, 4, mth(G_HASHES), [(W1, T0 + 3)], (W1,), 1))


def backfilled_bundles(fs: FixtureSet, t_a: str, started: dict[str, str]) -> None:
    """The backfilled mark (§8, §9, §10 "Backfilled"): the bundle's `backfilled` (the bundler's statement), the
    configuration's `started_at` (the consumer's own), both, neither. A mark, never a refusal."""

    def ok(name: str, index: int, tf: str, marked: bool, by: Sequence[str], size: int = 37) -> None:
        cos = [(W1, T0 + size)]
        b = bundle(index, size, a_checkpoint(size, cos))
        if marked:
            b["backfilled"] = True
        fs.bundle(name, b, tf, accepted(b, size, mth(A_HASHES[:size]), cos, (W1,), 1, by))

    hosted = _index_of(CERT_HOSTED)
    ok("valid_backfilled_marked_by_bundle", hosted, t_a, True, ["bundle"])
    # a bundle without the member (or stripped of it) is marked all the same when started_at is configured
    ok("valid_backfilled_started_after_fitted_at", hosted, started["after"], False, ["started_at"])
    ok("valid_backfilled_started_at_fitted_at", hosted, started["at"], False, [])
    ok("valid_backfilled_started_before_fitted_at", hosted, started["before"], False, [])
    ok("valid_backfilled_by_bundle_and_started_at", hosted, started["after"], True, ["bundle", "started_at"])
    ok("valid_backfilled_by_bundle_started_before", hosted, started["before"], True, ["bundle"])
    ok("valid_backfilled_v1_2_started_after", _index_of(CERT_V12), started["after"], False, ["started_at"])
    # other kinds: no mark is reported, whatever started_at says
    ok("valid_backfilled_keyset_leaf_no_mark", 4, started["after"], False, [], 8)

    def bad(name: str, index: int, size: int, value: Any) -> None:
        b = bundle(index, size)
        b["backfilled"] = value
        fs.bundle(f"invalid_{name}", b, t_a, refused("bundle_form"))

    bad("backfilled_false", hosted, 8, False)
    bad("backfilled_string", hosted, 8, "true")
    bad("backfilled_number", hosted, 8, 1)
    bad("backfilled_null", hosted, 8, None)
    bad("backfilled_beside_keyset_leaf", 4, 8, True)


def negative_bundles(fs: FixtureSet, t_a: str, t_m2: str, t_g: str, t_g_log_a: str) -> None:
    def bad(name: str, b: Any, error: str, tf: str = t_a) -> None:
        fs.bundle(f"invalid_{name}", b, tf, refused(error))

    def edited(edit: Callable[[dict[str, Any]], Any], index: int = 4, size: int = 8) -> dict[str, Any]:
        b = bundle(index, size)
        edit(b)
        return b

    def cp_edited(edit: Callable[[str], str], index: int = 4, size: int = 8) -> dict[str, Any]:
        b = bundle(index, size)
        b["checkpoint"] = edit(b["checkpoint"])
        return b

    # check 2: the bundle's form
    bad("wrong_spec", edited(lambda b: b.update(spec="decision-cert-inclusion.v2")), "bundle_form")
    bad("consistency_spec", edited(lambda b: b.update(spec=SPEC_CONSISTENCY)), "bundle_form")
    bad("unknown_member", edited(lambda b: b.update(note="x")), "bundle_form")
    bad("missing_proof", edited(lambda b: b.pop("proof")), "bundle_form")
    bad("log_id_uppercase", edited(lambda b: b.update(log_id=LOG_A[:4] + LOG_A[4:].upper())), "bundle_form")
    bad("leaf_index_negative", edited(lambda b: b.update(leaf_index=-1)), "bundle_form")
    bad("leaf_index_float", edited(lambda b: b.update(leaf_index=4.0)), "bundle_form")
    bad("leaf_index_above_2_53", edited(lambda b: b.update(leaf_index=2**53)), "bundle_form")
    bad("leaf_index_string", edited(lambda b: b.update(leaf_index="4")), "bundle_form")
    bad("leaf_not_an_object", edited(lambda b: b.update(leaf=json.dumps(b["leaf"]))), "bundle_form")
    bad("proof_not_an_array", edited(lambda b: b.update(proof=b["proof"][0])), "bundle_form")
    bad("proof_65_hashes", edited(lambda b: b.update(proof=b["proof"] * 22)), "bundle_form")
    bad("proof_hash_31_bytes", edited(lambda b: b["proof"].__setitem__(0, b64(bytes(31)))), "bundle_form")
    bad(
        "proof_hash_base64url",
        edited(lambda b: b["proof"].__setitem__(0, b64(b"\xfb" * 32).replace("+", "-").replace("/", "_"))),
        "bundle_form",
    )
    bad(
        "proof_hash_noncanonical_base64",
        edited(lambda b: b["proof"].__setitem__(0, noncanonical(b["proof"][0]))),
        "bundle_form",
    )
    bad("checkpoint_not_a_string", edited(lambda b: b.update(checkpoint=b["checkpoint"].split("\n"))), "bundle_form")
    bad("not_an_object", [bundle(4, 8)], "bundle_form")
    text = json.dumps(bundle(4, 8), indent=2, ensure_ascii=False).replace(
        '"spec": ', '"log_id": "' + LOG_A + '",\n  "spec": ', 1
    )
    bad("member_named_twice", text + "\n", "bundle_form")
    # a certificate present if and only if the leaf is a certificate leaf (clarification 2)
    cert = copy.deepcopy(CERT_OPERATOR)
    bad("certificate_beside_keyset_leaf", edited(lambda b: b.update(certificate=cert)), "bundle_form")
    bad(
        "certificate_beside_unknown_kind",
        edited(lambda b: (b.update(certificate=cert), b["leaf"].update(kind="receipt"))),
        "bundle_form",
    )
    bad(
        "certificate_beside_leaf_without_kind",
        edited(lambda b: (b.update(certificate=cert), b["leaf"].pop("kind"))),
        "bundle_form",
    )
    bad("certificate_leaf_without_certificate", edited(lambda b: b.pop("certificate"), index=1, size=8), "bundle_form")
    bad(
        "certificate_not_an_object",
        edited(lambda b: b.update(certificate=ct.certificate_id(b["certificate"])), index=1, size=8),
        "bundle_form",
    )

    # check 3: the leaf's form
    bad("leaf_unknown_kind", edited(lambda b: b["leaf"].update(kind="receipt")), "leaf_form")
    bad("leaf_kind_not_a_string", edited(lambda b: b["leaf"].update(kind=["keyset"])), "leaf_form")
    bad("leaf_missing_member", edited(lambda b: b["leaf"].pop("keyset")), "leaf_form")
    bad("leaf_unknown_member", edited(lambda b: b["leaf"].update(note="x")), "leaf_form")
    bad("leaf_seq_float", edited(lambda b: b["leaf"].update(seq=4.0)), "leaf_form")
    bad("leaf_seq_negative", edited(lambda b: b["leaf"].update(seq=-4)), "leaf_form")
    bad(
        "leaf_keyset_id_wrong_prefix",
        edited(lambda b: b["leaf"].update(keyset_id="ledger:" + hex_id("keyset"))),
        "leaf_form",
    )
    bad(
        "leaf_ledger_entry_hash_uppercase",
        edited(lambda b: b["leaf"].update(entry=b["leaf"]["entry"].upper().replace("SHA256:", "sha256:")), index=5),
        "leaf_form",
    )
    bad(
        "audit_head_malformed_digest",
        edited(lambda b: b["leaf"].update(digest="sha256:" + "g" * 64), index=7),
        "leaf_form",
    )
    bad(
        "audit_head_malformed_observed_at",
        edited(lambda b: b["leaf"].update(observed_at="2027-01-14T08:07:00+00:00"), index=7),
        "leaf_form",
    )
    bad(
        "audit_head_observed_at_leap_second",
        edited(lambda b: b["leaf"].update(observed_at="2026-12-31T23:59:60Z"), index=7),
        "leaf_form",
    )
    bad(
        "audit_head_observed_at_not_a_date",
        edited(lambda b: b["leaf"].update(observed_at="2027-02-29T00:00:00Z"), index=7),
        "leaf_form",
    )
    bad("audit_head_seq_zero", edited(lambda b: b["leaf"].update(seq=0), index=7), "leaf_form")
    bad("audit_head_chain_empty", edited(lambda b: b["leaf"].update(chain=""), index=7), "leaf_form")
    bad("audit_head_tenant_bad_charset", edited(lambda b: b["leaf"].update(tenant="acme/bank"), index=7), "leaf_form")
    bad(
        "certificate_leaf_v1_2_with_tenant",
        edited(lambda b: b["leaf"].update(tenant=TENANT), index=_index_of(CERT_V12)),
        "leaf_form",
    )
    bad(
        "certificate_leaf_v1_5_without_tenant",
        edited(lambda b: b["leaf"].pop("tenant"), index=_index_of(CERT_OPERATOR)),
        "leaf_form",
    )
    bad(
        "certificate_leaf_unknown_spec",
        edited(lambda b: b["leaf"].update(spec="decision-certificate.v2"), index=_index_of(CERT_V12)),
        "leaf_form",
    )
    bad(
        "certificate_leaf_fitted_at_leap_second",
        edited(lambda b: b["leaf"].update(fitted_at="2026-10-25T12:00:60Z"), index=_index_of(CERT_V12)),
        "leaf_form",
    )
    bad(
        "certificate_leaf_signer_key_id_short",
        edited(lambda b: b["leaf"].update(signer_key_id="ed25519:56475aa7"), index=_index_of(CERT_V12)),
        "leaf_form",
    )

    # check 4: a certificate leaf matches its certificate
    v12, op = _index_of(CERT_V12), _index_of(CERT_OPERATOR)
    bad(
        "leaf_for_another_certificate",
        edited(lambda b: b.update(certificate=copy.deepcopy(CERT_HOSTED)), index=op),
        "leaf_mismatch",
    )
    bad(
        "certificate_changed",
        edited(lambda b: b["certificate"].update(n=b["certificate"]["n"] + 1), index=v12),
        "leaf_mismatch",
    )
    bad(
        "leaf_signer_key_id_differs",
        edited(lambda b: b["leaf"].update(signer_key_id=kid(LOG_A_KEY)), index=v12),
        "leaf_mismatch",
    )
    bad(
        "leaf_spec_differs",
        edited(lambda b: b["leaf"].update(spec="decision-certificate.v1.3"), index=v12),
        "leaf_mismatch",
    )
    bad(
        "leaf_fitted_at_differs",
        edited(lambda b: b["leaf"].update(fitted_at="2026-10-25T12:00:01Z"), index=v12),
        "leaf_mismatch",
    )
    bad(
        "leaf_tenant_differs_from_certificate",
        edited(lambda b: b["leaf"].update(tenant=OTHER_TENANT), index=op),
        "leaf_mismatch",
    )

    # check 5: the leaf's tenant is the configuration's
    bad("v1_5_certificate_for_another_tenant", bundle(op, 8), "tenant_mismatch", t_g_log_a)
    bad(
        "audit_head_for_another_tenant",
        edited(lambda b: b["leaf"].update(tenant=OTHER_TENANT), index=7),
        "tenant_mismatch",
    )

    # check 6: a log of the expected tenant
    text = note_text(LOG_G, 4, mth(G_HASHES))
    gb = {
        "spec": SPEC_BUNDLE,
        "log_id": LOG_G,
        "leaf_index": 0,
        "leaf": G_LEAVES[0],
        "proof": [b64(x) for x in path(G_HASHES, 0)],
        "checkpoint": checkpoint(text, [log_line(text, LOG_G_KEY, LOG_G), cosig_line(text, W1, T0 + 3)]),
        "certificate": CERT_V12,
    }
    bad("leaf_in_another_tenants_log", gb, "unknown_log")
    bad("log_id_unknown", edited(lambda b: b.update(log_id="log:" + hex_id("log z"))), "unknown_log")

    # check 7: the checkpoint's form (every rule of §5.1, never bundle_form: clarification 1)
    note8 = a_note(8)
    good8 = a_checkpoint(8)
    log8, w8 = log_line(note8), cosig_line(note8, W1, T0 + 8)
    root8 = b64(mth(A_HASHES[:8]))
    forms: list[tuple[str, str]] = [
        ("not_a_note", "a checkpoint"),
        ("empty", ""),
        ("missing_final_newline", good8[:-1]),
        ("text_after_last_line", good8 + "x"),
        ("extra_line_in_note_text", note8 + "extension\n\n" + log8 + w8),
        ("no_empty_line", note8 + log8 + w8),
        ("no_signature_lines", note8 + "\n"),
        ("empty_signature_line", note8 + "\n" + log8 + "\n" + w8),
        ("carriage_return", good8.replace("\n", "\r\n", 1)),
        ("tab", good8.replace(f"{EM} ", f"{EM}\t", 1)),
        ("empty_origin", checkpoint(note_text("", 8, root8), [log8])),
        ("size_zero", checkpoint(note_text(LOG_A, 0, root8), [log8])),
        ("size_leading_zero", checkpoint(note_text(LOG_A, "08", root8), [log8])),
        ("size_not_decimal", checkpoint(note_text(LOG_A, "0x8", root8), [log8])),
        ("size_above_2_64", checkpoint(note_text(LOG_A, str(2**64), root8), [log8])),
        ("root_noncanonical_base64", checkpoint(note_text(LOG_A, 8, noncanonical(root8)), [log8])),
        ("root_31_bytes", checkpoint(note_text(LOG_A, 8, b64(mth(A_HASHES[:8])[:31])), [log8])),
        ("root_unpadded", checkpoint(note_text(LOG_A, 8, root8.rstrip("=")), [log8])),
        ("signature_line_hyphen", good8.replace(f"{EM} ", "- ", 1)),
        ("signature_line_no_value", note8 + "\n" + f"{EM} {LOG_A}\n"),
        ("signature_noncanonical_base64", good8.replace(log8, noncanonical(log8[:-1]) + "\n")),
        ("signature_value_4_bytes", note8 + "\n" + f"{EM} {LOG_A} {b64(c2sp_id(LOG_A, 1, LOG_A_KEY))}\n"),
        ("key_name_with_plus", note8 + "\n" + log8 + log_line(note8, LOG_A_KEY, "log+a")),
        ("key_name_256_characters", note8 + "\n" + log8 + log_line(note8, LOG_G_KEY, "n" * 256)),
        (
            "101_signature_lines",
            note8 + "\n" + log8 + "".join(log_line(note8, seeded(f"filler {i}"), f"filler{i}") for i in range(100)),
        ),
        ("log_line_twice", note8 + "\n" + log8 + log8 + w8),
        ("witness_cosignature_twice", note8 + "\n" + log8 + w8 + cosig_line(note8, W1, T0 + 9)),
    ]
    for name, cp in forms:
        b = bundle(4, 8)
        b["checkpoint"] = cp
        bad(f"checkpoint_{name}", b, "checkpoint_form")
    # one witness's cosignature twice with m = 2: refused, not counted once (§5.1)
    bad(
        "checkpoint_witness_twice_under_m2",
        cp_edited(lambda c: c + cosig_line(note8, W1, T0 + 9)),
        "checkpoint_form",
        t_m2,
    )
    # 100 lines are allowed: the 98 filler lines are ignored
    text = note8
    lines = [log8, w8, *(log_line(text, seeded(f"filler {i}"), f"filler{i}") for i in range(98))]
    b = bundle(4, 8, checkpoint(text, lines))
    fs.bundle("valid_100_signature_lines", b, t_a, accepted(b, 8, mth(A_HASHES[:8]), [(W1, T0 + 8)], (W1,), 1))

    # check 8: the checkpoint's origin
    text = note_text(LOG_G, 8, mth(A_HASHES[:8]))
    bad(
        "origin_another_log",
        edited(lambda b: b.update(checkpoint=checkpoint(text, [log_line(text), cosig_line(text, W1, T0)]))),
        "origin_mismatch",
    )

    # check 9: the audit path
    bad("leaf_member_changed", edited(lambda b: b["leaf"].update(seq=b["leaf"]["seq"] + 1)), "bad_proof")
    bad("wrong_leaf_index", edited(lambda b: b.update(leaf_index=5)), "bad_proof")
    bad("leaf_index_is_tree_size", edited(lambda b: b.update(leaf_index=8)), "bad_proof")
    bad(
        "path_for_another_tree_size",
        edited(lambda b: b.update(proof=[b64(x) for x in path(A_HASHES[:7], 4)])),
        "bad_proof",
    )
    bad("path_one_hash_short", edited(lambda b: b["proof"].pop()), "bad_proof")
    bad("path_one_hash_long", edited(lambda b: b["proof"].append(b["proof"][-1])), "bad_proof")
    bad("path_empty", edited(lambda b: b.update(proof=[])), "bad_proof")
    bad(
        "path_hash_altered",
        edited(
            lambda b: b["proof"].__setitem__(
                1, b64(bytes([base64.b64decode(b["proof"][1])[0] ^ 1]) + base64.b64decode(b["proof"][1])[1:])
            )
        ),
        "bad_proof",
    )
    bad(
        "path_of_size_300_against_size_8",
        edited(lambda b: b.update(proof=[b64(x) for x in path(A_HASHES, 4)])),
        "bad_proof",
    )
    # a tree hashed without the leaves' 0x00 prefix, signed and cosigned
    raw_hashes = [hashlib.sha256(ct.canonical(x)).digest() for x in A_LEAVES[:8]]
    text = note_text(LOG_A, 8, mth(raw_hashes))
    unprefixed = bundle(4, 8, checkpoint(text, [log_line(text), cosig_line(text, W1, T0)]))
    unprefixed["proof"] = [b64(x) for x in path(raw_hashes, 4)]
    bad("leaf_hashed_without_0x00_prefix", unprefixed, "bad_proof")

    # check 10: the log's signature
    other = a_note(7)
    bad(
        "log_signature_over_another_checkpoint",
        cp_edited(lambda c: c.replace(log8, log_line(note8, sig=LOG_A_KEY.sign(other.encode())))),
        "bad_log_signature",
    )
    sig = bytearray(LOG_A_KEY.sign(note8.encode()))
    sig[5] ^= 1
    bad(
        "log_signature_altered",
        cp_edited(lambda c: c.replace(log8, log_line(note8, sig=bytes(sig)))),
        "bad_log_signature",
    )
    bad(
        "log_signature_63_bytes",
        cp_edited(lambda c: c.replace(log8, log_line(note8, sig=LOG_A_KEY.sign(note8.encode())[:63]))),
        "bad_log_signature",
    )
    bad(
        "log_signature_with_timestamp",
        cp_edited(lambda c: c.replace(log8, log_line(note8, sig=bytes(8) + LOG_A_KEY.sign(note8.encode())))),
        "bad_log_signature",
    )
    bad(
        "log_signature_by_untrusted_key",
        cp_edited(lambda c: c.replace(log8, log_line(note8, ROGUE_LOG_KEY))),
        "log_signature_missing",
    )
    bad("log_signature_absent", cp_edited(lambda c: c.replace(log8, "")), "log_signature_missing")
    bad(
        "log_signature_under_another_name",
        cp_edited(lambda c: c.replace(log8, log_line(note8, name="log-a"))),
        "log_signature_missing",
    )
    bad(
        "log_signature_as_cosignature_type",
        cp_edited(lambda c: c.replace(log8, cosig_line(note8, LOG_A, T0, LOG_A_KEY))),
        "log_signature_missing",
    )

    # check 11: the witnesses' cosignatures
    bad(
        "cosignature_over_another_checkpoint",
        cp_edited(lambda c: c.replace(w8, cosig_line(a_note(7), W1, T0 + 8))),
        "bad_cosignature",
    )
    bad(
        "cosignature_time_changed",
        cp_edited(lambda c: c.replace(w8, cosig_line(note8, W1, T0 + 9, sign_time=T0 + 8))),
        "bad_cosignature",
    )
    bad(
        "cosignature_time_after_9999",
        cp_edited(lambda c: c.replace(w8, cosig_line(note8, W1, MAX_COSIGNATURE_TIME + 1))),
        "bad_cosignature",
    )
    no_time = f"{EM} {W1} {b64(c2sp_id(W1, 0x04, W[W1]) + W[W1].sign(note8.encode()))}\n"
    bad("cosignature_without_timestamp", cp_edited(lambda c: c.replace(w8, no_time)), "bad_cosignature")
    bad(
        "cosignature_of_one_witness_bad_among_three",
        cp_edited(
            lambda c: c.replace(
                w8, cosig_line(note8, W1, T0) + cosig_line(note8, W2, T0, sign_time=T0 + 1) + cosig_line(note8, W3, T0)
            )
        ),
        "bad_cosignature",
        t_m2,
    )

    # check 12: at least m distinct trusted witnesses
    bad("no_cosignature", cp_edited(lambda c: c.replace(w8, "")), "too_few_cosignatures")
    bad("one_cosignature_under_m2", bundle(4, 8), "too_few_cosignatures", t_m2)
    bad(
        "cosignature_from_untrusted_witness_only",
        cp_edited(lambda c: c.replace(w8, cosig_line(note8, ROGUE_W, T0, ROGUE_W_KEY))),
        "too_few_cosignatures",
    )
    bad(
        "cosignature_from_untrusted_witness_under_m2",
        cp_edited(lambda c: c + cosig_line(note8, ROGUE_W, T0, ROGUE_W_KEY)),
        "too_few_cosignatures",
        t_m2,
    )
    bad(
        "cosignature_by_another_key_under_witness_name",
        cp_edited(lambda c: c.replace(w8, cosig_line(note8, W1, T0, ROGUE_W_KEY))),
        "too_few_cosignatures",
    )
    bad(
        "cosignature_as_log_signature_type",
        cp_edited(lambda c: c.replace(w8, log_line(note8, W[W1], W1))),
        "too_few_cosignatures",
    )


def _index_of(c: dict[str, Any]) -> int:
    cid = ct.certificate_id(c)
    return next(i for i, x in enumerate(A_LEAVES) if x.get("certificate_id") == cid)


def consistency_cases(fs: FixtureSet, t_a: str, t_two_logs: str) -> None:
    def ok(name: str, doc: dict[str, Any], older: int, newer: int) -> None:
        fs.consistency(
            name, doc, t_a, {"verdict": "accepted", "log_id": doc["log_id"], "older_size": older, "newer_size": newer}
        )

    def bad(name: str, doc: Any, error: str, tf: str = t_a) -> None:
        fs.consistency(f"invalid_{name}", doc, tf, refused(error))

    def edited(edit: Callable[[dict[str, Any]], Any], older: int = 3, newer: int = 7) -> dict[str, Any]:
        d = consistency(older, newer)
        edit(d)
        return d

    for older, newer in ((1, 2), (3, 7), (7, 8), (8, 8), (1, 300), (100, 300), (150, 151), (299, 300)):
        ok(f"valid_{older}_to_{newer}", consistency(older, newer), older, newer)
    # cosignatures are not required, and witness lines are not checked (clarification 3)
    n3, n7 = a_note(3), a_note(7)
    bare = consistency(3, 7, checkpoint(n3, [log_line(n3)]), checkpoint(n7, [log_line(n7)]))
    ok("valid_log_signatures_only", bare, 3, 7)
    bad_w = consistency(3, 7, checkpoint(n3, [log_line(n3), cosig_line(n3, W1, T0, sign_time=T0 + 1)]))
    ok("valid_bad_witness_cosignature_not_checked", bad_w, 3, 7)
    over = consistency(3, 7, newer_cp=checkpoint(n7, [log_line(n7), cosig_line(n3, W1, T0)]))
    ok("valid_witness_cosignature_over_another_checkpoint_not_checked", over, 3, 7)

    # §7.2's form
    bad("wrong_spec", edited(lambda d: d.update(spec="decision-cert-consistency.v2")), "consistency_form")
    bad("bundle_given", bundle(4, 8), "consistency_form")
    bad("unknown_member", edited(lambda d: d.update(note="x")), "consistency_form")
    bad("missing_proof", edited(lambda d: d.pop("proof")), "consistency_form")
    bad("log_id_malformed", edited(lambda d: d.update(log_id="log-a")), "consistency_form")
    bad("older_not_a_string", edited(lambda d: d.update(older=None)), "consistency_form")
    bad("proof_not_base64", edited(lambda d: d["proof"].__setitem__(0, "not base64")), "consistency_form")
    bad("proof_65_hashes", edited(lambda d: d.update(proof=d["proof"] * 33)), "consistency_form")
    bad("not_an_object", [consistency(3, 7)], "consistency_form")
    text = json.dumps(consistency(3, 7), indent=2, ensure_ascii=False).replace(
        '"spec": ', '"proof": [],\n  "spec": ', 1
    )
    bad("member_named_twice", text + "\n", "consistency_form")
    # its log, checkpoints, origins and log signatures
    bad("log_id_unknown", edited(lambda d: d.update(log_id=LOG_G)), "unknown_log")
    bad("older_checkpoint_malformed", edited(lambda d: d.update(older=d["older"][:-1])), "checkpoint_form")
    bad("newer_checkpoint_not_a_note", edited(lambda d: d.update(newer="a checkpoint")), "checkpoint_form")
    bad(
        "newer_checkpoint_log_line_twice",
        edited(lambda d: d.update(newer=d["newer"] + log_line(n7))),
        "checkpoint_form",
    )
    bad(
        "newer_checkpoint_witness_line_twice",
        edited(lambda d: d.update(newer=d["newer"] + cosig_line(n7, W1, T0))),
        "checkpoint_form",
    )
    g7 = note_text(LOG_G, 7, mth(A_HASHES[:7]))
    bad("newer_origin_another_log", edited(lambda d: d.update(newer=checkpoint(g7, [log_line(g7)]))), "origin_mismatch")
    # checkpoints of log g, under a configuration that trusts both logs: g's checkpoint in a document for a
    bad(
        "checkpoint_of_another_trusted_log",
        edited(lambda d: d.update(newer=checkpoint(g7, [log_line(g7, LOG_G_KEY, LOG_G)]))),
        "origin_mismatch",
        t_two_logs,
    )
    bad(
        "older_log_signature_altered",
        edited(lambda d: d.update(older=checkpoint(n3, [log_line(n3, sig=LOG_A_KEY.sign(n7.encode()))]))),
        "bad_log_signature",
    )
    bad(
        "newer_log_signature_by_untrusted_key",
        edited(lambda d: d.update(newer=checkpoint(n7, [log_line(n7, ROGUE_LOG_KEY)]))),
        "log_signature_missing",
    )
    bad(
        "newer_cosigned_only",
        edited(lambda d: d.update(newer=checkpoint(n7, [cosig_line(n7, W1, T0)]))),
        "log_signature_missing",
    )
    bad(
        "log_signature_by_log_g_key",
        edited(lambda d: d.update(newer=checkpoint(n7, [log_line(n7, LOG_G_KEY)]))),
        "log_signature_missing",
        t_two_logs,
    )
    # sizes and the path
    bad("newer_smaller_than_older", consistency(7, 3), "size_regression")
    split_leaves = [*A_LEAVES[:5], keyset_leaf(10_000), *A_LEAVES[6:7]]
    split_note = note_text(LOG_A, 7, mth([jcs_leaf_hash(x) for x in split_leaves]))
    bad("split_view", consistency(7, 7, newer_cp=checkpoint(split_note, [log_line(split_note)])), "split_view")
    bad("path_altered", edited(lambda d: d["proof"].__setitem__(0, b64(bytes(32)))), "bad_consistency_proof")
    bad("path_empty", edited(lambda d: d.update(proof=[])), "bad_consistency_proof")
    bad("path_one_hash_short", edited(lambda d: d["proof"].pop()), "bad_consistency_proof")
    bad("path_one_hash_long", edited(lambda d: d["proof"].append(d["proof"][0])), "bad_consistency_proof")
    bad(
        "path_for_another_newer_size",
        edited(lambda d: d.update(proof=[b64(x) for x in proof(3, A_HASHES[:8])])),
        "bad_consistency_proof",
    )
    bad("equal_sizes_with_a_path", consistency(8, 8) | {"proof": [b64(mth(A_HASHES[:8]))]}, "bad_consistency_proof")
    # a newer checkpoint over another tree that does not extend the older one
    fork = [*A_LEAVES[:2], keyset_leaf(20_000), *A_LEAVES[3:7]]
    fork_note = note_text(LOG_A, 7, mth([jcs_leaf_hash(x) for x in fork]))
    bad(
        "newer_does_not_extend_older",
        consistency(3, 7, newer_cp=checkpoint(fork_note, [log_line(fork_note)])),
        "bad_consistency_proof",
    )


def policy_cases(fs: FixtureSet, policies: dict[str, str]) -> None:
    """§11: no bundle, a bundle that passes, a bundle that fails, under each policy."""
    good = bundle(_index_of(CERT_OPERATOR), 8)
    good_file = fs.put("bundles/policy_passes.json", good)
    failing = bundle(_index_of(CERT_OPERATOR), 8)
    failing["leaf_index"] = 2 if failing["leaf_index"] != 2 else 1
    failing_file = fs.put("bundles/policy_fails.json", failing)
    verdict = accepted(good, 8, mth(A_HASHES[:8]), [(W1, T0 + 8)], (W1,), 1)
    verdict.pop("verdict")
    expect: dict[tuple[str, str], dict[str, Any]] = {
        ("off", "none"): {"outcome": "load"},
        ("off", "passes"): {"outcome": "load"},
        ("off", "fails"): {"outcome": "load"},
        ("warn", "none"): {"outcome": "load_with_warning", "error": "inclusion_missing"},
        ("warn", "passes"): {"outcome": "load", "verdict": verdict},
        ("warn", "fails"): {"outcome": "refuse", "error": "bad_proof"},
        ("refuse", "none"): {"outcome": "refuse", "error": "inclusion_missing"},
        ("refuse", "passes"): {"outcome": "load", "verdict": verdict},
        ("refuse", "fails"): {"outcome": "refuse", "error": "bad_proof"},
    }
    docs = {"none": None, "passes": good_file, "fails": failing_file}
    for (p, d), e in expect.items():
        fs.cases.append(
            {"name": f"policy_{p}_{d}", "check": "policy", "trust": policies[p], "doc": docs[d], "expect": e}
        )


def rendered() -> dict[Path, str]:
    fs = build()
    files = {OUT / rel: text for rel, text in fs.files.items()}
    lines = [f"{hashlib.sha256(t.encode()).hexdigest()}  {rel}" for rel, t in fs.files.items()]
    files[OUT / "INCLUSION.sha256"] = "\n".join(sorted(lines, key=lambda x: x.split("  ")[1])) + "\n"
    return files


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="fail if any fixture would change, or a file is not ours")
    args = ap.parse_args()
    files = rendered()
    stale = [p for p, t in files.items() if not p.exists() or p.read_text(encoding="utf-8") != t]
    extra = [p for p in OUT.rglob("*") if p.is_file() and p not in files] if OUT.exists() else []
    if args.check:
        if stale or extra:
            names = ", ".join(p.relative_to(FIXTURES).as_posix() for p in [*stale, *extra])
            print(f"stale or unlisted: {names}; run tools/gen_inclusion_fixtures.py", file=sys.stderr)
            return 1
    else:
        for p in extra:
            p.unlink()
        for p in stale:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(files[p], encoding="utf-8")
    n = sum(1 for p in files if p.suffix == ".json")
    print(
        f"{'checked' if args.check else 'wrote'} fixtures/inclusion-v1 ({n} files, {len(stale) + len(extra)} changed)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
