"""The issuer's side of `decision-cert-inclusion.v1` (draft, spec/drafts/decision-cert-inclusion.v1.md):
the certificate leaf to append to a tenant's log, the backfill of certificates issued before the log
existed, and the bundle written once a proof arrives.

None of this calls a log. The issuer writes a certificate's leaf record (`leaf_record`) for whoever runs
the tenant's log to append, keeps the certificate with the leaf index the log gave it, and, once a
cosigned checkpoint includes the leaf, bundles the certificate with that checkpoint and its inclusion
proof (`bundle_certificate`). Until then the certificate is valid as a certificate; its proof follows at
the next cosigned checkpoint (`NotYetInCheckpoint`).

A leaf record is a JSON object with exactly `certificate_id`, `leaf` (§3) and `leaf_hash` (§4, standard
base64, the checkpoint's own encoding), written one per line (`leaf_records_text`). It is this
repository's tooling format, not part of the draft: only `leaf` is appended to the log.
"""

from __future__ import annotations

import base64
from collections.abc import Iterable, Mapping
from typing import Any

from ._inclusion import (
    SPEC_BUNDLE,
    ErrorName,
    InclusionError,
    InclusionVerdict,
    Leaf,
    LogTrust,
    leaf_hash,
    parse_checkpoint,
    verify_bundle,
)
from ._verify import SPEC_V1_5, Invalid, _tenant_ok, canonical, certificate_id


class NotYetInCheckpoint(InclusionError):
    """The checkpoint does not include the leaf yet: its tree size is not above `leaf_index`. The error
    name is §10's `bad_proof`; the certificate waits for a later cosigned checkpoint (plan, "Checkpoint
    cadence")."""

    def __init__(self, leaf_index: int, tree_size: int) -> None:
        super().__init__(
            ErrorName.BAD_PROOF,
            f"the checkpoint's tree of {tree_size} leaves does not include leaf {leaf_index} yet: bundle the "
            "certificate against a later cosigned checkpoint",
        )
        self.leaf_index = leaf_index
        self.tree_size = tree_size


def certificate_leaf(cert: Any) -> Leaf:
    """A certificate's leaf (§3.2): `kind`, `certificate_id` (the certificate's document hash), and its
    `signer_key_id`, `spec` and `fitted_at`, with `tenant` for a v1.5 certificate only. Refused as
    `leaf_form` when the certificate's values are out of the leaf's forms."""
    if not isinstance(cert, Mapping):
        raise InclusionError(ErrorName.LEAF_FORM, "a certificate is a JSON object")
    try:
        cid = certificate_id(cert)
    except Invalid as e:
        raise InclusionError(ErrorName.LEAF_FORM, str(e)) from None
    leaf: dict[str, Any] = {
        "kind": "certificate",
        "certificate_id": cid,
        "signer_key_id": cert.get("signer_key_id"),
        "spec": cert.get("spec"),
        "fitted_at": cert.get("fitted_at"),
    }
    if cert.get("spec") == SPEC_V1_5:
        leaf["tenant"] = cert.get("tenant")
    return Leaf.from_json(leaf)


def leaf_record(cert: Any) -> dict[str, Any]:
    """The leaf record of a certificate: `{"certificate_id", "leaf", "leaf_hash"}`, the hash in standard
    base64."""
    leaf = certificate_leaf(cert)
    return {
        "certificate_id": leaf.get_str("certificate_id"),
        "leaf": leaf.to_json(),
        "leaf_hash": base64.b64encode(leaf_hash(leaf)).decode("ascii"),
    }


def leaf_records_text(records: Iterable[Mapping[str, Any]]) -> str:
    """Leaf records as JSON Lines: one record per line, as its JCS text (members sorted, no spaces)."""
    return "".join(canonical(r).decode("utf-8") + "\n" for r in records)


def backfill_order(certs: Iterable[Any]) -> list[Any]:
    """The certificates in backfill order (§12): by `fitted_at`, then by `certificate_id` (ASCII order),
    each certificate once (a second copy of one certificate is dropped). A value that is not a
    certificate is refused as `leaf_form` (`certificate_leaf`)."""
    by_id: dict[str, tuple[str, Any]] = {}
    for c in certs:
        leaf = certificate_leaf(c)
        cid, fitted_at = leaf.get_str("certificate_id"), leaf.get_str("fitted_at")
        assert cid is not None and fitted_at is not None  # by the leaf's form
        by_id.setdefault(cid, (fitted_at, c))
    return [by_id[k][1] for k in sorted(by_id, key=lambda k: (by_id[k][0], k))]


def backfill_records(certs: Iterable[Any], tenant: str) -> list[dict[str, Any]]:
    """The leaf records to append to `tenant`'s log when it starts, before any new leaf, in backfill
    order (§12). A v1.5 certificate for another tenant is refused (`tenant_mismatch`): a log holds one
    tenant's leaves (§2); a `tenant` out of v1.5's form raises `ValueError`. A v1 to v1.4 certificate
    names no tenant: the issuer passes only `tenant`'s certificates.

    Nothing marks a backfilled leaf (§12): it has the form of any certificate leaf. It gets no early time
    evidence because of where it is: its `t_proven` is the cosignature time of the first checkpoint that
    includes it, after the log started, whatever its `fitted_at` says."""
    if not _tenant_ok(tenant):
        raise ValueError(f"tenant {tenant!r} is not 1 to 128 of A-Z a-z 0-9 . _ : -")
    records = []
    for c in backfill_order(certs):
        rec = leaf_record(c)
        t = rec["leaf"].get("tenant")
        if t is not None and t != tenant:
            raise InclusionError(
                ErrorName.TENANT_MISMATCH,
                f"certificate {rec['certificate_id']} is for tenant {t}, not {tenant}: it belongs in its own "
                "tenant's log",
            )
        records.append(rec)
    return records


def bundle_certificate(
    cert: Any, leaf_index: Any, proof: Any, checkpoint: Any, trust: LogTrust, log_id: str | None = None
) -> tuple[dict[str, Any], InclusionVerdict]:
    """The bundle (§8) for a certificate whose leaf is at `leaf_index` in the log, with the inclusion
    `proof` (§6, base64 node hashes) against `checkpoint` (its full signed-note text, cosignatures
    included), and its verdict under `trust`. The leaf is built from the certificate; `log_id` is the
    checkpoint's origin unless given.

    The bundle is checked as a consumer checks it (`verify_bundle`, §10) before it is returned, and
    refused with that check's error otherwise: a proof for another certificate's leaf (`bad_proof`), a
    certificate for another tenant (`tenant_mismatch`), a log the configuration does not hold
    (`unknown_log`). A checkpoint whose tree does not reach `leaf_index` yet raises `NotYetInCheckpoint`.
    The certificate itself is not verified here; `verify_for_tenant` does that."""
    leaf = certificate_leaf(cert)
    if log_id is None:
        log_id = checkpoint.split("\n", 1)[0] if isinstance(checkpoint, str) else ""
    bundle: dict[str, Any] = {
        "spec": SPEC_BUNDLE,
        "log_id": log_id,
        "leaf_index": leaf_index,
        "leaf": leaf.to_json(),
        "proof": proof,
        "checkpoint": checkpoint,
        "certificate": cert,
    }
    try:
        verdict = verify_bundle(bundle, trust)
    except InclusionError as e:
        if e.name is ErrorName.BAD_PROOF and isinstance(leaf_index, int):
            size = parse_checkpoint(checkpoint).tree_size  # check 7 passed before check 9
            if leaf_index >= size:
                raise NotYetInCheckpoint(leaf_index, size) from None
        raise
    return bundle, verdict


def bundle_bytes(bundle: Mapping[str, Any]) -> bytes:
    """A bundle as its JCS bytes, as an issuer writes it (§8)."""
    return canonical(bundle)
