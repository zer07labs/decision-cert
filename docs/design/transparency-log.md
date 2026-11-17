# A transparency log for issued certificates (#28)

> **Design only** (owner go for design docs, 2026-11-16). The owner's answers to its open questions
> are recorded below ([Decided](#decided-owner-2026-11-17), 2026-11-17). No code and no spec freeze
> are approved, and no third party has been contacted. Tracks
> [#28](https://github.com/zer07labs/decision-cert/issues/28). Shared rules: [README](README.md).

## The problem

A certificate's signature shows who signed it and that it was not altered (spec §3). It does not
show that the operator measured honestly, and nothing records what else the operator issued. An
operator could issue several certificates and show only the best. [R1's ledger](r1-issuance-ledger.md)
records every attempt, but the operator holds it and can rewrite it. [K1](k1-key-revocation-rotation.md)
needs to know when a certificate existed, independently of the `fitted_at` its signer wrote.

#28 proposed an append-only **public** log, in the style of Certificate Transparency or Sigstore
Rekor.

## The tenancy constraint

**The owner decided on 2026-11-16 that a tenant's certificates are tenant-only:** visible only
inside that tenant's scope, exportable by the tenant to its own auditor, with no cross-tenant and no
public view. A public log of certificates, or of their ids, is therefore ruled out, and so is any
log shared across tenants. This design keeps one log per tenant, inside the tenant's scope. Nothing
about a tenant's certificates is published: not the certificates, not their ids, not the tenant's
name. The section [What leaves a tenant's scope](#what-leaves-a-tenants-scope) lists every byte that
does, and to whom.

## Threat model

| | Adversary | Wants to | The log's answer |
|---|---|---|---|
| T1 | The issuing operator | Hide attempts or certificates, or delete them later | Every certificate and ledger entry is a leaf; deleting one breaks consistency with checkpoints the witnesses already cosigned. |
| T2 | The log operator (often the same party, or the hosting service) | Show the auditor one history and a consumer another (a split view), or roll back | Checkpoints are cosigned by witnesses, who refuse to cosign a checkpoint inconsistent with one they cosigned before. |
| T3 | A thief with a signing key | Backdate certificates | A witness's cosignature carries its own time, so it shows when a certificate was already in the log (K1's `t_proven`). |
| T4 | Other tenants, outsiders, curious witnesses | Learn about a tenant's certificates | Leaves never leave the tenant's scope. A witness sees an opaque log id, a size and a root hash. |

**Trust assumption.** At least one of the tenant's witnesses is honest: it checks consistency before
cosigning and keeps the last checkpoint it cosigned.

**Out of scope.** Whether the measurement was honest (the log records it, [#29](auditor-countersignature.md)
checks it); whether labels are right; an attacker who stops the log from running, which only delays
issuance.

## Design

### One log per tenant

- **Where.** In the tenant's scope. The tenant chooses who runs it: the tenant itself, or the
  hosting service inside that tenant's partition (owner, 2026-11-17). Never one log across tenants.
- **Identity.** `log_id` is random (`log:<32 hex>`), so it does not name the tenant.
- **Key.** The log signs checkpoints with a key of role `log` in the tenant's key set
  ([K1](k1-key-revocation-rotation.md)).
- **Tree.** A Merkle tree with RFC 9162 §2.1 hashing: a leaf's hash is SHA-256(0x00 ‖ JCS(leaf)),
  an inner node's SHA-256(0x01 ‖ left ‖ right).

### Leaves

Every leaf is a JCS object with a `kind`:

| `kind` | Members | Appended when |
|---|---|---|
| `certificate` | `certificate_id`, `signer_key_id`, `spec`, `fitted_at` | a certificate is signed |
| `ledger_entry` | `ledger_id`, `seq`, `entry` (the entry's hash) | every [R1](r1-issuance-ledger.md) entry, `begin` and `end` |
| `keyset` | `keyset_id`, `seq`, `keyset` (the key set's hash) | every [K1](k1-key-revocation-rotation.md) key set |
| `attestation` | `attestation` (its hash), `certificate_id` | every [#29](auditor-countersignature.md) attestation |

A leaf holds ids and hashes, not the certificate. The certificate itself stays in the tenant's
certificate store; inside the tenant's scope, a leaf could hold the whole certificate, but it does
not need to (#28's question "what goes in it").

### Checkpoints and witnesses

A **checkpoint** is a signed note in the C2SP `tlog-checkpoint` format: the origin (`log_id`), the
tree size and the root hash, signed by the log key. **Witnesses** add cosignatures in the C2SP
`tlog-cosignature` format, each carrying the witness's own timestamp. A witness cosigns a checkpoint
only after checking a consistency proof from the last checkpoint it cosigned, so it never cosigns two
histories.

Witnesses are chosen by the tenant and listed in its key set with role `witness`. Candidates: the
tenant's auditor, a second system of the tenant's outside the log operator's control, or an
independent witness that sees only checkpoints. At least one should be outside the control of
whoever runs the log.

The number of cosignatures a consumer requires, `m`, is configurable per tenant, default `m = 1`
(owner, 2026-11-17).

The log issues a checkpoint **hourly by default**, configurable per log (owner, 2026-11-17). The
cadence sets how long an issuer waits for a proof.

### The inclusion proof (a sidecar)

```json
{
  "spec": "decision-cert-inclusion.v1",
  "certificate_id": "sha256:<hex>",
  "log_id": "log:4e1a9c07b25d38f6e0a1b9c7d2e4f531",
  "leaf_index": 1234,
  "leaf": {
    "kind": "certificate",
    "certificate_id": "sha256:<hex>",
    "signer_key_id": "ed25519:0c6e5b7d2a913f84",
    "spec": "decision-certificate.v1.4",
    "fitted_at": "2026-11-16T09:31:10Z"
  },
  "proof": ["<base64 node hash>", "<base64 node hash>"],
  "checkpoint": "<the signed note: origin, size, root hash, log signature, witness cosignatures>"
}
```

It cannot be a certificate field: the leaf names `certificate_id`, the hash of the signed
certificate, so the certificate would have to contain a proof about itself (#28's question "a spec
field or a sidecar": a sidecar). The proof is not signed on its own; it is checked against the
checkpoint's signatures.

### What a consumer checks, offline

1. The leaf's `certificate_id` is the certificate's id, and its other members match the
   certificate.
2. The audit path leads from the leaf's hash at `leaf_index` to the checkpoint's root.
3. The checkpoint is signed by a `log` key in the tenant's key set that K1 accepts, and cosigned by
   at least `m` `witness` keys from it (default `m = 1`, configurable per tenant).
4. The earliest witness timestamp is `t_proven` for K1's compromise rule.

A consumer's policy for a certificate without a proof is `off`, `warn` or `refuse`. The default is
`warn` at first: a missing proof warns and is not refused (owner, 2026-11-17). Everything is in
the sidecar and the configuration, so loading a certificate never needs the log (#28's question
"what does a consumer do when the log is unreachable": it never needs to reach it).

### Issuing with a log

The issuer signs the certificate, appends its leaf (and the ledger's `end` entry), waits for the
next cosigned checkpoint (within the hour, at the default cadence), and attaches the proof. If the
log is down, the certificate exists but has
no proof yet; a consumer with policy `refuse` does not load it until the proof arrives. The log
client lives outside this library: the issuer writes the leaf and accepts a proof file, and never
makes a network call itself.

### What the tenant's auditor checks

This is where cherry-picking shows. The tenant exports the log (or a range of it) to its auditor.
The auditor:

1. checks consistency between every checkpoint it has seen, as a witness or earlier reviews;
2. lists every `certificate` leaf and every ledger attempt, and counts the attempts per threshold
   split as R1 describes;
3. checks that every certificate the tenant uses has a leaf, and that the ledger chain's every entry
   is in the log.

A consumer inside the tenant sees an inclusion proof, which shows that this certificate is in the
log. Seeing what else is in it is the auditor's job, inside the tenant's scope.

### What leaves a tenant's scope

| What | Goes to | Reveals |
|---|---|---|
| Leaves, certificates, ledger entries, attestations | Nobody outside the tenant, except the auditor the tenant exports to | — |
| Inclusion proofs | Whoever the tenant gives the certificate to | The proof's node hashes reveal nothing about other leaves without those leaves. |
| Checkpoints (log id, size, root hash) | The tenant's witnesses | The number of leaves, so roughly how active the tenant's issuance is. No certificate, id or name. The log does not pad it (owner, 2026-11-17). |
| Blind anchors (not now, owner 2026-11-17) | A public log | Nothing: a hiding commitment (below). |

**The optional blind anchor.** To gain public ordering without a public view, the tenant could
publish only `sha256(nonce ‖ checkpoint)`, with a fresh 32-byte nonce kept in its scope, to a public
log. Nobody without the nonce learns anything from it, and fresh nonces make anchors unlinkable to
each other. Only the tenant's auditor, given the nonce, can check it. It adds little over honest
witnesses, and it is still a public artefact whose timing is visible. **Not now** (owner,
2026-11-17): no anchors are published; the design is kept for a later decision.

## Composition with frozen certificates

- No certificate field changes. v1 to v1.4 certificates are logged by `certificate_id` exactly as
  they are. Certificates issued before a tenant's log existed are backfilled into it when the log
  starts (owner, 2026-11-17), with no early time evidence for them.
- The proof is a sidecar carried next to the certificate, like R1's ledger segment and #29's
  attestations.
- A consumer that records `certificate_id` with every decision (spec v1.2 §4) can later show, with
  the proof, that the certificate behind a decision was in the tenant's log by a known time.

## Alternatives considered

- **A public log of certificates or ids** (#28 as proposed, or Rekor). Ruled out by tenant-only.
- **One shared log with commitment leaves for all tenants.** Rejected: its operator sees every
  tenant's activity and timing, proofs carry other tenants' hashes, and it is a cross-tenant view
  in all but name.
- **R1's hash chain alone.** It gives order and tamper evidence to whoever kept an old head, but no
  compact inclusion proofs and no protection against two histories. The log anchors it instead.
- **RFC 3161 timestamps only.** They give K1 its time, but say nothing about completeness. They are
  a possible addition for K1 (K1, question 4), not a substitute.
- **A public blockchain anchor.** Rejected: public, slow, costly, and no better than the blind
  anchor.
- **Implementation engines.** An existing tile-based log (Trillian Tessera, which writes C2SP
  checkpoints) fits this design. Choosing one is an implementation decision, not part of the
  format.

## Decided (owner, 2026-11-17)

- **Q1. Witnesses: who, and how many (`m`)?** Configurable per tenant, default `m = 1`.
- **Q4. Consumer default for a certificate without a proof?** `warn` at first, not `refuse`.
- **Q5. Who runs a tenant's log?** The tenant chooses: itself, or a hosted partition.
- **Q6. Checkpoint cadence?** Hourly by default, configurable.
- **Q7. Old certificates?** Backfilled into the tenant's log when it starts, with no early time
  evidence for them.
- **Q2. Blind anchors under tenant-only?** Not now.
- **Q3. Tree size: is the number of leaves a witness sees acceptable, or should the log pad it?**
  Acceptable; no padding.

These answers record design choices only. No code and no spec freeze are approved.

## What an implementation would touch

- **A new spec** for leaves and the inclusion proof: `spec/decision-cert-inclusion.v1.md` and its
  schema, citing RFC 9162 §2.1 and the C2SP checkpoint and cosignature formats. No certificate spec
  changes.
- **Verifiers:** a Merkle audit-path check and a signed-note check (log signature, witness
  cosignatures) in the Rust crate and the Python verifier, with no network code; the CLI's
  `verify --inclusion`.
- **Issuer:** write the leaf (and R1's entries as leaves), accept a proof file, bundle it with the
  certificate. The log server and its client are not in this repository.
- **Fixtures:** a new `fixtures/log/` set: valid proofs, a wrong path, a checkpoint short of `m`
  cosignatures, an untrusted witness, a leaf that does not match its certificate.
- **Docs:** [`docs/certificates.md`](../certificates.md), [`docs/model-risk.md`](../model-risk.md)
  ("Any record of other certificates issued on the same cases"), [`SECURITY.md`](../../SECURITY.md).
