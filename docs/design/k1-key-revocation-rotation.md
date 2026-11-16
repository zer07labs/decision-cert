# K1: key revocation and rotation

> **Design only** (owner go for design docs, 2026-11-16). No code, no spec freeze. This develops
> item K1 of the [v1.3 draft](../../spec/drafts/decision-certificate.v1.3.md#k1-key-revocation-rotation-and-key-id-lifetime),
> which stays as the record of the question. Shared rules: [README](README.md).

## The problem

A consumer trusts a key as long as it sits in the consumer's trusted-keys map, key id to base64url
public key (spec v1.2 §3 and §4, [`SECURITY.md`](../../SECURITY.md)). That map has no validity
period, no revocation and no rotation:

- **A leaked key stays trusted** until every consumer edits its configuration, and nothing tells a
  consumer that it should.
- **Removing a key refuses everything it ever signed**, the honest certificates included. Today's
  documented answer to a lost or leaked key is to replace it ([`docs/certificates.md`](../certificates.md#signing-keys)),
  and every certificate under the old key then has to be issued again.
- **The signer writes `fitted_at`.** A thief holding a leaked key can date a certificate before the
  leak, so the certificate's own timestamp cannot say whether it was signed before or after.
- **Key ids are short and not checked for duplicates.** `signer_key_id` is `ed25519:` + 16 hex
  characters (64 bits) of the key's SHA-256, a pattern every frozen schema fixes. A trusted-keys
  file that lists one id twice keeps only the last entry in the Python verifier, without a word.
  The verifiers check that the trusted key hashes to its id, so a collision makes the lookup
  ambiguous but cannot forge a signature.
- **Hosted tenants.** Who signs a hosted tenant's certificates is not decided (the owner has sent
  that question to the hosted multi-tenant design). Whatever the answer, the tenant needs a way to
  stop trusting a key it did not generate itself.

## Threat model

| | Adversary or event | What it can do today |
|---|---|---|
| T1 | A thief with a signing key | Sign new certificates that verify, dated whenever it likes. |
| T2 | A retired key used by mistake | Sign certificates after its holder meant to stop using it. |
| T3 | Rollback: a stale or replayed key list | Make a consumer trust a key that was revoked. |
| T4 | Substitution: an attacker's key added to a consumer's list | Sign certificates the consumer accepts. |
| T5 | Two keys with one 64-bit id | Make the trusted-key lookup ambiguous. |

**Out of scope.** A consumer whose own configuration or process is compromised (no format helps). A
signer who measures dishonestly with its own valid key: that is [R1](r1-issuance-ledger.md),
[the transparency log](transparency-log.md) and [the auditor countersignature](auditor-countersignature.md).
Post-quantum signatures.

## Design

K1 changes **no certificate field**. It is the consumer's trust configuration and how a verifier
uses it (the draft's question 1: K1 is not a certificate change).

### Key roles and the key set

Each tenant has:

- **a root key**, kept offline, which signs only key sets. A consumer pins the root's key id and
  public key, instead of a flat list of signing keys;
- **role keys**, each listed in the key set with one role:

| Role | Signs |
|---|---|
| `certificate` | certificates, and the tenant's ledger entries ([R1](r1-issuance-ledger.md)) |
| `log` | the tenant log's checkpoints ([#28](transparency-log.md)) |
| `witness` | cosignatures on another log's checkpoints ([#28](transparency-log.md)) |
| `attester` | an auditor's attestations ([#29](auditor-countersignature.md)) |

A key has one role. A key set lists every key the tenant has ever used, revoked ones included,
because old certificates are judged against them.

```json
{
  "spec": "decision-cert-keyset.v1",
  "keyset_id": "keyset:9d41c0e2a7b35f18e6d0c4a29b7e1f03",
  "seq": 12,
  "issued_at": "2026-11-16T00:00:00Z",
  "next_update": "2027-02-14T00:00:00Z",
  "root_key_id": "ed25519:5ad0e3f19c7b2468",
  "keys": [
    {
      "key_id": "ed25519:1f217282bf49a241",
      "public_key": "TA1U9XSMsXFbAw3EnYGLKL6vxjYJo8xvWh2eTirq6Yo",
      "role": "certificate",
      "not_before": "2026-08-01T00:00:00Z",
      "not_after": "2026-11-16T00:00:00Z",
      "revoked": null
    },
    {
      "key_id": "ed25519:0c6e5b7d2a913f84",
      "public_key": "<base64url raw public key>",
      "role": "certificate",
      "not_before": "2026-11-16T00:00:00Z",
      "not_after": null,
      "revoked": null
    },
    {
      "key_id": "ed25519:77e0a4c9d1b3f526",
      "public_key": "<base64url raw public key>",
      "role": "certificate",
      "not_before": "2026-03-01T00:00:00Z",
      "not_after": null,
      "revoked": {
        "at": "2026-07-20T00:00:00Z",
        "reason": "compromise",
        "compromised_since": "2026-07-01T00:00:00Z"
      }
    }
  ],
  "root_successor": null,
  "signature": "<base64url Ed25519 by the root key over 'decision-cert/keyset.v1\\n' + JCS>"
}
```

- `keyset_id` is opaque (random), so the document does not name the tenant.
- `seq` rises by one with each key set. `next_update` is when the tenant promises the next one at
  the latest, so a consumer can tell a stale key set from a current one.
- `revoked.reason` is `superseded`, `retired` or `compromise`. `compromised_since` (compromise only)
  is the earliest time the key may have been in other hands; when that is unknown, it is the key's
  `not_before`.
- Every timestamp has the certificate's form (spec v1.1 §2).
- A verifier refuses a key set in which two entries share a `key_id`, an entry whose `public_key`
  does not hash to its `key_id`, or a key with more than one role. An issuer refuses to create a key
  whose 64-bit id is already in the key set's history, so an id is never reused (T5).

### What a verifier checks

Given a certificate `C` signed with key id `k`, a key set `S`, the lowest `seq` the consumer will
accept, and optional time evidence for `C`:

1. `S` verifies against the pinned root, and `S.seq` is at least the consumer's minimum (T3). The
   library keeps no state, so the consumer passes the highest `seq` it has seen.
2. `k` is in `S` with role `certificate` (T4), its public key hashes to `k`, and `C`'s signature
   verifies strictly. These are today's checks.
3. Time. `t_claimed` is `C.fitted_at`, written by the signer. `t_proven`, when present, is the
   earliest time an independent source shows `C` existed: a cosigned checkpoint of the tenant log
   that includes `C` ([#28](transparency-log.md)), or an RFC 3161 timestamp token over
   `certificate_id` from a trusted timestamp authority.
4. Validity, by the key's entry:

| The key's state | `C` is accepted when |
|---|---|
| active | `not_before` ≤ `t_claimed`, and `t_claimed` ≤ `not_after` when `not_after` is set |
| revoked, `superseded` or `retired`, at `r` | as active, and `t_claimed` ≤ `r` |
| revoked, `compromise`, `compromised_since` `c` | `t_proven` exists and `t_proven` < `c`. `t_claimed` is not used. |

5. Then `expires_at` and the consumer's `on_expired` policy apply as today (spec v1.2 §4).

`superseded` and `retired` rely on the signer's clock, because they guard against mistakes (T2), not
theft. Rotation is sound only when the old private key is destroyed. A rotated key that later leaks
is revoked for `compromise`, and then only independent time keeps its certificates.

**Failing closed** (the draft's question 3). A certificate refused here is refused like any other:
spec §4 has the consumer refuse the decision's certificate, so every case of that decision goes to a
person. That is already the "refer" outcome at the decision level, so a separate refer verdict for
compromised keys adds nothing.

**A stale key set.** After `next_update`, the consumer's `on_stale_keyset` policy applies: `warn`
(decide and log) or `refuse`. Revocation reaches a consumer only as fast as its configuration is
delivered, because the library never fetches anything (the draft's question 2). `next_update`
makes a consumer that stopped receiving key sets visible.

### Rotation and compromise, step by step

**Planned rotation.** (1) Generate the new key. (2) Sign key set `seq + 1` with the new key active
from now and the old key's `not_after` set to now. (3) Destroy the old private key. (4) Deliver the
key set. Certificates signed before the rotation keep verifying until their own `expires_at`.

**Compromise.** (1) Sign key set `seq + 1` revoking the key with `reason: compromise` and a
conservative `compromised_since`. (2) Deliver it at once. (3) Every certificate under that key
without independent time before `compromised_since` is now refused. Issue it again with a new key:
the same inputs give the same measured fields, and [R1](r1-issuance-ledger.md) records the run as a
reissue, so it does not count as another attempt.

**Root rotation.** A key set signed by the old root names `root_successor` (key id and public key)
and carries a second signature by the new root, over the same bytes. A consumer that verifies both
moves its pin. A compromised root is replaced out of band, as a signing key is today.

### Composition with frozen certificates

- No certificate changes. `signer_key_id` keeps its frozen form, and a key set looks keys up by it.
- **Today's flat map stays valid.** A verifier given the v1 trusted-keys map (key id to public key)
  treats each entry as an active `certificate` key with no dates. `verify(cert, keys)` keeps its
  meaning; a key-set path is added beside it.
- A duplicated key id in the flat map would be refused, a change to the verifiers and to
  [`docs/conformance.md`](../conformance.md), not to any spec. A certificate does not change, so its
  `certificate_id` does not.

### Tenancy

One key set per tenant. A signing key never signs for two tenants, so one tenant's leak never
reaches another tenant's certificates. A key set lists public keys and dates, and nothing about any
certificate. When a hosting service holds a tenant's signing key, the tenant should hold the root,
so that it can revoke the service's key without the service's help.

## Alternatives considered

- **Validity fields inside the certificate** (a later `spec` value). Rejected: revocation is learned
  after signing, and a certificate cannot carry what was unknown when it was signed. The key's
  `not_before` and `not_after` belong to the key.
- **X.509 with CRLs or OCSP.** Rejected for the verifiers: OCSP needs a network call, and the
  naming and chain machinery buys nothing here. An operator may still keep its keys in a PKI and
  export a key set from it.
- **Short-lived keys from a public signing service with a public log** (Sigstore Fulcio and Rekor).
  Rejected: it needs network calls, and its public log contradicts tenant-only.
- **Trusting `fitted_at` for compromise.** Rejected: a thief writes whatever date it likes.
- **Short-lived signing keys** (for example rotated monthly). Not a format change, and recommended
  practice: it limits how much a leak can backdate, but not without independent time.
- **A threshold of root signatures** (m of n roots, as TUF does). Deferred to an open question; one
  offline root is enough for a first version.

## Open questions for the owner

1. **Root key.** Require a separate offline root that signs key sets (recommended), or allow a
   signing key to sign its own key set?
2. **Hosted tenants.** Who holds the signing key and who holds the root? This waits on the hosted
   multi-tenant design, where the owner sent "who signs a hosted tenant's certificates". The
   recommendation above: the tenant holds the root in either case.
3. **Stale key sets.** Default `on_stale_keyset`: `warn` or `refuse`?
4. **Independent time.** Accept only the tenant log's cosigned checkpoints, or RFC 3161 tokens as
   well? A timestamp authority sees only a hash, but it is a third party.
5. **Unknown compromise time.** Default `compromised_since` to the key's `not_before`, refusing
   everything without independent time (recommended)?
6. **m of n roots.** Wanted now, or later?
7. **Duplicate ids in the flat map.** Refuse them now, as a verifier change on its own, ahead of the
   rest of K1?

## What an implementation would touch

- **A new spec** for the key set: `spec/decision-cert-keyset.v1.md` and its schema. Not a
  certificate `spec` value; no certificate schema changes.
- **Rust:** `rust/src/lib.rs`, where `verify` looks up `signer_key_id` and checks the key's hash
  (around lines 391 to 411); a new key-set module; the CLI's `verify --keyset`.
- **Python verifier:** `python/src/decision_cert/_verify.py` (`verify`, around line 732), a new
  key-set module, and the same CLI flag. Duplicate-key detection when trusted keys are parsed.
- **Issuer:** `keygen` (`python/src/decision_cert/issue/certify.py`, around line 921) gains key-set
  commands: create, rotate, revoke, sign with the root.
- **Fixtures:** a new `fixtures/keyset/` set with its manifest: rotation, each revocation reason,
  independent time before and after `compromised_since`, rollback, duplicate ids, root succession.
  The certificate fixture sets do not change.
- **Docs:** [`docs/certificates.md`](../certificates.md) ("Signing keys"),
  [`SECURITY.md`](../../SECURITY.md), [`docs/conformance.md`](../conformance.md), and the "Change
  control" row of [`docs/model-risk.md`](../model-risk.md).
