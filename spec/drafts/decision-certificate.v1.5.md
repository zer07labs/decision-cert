> **Draft.** Owner go to draft, 2026-11-16 ("Draft v1.5 hosted-signer mode"). Design only:
> - No field, check, schema or fixture of this draft exists in any verifier or issuer.
> - Freezing it, and building it, are later owner decisions, taken separately.
> - v1 to v1.4 stay frozen and unchanged.

# Decision certificate, v1.5 (draft): tenant binding and a hosted signer

v1.5 would extend [`decision-certificate.v1.4`](../decision-certificate.v1.4.md) under a new `spec` value,
`decision-certificate.v1.5`. As with v1.1 to v1.4:

- v1 to v1.4 certificates, their fixture sets and their verdicts stay unchanged and valid;
- verifiers would accept all six values of `spec`, each against its own schema;
- a v1.5 fixture set would be added beside the others.

[`certificate_id`](../ERRATA.md) (ERRATA, 2026-11-15) does not change. It is still `"sha256:"` + hex SHA-256 of the
JCS bytes of the whole signed certificate, `signature` included. A v1.5 certificate's id therefore covers the two
new fields, because they are part of the signed object. The rule itself is untouched.

## The problem

**1. A certificate names no tenant.** One service may host many tenants, each with its own certificates. A
certificate issued for tenant `a` names nothing that ties it to `a`. Only the consumer's configuration does that:
the key must be in `a`'s trusted keys. Two cases go wrong:

- If one key ever signs for two tenants, a certificate can be replayed from one to the other.
- A consumer that loads a certificate under the wrong tenant's configuration has nothing in the certificate to
  catch the mistake.

**2. The signer rule excludes a hosting service.** v1.2 §3, which v1.3 and v1.4 inherit unchanged, says:

> **The signer** is the operator running the calibration in their own environment, with their own key. Nobody
> else holds a signing key for another operator's certificates.

([`decision-certificate.v1.2.md`](../decision-certificate.v1.2.md), §3; v1 §3 says the same.)

A hosting service that calibrates and certifies on a tenant's behalf, with a key it holds for that tenant, cannot
issue a certificate that conforms to this text. The rule is right for an operator that signs its own
certificates. It does not cover a service signing for a tenant, and a certificate should say which of the two
happened.

## Proposed shape

### Fields

v1.4's fields, plus two:

| Field | Type | Meaning |
|---|---|---|
| `tenant` | string | The tenant the certificate is issued for: 1 to 128 characters from `A-Z a-z 0-9 . _ : -`. An operator that signs its own certificates is its own tenant and writes its own id. Opaque to verifiers; compared only for byte equality. |
| `signer` | object | Who signed. Either `{"mode": "operator"}` (the tenant signed, with its own key, as in v1 to v1.4) or `{"mode": "hosted", "host": <string>}` (a hosting service signed for `tenant`, with a key it holds for that tenant only; `host` names the service in the same character set and length as `tenant`). |

- `signer_key_id`, `signature` and every v1.4 field keep their meaning.
- A v1.5 certificate without `tenant` or `signer` fails the schema.
- `tenant` and `signer` are unknown fields in a v1 to v1.4 certificate, which those verifiers already reject.

### Signed bytes: domain separation and the tenant

v1 to v1.4 sign the bare JCS bytes of the certificate without `signature`. A v1.5 signature is Ed25519, verified
strictly as in v1.2 §3, over:

```
"decision-cert/certificate.v1.5" || 0x0A || tenant || 0x0A || JCS(certificate without signature)
```

- **The context string** follows the rule of the trust designs ([`docs/design/README.md`](../../docs/design/README.md),
  "New documents, separate signatures"). A v1 to v1.4 signature is over bytes that begin with `{`, and a v1.5
  signature is over bytes that begin with `d`. So a v1.5 signature never verifies as an earlier version's, or the
  reverse, and none verifies as a key set, ledger entry or attestation, even when one key signs both kinds.
- **The tenant appears twice:** in the prefix, and as the `tenant` field inside the JCS.
  - The verifier builds the prefix from the tenant **it expects**, from its own configuration, not from the
    certificate. A certificate for `b`, checked by a consumer that expects `a`, then fails the signature check
    itself, even if a consumer forgets the field comparison below.
  - The field keeps the tenant readable and puts it under `certificate_id`.
- The tenant cannot contain `0x0A` (character set above), so the framing is unambiguous.

### §3, the signer rule, amended for v1.5 only

The v1.2 §3 signer rule stays as written for v1 to v1.4, and for a v1.5 certificate with `signer.mode`
`operator`. For a v1.5 certificate with `signer.mode` `hosted`, it is replaced by:

> **The signer** is the hosting service named in `signer.host`, signing for the tenant named in `tenant`. The
> hosting service holds one signing key per tenant and uses it only for that tenant's certificates. No key signs
> for two tenants, and no key signs in both modes.

Operator-signed certificates stay valid in every version, v1.5 included. The hosted mode is an addition, not a
replacement.

### §4, what a verifier checks (additions for v1.5)

A v1.5 verifier is given:

- the **expected tenant**, a string from the consumer's configuration;
- that tenant's **trusted keys**, in which each key states the mode it may sign in: `operator`, or `hosted` with
  its `host`.

For today's flat map (key id to public key), every entry is an `operator` key. A hosted key needs the richer
entry; its form is an open question below, shared with K1.

The verifier refuses the certificate when any of these fails, in addition to every v1.4 check:

1. **Tenant.** `tenant` equals the expected tenant, byte for byte.
2. **Key allowed for the tenant.** `signer_key_id` is in the expected tenant's trusted keys. Its public key hashes
   to the id, as today.
3. **Key allowed for the mode.**
   - When `signer.mode` is `operator`, the key's entry is an `operator` key.
   - When it is `hosted`, the entry is a `hosted` key whose `host` equals `signer.host`.
4. **Signature.** It verifies strictly over the v1.5 signed bytes above, built with the **expected** tenant.

A consumer still applies v1.4 §4 (domain, decision, options, map, costs, segments, expiry) after these checks.

A verifier cannot see another tenant's configuration, so it cannot itself detect one key listed under two tenants.
"No key signs for two tenants" is an issuer and hosting-service rule. A consumer that holds several tenants'
configurations refuses a configuration in which one key id appears under two tenants.

### Keys: rotation and revocation

Rotation, revocation and compromise of a hosted key are [K1](../../docs/design/k1-key-revocation-rotation.md):

- one key set per tenant, with key validity and revocation dated in it;
- the tenant, not the hosting service, holds the root that signs it (K1, "Tenancy"). The tenant can then revoke
  the hosting service's key without the service's help.

K1 changes no certificate field, so it composes with v1.5 unchanged. The one link is the hosted key's entry
(check 3), which would become a role or an attribute in the K1 key set (question 3).

### What stays the same

- v1 to v1.4: text, schemas, fixtures and verdicts. `certificate_id`'s derivation.
- The operator-signed path, in every version.
- `signer_key_id`'s form. The canonical form and number rules of v1.2 §3.
- The tenant-only rule (owner, 2026-11-16; [`docs/design/README.md`](../../docs/design/README.md)). The `tenant`
  field is read only inside that tenant's scope, as the rest of the certificate is.

## Open questions for the owner

1. **Pre-v1.5 certificates in a hosted consumer.** May a consumer that hosts several tenants accept a v1 to v1.4
   certificate, which binds no tenant? Recommended: yes, for an `operator` key only, relying on check 2 (a key in
   one tenant's set). A `hosted` key signs only v1.5.
2. **Tenant in both prefix and field.** Keep both (recommended, for the reason above), or the field only, with
   the context string alone separating the versions?
3. **The hosted key's entry.** Is it a K1 role (`certificate-hosted` beside `certificate`), or an attribute on
   the `certificate` role (`mode`, `host`)? Recommended: an attribute, since the key signs the same documents.
4. **`host` identity.** A free string, as proposed, or a key id of the hosting service's own key, so a consumer can
   pin the host as well as the tenant?
5. **Tenant id form.** The proposed character set fits common tenant ids. Is 128 characters the right ceiling?

## What freezing would touch

None of this is approved:

- **Spec and schema.** `spec/decision-certificate.v1.5.md` and `decision-certificate.v1.5.schema.json`.
- **Verifiers.** The Rust crate and the Python verifier would gain the expected-tenant input and checks 1 to 4.
  `verify(cert, keys)` keeps its meaning for v1 to v1.4.
- **Issuer.** The reference issuer would gain `--spec decision-certificate.v1.5`, `--tenant` and the signer mode.
- **Fixtures.** `fixtures/v1.5/`, with negatives for:
  - a wrong tenant;
  - a key not in the tenant's set;
  - an operator key on a hosted certificate, and the reverse;
  - a `host` mismatch;
  - a v1.5 signature over bare JCS;
  - a v1.4 signature replayed under v1.5 framing.
- **Docs.** [`docs/conformance.md`](../../docs/conformance.md).

## Decision log

| Date | Item | Decision |
|---|---|---|
| 2026-11-16 | draft | Opened as a design draft (owner go: "Draft v1.5 hosted-signer mode"). Nothing approved for implementation or freezing. |
