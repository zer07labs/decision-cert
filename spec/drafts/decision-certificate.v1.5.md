> **Draft, answered.** Owner go to draft, 2026-11-16 ("Draft v1.5 hosted-signer mode"). The owner answered the five
> open questions on 2026-11-17 ([Owner answers](#owner-answers-2026-11-17)) and approved freezing v1.5 on those
> answers. The frozen text is [`spec/decision-certificate.v1.5.md`](../decision-certificate.v1.5.md); this draft is
> kept as the record of how it was reached. v1 to v1.4 stay frozen and unchanged.

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
| `signer` | object | Who signed. Either `{"mode": "operator"}` (the tenant signed, with its own key, as in v1 to v1.4) or `{"mode": "hosted", "host": <key id>}` (a hosting service signed for `tenant`, with a key it holds for that tenant only). `host` is the key id of the hosting service's own key, in `signer_key_id`'s form (`ed25519:` and 16 lowercase hex), so a consumer can pin the host as well as the tenant (answer 4). |

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
  its `host` (the hosting service's key id).

For today's flat map (key id to public key), every entry is an `operator` key. A hosted key's entry carries the
mode as an attribute of the same certificate-signing role, `{"key": <public key>, "mode": "hosted", "host": <key
id>}` (answer 3); K1's key set would carry the same attributes on its `certificate` role.

The verifier refuses the certificate when any of these fails, in addition to every v1.4 check:

1. **Tenant.** `tenant` equals the expected tenant, byte for byte.
2. **Key allowed for the tenant.** `signer_key_id` is in the expected tenant's trusted keys. Its public key hashes
   to the id, as today.
3. **Key allowed for the mode.**
   - When `signer.mode` is `operator`, the key's entry is an `operator` key.
   - When it is `hosted`, the entry is a `hosted` key whose `host` equals `signer.host`, byte for byte.
4. **Signature.** It verifies strictly over the v1.5 signed bytes above, built with the **expected** tenant.

A consumer still applies v1.4 §4 (domain, decision, options, map, costs, segments, expiry) after these checks.

**Earlier certificates under an expected tenant (answer 1).** A v1 to v1.4 certificate binds no tenant. A verifier
given an expected tenant accepts one only when its `signer_key_id` is in that tenant's trusted keys as an `operator`
key, relying on check 2. A `hosted` key signs v1.5 certificates only, so an earlier certificate under a hosted key is
refused.

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

Answered by the owner on 2026-11-17; see [Owner answers](#owner-answers-2026-11-17). The questions as they were put:

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

## Owner answers (2026-11-17)

1. **Earlier certificates:** accepted under an `operator` key only (as recommended).
2. **Tenant:** in both the prefix and the field (as recommended).
3. **Hosted key entry:** the same certificate-signing role, with `mode` and `host` attributes (as recommended).
4. **`host`:** the key id of the hosting service's own key, which a consumer can pin. This is the alternative to the
   free string the draft proposed; the fields and checks above are amended to it.
5. **Tenant id:** 1 to 128 characters of `A-Z a-z 0-9 . _ : -` (as recommended).

## What freezing would touch

Approved by the owner on 2026-11-17, on the answers above:

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
| 2026-11-17 | answers | The owner answered the five open questions (above); `host` became the hosting service's key id. |
| 2026-11-17 | freeze | Owner go to freeze v1.5 on these answers: [`spec/decision-certificate.v1.5.md`](../decision-certificate.v1.5.md), with the schema, both verifiers, the issuer and `fixtures/v1.5/`. |
