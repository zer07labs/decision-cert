# Decision certificate, v1.5

Status: **frozen** (2026-11-17). v1.5 is [`decision-certificate.v1.4`](decision-certificate.v1.4.md)
with two additions from the [v1.5 draft](drafts/decision-certificate.v1.5.md): the `tenant` a
certificate is issued for, bound into its signature, and a `signer` that says whether the tenant
signed it or a hosting service signed it for the tenant (§2, §3, §4). Corrections go in
[`ERRATA.md`](ERRATA.md). The v1.4 spec text applies to a v1.5 certificate except where this document
says otherwise. v1 to v1.4 certificates, fixtures and verdicts do not change.

**Versions.** Verifiers accept `decision-certificate.v1`, `v1.1`, `v1.2`, `v1.3`, `v1.4` and `v1.5`,
each against its own schema. v1.5 certificates have the v1.4 fields and two more, `tenant` and
`signer`. They are required in a v1.5 certificate and are unknown fields in an earlier one. An issuer
writes v1.5 only when asked (the reference issuer's `--spec decision-certificate.v1.5 --tenant
<id>`); its default stays v1.2.

A decision certificate is a signed record of **a measured process**. As in v1.4, it describes how
the thresholds were measured and how wide the uncertainty is, and it never guarantees an outcome.
`tenant` and `signer` say for whom and by whom it was signed. They make no claim about the
measurement.

Machine-readable schema: [`decision-certificate.v1.5.schema.json`](decision-certificate.v1.5.schema.json).
Conformance fixtures: [`fixtures/v1.5/`](../fixtures/v1.5/).

## 1. What is measured

v1.4 §1, unchanged. A v1.5 certificate makes the same claim, by the same procedure, as a v1.4
certificate with the same fields.

## 2. Fields

v1.4's fields, plus two:

| Field | Type | Meaning |
|---|---|---|
| `tenant` | string | The tenant the certificate is issued for: 1 to 128 characters of `A-Z a-z 0-9 . _ : -`. An operator that signs its own certificates is its own tenant and writes its own id. Verifiers compare it for byte equality only and give it no other meaning. |
| `signer` | object | Who signed. Either `{"mode": "operator"}`: the tenant signed, with its own key, as in v1 to v1.4. Or `{"mode": "hosted", "host": <key id>}`: a hosting service signed for `tenant`, with a key it holds for that tenant only. `host` is the key id of the hosting service's own key, in `signer_key_id`'s form (`ed25519:` and 16 lowercase hex), so a consumer can pin the host as well as the tenant. |

- `signer_key_id`, `signature` and every v1.4 field keep their meaning.
- `data_hash` is unchanged from v1.4. `tenant` and `signer` are not measured.
- [`certificate_id`](ERRATA.md) is unchanged (ERRATA, 2026-11-15): `"sha256:"` + hex SHA-256 of the
  JCS bytes of the whole signed certificate, `signature` included. It covers `tenant` and `signer`,
  because they are part of the signed object.

**Checks beyond the schema.** As v1.4, plus:

- `tenant` is 1 to 128 characters, each one of `A-Z a-z 0-9 . _ : -`.
- `signer` is exactly `{"mode": "operator"}` or `{"mode": "hosted", "host": <key id>}`: no other
  mode, no `host` in operator mode, a `host` in hosted mode, and no other field.
- A v1.5 certificate without `tenant` or `signer` is refused; a v1 to v1.4 certificate with either
  is refused as having an unknown field.

## 3. Canonical form and signature

v1.4 §3 (v1.2 §3) applies, with two changes for a v1.5 certificate.

**Signed bytes.** v1 to v1.4 sign the bare JCS bytes of the certificate without `signature`. A v1.5
signature is Ed25519, verified strictly as in v1.2 §3, over:

```
"decision-cert/certificate.v1.5" || 0x0A || tenant || 0x0A || JCS(certificate without signature)
```

- **The context string** separates the versions and the kinds of signed document. A v1 to v1.4
  signature is over bytes that begin with `{`, and a v1.5 signature is over bytes that begin with
  `d`. So a v1.5 signature never verifies as an earlier version's, or the reverse, even when one
  key signs both.
- **The tenant appears twice:** in the prefix, and as the `tenant` field inside the JCS.
  - The verifier builds the prefix from the tenant **it expects**, from its own configuration, never
    from the certificate. A certificate for tenant `b`, checked by a consumer that expects `a`, then
    fails the signature check too, even where a consumer omits the field comparison (§4, check 1).
  - The field keeps the tenant readable and puts it under `certificate_id`.
- `tenant` cannot contain `0x0A` (its character set, §2), so the framing is unambiguous.

**The signer.** The v1.2 §3 signer rule stays as written for v1 to v1.4, and for a v1.5
certificate with `signer.mode` `operator`. For a v1.5 certificate with `signer.mode` `hosted`, it
is replaced by:

> **The signer** is the hosting service named in `signer.host`, signing for the tenant named in
> `tenant`. The hosting service holds one signing key per tenant and uses it only for that tenant's
> certificates. No key signs for two tenants, and no key signs in both modes.

Operator-signed certificates stay valid in every version, v1.5 included. The hosted mode is an
addition, not a replacement.

## 4. How a consumer uses it

v1.4 §4 applies, with these additions.

**What a verifier is given.** A v1.5 verifier is given:

- the **expected tenant**, a string from the consumer's configuration, in the form of §2's `tenant`;
- that tenant's **trusted keys**: key id → key entry. A key entry is either a bare public key
  (base64url, no padding, as in v1 to v1.4), which is an `operator` key, or an object:
  - `{"key": <public key>, "mode": "operator"}`, or
  - `{"key": <public key>, "mode": "hosted", "host": <key id>}`, where `host` is the hosting service's
    key id, in `signer_key_id`'s form.

  The mode is an attribute of the same certificate-signing role, not a separate role: a hosted key
  signs the same documents as an operator key. An entry of any other form is refused.

**The checks.** Given a v1.5 certificate, the verifier first checks the expected tenant's form,
then the certificate's schema and every v1.4 check (§2). It then refuses the certificate when any of
these fails, in this order:

1. **Tenant.** `tenant` equals the expected tenant, byte for byte.
2. **Key allowed for the tenant.** `signer_key_id` is in the expected tenant's trusted keys, and its
   public key hashes to the id, as in v1 to v1.4.
3. **Key allowed for the mode.**
   - When `signer.mode` is `operator`, the key's entry is an `operator` key.
   - When it is `hosted`, the entry is a `hosted` key whose `host` equals `signer.host`, byte for
     byte.
4. **Signature.** It verifies strictly over the v1.5 signed bytes (§3), built with the **expected**
   tenant.

A consumer still applies v1.4 §4 (domain, decision, options, map, costs, segments, expiry) after
these checks.

**Earlier certificates under an expected tenant.** A v1 to v1.4 certificate binds no tenant. A
verifier given an expected tenant accepts one only when its `signer_key_id` is in that tenant's
trusted keys as an `operator` key: check 2 is what ties it to the tenant. A `hosted` key signs v1.5
certificates only, so an earlier certificate under a hosted key is refused. Its checks are the
schema and v1.4's, then check 2, then the operator-entry requirement, then the signature over the
bare JCS bytes, as in v1 to v1.4.

**Verifying without a tenant.** Verification of a v1 to v1.4 certificate against a flat key map
keeps its meaning. A v1.5 certificate is always verified for an expected tenant. Without one, a
verifier refuses it after its schema and §2 checks.

**One key under two tenants.** A verifier sees one tenant's configuration, so it cannot itself
detect one key listed under two tenants. "No key signs for two tenants" (§3) is an issuer and
hosting-service rule. A consumer that holds several tenants' configurations refuses a configuration
in which one key id appears under two tenants.

**Keys: rotation and revocation.** Rotation, revocation and compromise of a hosted key belong to the
key-set design, [K1](../docs/design/k1-key-revocation-rotation.md): one key set per tenant, with key
validity and revocation dated in it. The tenant, not the hosting service, holds the root that signs
it, so the tenant can revoke the hosting service's key without the service's help. K1 changes no
certificate field, so it composes with v1.5 unchanged. Its key set carries a hosted key as the
`certificate` role with the `mode` and `host` attributes above.

## 5. What a certificate does not claim

v1.4 §5 applies in full. In addition:

- `tenant` names the tenant a certificate was issued for. It says nothing about who owns the
  data, the model or the decisions, and it is read only inside that tenant's scope, as the rest of
  the certificate is.
- `signer` says who held the signing key. A hosted certificate states the same measurement as an
  operator one, and the hosting service's key id says which service signed, not that the service
  is trustworthy: that is the consumer's trusted-keys decision.

## 6. Size, binning and privacy of the histogram

v1.4 §6 (v1.3 §6), unchanged.

## Changes from v1.4

- `tenant` and `signer` (§2), required, with their checks.
- The v1.5 signed bytes: a context string and the expected tenant before the JCS bytes (§3).
- The hosted-signer rule for `signer.mode` `hosted` (§3).
- The expected tenant, moded trusted keys and checks 1 to 4; earlier certificates under an operator
  key only; the consumer rule on one key id under two tenants (§4).
- `spec` is `decision-certificate.v1.5`. The procedure and every v1.4 field are unchanged.

The draft's five questions were answered by the owner on 2026-11-17
([draft](drafts/decision-certificate.v1.5.md#owner-answers-2026-11-17)). None is open.
