# An independent auditor's countersignature (#29)

> **Design only** (owner go for design docs, 2026-11-16). No code, no spec freeze, no third party
> contacted. Tracks [#29](https://github.com/zer07labs/decision-cert/issues/29). Shared rules:
> [README](README.md).

## The problem

Each operator signs its own certificates (spec §3), so a consumer's trust rests on the operator. A
verifier checks the signature and the fields, never the measurement: "A verifier cannot check that
these numbers were computed from the cases. A re-run from the data does that" (spec v1.3 §2, v1.4
§2). Today the only independent check is an auditor who obtains the data, recomputes `data_hash` and
`manifest_hash`, re-runs the reference issuer and compares the thresholds
([`docs/model-risk.md`](../model-risk.md), "Re-run it"). That is manual and leaves no trace on the
certificate.

Under the owner's tenant-only decision (2026-11-16), the auditor is the **tenant's own auditor**, to
whom the tenant exports its certificates and data. The attestation stays in the tenant's scope like
the certificate it names; nothing about it is published.

## Threat model

| | Adversary | Wants to | The design's answer |
|---|---|---|---|
| T1 | The operator | Ship numbers that do not come from the stated cases: a wrong `data_hash`, edited thresholds, reused cases, a selected attempt | The auditor recomputes and re-runs, and states each check and its result. |
| T2 | A careless or captured auditor | Sign without checking | The attestation names each check, the tool and version used, and a hash of the auditor's working record, so a second auditor can repeat it. Its key can be revoked (K1). |
| T3 | Anyone | Move an attestation to another certificate | It names `certificate_id`. |
| T4 | A thief with an auditor's key | Forge attestations | K1 revocation, and the tenant log's time evidence. |
| T5 | Outsiders | Learn about the tenant | The attestation holds only the certificate id, the checks and hashes, and stays in the tenant's scope. |

**Out of scope.** Whether the labels are right, beyond a re-label sample the auditor reports; how the
auditor obtains the data (the tenant's export process); accreditation of auditors as a profession.

## Design

### A separate attestation, not a certificate field

An attestation is a sidecar that names a certificate by `certificate_id`. It is not a field of the
certificate (#29's first question): adding one would change the signed bytes and so the
`certificate_id`, the auditor signs after the operator, and frozen v1 to v1.4 certificates could
not carry it. As a sidecar it applies to every certificate, past ones included, and one certificate
can have several attestations.

```json
{
  "spec": "decision-cert-attestation.v1",
  "certificate_id": "sha256:<hex>",
  "attested_at": "2026-12-01T10:00:00Z",
  "checks": [
    {"check": "data_hash", "result": "match"},
    {"check": "manifest_hash", "result": "not_applicable"},
    {
      "check": "reproduce",
      "result": "match",
      "tool": {"tool": "decision-cert", "version": "0.5.0"},
      "comparison": "exact"
    },
    {"check": "ledger", "result": "match", "ledger_id": "ledger:3b9e07d2c51a4f68a0e9d7b2c4f1836e", "through_seq": 57, "counted_attempts": 1},
    {"check": "roles", "result": "match"},
    {"check": "inclusion", "result": "match", "log_id": "log:4e1a9c07b25d38f6e0a1b9c7d2e4f531", "tree_size": 1290},
    {"check": "relabel_sample", "result": "reported", "n": 200, "disagreements": 7, "seed": 42}
  ],
  "evidence_hash": "sha256:<hash of the auditor's working record, kept by the auditor>",
  "attester_key_id": "ed25519:9b2f4e61a0c7d358",
  "signature": "<base64url Ed25519 over 'decision-cert/attestation.v1\\n' + JCS>"
}
```

### What the auditor attests

The attestation is a list of named checks, each with a result: `match`, `mismatch`,
`not_applicable` or `reported`. A check that is not listed was not done. A fixed vocabulary keeps
two auditors' attestations comparable (#29's second question: "recomputed and matched", or a
re-label, become separate checks rather than one statement):

| Check | What the auditor did | Needs |
|---|---|---|
| `data_hash` | Recomputed `data_hash` from the labelled cases the tenant exported, with the tuple of the certificate's `spec` (spec v1.3 §2 adds `cannot_tell`). | the data |
| `manifest_hash` | Hashed the manifest file. `not_applicable` when the certificate's is null. | the manifest |
| `reproduce` | Re-ran an issuer on the same inputs and configuration and compared every measured field: all fields except `fitted_at`, `expires_at` (which follows it when `window` is null), `issuer`, `signer_key_id` and `signature`. `comparison` is `exact`, or `tolerance` with the bound used (open question 2). | the data, predictions, configuration |
| `ledger` | Verified the ledger chain through `through_seq` and counted the attempts on the same threshold split ([R1](r1-issuance-ledger.md)). | the ledger |
| `roles` | Checked the role declarations against the tenant's records of training, tuning and selection, and opened the role commitments with the salt (R1). | the salt and records |
| `inclusion` | Checked the certificate's inclusion and the log's consistency ([#28](transparency-log.md)). | the log export |
| `relabel_sample` | Re-labelled a random sample of the labelled cases and reports how many labels differ. Descriptive: no bound is claimed for it. | the cases, a labeller |

An attestation can carry a `mismatch`. A negative attestation is still signed and still useful: it
records that the check was done and failed.

**The statement.** An attestation records that the attester ran the listed checks on the inputs the
tenant provided, and their results. It says nothing more about the decisions than the certificate
does: it describes a measured process and never guarantees an outcome (#29's fourth question). It
does not make the bound stronger. It makes the claim that the stated measurement was the one carried
out checkable by someone other than the operator.

### Keys and accreditation

An auditor's key has role `attester` in the tenant's key set ([K1](k1-key-revocation-rotation.md)),
so the tenant chooses which auditors its consumers trust, and K1 rotates and revokes those keys like
any other. There is no central list of auditors: a shared registry would be a cross-tenant view of
who audits whom. Whether any recognised list should ever exist is an open question (#29's third
question).

### What a consumer checks, offline

1. The attestation's `certificate_id` is the certificate's id.
2. Its signature verifies strictly against an `attester` key that K1 accepts at `attested_at`.
3. Its checks satisfy the consumer's policy, for example:

```yaml
certificate:
  attestations:
    required: 1                            # at least this many attestations
    checks: [data_hash, reproduce]         # each with result match
    on_missing: warn                       # off | warn | refuse
```

A consumer that requires attestations then needs both the operator's signature and an auditor's,
from keys it trusts, as #29 proposes. Nothing needs the network.

### Attestations in the tenant log

Each attestation is appended to the tenant log as a leaf ([#28](transparency-log.md)), so an auditor
cannot quietly withdraw one and a tenant cannot quietly drop a negative one: the tenant's next
auditor sees every attestation ever made for a certificate.

## Composition with frozen certificates

- No certificate changes. Attestations name v1 to v1.4 certificates by `certificate_id` as they are.
- `reproduce` follows the procedure of the certificate's own `spec`: a v1 certificate is re-run by
  the v1 procedure (the reference issuer's `--spec decision-certificate.v1`), a v1.4 one by v1.4's.
- The re-run the docs already describe ([`docs/model-risk.md`](../model-risk.md), "What a validator
  should check") becomes a signed record instead of a private one.

## Alternatives considered

- **A countersignature field in a later certificate `spec` value.** Rejected: it changes the signed
  bytes, the auditor would sign after the operator, and no frozen certificate could carry it.
- **Both parties sign one certificate** (an issuance with two signatures). This makes the auditor
  part of issuing, before any consumer sees the certificate. An auditor who wants that can issue its
  own certificate on the same data and attest that it `reproduce`s the operator's. Not the default.
- **in-toto attestations in a DSSE envelope.** A reasonable envelope: DSSE separates contexts by
  design, and in-toto's statement names a subject by digest, which `certificate_id` is. Against it:
  a second canonicalisation and envelope beside JCS, and more dependencies for the verifiers, which
  keep two. Left as an open question.
- **W3C Verifiable Credentials.** Heavier still (JSON-LD, identifiers), with nothing this needs.
- **Status quo: the auditor re-runs and writes a report.** Leaves no machine-checkable trace.

## Open questions for the owner

1. **The minimum attestation.** Which checks must an attestation have for a consumer's default
   policy: `data_hash` and `reproduce` (recommended)?
2. **Reproduction across versions.** `exact` only with the same issuer version, or a stated
   tolerance on floating-point fields (the temperature and the thresholds that follow from it,
   `ucb`, the bands) when the auditor's numeric libraries differ? Counts would always be exact.
3. **Accreditation.** Tenant-chosen auditors only (recommended), or a recognised list later?
4. **Re-label samples.** In the first version, and with which sampling rule?
5. **Envelope.** This repository's JCS form (recommended), or in-toto with DSSE?
6. **Negative attestations.** Must every attestation, `mismatch` included, go into the tenant log?
7. **The auditor's access** to a hosted tenant's data: part of the hosted multi-tenant design, not
   this format. Confirm.

## What an implementation would touch

- **A new spec** for the attestation and its check vocabulary: `spec/decision-cert-attestation.v1.md`
  and its schema. No certificate spec changes.
- **Verifiers:** `verify_attestation` in the Rust crate and the Python verifier (schema, `certificate_id`
  binding, signature, the key's role through K1), and a policy check against required checks; the
  CLI's `verify --attestation`.
- **Issuer:** an `audit` command in `python/src/decision_cert/issue/` that recomputes `data_hash`,
  re-runs the measurement by the certificate's `spec`, compares the measured fields and writes an
  unsigned attestation for the auditor to sign with its own key.
- **Fixtures:** a new `fixtures/attestation/` set: match, mismatch, a wrong `certificate_id`, an
  untrusted or revoked attester, a policy that is not met.
- **Docs:** [`docs/model-risk.md`](../model-risk.md) ("What a validator should check"),
  [`docs/certificates.md`](../certificates.md).
