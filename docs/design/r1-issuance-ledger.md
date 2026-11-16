# R1: the issuance ledger and dataset roles

> **Design only** (owner go for design docs, 2026-11-16). No code, no spec freeze. This develops
> item R1 of the [v1.3 draft](../../spec/drafts/decision-certificate.v1.3.md#r1-dataset-roles-and-an-issuance-ledger),
> which stays as the record of the question. Shared rules: [README](README.md).

## The problem

The `ltt` statement (spec v1.2 §1) holds for one test whose threshold-split cases were not used by
anything chosen before the test: training, adapting, tuning a prompt or a threshold, or choosing the
model, `alpha` or the cost matrix. Two things break that, and a certificate shows neither:

- **Reused cases.** Apart from refusing a repeated `case_id`, the issuer checks one overlap between
  roles: a `dr` map's recalibration cases against the two splits (`fit_dr`,
  `python/src/decision_cert/issue/certify.py`, around line 488). A certificate does not record which
  cases were used for what.
- **Selection over attempts.** Issuing at several values of `alpha`, seeds, windows, models,
  segment configurations or cost matrices on the same cases, and keeping the best, is selection the
  bound does not cover ([`docs/credit-approval.md`](../credit-approval.md), "The error target is
  chosen"; [`docs/model-risk.md`](../model-risk.md), "Alpha was chosen before the measurement").
  Nothing records how many attempts were made.

## Threat model

| | Adversary or event | Effect |
|---|---|---|
| T1 | An operator who runs many attempts and shows the best | The shown certificate's `delta` understates the chance its claim fails. |
| T2 | A pipeline that trains or tunes on the certification cases | The test is no longer on unused cases; the bound has no basis. |
| T3 | An operator who deletes failed attempts from its record | The record looks clean. |
| T4 | Dry runs: attempts made without issuing | Selection without a certificate to show for it. |
| T5 | Two ledgers, one shown | The shown ledger looks complete. |

The parties who read a ledger are inside the tenant's scope: the tenant's own validators and
consumers, and the auditor the tenant exports to. No one else.

**What no format can see.** An operator that computes thresholds with another tool, entirely outside
the issuer, leaves no entry. A ledger makes selection through the issuer visible, and makes skipping
the issuer a deliberate act. Only an independent party holding the data ([#29](auditor-countersignature.md))
narrows the rest. Labels that are wrong are out of scope here, as everywhere (spec §5).

## Design

Two parts: a hash-chained ledger of every attempt, and commitments to which cases had which role.

### The ledger

One tenant has one or more ledgers, each with an opaque id. A ledger is append-only: entry `seq`
names the hash of entry `seq − 1` in `prev`. Each entry is signed by a key with role `certificate`
in the tenant's key set ([K1](k1-key-revocation-rotation.md)), the same key that signs the
tenant's certificates, so a certificate and its ledger entries share one trust path.

An attempt is two entries. **`begin`** is written before the issuer reads the threshold split's
labels, and records everything chosen before the test. **`end`** records what happened.

```json
{
  "spec": "decision-cert-ledger-entry.v1",
  "ledger_id": "ledger:3b9e07d2c51a4f68a0e9d7b2c4f1836e",
  "seq": 41,
  "prev": "sha256:<hash of entry 40>",
  "recorded_at": "2026-11-16T09:30:00Z",
  "kind": "begin",
  "attempt": {
    "purpose": "certify",
    "reissue_of": null,
    "domain": "credit",
    "decision": "approved",
    "model_id": "lgbm/approval@7",
    "manifest_hash": "sha256:<hex>",
    "data_hash": "sha256:<hex>",
    "spec": "decision-certificate.v1.4",
    "method": "ltt",
    "risk": "selective_error",
    "alpha": 0.05,
    "delta": 0.1,
    "split": {"method": "time", "seed": null},
    "calibration_map_kind": "temperature",
    "config_hash": "sha256:<JCS of the decision's certificate config: segments, ttl_days, histogram_min_n, automate_options, cost>",
    "roles": "sha256:<hash of the roles entry in force>"
  },
  "signer_key_id": "ed25519:0c6e5b7d2a913f84",
  "signature": "<base64url Ed25519 over 'decision-cert/ledger-entry.v1\\n' + JCS>"
}
```

```json
{
  "spec": "decision-cert-ledger-entry.v1",
  "ledger_id": "ledger:3b9e07d2c51a4f68a0e9d7b2c4f1836e",
  "seq": 42,
  "prev": "sha256:<hash of entry 41>",
  "recorded_at": "2026-11-16T09:31:12Z",
  "kind": "end",
  "end": {
    "begin": "sha256:<hash of entry 41>",
    "outcome": "issued",
    "certificate_id": "sha256:<hex>"
  },
  "signer_key_id": "ed25519:0c6e5b7d2a913f84",
  "signature": "<...>"
}
```

- `purpose` is `certify`, `dry_run` or `reissue`. A `reissue` names the certificate it reissues
  (`reissue_of`), for example after a key is revoked (K1).
- `outcome` is `issued`, `issued_abstain_all` (`abstain_below` 1.01), `refused_floor` (spec §1.1
  step 8), `refused_input` (missing labels, unknown model version and the other input refusals) or
  `aborted`. `certificate_id` is set only when a certificate was signed.
- Entry hashes follow the rule of the [README](README.md): SHA-256 of the whole signed entry's JCS
  bytes. The `end` entry follows the certificate, so it can name `certificate_id` without a cycle.

**Dry runs count** (the draft's question 4). The reference issuer would append `begin` for every
run that reads the threshold split's labels, `--dry-run` included, and refuse to run without a
ledger once one is configured. So selection by dry runs through the issuer leaves entries.

### Data roles

A **`roles`** entry commits to which cases had which role, before the attempts that use it. For each
role, the number of cases and a Merkle root over salted case ids:

| Role | Cases |
|---|---|
| `train` | used to fit the model |
| `adapt` | used to fit an adapter or posterior for this tenant |
| `tune` | used to tune a prompt, a hyperparameter or a decision rule |
| `select` | used to choose the model, `alpha`, the cost matrix or the segment configuration |
| `recalibrate` | a `dr` map's recalibration set (spec v1.2 §1.1 step 2) |
| `certify_temperature` | the temperature split |
| `certify_threshold` | the threshold split |

```json
"roles": {
  "salt_id": "salt:1",
  "train": {"declared": true, "n": 120000, "root": "sha256:<Merkle root>"},
  "adapt": {"declared": true, "n": 0, "root": null},
  "tune": {"declared": true, "n": 4000, "root": "sha256:<Merkle root>"},
  "select": {"declared": true, "n": 4000, "root": "sha256:<Merkle root>"},
  "recalibrate": {"declared": true, "n": 0, "root": null},
  "certify_temperature": {"declared": true, "n": 2500, "root": "sha256:<Merkle root>"},
  "certify_threshold": {"declared": true, "n": 2500, "root": "sha256:<Merkle root>"}
}
```

- **Leaves** are SHA-256(salt ‖ UTF-8 `case_id`), sorted bytewise, hashed into a tree as RFC 9162
  §2.1 does. The salt is 32 random bytes per ledger, kept in the tenant's scope and given only to
  the tenant's auditor. A Merkle root lets the tenant show one case's role without revealing the
  others, and the salt stops anyone who guesses a `case_id` from testing whether it was used (the
  draft's question 2).
- **`declared: false`** says a role is unknown to the operator, for example `train` for a model the
  operator did not train (the draft's question 7). It is shown to every reader as undeclared, never
  as empty.
- **The splits are two roles** (the draft's question 6). The bound needs the threshold split unused
  by anything chosen before the test. The temperature split builds the grid, so it is a role of its
  own, and the issuer already keeps the two apart.
- **The issuer refuses** a `certify_threshold` case that is in any other declared role, and a
  `recalibrate` case in either split (today's check, kept). It can check only what it is told. A
  validator with the data, such as the tenant's auditor, checks that the declarations are true.

### How it binds to a certificate

- **v1 to v1.4 certificates (frozen).** No field. The ledger's `end` entry names `certificate_id`,
  so the link runs from ledger to certificate. A consumer is given the attempt's entries and the
  chain segment as a sidecar.
- **A later `spec` value** could add, inside the signed body, an `issuance` object:
  `{ledger_id, begin, attempts_on_data}`, where `begin` is the hash of the attempt's `begin` entry and
  `attempts_on_data` the number of earlier counted attempts (below) on the same threshold split in
  this ledger. The certificate would then state its own attempt count, and leaving out attempts would
  need a forked ledger, which [the transparency log](transparency-log.md) exposes. That would be a
  new `spec` value, decided by the owner; it changes no frozen spec and no `certificate_id`
  derivation.

### What a reader does with the ledger

1. Verify the chain from `seq` 0 (or from a log checkpoint, once [#28](transparency-log.md) exists)
   to the certificate's `end` entry: contiguous `seq`, matching `prev`, every signature by a
   `certificate` key that K1 accepts at that entry.
2. Find the **counted attempts** on the same threshold split: `begin` entries whose
   `certify_threshold` root matches (or, without roles, whose `data_hash` matches) and whose
   outcome ran a test. `refused_floor` and `refused_input` ran no test and do not count. Attempts
   with identical inputs and procedure parameters give identical results, so they count once; a
   `reissue` of the same inputs is one of those.
3. **Show the effective level** (the draft's question 5). If `m` `ltt` attempts ran on the same
   threshold split, each claim fails with probability at most its own `delta`, so whichever one was
   kept fails with probability at most the sum of the `delta`s (a union bound, whatever the rule for
   choosing). A reader can state that sum, capped at 1, next to the certificate's `delta`, without
   re-running anything. For `crc` attempts, whose claim is an expectation, the union bound does not
   apply, and the count is shown alone.
4. **Apply the consumer's policy**: show only, or refuse when the effective level exceeds a
   configured maximum.

### Anchoring

An operator holds its own ledger and could rewrite it (T3) or keep two (T5). Until the tenant log
exists, a ledger is tamper-evident only to a party that kept an earlier head, for example the tenant's
auditor at its last review. The recommendation (the draft's question 3): **ship the local ledger
first**, export its head to the tenant's auditor at each review, and let the tenant log
([#28](transparency-log.md)) anchor it later, every ledger entry becoming a log leaf. A key set (K1)
could also list a tenant's ledger ids, so a ledger outside that list is visibly not the tenant's.

### Tenancy

Ledgers are per tenant and never pooled. Entries carry domain, decision and model ids, which stay in
the tenant's scope with the certificates. Role commitments are salted per ledger, so the same case
id in two tenants' ledgers gives unrelated leaves.

## Alternatives considered

- **An attempt counter inside the certificate, with no ledger.** Rejected: the operator writes the
  counter and can start again from 1.
- **A plain hash of the sorted case ids per role** (the draft's first shape). Smaller, but proving
  one case's role needs every id. The salted Merkle root costs the same 32 bytes in the entry.
- **Bloom filters for roles.** Rejected: false positives would refuse honest certificates.
- **Preregistration in a public registry.** Rejected by tenant-only. A `begin` entry anchored in the
  tenant log is a registration of intent inside the tenant's scope.
- **One ledger across tenants.** Rejected by tenant-only.
- **Correcting the certificate's level automatically.** Not possible: the threshold was chosen at
  the certificate's own `delta`, and a stricter level would choose a different one. The union-bound
  level above is a statement about the claim, not a new threshold.

## Open questions for the owner

1. **Attempt policy.** Show the count and the effective level only (recommended first), or let a
   consumer refuse above a cap?
2. **What counts as the same attempt.** Which parameter changes make a new attempt? The proposal:
   any change to `data_hash`, the threshold-split root, `alpha`, `delta`, `method`, `risk`, the map
   kind, `config_hash` or the model makes a new one; a change of `spec` value alone, which gives the
   same measured numbers, does not.
3. **Required roles.** Must every role be declared, or only the two certification roles, with the
   rest optional?
4. **Ledger scope.** One ledger per tenant (recommended), or one per domain or decision?
5. **The salt.** Give the tenant's auditor the whole salt, or only per-case openings?
6. **Retention.** Keep entries for as long as any certificate they name can be checked
   (recommended), or a fixed period?
7. **The `issuance` field.** Plan it for a later certificate `spec` value, or keep R1 a sidecar
   only?

## What an implementation would touch

- **A new spec** for ledger entries and role commitments: `spec/decision-cert-ledger.v1.md` and its
  schema. A later certificate `spec` value only if question 7 says so.
- **Issuer:** `python/src/decision_cert/issue/certify.py`: `begin` before the threshold split's
  labels are read, `end` after signing or refusing, the roles check beside `fit_dr`'s overlap check
  (around line 488), flags `--ledger` and `--roles`; a new `issue/ledger.py` for the chain, the
  Merkle roots and the salt.
- **Verifiers:** a ledger module in the Rust crate and the Python verifier that checks a chain
  segment and counts attempts, kept in agreement by the differential test.
- **Fixtures:** a new `fixtures/ledger/` set: valid chains, a gap, a broken `prev`, a forked
  ledger, an entry signed by a revoked key, counted and uncounted outcomes.
- **Docs:** [`docs/model-risk.md`](../model-risk.md) ("No case was used twice", "Alpha was chosen
  before the measurement"), [`docs/certificates.md`](../certificates.md),
  [`docs/credit-approval.md`](../credit-approval.md).
