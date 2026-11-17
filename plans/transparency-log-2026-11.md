# Plan: the per-tenant transparency log (#28)

**Status.** Plan; owner go for the build after the design decisions of 2026-11-17; no code in this PR.
The design is [`docs/design/transparency-log.md`](../docs/design/transparency-log.md), with the
owner's answers in its [Decided](../docs/design/transparency-log.md#decided-owner-2026-11-17)
section. The shared rules for every trust design are in [`docs/design/README.md`](../docs/design/README.md).
A certificate describes a measured process and never guarantees an outcome; the log records what was
issued and when, and says nothing about whether a measurement was right.

## Scope

**What is built.** A sidecar format that shows a document was in a tenant's append-only log by a
witnessed time, the verifiers for it, its fixtures, the issuer's side of it, and a small reference
log and reference witness that a tenant can run itself. One log per tenant, inside the tenant's scope;
nothing about a tenant's certificates is published.

**The frozen-spec relationship.** v1 to v1.5 certificates, their schemas, fixtures and verdicts do not
change, and neither does `certificate_id` ([ERRATA, 2026-11-15](../spec/ERRATA.md)). The log is a
**sidecar**: a new document kind with its own `spec` string, `decision-cert-inclusion.v1`, that names
a certificate by `certificate_id`. A certificate verifies exactly as before with or without one.

**What this repository ships, and what it does not.** This repository ships the format, the verifiers,
the fixtures, the issuer's bundling, and the reference log and witness as file-based command-line
tools. It does not ship a log server, a network client, or a hosted partition: those belong to whoever
runs a tenant's log (see [Phase 5](#phase-5--the-log-the-reference-log-and-witness)). The verifiers
stay offline, as today.

## Phases

Each phase is its own PR, merged with a merge commit. Every PR passes CI, the `wording` job included.

### Phase 1 — spec draft: `decision-cert-inclusion.v1`

A draft at `spec/drafts/decision-cert-inclusion.v1.md` with a draft schema
`spec/drafts/decision-cert-inclusion.v1.schema.json`. It moves to `spec/` only at the freeze
([Phase 6](#phase-6--freeze)), as v1.5 did. It defines:

1. **Leaves.** Every leaf is a JCS (RFC 8785) object with a `kind`, holding ids and hashes, never a
   document's contents. Unknown members and unknown kinds are refused. A document's hash is the shared
   rule's: `sha256:` + hex SHA-256 of the JCS bytes of the whole signed document, `signature` included.

   | `kind` | Members | Appended when |
   |---|---|---|
   | `certificate` | `certificate_id`, `signer_key_id`, `spec`, `fitted_at`, and `tenant` for a v1.5 certificate only (equal to its `tenant`) | a certificate is signed, or backfilled |
   | `ledger_entry` | `ledger_id`, `seq`, `entry` (the entry's hash) | every [R1](../docs/design/r1-issuance-ledger.md) entry, `begin` and `end` |
   | `keyset` | `keyset_id`, `seq`, `keyset` (the key set's hash) | every [K1](../docs/design/k1-key-revocation-rotation.md) key set |
   | `attestation` | `attestation` (its hash), `certificate_id` | every [auditor attestation](../docs/design/auditor-countersignature.md), `mismatch` included |
   | `audit_head` | `tenant`, `chain`, `seq`, `digest`, `observed_at` | a service anchors the head of its own audit chain (below) |

   **The audit-head checkpoint leaf.** A service that keeps a per-tenant hash-chained audit log can
   record its chain's head in the tenant's log: `tenant` (the tenant id, in v1.5's `tenant` form),
   `chain` (an opaque name the tenant gives the chain, so one tenant can anchor several), `seq` (the
   head's position, an integer from 1), `digest` (the digest the chain's next record must link to,
   `sha256:` + 64 lowercase hex) and `observed_at` (when the service read the head, in the strict
   `YYYY-MM-DDTHH:MM:SSZ` form). A hash chain cannot show by itself that its tail was removed: the
   remaining chain still verifies, with an earlier head. A head recorded in the tenant's log, outside
   the chain writer's control, can be compared with the chain at the next check. `observed_at` is the
   service's own claim; the independent time is the witnesses' cosignature time on the checkpoint that
   includes the leaf. The leaf is evidence about the chain, not about the records in it. Comparing a
   head with a chain is the chain verifier's job, outside this repository.

2. **Hashing.** RFC 9162 §2.1 (RFC 6962 style), domain-separated: a leaf's hash is
   SHA-256(0x00 ‖ JCS(leaf)), an inner node's SHA-256(0x01 ‖ left ‖ right). Inclusion proofs and
   their verification follow RFC 9162 §2.1.3, consistency proofs §2.1.4.

3. **Checkpoints.** The C2SP `tlog-checkpoint` signed note: origin line = the `log_id`
   (`log:` + 32 lowercase hex, random, so it does not name the tenant), tree size, root hash, signed by
   the log key. Witnesses add C2SP `tlog-cosignature` (`cosignature/v1`) signatures, each with its
   own timestamp. The draft pins the C2SP revisions it cites, how a C2SP key name and key hash map to
   this repository's `ed25519:` key ids, and that a checkpoint carries no extension lines in v1.

4. **The bundle** that travels with a certificate, a JCS object with `spec` =
   `decision-cert-inclusion.v1`:

   | Member | |
   |---|---|
   | `log_id` | the log's id |
   | `leaf_index`, `leaf` | the leaf and its position |
   | `proof` | the audit path: node hashes in standard base64, the checkpoint's own encoding, so a computed root compares byte for byte |
   | `checkpoint` | the signed note text, the log's signature and the witness cosignatures included |
   | `certificate` | the certificate as issued, for a `certificate` leaf; absent for the other kinds, whose documents travel on their own |

   The bundle is not signed on its own; it is checked against the checkpoint's signatures.

5. **The consistency proof** document: two checkpoints of one log and the RFC 9162 §2.1.4 path between
   them.

6. **The log trust configuration**, the consumer's, as trusted keys are today: the expected tenant;
   that tenant's logs (`log_id`, C2SP key name, public key); its witnesses (name, public key); `m`, the
   number of distinct trusted witness cosignatures required (default 1); and `policy` for a certificate
   without a proof, `off`, `warn` or `refuse` (default `warn`). One configuration per tenant; a
   `log_id` listed under two tenants is refused, as one key under two tenants is (v1.5 §4). When K1
   lands, its key set's `log` and `witness` roles supply these keys, and the configuration keeps `m`
   and `policy`.

7. **What a consumer checks, offline**, in order: the bundle's form; for a `certificate` leaf, that
   `certificate_id` is the certificate's id and the other members match it, and for a v1.5
   certificate that its `tenant` equals the leaf's and the expected tenant; that `log_id` is one of the
   expected tenant's logs; the audit path from the leaf hash at `leaf_index` to the checkpoint's root;
   the log's signature; at least `m` cosignatures from distinct trusted witnesses (untrusted ones are
   ignored; a checkpoint with two lines from one key is refused as malformed). The verdict reports
   `t_proven`, the `m`-th earliest cosignature time among the trusted witnesses counted, for K1's
   compromise rule.

**Done when** the draft and its schema are merged, every member above has a stated form and every
check a stated refusal, and the draft lists its open questions (none expected beyond the ones below).

### Phase 2 — the Rust verifier (the oracle)

A new module `rust/src/inclusion.rs`, additive only, with no new dependencies beyond what the crate
already uses for SHA-256 and Ed25519. Proposed API:

| Function | Does |
|---|---|
| `inclusion::leaf_hash(&Leaf) -> [u8; 32]` | the 0x00-prefixed leaf hash of any leaf kind |
| `inclusion::node_hash(&[u8; 32], &[u8; 32]) -> [u8; 32]` | an inner node |
| `inclusion::parse_checkpoint(&str) -> Result<Checkpoint, CertError>` | parse a signed note, without trusting it |
| `inclusion::LogTrust::from_json(&Value)` | the log trust configuration |
| `inclusion::verify_bundle(&Value, &LogTrust) -> Result<InclusionVerdict, CertError>` | Phase 1's checks; the verdict carries `log_id`, `tree_size`, `leaf_index`, the counted witnesses and `t_proven` |
| `inclusion::verify_consistency(&Value, &LogTrust) -> Result<ConsistencyVerdict, CertError>` | both checkpoints signed by the same trusted log key, and the path between them |
| `inclusion::apply_policy(Option<Result<InclusionVerdict, CertError>>, Policy) -> PolicyOutcome` | `off`, `warn` or `refuse` for a missing or failed proof |

For a v1.5 certificate, `verify_bundle` is used with `verify_for_tenant`; the bundle check does not
replace the certificate's own verification. The CLI (feature `cli`) gains `verify-bundle` and
`verify-consistency` with the existing exit codes (0 accepted, 1 refused, 2 unreadable or a usage
error); under `warn`, a certificate without a proof exits 0 with a warning on stderr.

**Done when** the module and CLI are merged with unit tests over hand-built small trees (sizes 1 to 9,
every index) and RFC 9162's own algorithms, clippy and fmt clean, and the crate's existing API and
fixtures are unchanged.

### Phase 3 — the Python verifier, the generator and `fixtures/inclusion-v1/`

The Python verifier gets the same functions (`decision_cert.leaf_hash`, `verify_bundle`,
`verify_consistency`, `parse_checkpoint`, `apply_policy`, `LogTrust`), with no new dependencies, and
`python -m decision_cert verify-bundle` / `verify-consistency` with the Rust CLI's exit codes.

A new generator, `python/tools/gen_inclusion_fixtures.py`, builds deterministic trees with test keys
derived from fixed seeds (public keys and deterministic signatures only), writes
`fixtures/inclusion-v1/` and its manifest `fixtures/inclusion-v1/INCLUSION.sha256`, and has a
`--check` mode run in CI. Fixtures are never hand-edited. The expected verdicts are recorded by running
the Rust crate, and both verifiers must agree on every file; the differential test covers random trees
and indices. The design's `fixtures/log/` name is replaced by `fixtures/inclusion-v1/`.

**Positive cases:** a certificate leaf for a v1.2, a v1.5 `operator` and a v1.5 `hosted` certificate;
tree sizes 1, 2, 3, 7, 8 and a few hundred, at the first, last and a middle index; `m = 1` with one
witness and `m = 2` with three witnesses of which two cosign; an `audit_head` leaf; leaf-hash vectors
for `ledger_entry`, `keyset` and `attestation`; consistency proofs 1→2, 3→7, 7→8 and an equal size;
a backfilled certificate.

**Negative cases**, each with its refusal:

- a leaf member changed (bad leaf hash), and a leaf hashed without the 0x00 prefix;
- the wrong `leaf_index`; a path for another tree size; a path one hash short or long;
- the checkpoint's log signature wrong; signed by a log key the tenant does not trust; origin not the
  bundle's `log_id`; a malformed note (missing final newline, extra line, non-canonical base64);
- too few cosignatures for `m`; a cosignature from an untrusted witness (ignored, then short of `m`);
  one witness's cosignature twice (refused: two lines from one key, `checkpoint_form`); a
  cosignature over another checkpoint;
- a consistency proof that does not extend the older checkpoint; a newer size smaller than the older;
  two checkpoints of one size with different roots (a split view);
- a leaf for another certificate (`certificate_id` mismatch); a leaf whose `signer_key_id`, `spec` or
  `fitted_at` does not match the certificate;
- a leaf for another tenant's certificate: the bundle's `log_id` belongs to another tenant's
  configuration;
- a v1.5 certificate whose `tenant` does not match the log's tenant, and a leaf whose `tenant` does not
  match its certificate's;
- an unknown leaf kind, an unknown bundle member, a wrong `spec` string; an `audit_head` leaf with a
  malformed `digest` or `observed_at`;
- the policy table: no proof under `off`, `warn` and `refuse`.

**Done when** the fixtures are generated, `--check` passes in CI, CI counts the set (as it counts
`fixtures/v1.5/`), and the Rust crate and the Python verifier agree on every file and in the
differential test. Once, outside CI, a fixture checkpoint and cosignature are checked with an
independent C2SP implementation and the result is recorded in the PR.

### Phase 4 — issuer and tooling

- **The issuer writes the leaf.** After signing, the reference issuer writes the certificate's leaf
  (`--leaf-out`) for whoever runs the log to append. It never calls a log: it writes files and reads
  files.
- **It accepts a proof and bundles it.** `python -m decision_cert bundle --certificate <c> --proof <p>`
  checks the proof against the certificate and a log trust configuration, then writes the bundle.
- **`verify-bundle`** in both CLIs (Phase 2 and 3), and the same check in `verify-pack` for a later
  pack version (not in this plan).
- **Backfill** (owner, 2026-11-17). `python -m decision_cert log backfill` appends a leaf for each
  certificate issued before the tenant's log existed, ordered by `fitted_at` then `certificate_id`,
  before any new leaf. A backfilled certificate's `t_proven` is the first cosigned checkpoint after
  the backfill: it gets no early time evidence. Under K1's compromise rule it therefore counts as
  signed after the log started. The docs say so, and the fixtures include one.
- **Backfilled certificates are marked** (owner, 2026-11-17): a reader sees plainly that a certificate
  was backfilled, beyond the absence of early time evidence, and the leaf stays byte-identical (no new
  leaf member; every leaf and leaf hash unchanged). `log backfill`'s leaf records carry
  `"backfilled": true` (an issued certificate's record has no such member); `bundle` copies it into the
  bundle's OPTIONAL `backfilled` (`--backfilled`, or `--leaf-record`), the bundler's statement; the log
  trust configuration's OPTIONAL per-log `started_at` is the consumer's authenticated basis; the verdict
  reports `backfilled` and `backfilled_by` (`bundle`, `started_at`) for a certificate leaf, and never
  refuses on it (draft §8 to §10, §12). Both verifiers implement it, and the fixtures cover the bundle's
  mark, `started_at` after, at and before `fitted_at`, both together, and the refusals of a malformed
  `backfilled` (`bundle_form`) and `started_at` (`trust_form`).

**Done when** a certificate can go from the issuer, through the reference log of Phase 5 (or any log
that emits a conforming proof), to a bundle that both verifiers accept; documented in
[`docs/certificates.md`](../docs/certificates.md).

### Phase 5 — the log: the reference log and witness

**Where the log runs.** Two places fit the owner's decision that the tenant chooses who runs its log:

| | (a) A reference log in this repository | (b) A hosted partition in a hosting service |
|---|---|---|
| What | A minimal file-backed log, C2SP `tlog-tiles` layout, as Python commands: `log init`, `append`, `checkpoint`, `prove`, `consistency`, `backfill` | One log per tenant inside the hosting service, written by the service as it issues, each partition with its own `log_id` and key |
| For | A tenant that runs its own log; the generator's deterministic trees; anyone checking the format | Hosted tenants |
| Licence | This repository's Apache-2.0, no new dependency | The service's choice, for example Trillian Tessera (Apache-2.0, Go), which writes C2SP checkpoints |
| Operations | Files on the tenant's disk, run on the tenant's schedule; no server | A server with storage, uptime and backups |
| Repository rules | Fits: no data, no network, no server | A server and its storage do not belong in this repository |
| Tenant-only | One log per directory, one tenant per log | One partition per tenant; never a shared log |

**Recommendation for the first build: (a).** The reference log is small (a tree, a tile layout and a
signer, no server), and the generator needs most of it anyway to build deterministic fixtures. It keeps
this repository's rules: no data, no network service, no server, and no new toolchain (a Go engine
would add one). It gives a self-hosting tenant a log on the first release, and it gives a hosting
service a reference whose output its own implementation must match byte for byte. The hosted partition
(b) follows in the hosting service, against the frozen spec, and is checked with this repository's
verifiers and fixtures; it is planned there, not here. Neither shares a log across tenants, and neither
publishes anything: no public anchors (owner, 2026-11-17).

**This repository ships:** the spec, both verifiers, the fixtures, the issuer's leaf and bundle steps,
the reference log commands, and a reference witness. **A hosting service ships:** its per-tenant
partitions, its own log client in the issuing path, the network transport between log and witnesses,
storage and retention, and the hourly schedule.

**The reference witness.** `python -m decision_cert witness cosign --state <file> --checkpoint <new>
--consistency <proof>` checks the log's signature and the consistency proof from the last checkpoint it
cosigned (kept in its state file), then writes a `cosignature/v1` line with its timestamp and updates
its state. It refuses a checkpoint that does not extend the previous one, so it never cosigns two
histories. It is file-based; carrying checkpoints to a witness over a network is the operator's. Which
witnesses a tenant uses, and `m`, are the tenant's choice (owner, 2026-11-17): its auditor, a second
system of its own outside the log operator's control, or an independent witness. The docs say that some
independent witnesses republish what they cosign, which shows a tenant's log size to others, so a
tenant picks one that does not, or accepts that.

**The backfilled mark in the reference log.** `log init` records the log's `started_at` (the time of its
first entry) and prints it for the tenant's consumers to put in their log trust configurations (draft
§9); `log backfill` keeps writing `"backfilled": true` in each record, beside the leaf it appends, and
`prove` hands that record's mark to `bundle`. The log itself stores only leaves.

**Done when** the reference log and witness commands are merged, the generator builds its fixtures
through them, and an end-to-end test runs issue → append → checkpoint → cosign → prove → bundle →
verify in both verifiers.

### Checkpoint cadence (part of Phases 4 and 5)

- **Hourly by default, configurable per log** (owner, 2026-11-17). The reference log has no scheduler:
  its operator runs `log checkpoint` on the configured cadence (a hosting service runs its own
  schedule).
- **While waiting**, the certificate exists and is valid as a certificate; its proof follows at the next
  cosigned checkpoint. The issuer keeps the certificate with its leaf index and bundles it when the
  proof arrives. A proof against an older checkpoint stays valid; it never needs refreshing.
- **Under `warn`** (the default), a consumer loads a certificate without a proof and records a warning
  naming `certificate_id`. Under `refuse`, it does not load it until the bundle arrives. Under `off`,
  it does not look. A proof that is present but fails is refused under `warn` and `refuse` alike: `warn`
  covers a missing proof, not a bad one.

### Phase 6 — freeze

The draft moves to `spec/decision-cert-inclusion.v1.md` and `spec/decision-cert-inclusion.v1.schema.json`,
frozen from then on (corrections go in `spec/ERRATA.md`). Docs updated: `docs/certificates.md`,
`docs/model-risk.md` ("Any record of other certificates issued on the same cases"),
`docs/conformance.md`, `SECURITY.md`, `CLAUDE.md` and `README.md`. The design's banner says it is built.

**Done when** the owner says go for the freeze and the freeze PR is merged with CI green.

### Phase 7 — release

A minor release (0.7.0) after the freeze: version bump and `CHANGELOG.md`. The owner pushes the tag;
`release.yml` publishes. No session tags or publishes.

**Done when** the owner has tagged `v0.7.0` and both packages are published.

## Decisions (owner, 2026-11-17)

From the design's [Decided](../docs/design/transparency-log.md#decided-owner-2026-11-17) section:

| | Decision | In this plan |
|---|---|---|
| Witnesses and `m` | Configurable per tenant, default `m = 1` | Log trust configuration; fixtures with `m = 1` and `m = 2` |
| Consumer default without a proof | `warn`, not `refuse` | `apply_policy`; `warn` covers a missing proof, never a bad one |
| Who runs a tenant's log | The tenant chooses: itself, or a hosted partition | Reference log here; hosted partition in a hosting service |
| Checkpoint cadence | Hourly by default, configurable | Run on the log operator's schedule |
| Older certificates | Backfilled when the log starts, with no early time evidence, and marked as backfilled (leaf unchanged) | `log backfill`; `t_proven` from the first checkpoint after it; the bundle's `backfilled`, the configuration's `started_at`, the verdict's `backfilled` |
| Blind anchors | Not now | Not built |
| Tree-size padding | None | Not built |

## Open for the owner

1. **Build before K1?** The design's suggested order puts K1's key set first, and K1's questions are
   still open. *Recommendation:* do not wait. The log trust configuration carries the log and witness
   keys directly, as trusted keys work today, and K1's roles replace that part of it when K1 lands.
   `t_proven` is reported from the start and used by K1's compromise rule once K1 exists.
2. **All five leaf kinds in v1, before R1, K1 and attestations have specs?** *Recommendation:* yes.
   The leaves hold only ids, sequence numbers and hashes under the shared hashing rule, so their form
   does not depend on those documents' contents, and an auditor's export can read every leaf from the
   first release. Checking a leaf against its document comes with each document's own spec.
3. **The hosted partition's schedule.** *Recommendation:* the hosting service plans it in its own
   repository once Phase 1's draft is merged, so it builds against the draft and switches to the frozen
   spec at Phase 6.

## Out of scope

- **Blind anchors** to a public log (owner, 2026-11-17: not now).
- **Tree-size padding** (owner, 2026-11-17: none).
- **Re-labelling** samples, deferred in the [auditor design](../docs/design/auditor-countersignature.md).
- **An auditor's access to a tenant's data**, which belongs to a hosting service's multi-tenant design.
- **Anything that publishes a tenant's data**: no public log, no shared log across tenants, no
  certificate, id or tenant name outside the tenant's scope. Only checkpoints (log id, size, root hash)
  reach the tenant's witnesses.
- A log server, a network client or a witness network in this repository; the hosted partition itself.
- Changing any frozen certificate spec, schema, fixture or `certificate_id`.
- Carrying bundles in evidence packs, which needs a later pack version.
