> **Draft, not frozen.** Phase 1 of the build plan
> [`plans/transparency-log-2026-11.md`](../../plans/transparency-log-2026-11.md), on the design
> [`docs/design/transparency-log.md`](../../docs/design/transparency-log.md) and the owner's decisions
> of 2026-11-17 ([Decision log](#decision-log)). The Rust verifier (`decision_cert::inclusion`) implements
> it; the Python verifier, fixtures, issuer tooling and reference log follow. The text may change until the owner approves the freeze, when it moves to `spec/decision-cert-inclusion.v1.md`
> (plan, Phase 6). The certificate specs v1 to v1.5 are frozen and unchanged by it.

# Decision certificate inclusion, v1 (draft): a tenant's transparency log

This document defines how a tenant's append-only log records what was issued, and the offline proof,
carried next to a certificate, that the log recorded it by a time its witnesses vouch for:

- the **leaves** a log holds, one per recorded document, and how they are hashed into a Merkle tree;
- the **checkpoint**, a signed note naming the log, its size and its root hash, and the witnesses'
  **cosignatures** on it;
- the **bundle**, which carries a leaf, its inclusion proof and a cosigned checkpoint, and for a
  certificate leaf the certificate itself;
- the **consistency proof** document between two checkpoints of one log;
- the consumer's **log trust configuration**, the **checks** a consumer makes with it, in order, each
  with an error name, and the consumer's **policy** for a certificate without a bundle.

Machine-readable schema (draft): [`decision-cert-inclusion.v1.schema.json`](decision-cert-inclusion.v1.schema.json).

## 0. Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT",
"RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as
described in BCP 14 ([RFC 2119](https://www.rfc-editor.org/rfc/rfc2119),
[RFC 8174](https://www.rfc-editor.org/rfc/rfc8174)) when, and only when, they appear in all capitals.

- `||` is byte concatenation; `0x00` is a byte; `"..."` in a byte expression is its ASCII bytes.
- **JSON.** Every document here is a JSON object ([RFC 8259](https://www.rfc-editor.org/rfc/rfc8259))
  that is also I-JSON ([RFC 7493](https://www.rfc-editor.org/rfc/rfc7493)): UTF-8, and no object has
  two members with the same name. An integer member is written as a JSON integer, with no fraction and
  no exponent, and is at most 2^53 − 1. A verifier refuses a document that breaks any of these as a
  form error of that document (§10).
- **JCS.** The canonical bytes of a JSON value are its JSON Canonicalization Scheme bytes
  ([RFC 8785](https://www.rfc-editor.org/rfc/rfc8785)), as for certificates (spec v1.2 §3).
- **Hashes.** SHA-256 as in FIPS 180-4. A *document hash* is `sha256:` + the 64 lowercase hex
  characters of SHA-256 of the JCS bytes of the whole signed document, `signature` included: the rule
  of [`certificate_id`](../ERRATA.md) (ERRATA, 2026-11-15) and of the trust designs
  ([`docs/design/README.md`](../../docs/design/README.md)).
- **base64** is the standard alphabet with `=` padding ([RFC 4648 §4](https://www.rfc-editor.org/rfc/rfc4648#section-4)),
  canonical as in RFC 4648 §3.5: an encoder writes canonical base64 and a decoder refuses any other.
  A 32-byte hash is therefore exactly 44 characters, the 43rd one of `AEIMQUYcgkosw048`, and the
  44th `=`. **base64url** is RFC 4648 §5 without padding, as public keys are written today.
- **Times** in JSON are UTC in the strict form `YYYY-MM-DDTHH:MM:SSZ`, as `fitted_at` is, naming a
  real calendar date with hours 00 to 23, minutes 00 to 59 and seconds 00 to 59. A time with seconds
  `60` (a leap second) is out of this form and refused: in a leaf, as `leaf_form`.
- **Ed25519** signatures are [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) signatures, verified
  strictly as certificates are (spec v1.2 §3): a verifier also rejects a small-order public key, a
  small-order `R`, and `S` at or above the group order.
- **Key ids.** A key's id in this repository's form is `ed25519:` + the first 16 lowercase hex
  characters of SHA-256 of the raw 32-byte public key (spec v1.2 §2, `signer_key_id`).
- **Pinned external specifications.** This draft cites the C2SP specifications at their v1.1.0
  revisions and no other: [`c2sp.org/signed-note@v1.1.0`](https://c2sp.org/signed-note@v1.1.0),
  [`c2sp.org/tlog-checkpoint@v1.1.0`](https://c2sp.org/tlog-checkpoint@v1.1.0) and
  [`c2sp.org/tlog-cosignature@v1.1.0`](https://c2sp.org/tlog-cosignature@v1.1.0). Where this document
  is stricter than those, this document applies. Merkle trees follow
  [RFC 9162 §2.1](https://www.rfc-editor.org/rfc/rfc9162#section-2.1).

## 1. Relation to the certificate specs

- **A sidecar.** No certificate field changes. v1 to v1.5 certificates, their schemas, fixtures and
  verdicts, and `certificate_id`, are unchanged. A certificate verifies under its own spec exactly as
  before, with or without a bundle, and a bundle's checks never replace that verification (§10).
- **Spec strings.** This document defines three document kinds, each named by its `spec` member:

  | `spec` | Document | Section |
  |---|---|---|
  | `decision-cert-inclusion.v1` | the bundle | §8 |
  | `decision-cert-consistency.v1` | the consistency proof document | §7 |
  | `decision-cert-log-trust.v1` | the consumer's log trust configuration | §9 |

  Leaves (§3) are not documents on their own; they carry `kind` and travel inside a bundle.
- **Not signed on their own.** A bundle and a consistency proof document carry no signature of their
  own. They are checked against the signatures in the checkpoints they carry.

## 2. Tenancy

- **One log, one tenant.** A log belongs to exactly one tenant and holds only that tenant's leaves. A
  log MUST NOT hold leaves for two tenants, and there is no log across tenants. A tenant MAY have more
  than one log.
- **`log_id`.** A log is named by `log_id`: `log:` + 32 lowercase hex characters, chosen at random
  (from a cryptographically secure source, 128 bits) when the log is created. It names neither the
  tenant nor its operator, because it is the one name that reaches the tenant's witnesses (§5).
- **The tenant in a leaf.** A `certificate` leaf for a v1.5 certificate, and every `audit_head` leaf,
  carry `tenant`, which MUST equal the tenant whose log holds the leaf. A consumer refuses a v1.5
  certificate whose `tenant` differs from the log's tenant, the tenant of its configuration (§10,
  `tenant_mismatch`). A v1 to v1.4 certificate names no tenant; for it, the tie to the tenant is that
  the bundle's `log_id` is one of the expected tenant's logs (§10, `unknown_log`).
- **One log under two tenants.** A consumer that holds several tenants' configurations refuses them
  when one `log_id`, or one log key, appears under two tenants (§9, `trust_cross_tenant`), as one
  certificate key under two tenants is refused (spec v1.5 §4). A witness MAY serve several tenants:
  it sees only checkpoints.
- **Who runs a log** (the tenant itself, or a hosting service inside the tenant's partition) is
  outside this document. Everything here holds whoever runs it.

## 3. Leaves

### 3.1 Common rules

- A leaf is a JSON object with a member `kind`, one of the five kinds below, and exactly the members
  that kind lists: none missing, none unknown. A verifier refuses an unknown `kind`, an unknown
  member, a missing member, and a member out of its form (`leaf_form`).
- A leaf holds ids, sequence numbers, times and hashes. It never holds a document's contents.
- A leaf's **canonical bytes** are the JCS bytes of the leaf object. Every member's value is ASCII by
  its form, so the bytes are fixed by the members alone.
- `kind` is the leaf's type and its version: the five kinds are those of `decision-cert-inclusion.v1`.
  A later version adds kinds under new names and never changes a v1 kind's members.

### 3.2 The kinds

| `kind` | Members (besides `kind`) | Appended when |
|---|---|---|
| `certificate` | `certificate_id`, `signer_key_id`, `spec`, `fitted_at`, and `tenant` for a v1.5 certificate only | a certificate is signed, or backfilled (§12) |
| `ledger_entry` | `ledger_id`, `seq`, `entry` | an issuance-ledger entry is written, `begin` and `end` alike |
| `keyset` | `keyset_id`, `seq`, `keyset` | a key set is signed |
| `attestation` | `attestation`, `certificate_id` | an auditor's attestation is signed, `mismatch` included |
| `audit_head` | `tenant`, `chain`, `seq`, `digest`, `observed_at` | a service records the head of its own audit chain |

**`certificate`.** The certificate's own values, copied, so a leaf can be matched to its certificate
member by member:

| Member | Form |
|---|---|
| `certificate_id` | the certificate's document hash (§0): `sha256:` + 64 lowercase hex |
| `signer_key_id` | the certificate's `signer_key_id`: `ed25519:` + 16 lowercase hex |
| `spec` | the certificate's `spec`: one of `decision-certificate.v1`, `.v1.1`, `.v1.2`, `.v1.3`, `.v1.4`, `.v1.5` |
| `fitted_at` | the certificate's `fitted_at`, a time (§0) |
| `tenant` | present if and only if `spec` is `decision-certificate.v1.5`: the certificate's `tenant`, 1 to 128 characters of `A-Z a-z 0-9 . _ : -` |

A `certificate` leaf for a v1 to v1.4 certificate that carries `tenant`, and one for a v1.5
certificate that lacks it, are refused (`leaf_form`).

**`ledger_entry`.** An entry of a tenant's issuance ledger
([R1 design](../../docs/design/r1-issuance-ledger.md)). `ledger_id` is `ledger:` + 32 lowercase hex;
`seq` is the entry's position, an integer from 0; `entry` is the entry's document hash.

**`keyset`.** A tenant's key set ([K1 design](../../docs/design/k1-key-revocation-rotation.md)).
`keyset_id` is `keyset:` + 32 lowercase hex; `seq` is the key set's sequence number, an integer from
0; `keyset` is the key set's document hash.

**`attestation`.** An auditor's attestation on a certificate
([auditor design](../../docs/design/auditor-countersignature.md)). `attestation` is the attestation's
document hash; `certificate_id` is the id of the certificate it names.

For these three kinds this document fixes the leaf only. Checking a leaf against its document (that
`entry` is the hash of a given ledger entry, say) belongs to that document's own spec, written later.

**`audit_head`.** The head of a hash-chained audit log that a service keeps for the tenant, recorded
in the tenant's log, outside the chain writer's control. A hash chain cannot show by itself that its
tail was removed (the shorter chain still verifies, with an earlier head); a recorded head can be
compared with the chain at the next check.

| Member | Form |
|---|---|
| `tenant` | the tenant, in v1.5's `tenant` form; it MUST equal the log's tenant |
| `chain` | an opaque name the tenant gives the chain, so one tenant can record several: 1 to 128 characters of `A-Z a-z 0-9 . _ : -` |
| `seq` | the head's position in the chain, an integer from 1 |
| `digest` | the digest the chain's next record must link to: `sha256:` + 64 lowercase hex |
| `observed_at` | when the service read the head, a time (§0) |

`observed_at` is the service's own claim. The independent time is the witnesses' cosignature time on
a checkpoint that includes the leaf (§10, `t_proven`). The leaf is evidence about the chain, not about
the records in it; comparing a head with a chain is the chain verifier's job, outside this document.

### 3.3 Example

```json
{"certificate_id":"sha256:<64 hex>","fitted_at":"2026-11-16T09:31:10Z","kind":"certificate","signer_key_id":"ed25519:0c6e5b7d2a913f84","spec":"decision-certificate.v1.5","tenant":"acme-eu"}
```

## 4. The tree

A log is a Merkle tree over its leaves in the order they were appended, numbered from 0, with RFC 9162
§2.1.1 hashing, domain-separated between leaves and inner nodes:

```
leaf_hash(leaf)  = SHA-256(0x00 || JCS(leaf))
node_hash(l, r)  = SHA-256(0x01 || l || r)
```

The root of a tree of `n` leaves is RFC 9162's MTH over the leaf hashes: for `n = 1` the leaf hash
itself, and for `n > 1`, with `k` the largest power of two smaller than `n`,
`node_hash(MTH(leaves[0:k]), MTH(leaves[k:n]))`. A log holds at least one leaf before its first
checkpoint; this document defines no empty tree.

## 5. Checkpoints and cosignatures

### 5.1 The checkpoint

A checkpoint is a C2SP `tlog-checkpoint` signed note (c2sp.org/tlog-checkpoint@v1.1.0, over
c2sp.org/signed-note@v1.1.0). In this version its form is fixed exactly:

```
<origin>\n
<tree size>\n
<root hash>\n
\n
— <key name> <base64 signature>\n
...
```

- **Note text.** Exactly three lines, each ending in a newline (U+000A):
  1. the **origin**, a non-empty line, which MUST be the log's `log_id`. Its value is not part of the
     note's form: an origin other than the document's `log_id` is `origin_mismatch` (§10, check 8),
     not `checkpoint_form`;
  2. the **tree size**, the number of leaves, in ASCII decimal with no leading zeros, at least 1 and
     at most 2^64 − 1;
  3. the **root hash**, the base64 of the tree's 32-byte root (§4).

  A checkpoint carries **no extension lines** in v1. The note text includes its final newline.
- **Signatures.** After the note text, one empty line, then 1 to 100 signature lines, each: em dash
  (U+2014), space, key name, space, base64 signature value, newline. The note ends with the newline
  of its last signature line; nothing follows it.
- **Bytes.** The note is UTF-8 with no control character other than U+000A (no carriage return, no
  tab). A key name is 1 to 255 characters, printable ASCII (U+0021 to U+007E) other than `+`.
- **Signature values.** Each decodes, as canonical base64, to at least 5 bytes: a 4-byte key ID,
  big-endian, then the signature.
- **No repeated key.** No two signature lines have both the same key name and the same key ID
  (c2sp.org/tlog-checkpoint@v1.1.0, "Signatures"). A checkpoint with two or more lines from one key,
  a witness's or the log's, is refused, however many of them verify.

A verifier refuses a checkpoint that breaks any rule of this section as `checkpoint_form`, whether or
not the broken line belongs to a trusted key. A malformed checkpoint is always `checkpoint_form` (§10,
check 7), never `bundle_form`: the bundle's form check (check 2) and the consistency document's (§7.2)
require only that a checkpoint member is a JSON string, and every rule of this section is checked at
check 7.

### 5.2 The log's signature

The log signs with an Ed25519 log signature (c2sp.org/tlog-checkpoint@v1.1.0, "Ed25519 Log
Signatures"; signed-note type `0x01`): an Ed25519 signature over the note text, its final newline
included. Its signature line carries the log key's **key name** (§9; it SHOULD be the `log_id`) and the
value base64(key ID || signature), 68 bytes, with

```
key ID = SHA-256(key name || 0x0A || 0x01 || 32-byte public key)[:4]
```

### 5.3 Witness cosignatures

A witness cosigns with an Ed25519 checkpoint cosignature, `cosignature/v1`
(c2sp.org/tlog-cosignature@v1.1.0, "Ed25519"; signed-note type `0x04`). Its signature line carries
the witness's **name** (§9) and the value base64(key ID || timestamp || signature), 76 bytes, with

```
key ID    = SHA-256(witness name || 0x0A || 0x04 || 32-byte public key)[:4]
timestamp = the cosigning time, POSIX seconds, as an 8-byte big-endian unsigned integer
signature = Ed25519 over:
            "cosignature/v1" || 0x0A ||
            "time " || <timestamp in ASCII decimal> || 0x0A ||
            <the checkpoint's note text>
```

The signed message is the C2SP one: the fixed line, the time line, then the checkpoint's three lines,
each ending in a newline. A witness cosigns a checkpoint only after checking that it is consistent with
the last checkpoint of that log it cosigned (§7), and never cosigns two inconsistent checkpoints of one
log. In this version a cosignature's timestamp is at most 253402300799 (9999-12-31T23:59:59Z), so it
has a time in §0's form.

Other C2SP signature types (ML-DSA-44 cosignatures among them) are not used in v1. A line of another
type matches no trusted key (its key ID is computed with another type byte) and is ignored (§5.4).

### 5.4 Which lines count

A signature line **matches** a trusted key when its key name equals the key's name and its key ID
equals the key ID computed for that key's type above. Following c2sp.org/signed-note@v1.1.0:

- a line that matches no trusted key is ignored, even when it shares a name or a key ID (not both)
  with one;
- a line that matches a trusted key MUST verify; if it does not, the checkpoint is refused
  (`bad_log_signature` or `bad_cosignature`);
- a checkpoint with no line that matches the log's key is refused (`log_signature_missing`).

Because no key has two lines (§5.1), each trusted witness has at most one cosignature in a
checkpoint, and each counts once.

### 5.5 Key names, key IDs and key ids

One public key has three names here, each for its own job:

| Name | Form | Used for |
|---|---|---|
| key id | `ed25519:` + 16 hex of SHA-256(public key) (§0) | this repository's identity of a key: the trust configuration, verdicts, and the K1 key set |
| C2SP key name | the log key's `key_name`, or the witness's `name` (§9) | the name on a signature line |
| C2SP key ID | 4 bytes, computed from key name, type byte and public key (§5.2, §5.3) | matching a signature line to a key; never an identity |

The configuration carries the public key, its key id and its C2SP name; the C2SP key ID is always
computed, never configured. A configured key id that is not the hash of its public key is refused
(`trust_form`). For interoperation with C2SP tools, a log key is the C2SP verifier key
`<key_name>+<hex key ID>+<base64(0x01 || public key)>`, and a witness key the same with `0x04`.

## 6. The inclusion proof

The proof that the leaf at `leaf_index` is in a tree of `tree_size` leaves with root `root_hash` is the
RFC 9162 §2.1.3.1 audit path: a list of node hashes, each 32 bytes, from the leaf's sibling upward.
In JSON it is an array of base64 strings, the checkpoint's own encoding, so a computed root compares
with the checkpoint's line byte for byte. It has at most 64 entries.

A verifier checks it with the algorithm of RFC 9162 §2.1.3.2, with `hash` = `leaf_hash(leaf)`:

1. If `leaf_index` ≥ `tree_size`, fail.
2. Set `fn` = `leaf_index`, `sn` = `tree_size` − 1, `r` = `hash`.
3. For each `p` in the path, in order:
   1. if `sn` = 0, fail;
   2. if LSB(`fn`) is set, or `fn` = `sn`: set `r` = `node_hash(p, r)`; then, if LSB(`fn`) is not
      set, right-shift `fn` and `sn` together until LSB(`fn`) is set or `fn` = 0;
      otherwise: set `r` = `node_hash(r, p)`;
   3. right-shift `fn` and `sn` once.
4. Succeed only if `sn` = 0 and `r` equals `root_hash`.

A path for another index, or one hash short or long, fails this check (`bad_proof`), and so does a
path checked against another tree's root. The algorithm does not bind the tree size on its own: a path
can verify for another tree size when that size's root is the same value (the leftmost leaf's path in
trees of 3 and 4 leaves, against one root, is an example). This is not a gap: the size and the root are
both lines of the signed checkpoint (§5.1), so a verifier checks a path only against a size and root
the log signed together, and a different size comes with its own root.

## 7. The consistency proof

### 7.1 The algorithm

The proof that a tree of `older` leaves with root `older_root` is a prefix of a tree of `newer` leaves
with root `newer_root` is the RFC 9162 §2.1.4.1 consistency path, a list of node hashes in base64, at
most 64 entries. For `0 < older < newer`, a verifier checks it with the algorithm of RFC 9162
§2.1.4.2:

1. If the path is empty, fail.
2. If `older` is an exact power of two, prepend `older_root` to the path.
3. Set `fn` = `older` − 1, `sn` = `newer` − 1.
4. If LSB(`fn`) is set, right-shift `fn` and `sn` together until LSB(`fn`) is not set.
5. Set `fr` and `sr` to the path's first value.
6. For each later value `c`, in order:
   1. if `sn` = 0, fail;
   2. if LSB(`fn`) is set, or `fn` = `sn`: set `fr` = `node_hash(c, fr)` and
      `sr` = `node_hash(c, sr)`; then, if LSB(`fn`) is not set, right-shift `fn` and `sn` together
      until LSB(`fn`) is set or `fn` = 0;
      otherwise: set `sr` = `node_hash(sr, c)`;
   3. right-shift `fn` and `sn` once.
7. Succeed only if `fr` equals `older_root`, `sr` equals `newer_root`, and `sn` = 0.

When `older` = `newer`, the path MUST be empty and the roots MUST be equal. Two checkpoints of one log
with one size and different roots are a **split view**: the log has shown two histories, and the
verifier refuses them (`split_view`). When `newer` < `older`, the verifier refuses (`size_regression`).

### 7.2 The consistency proof document

A JSON object with exactly these members:

| Member | Form |
|---|---|
| `spec` | `decision-cert-consistency.v1` |
| `log_id` | the log's id (§2) |
| `older` | a checkpoint (§5.1) of the log, as its full signed-note text |
| `newer` | a later checkpoint of the same log, as its full signed-note text |
| `proof` | the consistency path from `older` to `newer` (§7.1), base64 node hashes |

A verifier, given the expected tenant's configuration (§9), checks in order: the document's form
(`consistency_form`); that `log_id` is one of the expected tenant's logs (`unknown_log`); each
checkpoint's form (`checkpoint_form`) and origin (`origin_mismatch`); each checkpoint's log signature
under that log's key (`log_signature_missing`, `bad_log_signature`); then the sizes and the path
(`size_regression`, `split_view`, `bad_consistency_proof`). It does not require cosignatures, and it
does not check witness lines (a witness checks a consistency proof to a checkpoint it has not yet
cosigned): a line that matches a trusted witness is ignored there, whether or not it verifies. Only the
log's lines, and the form of every line (§5.1), are checked. Its verdict names `log_id` and the
two sizes.

## 8. The bundle

The bundle travels with what it proves. It is a JSON object with exactly these members:

| Member | Form |
|---|---|
| `spec` | `decision-cert-inclusion.v1` |
| `log_id` | the log's id (§2) |
| `leaf_index` | the leaf's position in the log, an integer from 0 |
| `leaf` | the leaf (§3) |
| `proof` | the audit path (§6): an array of 0 to 64 base64 node hashes |
| `checkpoint` | the checkpoint's full signed-note text (§5.1), its log signature and the witness cosignatures included, as one JSON string |
| `certificate` | the certificate as issued, a JSON object, present if and only if `leaf.kind` is `certificate`; absent for the other kinds, whose documents travel on their own |
| `backfilled` | OPTIONAL, for a `certificate` leaf only: `true`, the bundler's statement that the certificate was backfilled (§12). Any other value, or the member beside a leaf of another kind, is refused as `bundle_form` |

`backfilled` is not part of the leaf, so it changes no leaf and no leaf hash; the log never holds it.
It is the bundler's statement and nothing authenticates it: whoever holds a bundle can add or remove
it. A consumer reports it (§10, "Backfilled") and never relies on its absence; the configuration's
`started_at` (§9) is the authenticated basis for the mark. An issuer copies it from the certificate's
leaf record (§12).

An issuer SHOULD write a bundle as its JCS bytes. A verifier depends only on the parsed values: the
certificate's id is computed from the parsed certificate (§0, document hash), and the leaf's hash from
the parsed leaf (§4).

A proof against an older checkpoint stays valid as the log grows. A bundle never needs refreshing.

```json
{
  "spec": "decision-cert-inclusion.v1",
  "log_id": "log:4e1a9c07b25d38f6e0a1b9c7d2e4f531",
  "leaf_index": 1234,
  "leaf": {"kind": "certificate", "certificate_id": "sha256:<64 hex>", "signer_key_id": "ed25519:0c6e5b7d2a913f84", "spec": "decision-certificate.v1.5", "fitted_at": "2026-11-16T09:31:10Z", "tenant": "acme-eu"},
  "proof": ["<base64 node hash>", "<base64 node hash>"],
  "checkpoint": "log:4e1a9c07b25d38f6e0a1b9c7d2e4f531\n1301\n<base64 root>\n\n— log:4e1a9c07b25d38f6e0a1b9c7d2e4f531 <base64>\n— witness.example/w1 <base64>\n",
  "certificate": {"spec": "decision-certificate.v1.5", "...": "..."}
}
```

## 9. The log trust configuration

The consumer's configuration, one per tenant, kept as the trusted keys are today. A JSON object with
these members:

| Member | Form |
|---|---|
| `spec` | `decision-cert-log-trust.v1` |
| `tenant` | the expected tenant, in v1.5's `tenant` form |
| `logs` | 1 or more of the tenant's logs: `{"log_id", "key_name", "key_id", "key"}`, and OPTIONAL `started_at` |
| `witnesses` | 1 or more of the tenant's witnesses: `{"name", "key_id", "key"}` |
| `m` | OPTIONAL, default 1: the number of distinct trusted witnesses whose cosignatures a checkpoint needs, an integer from 1 to the number of `witnesses` |
| `policy` | OPTIONAL, default `warn`: `off`, `warn` or `refuse`, for a certificate without a bundle (§11) |

In each entry, `key` is the Ed25519 public key in base64url (43 characters), `key_id` its key id (§0),
`key_name` the log key's C2SP key name (§5.2, SHOULD equal `log_id`), and `name` the witness's C2SP
cosigner name (§5.3). Key names and witness names are 1 to 255 characters of printable ASCII other
than `+` (§5.1). `started_at`, when given, is the time of the log's first entry, a time in §0's strict
form: a certificate whose `fitted_at` is earlier was issued before the log existed, and is marked
backfilled (§10, "Backfilled"). The consumer takes it, as it takes the keys, from the tenant or the
log's operator when it sets up the configuration; it is trusted input, not read from any bundle.

A verifier refuses the configuration (`trust_form`), before any bundle, when:

- a member is missing, unknown or out of its form (a `started_at` that is not a time in §0's form
  included), or `m` exceeds the number of witnesses;
- a `key_id` is not the key id of its `key`, or `key` is not a valid Ed25519 public key under strict
  verification (§0);
- two logs share a `log_id` or a key; two witnesses share a `name` or a key;
- a witness's key is also a log's key.

A consumer that holds several tenants' configurations refuses them when one `log_id`, or one log key,
appears under two tenants (`trust_cross_tenant`). Witnesses MAY appear under several tenants.

**Before key sets exist.** In v1 the configuration carries the log keys and witness keys directly, as
trusted keys work today. When the key-set design ([K1](../../docs/design/k1-key-revocation-rotation.md))
is specified, its `log` and `witness` roles take over `logs[].key` and `witnesses[].key`, and the
configuration keeps `tenant`, `m` and `policy`. That change is a later version of this configuration;
v1 configurations keep their meaning.

```json
{
  "spec": "decision-cert-log-trust.v1",
  "tenant": "acme-eu",
  "logs": [{"log_id": "log:4e1a9c07b25d38f6e0a1b9c7d2e4f531", "key_name": "log:4e1a9c07b25d38f6e0a1b9c7d2e4f531", "key_id": "ed25519:<16 hex>", "key": "<base64url>", "started_at": "2026-11-17T00:00:00Z"}],
  "witnesses": [{"name": "witness.example/w1", "key_id": "ed25519:<16 hex>", "key": "<base64url>"}],
  "m": 1,
  "policy": "warn"
}
```

## 10. What a consumer checks, offline

A consumer is given a bundle and the expected tenant's log trust configuration. It checks, in this
order, and refuses at the first failure with that check's error name:

| # | Check | Error |
|---|---|---|
| 1 | The configuration is well formed (§9) | `trust_form` |
| 2 | The bundle is well formed: I-JSON, `spec` is `decision-cert-inclusion.v1`, exactly the members of §8 in their forms (`leaf` a JSON object and `checkpoint` a JSON string, their contents checked at checks 3 and 7), and `certificate` present if and only if `leaf.kind` is `certificate`: a `certificate` beside a leaf of another kind, an unknown kind or no `kind` is refused here; `backfilled`, if present, is `true` and beside a `certificate` leaf | `bundle_form` |
| 3 | The leaf is well formed (§3) | `leaf_form` |
| 4 | For a `certificate` leaf: `certificate_id` is the bundle certificate's document hash, and `signer_key_id`, `spec`, `fitted_at` (and for v1.5 `tenant`) equal the certificate's | `leaf_mismatch` |
| 5 | For a v1.5 `certificate` leaf, and for an `audit_head` leaf: the leaf's `tenant` (equal, by check 4, to a v1.5 certificate's) equals the configuration's `tenant` | `tenant_mismatch` |
| 6 | `log_id` is one of the configuration's logs | `unknown_log` |
| 7 | The checkpoint is a well-formed note (§5.1) | `checkpoint_form` |
| 8 | The checkpoint's origin equals `log_id` | `origin_mismatch` |
| 9 | The audit path leads from `leaf_hash(leaf)` at `leaf_index` to the checkpoint's root at its tree size (§6) | `bad_proof` |
| 10 | A signature line matches that log's key (§5.4), and every line that matches it verifies (§5.2) | `log_signature_missing`, `bad_log_signature` |
| 11 | Every line that matches a trusted witness verifies (§5.3) and has a timestamp at most 253402300799 | `bad_cosignature` |
| 12 | At least `m` distinct trusted witnesses have a verified cosignature (one line each, §5.1); lines from untrusted keys are ignored | `too_few_cosignatures` |

**The certificate's own verification.** For a `certificate` leaf, the consumer also verifies the
bundle's certificate under its own spec (for v1.5, for the expected tenant, spec v1.5 §4), separately
and before relying on the bundle. A bundle that passes every check above does not make an invalid
certificate valid. When a consumer holds the certificate from elsewhere, it uses a bundle only when
the bundle certificate's id equals that certificate's id; otherwise it refuses the bundle
(`leaf_mismatch`).

**The verdict.** On success the verdict reports: `log_id`; the checkpoint's tree size and root hash;
`leaf_index` and the leaf's `kind`; for a certificate leaf, `certificate_id`; the counted witnesses, each
with its name, key id and cosignature time, listed in ascending order of cosignature time and, for equal
times, of name (ASCII order); **`t_proven`**, as a time (§0); and for a certificate leaf only,
**`backfilled`** and **`backfilled_by`** ("Backfilled", below).

**`t_proven`** is the `m`-th earliest cosignature time among the counted witnesses: sort their times
in ascending order and take the `m`-th (counting from 1). It is the earliest time by which `m`
distinct trusted witnesses had cosigned the checkpoint, so no fewer than `m` witnesses set it; one
witness's early time alone does not. For `m` = 1 it is the earliest counted time. The verdict is for
the key-set design's compromise rule: a certificate in the log by `t_proven` was signed no later than
`t_proven`.

**Backfilled.** For a certificate leaf the verdict reports `backfilled`, `true` or `false`, and
`backfilled_by`, the bases for it in this order: `bundle`, when the bundle carries `backfilled: true`
(§8); `started_at`, when the configuration's entry for `log_id` has a `started_at` and the leaf's
`fitted_at` (equal, by check 4, to the certificate's) is earlier than it, compared as times. `backfilled`
is `true` if and only if `backfilled_by` is not empty. For the other kinds the verdict has neither
member. The mark is reported only after every check passes, and it is never a reason to refuse: a
backfilled certificate is valid as a certificate, and its bundle proves inclusion like any other. What
it tells the reader is §12's: the certificate has no early time evidence.

The two bases are not equal. `started_at` is the consumer's own configuration, so with it the mark
does not depend on the bundle: removing `backfilled` from a bundle cannot hide that a certificate
fitted before the log started was backfilled. Without `started_at` the mark rests on the bundler's
statement alone, which anyone holding the bundle can add or remove; a consumer that needs the mark
configures `started_at`.

**What is not compared.** A verifier does not compare a cosignature time with its own clock, nor with
`fitted_at` or `observed_at`; `fitted_at` is compared only with `started_at`, for the backfilled mark,
which refuses nothing. A consumer MAY refuse cosignature times in its future by its own rule.

## 11. Policy for a certificate without a bundle

The configuration's `policy` says what a consumer does when it loads a certificate:

| Policy | No bundle | A bundle that passes §10 | A bundle that fails §10 |
|---|---|---|---|
| `off` | load; no inclusion check | not checked; load | not checked; load |
| `warn` (default) | load, with a warning `inclusion_missing` naming `certificate_id` | load, with the verdict | **refuse**, with the failing check's error |
| `refuse` | **refuse**: `inclusion_missing` | load, with the verdict | **refuse**, with the failing check's error |

The "no bundle" rows are a consumer's library policy (`apply_policy` in the reference verifiers): a
command that checks a bundle, such as `verify-bundle`, is always given one, and reports that bundle's
verdict.

`warn` covers a **missing** bundle only. A bundle that is present but fails is refused under `warn`
and `refuse` alike. Under `off`, the consumer does not look at bundles. In every row the certificate
must still pass its own verification. While a certificate waits for the next cosigned checkpoint, it
is valid as a certificate; a consumer under `refuse` loads it once its bundle arrives.

The policy applies to certificates. Bundles for the other leaf kinds are checked when a consumer asks
for them (an auditor, say); this document sets no default for them.

## 12. Backfill

Certificates issued before a tenant's log existed are appended to it when the log starts, before any
new leaf, ordered by `fitted_at` and then by `certificate_id` (ASCII order).

A backfilled certificate is **marked as backfilled**, so that a reader sees it plainly, beyond the
absence of early time evidence. The leaf is not where the mark lives: a backfilled leaf has the same
form as any other `certificate` leaf, and the same leaf hash, so every leaf and every log stays as it
is. The mark travels beside it:

- the issuer's record of a backfilled leaf, the thing it hands the log to append, says so; only the
  leaf is appended;
- the bundle carries `backfilled: true` (§8), the bundler's statement;
- the consumer's configuration MAY give the log's `started_at` (§9): a certificate whose `fitted_at` is
  earlier is marked whatever its bundle carries;
- the verdict reports `backfilled` and the bases for it (§10, "Backfilled").

The mark is information, never a refusal.

A backfilled certificate gets **no early time evidence**: its `t_proven` is the cosignature time of
the first checkpoint that includes it and passes §10 (the `m`-th earliest counted cosignature time
on it), after the log started. Under the key-set design's
compromise rule it therefore counts as signed when it was logged, not when its `fitted_at` says. A
log SHOULD append a given certificate's leaf once; if it appears twice, either leaf's bundle proves
inclusion, and an auditor sees both.

## 13. What inclusion does not claim

- A verified bundle shows that the tenant's log recorded the leaf at or before the checkpoint it
  carries, and that at least `m` of the tenant's trusted witnesses cosigned that checkpoint, `m` of
  them by `t_proven`. It shows no more.
- It says nothing about whether a measurement was right, whether labels were right, or what outcome
  a decision will have. A certificate describes a measured process and never guarantees an outcome;
  a log records that the process was recorded.
- It does not show that the log is complete, or that no other certificate was issued on the same
  cases. Seeing what else is in a log is the tenant's auditor's job, from an export of the log and
  the consistency of every checkpoint it has seen.
- It does not show when a document was created, only that it was in the log by `t_proven`.
  `fitted_at` and `observed_at` remain their writers' claims.
- A witness's cosignature describes what the witness checked (consistency with what it cosigned
  before) and the time it records. Its value rests on the tenant's choice of witnesses: at least one
  of them honest, and outside the control of whoever runs the log.

## 14. Error names

| Error | Meaning |
|---|---|
| `trust_form` | the log trust configuration is malformed (§9) |
| `trust_cross_tenant` | a `log_id` or log key appears under two tenants' configurations (§2, §9) |
| `bundle_form` | the bundle is malformed, or its `spec` is not `decision-cert-inclusion.v1` (§8) |
| `leaf_form` | the leaf has an unknown `kind`, an unknown or missing member, or a member out of form (§3) |
| `leaf_mismatch` | a `certificate` leaf does not match its certificate (§10, check 4) |
| `tenant_mismatch` | a leaf's tenant, or a v1.5 certificate's, is not the configuration's tenant (§2) |
| `unknown_log` | `log_id` is not one of the expected tenant's logs |
| `checkpoint_form` | the checkpoint is not a well-formed v1 note, or has two or more lines from one key (§5.1) |
| `origin_mismatch` | the checkpoint's origin is not the document's `log_id` |
| `bad_proof` | the audit path does not lead from the leaf to the root (§6) |
| `log_signature_missing` | no signature line matches the log's key (§5.4) |
| `bad_log_signature` | a line matching the log's key does not verify (§5.2) |
| `bad_cosignature` | a line matching a trusted witness does not verify, or its timestamp is out of range (§5.3) |
| `too_few_cosignatures` | fewer than `m` distinct trusted witnesses cosigned (§10, check 12) |
| `consistency_form` | the consistency proof document is malformed (§7.2) |
| `size_regression` | the newer checkpoint is smaller than the older (§7.1) |
| `split_view` | two checkpoints of one log with one size and different roots (§7.1) |
| `bad_consistency_proof` | the consistency path does not connect the two checkpoints (§7.1) |
| `inclusion_missing` | no bundle for a certificate: a warning under `warn`, a refusal under `refuse` (§11) |

Implementations name their errors as they choose, and map each to one of these names.

## Decision log

| Date | Item | Decision |
|---|---|---|
| 2026-11-17 | draft | Opened as Phase 1 of the build plan, on the design and the owner's decisions of 2026-11-17. Not frozen. |
| 2026-11-17 | build before K1 | Owner: build without waiting for key sets. The log trust configuration carries the log key and witness keys directly (§9); K1's `log` and `witness` roles take over later. `t_proven` is reported from the start. |
| 2026-11-17 | leaf kinds | Owner: all five kinds in v1 (`certificate`, `ledger_entry`, `keyset`, `attestation`, `audit_head`), with `chain` a required member of `audit_head` (§3). A leaf holds ids and hashes only, so its form does not wait on the other documents' specs. |
| 2026-11-17 | hosting | Owner: the hosted partition is deferred. This document specifies only what a bundle and its proofs need; who runs a log is outside it (§2). |
| 2026-11-17 | policy | Owner: `off`, `warn` or `refuse`, default `warn`; `warn` covers only a missing bundle, and a present bundle that fails is refused under `warn` and `refuse` alike (§11). `m` defaults to 1; witnesses and `m` are per tenant (§9). |
| 2026-11-17 | tenant in a leaf | Owner: the `certificate` leaf carries `tenant` for v1.5 certificates only (§3.2). Proof node hashes are standard base64, the checkpoint's encoding (§6). |
| 2026-11-17 | C2SP revisions | Maintainers: cite `signed-note`, `tlog-checkpoint` and `tlog-cosignature` at v1.1.0 only; Ed25519 log signatures (type `0x01`) and Ed25519 `cosignature/v1` cosignatures (type `0x04`) only; no extension lines; key names in printable ASCII; at most 100 signature lines (§5). |
| 2026-11-17 | document kinds | Maintainers: the consistency proof document and the trust configuration get their own `spec` strings, `decision-cert-consistency.v1` and `decision-cert-log-trust.v1`, so each document is refused when given in the wrong place (§1). |
| 2026-11-17 | error names | Maintainers: one stable error name per check (§14), for both verifiers and the fixtures. |
| 2026-11-17 | `t_proven` | Maintainers: `t_proven` is the `m`-th earliest cosignature time among the counted witnesses, not the earliest, so that `m` witnesses, not one, set it; it is the earliest at `m` = 1 (§10). The verdict also reports every counted witness's time. |
| 2026-11-17 | duplicate lines | Maintainers: a checkpoint with two or more signature lines with the same key name and key ID (one witness's key, or the log's) is refused as `checkpoint_form`, as c2sp.org/tlog-checkpoint@v1.1.0 requires, rather than counting the witness once (§5.1, §5.4). |
| 2026-11-17 | schema | Maintainers: one draft schema file covering the bundle, the leaves, the consistency proof document and the trust configuration, moving to `spec/` with this text at the freeze. |
| 2026-11-17 | clarifications | Maintainers: clarifications from the reference verifier (the Rust crate), with no change of meaning: (1) a malformed checkpoint is `checkpoint_form` at check 7, never `bundle_form`; check 2 and §7.2 take a checkpoint as a string, and an origin other than `log_id` is `origin_mismatch` (§5.1, §10; the schema's checkpoint pattern is dropped to match); (2) a `certificate` beside a non-certificate or unknown leaf kind is `bundle_form` at check 2; (3) witness lines in a consistency proof document are not checked (§7.2); (4) the verdict lists counted witnesses by cosignature time, then name (§10); (5) §6 states that a path can verify for another size with the same root, and why the signed checkpoint makes that no gap; (6) leaf times with seconds `60` are refused (§0). Also: the "no bundle" policy rows are a library policy; `verify-bundle` always takes a bundle (§11). |
| 2026-11-17 | backfilled mark | Owner: backfilled certificates are added **marked as backfilled**: a reader must see plainly that a certificate was backfilled, beyond the absence of early time evidence. Constraint: the leaf stays byte-identical, with no new leaf member, so every leaf and leaf hash is unchanged. Maintainers' design: the bundle's OPTIONAL `backfilled: true` (the bundler's statement, unauthenticated, §8), the configuration's OPTIONAL per-log `started_at` (trusted input, the authenticated basis, §9), and the verdict's `backfilled` and `backfilled_by` for a certificate leaf (§10). A mark, never a refusal; this replaces "nothing marks it" in §12. |

## Open questions

None open. The two questions the first draft raised were decided by the maintainers on 2026-11-17
(Decision log: `t_proven`, duplicate lines).
