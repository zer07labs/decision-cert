# Evidence packs (`decision-evidence-pack.v1`)

An evidence pack bundles one tenant's decision certificates with what an auditor needs to check them
without access to the operator's systems: the certificates as issued, the public keys that signed
them, where the measured cases live (and optionally the cases themselves), and a manifest that hashes
every file. `python -m decision_cert verify-pack` checks a pack.

This page is the format, v1. It is not a certificate spec: it adds nothing to what a certificate
states. A certificate describes a measured process and never guarantees an outcome; a pack only
carries certificates and the material to re-check them. What a certificate claims and does not claim
is in [`certificates.md`](certificates.md) and each spec's §5.

## Who does what

| Part | Where |
|---|---|
| The format (this page) and the verifier | this repository (`decision_cert`, `verify-pack`) |
| Assembling a pack from what an operator holds | the operator's own system: a decision service exporting one domain's certificates, or a hosted platform assembling each tenant's |
| Showing a pack's checks to a person | a console, reading the verifier's report |

## One pack, one tenant

A pack belongs to exactly one tenant: every certificate in it was issued for that tenant, and its
measured cases are that tenant's. The tenant may hand its pack to its own auditor. A pack has no field
that refers to another tenant, and an assembler never puts two tenants' material in one pack. There is
no cross-tenant or public pack.

The format cannot check tenancy: `tenant` is a label the assembler writes, not something a verifier
can authenticate. Keeping a pack to one tenant is the assembler's duty and the access control around
it.

## Layout

A pack is a **directory** of regular files:

```
pack.json                      the manifest (the only file it does not list)
trusted-keys.json              key id -> base64url Ed25519 public key
certificates/<name>.json       each certificate as issued, one per file
cases/<name>.jsonl             optional: the cases a certificate was measured on
```

Only `pack.json` has a fixed name. The other paths are whatever the manifest names; the names above
are the convention.

For transport, a pack is a **tar** of that directory: a POSIX ustar archive (gzip-compressed or not)
whose members are the pack's files at their paths, optionally under `./`. A verifier reads the archive
in memory and never extracts it.

**Member paths.** Relative, `/`-separated, each part matching `[A-Za-z0-9][A-Za-z0-9._-]*` (so no
`..`, no absolute paths, no hidden files, no backslashes). A pack holds regular files only: a verifier
rejects links, devices and other special files, and a tar member named twice.

**Read limits.** A verifier bounds what it reads, and enforces the bounds while reading, before each
member's bytes are read (or, in a compressed tar, decompressed), for a directory and a tar alike: no
more than 1 GiB of member content in all, no member larger than 256 MiB, and no more than 10,000
entries, all uncompressed. The reference verifier's defaults are these, and `--max-total-bytes`,
`--max-member-bytes` and `--max-members` change them. A pack over a limit is not read: the verifier
stops with a usage error (exit 2) naming the limit, not a verdict.

## The manifest (`pack.json`)

A JSON object. Every field below is required; nullable ones are marked. **No object in the manifest
repeats a key**: a verifier rejects a manifest that does. (A certificate parsed as `serde_json` parses
keeps a repeated key's last value; the manifest is a new format with no such history, so a repeated
key, whose meaning would depend on the parser, is refused.)

| Field | Type | Meaning |
|---|---|---|
| `format` | `"decision-evidence-pack.v1"` | The format and its major version. |
| `created_at` | timestamp | When the pack was assembled, `YYYY-MM-DDTHH:MM:SSZ` (the certificate timestamp form). |
| `tenant` | string \| null | The one tenant the pack belongs to, as the assembler names it. Null when the assembler serves a single scope and has no tenant name. Not authenticated. |
| `assembled_by` | `{tool, version}` | The software that assembled the pack. Not checked. |
| `trusted_keys` | path | The trusted-keys file: a JSON object of key id (`ed25519:<16 hex>`) to base64url raw public key, as `decision-cert verify --keys` reads. |
| `certificates` | array, at least one | One entry per certificate, below. |
| `files` | object | Every file in the pack except `pack.json`, by path, to `sha256:<64 lowercase hex>` of its bytes. |

Each `certificates` entry:

| Field | Type | Meaning |
|---|---|---|
| `path` | path | The certificate file, listed in `files`. Each path appears once. |
| `certificate_id` | `sha256:<hex>` | The certificate's id (spec §2: SHA-256 of its JCS bytes, signature included). |
| `measurement.data_hash` | `sha256:<hex>` | The certificate's `data_hash`: the hash of its calibration split, binding each measured case's id, label, raw scores (the predictions), decision time, segment, propensity and, from v1.3, `cannot_tell` (spec v1.2 §2, v1.3 §2). |
| `measurement.location` | string \| null | Where the measured cases live, as the operator names it: a path, a URI, a record id. Opaque; a verifier never fetches it. |
| `measurement.cases` | path \| null | The measured cases, when the pack includes them, listed in `files`. |
| `measurement.procedure` | object \| null | The issuer inputs the certificate does not record (below). Read only with `cases`. |

`location` and `cases` may both be set, but not both be null: a pack always says where a
certificate's measured cases are.

The certificate file's bytes are the issuer's output; its formatting is free, since the id and the
signature are over the canonical form. The manifest hashes the bytes, so a reformatted file is a
changed file.

### Measured cases (`cases`)

JSON Lines, UTF-8, one object per line, with exactly these fields:

| Field | Type | Meaning |
|---|---|---|
| `case_id` | string | Unique within the file. |
| `set` | `"calibration"` \| `"recalibration"` | `calibration`: one of the two splits (spec v1.2 §1.1 step 1). `recalibration`: a `dr` map's recalibration case (step 2). |
| `label_index` | integer | The label's index in the certificate's `options`. |
| `raw_scores` | number[] \| null | The model's raw score per option, in option order. Null: the model did not score the case. |
| `decided_at` | timestamp \| null | In the certificate's timestamp form (normalised as spec v1.2 §1.1 step 1 says). |
| `segment` | string \| null | The case's declared segment value, or null. |
| `propensity` | number \| null | The audit propensity (spec §1.4), or null. |
| `cannot_tell` | number \| null | The prediction's `cannot_tell` value, or null. |

These are exactly the members of the certificate's `data_hash` entries, so the file recomputes
`data_hash` without the cases' payloads: a pack never carries case fields beyond these. Before v1.3
a `data_hash` entry has no `cannot_tell`, so for those certificates the `cannot_tell` values are not
bound by the hash.

**`set` is not bound by `data_hash`.** A `data_hash` entry has no member for `set`, so the hash fixes
which cases were measured but not which of them were calibration and which recalibration cases.
Step 6 checks only the counts (calibration cases number `n_cal` + `n_temperature`; scored
recalibration cases number `label_budget`); only a recompute (step 7) checks the assignment itself,
because a different split of the same cases gives different figures. Where the recompute is skipped,
`set` is the assembler's statement.

**Order.** The lines are in the order the issuer passed the cases to the procedure (for the reference
issuer, the order of its `--data` file). `data_hash` sorts the cases, so the order does not change
it; but a `seeded` split permutes that order (spec v1.2 §1.1 step 1), so the recompute needs it.

### Procedure inputs (`procedure`)

The certificate fixes everything the procedure reads except four inputs from the issuer's domain
config. `procedure` gives them:

| Field | Type | Meaning |
|---|---|---|
| `ttl_days` | integer ≥ 1 | The domain's `certificate.ttl_days` (sets `expires_at`). |
| `histogram_min_n` | integer ≥ 0 | The domain's `certificate.histogram_min_n` (v1.2 on: which histograms are withheld). |
| `segment_floor` | integer \| null | The domain's `certificate.segments.floor`; null without segments. |
| `dr_prior` | `{mu_a, sigma_a, sigma_b}` \| null | A `dr` map's prior (the issuer's `--prior`); null for a `temperature` map. |

These are the assembler's statements, not signed. A recompute that matches shows the certificate
follows from the included cases under these inputs; wrong inputs make it fail, never pass.

## Versioning

`format` names the major version. v1 changes only by **addition**: a later v1 assembler may add
optional fields to the manifest or to a certificate entry, and a v1 verifier ignores fields it does
not know, lists them in its report as not checked, and verifies the rest. A field whose meaning
changes, a new required field, or a change to the layout or the cases format is a new major version
(`decision-evidence-pack.v2`), which a v1 verifier refuses as an unknown format.

The certificates inside follow their own specs: a v1 pack carries certificates of any spec the
verifier accepts (v1 to v1.4 today).

## Verifying a pack

A verifier runs these checks in order. A failure in steps 1 to 4 stops it; a failure in one
certificate's steps skips the rest of that certificate's steps and goes on to the next certificate.

1. **Layout.** The pack reads as a directory or a tar under the rules above, with `pack.json` at the
   top. A pack that cannot be read at all (missing, truncated or corrupt, unreadable, over a read
   limit) is a usage error (exit 2), not a verdict.
2. **Manifest.** `pack.json` parses as JSON (strictly, as the certificate verifier parses, and with no
   repeated key in any object), `format` is `decision-evidence-pack.v1`, and every field above has its
   type. Unknown fields are reported.
3. **Files.** The paths in `files` are exactly the pack's files other than `pack.json` (nothing
   missing, nothing unlisted), each file's SHA-256 matches, and every path the manifest names
   (`trusted_keys`, each `path` and `cases`) is listed.
4. **Trusted keys.** The trusted-keys file is a JSON object of strings. The keys a verifier checks
   signatures against are **the caller's**, when given (`--keys`), else the pack's own. A pack that
   carries its own keys can only show that it is consistent; to check who signed, the auditor gets the
   operator's public keys separately and passes them. Without `--keys` this check reports `warn`,
   not `ok`, and the verdict line says so (below).
5. **Each certificate.** The file verifies as a certificate (schema, the checks beyond the schema, a
   trusted key, the signature; as `decision-cert verify`), its id equals the entry's `certificate_id`,
   and its `data_hash` equals `measurement.data_hash`. Expiry is reported against the check time
   (`--now`), not failed: a pack is often checked after its certificates expired.
6. **Each set of measured cases**, when `cases` is set. Every line is a measured case as above; the
   cases hash to the certificate's `data_hash` under its spec; the calibration cases number
   `n_cal` + `n_temperature`; recalibration cases appear only under a `dr` map, and the scored ones
   number its `label_budget`. Without `cases`, the step is skipped and the report names `location`.
   `set` itself is not bound by `data_hash`; only step 7 checks it.
7. **Each recompute**, when `cases` and `procedure` are set and the reference issuer is installed
   (`pip install 'decision-cert[issue]'`). Below.

The verdict is **verified** when no check failed and **rejected** otherwise. Each check reports `ok`,
`warn` (passed, with a limit on what it shows), `fail` or `skipped`; skipped checks are listed with
their reason, and `--require-recompute` turns a skipped recompute into a rejection. Verified against
the pack's own keys, the verdict line reads `pack verified: N certificate(s); consistent with its own
keys only; pin keys with --keys`; verified against the caller's keys, `pack verified: N
certificate(s)`.

### The recompute

The verifier re-runs the reference issuer's procedure (`certify_decision`) on the calibration cases,
in file order, with:

- from the certificate: `spec`, `domain`, `decision`, `options`, `model_id`, `manifest_hash`, `alpha`,
  `delta`, `method`, the audit mode, the split seed, `rule.cannot_tell_above`, `automate_options`
  (v1.3 on), `cost` (v1.4), and `fitted_at` as the issuing time;
- from `procedure`: `ttl_days`, `histogram_min_n`, `segment_floor` (with the segments' `field`), and a
  `dr` map's prior, fitted on the recalibration cases.

It compares the result with the certificate, every field except `signature`, `signer_key_id` and
`issuer`: the split, the calibration map, each test's threshold, `n`, coverage, `ucb` and
`realized_band`, the segments, the histograms, the automated and cost blocks, the window and
`expires_at`. Numbers agree up to 1e-9 (relative, or absolute near 0), as the reference
implementations agree on the shift score; everything else exactly. The report names the fields that
differ.

The recompute reproduces the reference issuer. A certificate issued by another issuer that follows
the spec's procedure should agree; where it does not, the report names the differing fields, and the
spec's procedure is the arbiter.

## What a verified pack shows, and what it never claims

A verified pack shows that:

- its files are the ones the manifest lists, unchanged since the manifest was written;
- each certificate is intact, of a spec the verifier accepts, and signed by a key the verifier was
  given;
- where cases are included, each certificate was measured on exactly those cases (`data_hash`), and,
  where recomputed, its figures follow from them by the procedure.

It never claims:

- **Anything a certificate does not.** The bound in a certificate is about a measured process under
  exchangeability with the calibration cases; a pack adds no statement about outcomes, single
  decisions, fairness, label quality or populations that were never sampled.
- **Who assembled it, or for whom.** The manifest is not signed. `tenant`, `created_at`,
  `assembled_by`, `location` and `procedure` are the assembler's statements. Anyone holding the files
  could rebuild a manifest; the certificates' signatures and `data_hash` are what bind the content.
- **Who signed, without the caller's keys.** Checked against the pack's own trusted keys, a pack only
  shows that it is consistent, and the verdict line says so.
- **Which cases were calibration and which recalibration, without a recompute.** `data_hash` does not
  bind `set`.
- **That the cases at `location` are the cases.** A verifier never fetches `location`. Cases fetched
  from there match only if they hash to `data_hash`.
- **That the labels are right.** The recompute checks arithmetic on the labels given, not the labels.
- **That a certificate was in force for any decision.** Records of which decisions used which
  certificate are not part of v1.
- **That a certificate is the only one issued.** A pack holds the certificates its assembler chose.

## Privacy

A pack holds no case payloads: the measured cases carry only the members of `data_hash`. Those are
still the tenant's data (ids, labels, scores, timestamps), so a pack that includes `cases` is as
sensitive as the calibration split, and stays in the tenant's scope. An assembler that should not
release the cases writes `location` only: the pack then carries the hash, the auditor obtains the
cases from the tenant, and checks them against `data_hash` (for example by assembling a second pack
with `cases`).

## Worked example

`python/tests/packs/valid/` is a synthetic pack (`tools/gen_pack_fixtures.py` writes it; every number
in it is simulated). It holds two certificates for tenant `tenant-synthetic`: `approved` (v1.3, two
options, a seeded split, two certified segments) and `route` (v1.2, three options, a time split).
Its manifest, abridged:

```json
{
  "format": "decision-evidence-pack.v1",
  "created_at": "2026-11-16T00:00:00Z",
  "tenant": "tenant-synthetic",
  "assembled_by": {"tool": "decision-cert/tools/gen_pack_fixtures.py", "version": "1"},
  "trusted_keys": "trusted-keys.json",
  "certificates": [
    {
      "path": "certificates/route.json",
      "certificate_id": "sha256:1c3cf055e29cff4d1ca58d6b9b79adf95ba5ae1ac741bd58d8ce15b59c3f41ae",
      "measurement": {
        "data_hash": "sha256:d7d4458676d7a3125d8e5daac48823e12859415e3226f587f64fe7da9c780d40",
        "location": "example://tenant-synthetic/calibration/route.jsonl",
        "cases": "cases/route.jsonl",
        "procedure": {"ttl_days": 90, "histogram_min_n": 30, "segment_floor": 60, "dr_prior": null}
      }
    }
  ],
  "files": {
    "cases/route.jsonl": "sha256:1b5f7d7dd48ffcf56edc2448055df235fdc0bb73ea61aba7309b0061d834d917",
    "certificates/route.json": "sha256:05d0282947beff6bb90a5987a8d1d2ba323564aac17c9873f0a208771ebbe7a3",
    "trusted-keys.json": "sha256:d31db62f54f27171f23e8d156cbc17fd32e0fbf7232fe60e1c157e574fb48760"
  }
}
```

The first line of `cases/route.jsonl`:

```json
{"case_id":"syn-2-0000","set":"calibration","label_index":2,"raw_scores":[-0.5227,-0.4131,0.559],"decided_at":"2026-09-01T00:00:00Z","segment":null,"propensity":null,"cannot_tell":null}
```

Verifying it, with the signer's key obtained separately:

```bash
cd python
uv run python -m decision_cert verify-pack tests/packs/valid --keys signer-keys.json --now 2026-11-16T00:00:00Z
```

prints one line per check (ids abridged here):

```
ok      layout: 6 regular files, pack.json at the top
ok      manifest: decision-evidence-pack.v1, tenant 'tenant-synthetic', 2 certificate(s)
ok      files: 5 files listed, every sha256 matches, nothing unlisted
ok      trusted-keys: 1 key(s) given by the caller, the same as the pack's own
ok      certificate certificates/approved.json: sha256:a3d0…, decision-certificate.v1.3, synthetic-lending/approved, …
ok      cases certificates/approved.json: 600 cases (cases/approved.jsonl) hash to the certificate's data_hash; …
ok      recompute certificates/approved.json: re-running the procedure gives every measured figure
ok      certificate certificates/route.json: sha256:1c3c…, decision-certificate.v1.2, synthetic-lending/route, …
ok      cases certificates/route.json: 300 cases (cases/route.jsonl) hash to the certificate's data_hash; …
ok      recompute certificates/route.json: re-running the procedure gives every measured figure
pack verified: 2 certificate(s)
```

and exits 0. The same pack as a tar (`valid.tar`) gives the same checks. The rejected fixtures beside
it each break one step: a file changed after the manifest (`invalid_tampered_file`), a file the
manifest does not list, a listed file missing, an unknown format, a wrong `certificate_id`, a
certificate signed by a key the pack does not list, one label changed in the cases
(`invalid_cases_hash`), a certificate signed by the trusted key whose coverage the cases do not give
(`invalid_recompute`), and a tar member outside the pack (`invalid_traversal.tar`).
`tests/packs/expected.json` gives each one's verdict and first failing check.

## Exit codes

`python -m decision_cert verify-pack <pack> [--keys K] [--now T] [--no-recompute | --require-recompute]
[--max-total-bytes N] [--max-member-bytes N] [--max-members N]`: 0 verified (with
`--require-recompute`, also every recompute run; without `--keys`, verified as consistent with the
pack's own keys only, and the verdict line says so), 1 rejected, 2 a usage error, a pack or keys file
that cannot be read (missing, truncated, corrupt, unreadable), or a pack over a read limit; the
message goes to stderr, never a traceback. From Python: `decision_cert.verify_pack(path, keys)` returns
the report (`report.ok`, `report.checks`).
