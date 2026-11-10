> **Draft, design only.** Nothing here is approved for implementation. No field, check or fixture
> below exists in any verifier or issuer, and no release carries it. The owner decides each item
> before any of it is built. v1, v1.1 and v1.2 stay frozen.

# Decision certificate, v1.3 (draft)

v1.3 would extend [`decision-certificate.v1.2`](../decision-certificate.v1.2.md) under a new
`spec` value. As with v1.1 and v1.2:

- v1, v1.1 and v1.2 certificates and their fixture sets stay unchanged and valid;
- verifiers would accept all four values of `spec`, each against its own schema;
- a v1.3 fixture set would be added beside the others.

Each item states the problem in v1.2 (with the file and line where it shows), a proposed shape, and
the **open questions** the owner must decide. The proposed shapes are a starting point for those
decisions, not decisions.

## Items

### F1. A deployment fingerprint

**Problem.** A v1.2 certificate names what was measured with `model_id`
(`<backend>/<model>@<version>`) and an optional `manifest_hash`. Spec v1.2 §4 asks a consumer only
to refuse a certificate whose `model_id` does not start with `<backend>/`. §4 already refuses on
`domain`, `decision`, `options`, the calibration map and its parameters, `rule.cannot_tell_above`
and the segment field, and `manifest_hash` is written but no consumer is asked to compare it. The
rest is not bound: a consumer can apply a certificate to a different model version or weights, a
changed preprocessing step, other decision rules or another population, and nothing refuses it. The measured error
belongs to the whole pipeline that turned a case into scores and an abstention, not to the backend.

**Proposed shape.** A `deployment` object (which components are required is question 1), each
component a hash or null:

| Component | What it binds |
|---|---|
| `model` | model id and version, and a hash of the weights or of the serving artifact |
| `manifest` | the pool or manifest of models and prompts (today's `manifest_hash`) |
| `preprocessing` | the code or configuration that turns a case into model input |
| `input_schema` | the case schema the model was measured on |
| `rules` | the decision rules applied around the model (policy overrides, hard declines) |
| `population` | the declared intended population: a hash of its written definition |
| `adapter` | an adapter or posterior fitted for one customer, when one is applied |
| `selector` | the abstention selector (the `cannot_tell` source and any uncertainty selector, U1) |

`deployment_fingerprint` = `sha256:` + hex SHA-256 of the JCS bytes of `deployment`. A consumer
computes its own `deployment` from what it has in force and refuses a certificate whose fingerprint
differs, naming the components that differ.

**Open questions.**

1. Which components are required (non-null) for every certificate, and which may be null with a
   stated meaning ("not applicable" against "not bound")?
2. Who computes each hash, and over what bytes? A hash of a configuration file depends on its
   formatting. Should v1.3 define a canonical form per component, or leave the bytes to the operator
   and require only that issuer and consumer hash the same artifact?
3. Is a whole-object match too strict? A logging-only preprocessing change would force a new
   certificate. The alternative is a per-component policy in the consumer, which weakens the
   binding.
4. `population` is a definition, not data. Is a hash of a written definition worth binding, or does
   it give the appearance of a check that it is not?
5. Should v1.3 also tighten spec §4's `model_id` rule to an exact match? That change stands on its
   own, without the rest of F1.
6. What does `model` bind for a hosted model whose weights the operator cannot hash (today's null
   `manifest_hash`)?
7. Does `deployment` replace `manifest_hash`, or sit beside it?

### R1. Dataset roles and an issuance ledger

**Problem.** The bound needs the threshold-split cases to be unused by anything chosen before the
test: training, adapting, tuning a prompt or a threshold, or choosing the model or `alpha`. Apart
from refusing a repeated `case_id`, which keeps the two splits disjoint, the v1.2 issuer checks only
one cross-role overlap: a `dr` map's recalibration cases against the calibration cases
(`python/src/decision_cert/issue/certify.py:488`, in `fit_dr`). A certificate does not record
which cases were used for what, so reuse cannot be detected. It also does not record repeated
attempts, so issuing at several values of `alpha` (or several seeds, windows or models) on the same
cases and keeping the best is invisible, although the bound does not cover that selection
([`docs/credit-approval.md`](../../docs/credit-approval.md), "The error target is chosen").

**Proposed shape.**

- `data_roles`: for each role (`train`, `adapt`, `tune`, `select`, `recalibrate`, `certify`), the
  number of cases and a commitment to their ids: a hash of the sorted case ids, or the root of a
  Merkle tree so that one case's membership can be shown without revealing the others. The issuer
  would refuse a `certify` case that appears in any other declared role.
- `issuance`: `{ledger_id, seq, prev}`. `seq` counts the operator's certification attempts on a
  ledger, and `prev` is the hash of the ledger's previous entry. Every attempt appends an entry
  (`data_hash`, `alpha`, `delta`, `method`, seed, outcome, certificate id or null), including
  attempts that refuse or abstain on everything.

**Open questions.**

1. The issuer can only check the roles it is told about. Is a declared-roles commitment worth its
   size when it binds only what the operator declares? A validator with the data can check it.
2. Commitment form: a plain hash of the sorted ids (small, but proving membership needs every id),
   or a Merkle root (larger, supports selective proof)? Should the case ids be salted, so that a
   commitment does not leak whether a known case was used?
3. The ledger is held by the operator, who can rewrite it. It is tamper-evident only when its heads
   are published somewhere the operator cannot rewrite, which is the transparency log of #28 (held).
   Should R1 wait for #28, or ship a local ledger that #28 later anchors?
4. Does an attempt that the operator never signs (a dry run) count as an attempt? If not, what
   stops selection by dry runs?
5. What does a consumer do with `seq` > 1: refuse, apply a correction to the level, or only show
   it? Without a rule the ledger records selection but changes nothing about the bound.
6. How do the roles map onto the two splits? The bound needs the threshold split unused; is
   `certify` both splits, or the threshold split only?
7. For a model the operator did not train, `train` cannot be declared at all. Is it then null with
   a stated meaning?

### K1. Key revocation, rotation and key-id lifetime

**Problem.** v1.2 trusts a key as long as it is in the consumer's trusted-keys map (spec v1.2 §3,
§4). There is no validity period, no revocation and no rotation. A key that leaks stays trusted
until every consumer removes it, and removing it also refuses every honest certificate it signed.
`signer_key_id` is `ed25519:` + the first 16 hex characters (64 bits) of the key's SHA-256, with no
rule against duplicate entries. A trusted-keys file that lists one id twice keeps only the last
entry in the Python verifier, without a word.

**Proposed shape.** A trusted-key entry becomes
`{public_key, not_before, not_after, revoked_at, reason}`:

- a certificate verifies only if its `fitted_at` is within `[not_before, not_after]` of its key;
- **rotation** (planned): the old key gets a `not_after`, and certificates it signed before then
  keep verifying; after their own `expires_at` the consumer's expiry policy applies as in v1.2.
  Rotation binds only a signer who retires the old private key: `fitted_at` is the signer's;
- **revocation for compromise**: `fitted_at` is written by the signer, so a holder of a leaked key can
  backdate it. A compromised key's certificates would therefore all be refused, unless the time of
  signing is shown by a source the key holder does not control (a timestamp from #28 or an RFC 3161
  authority). Revocation for another reason (`reason: superseded`) would refuse only certificates
  with `fitted_at` after `revoked_at`, which again relies on the signer's own clock.
- A key id would never be reused, and a consumer would refuse two trusted entries with one key id.

**Open questions.**

1. Is K1 a certificate change at all? Most of it is the consumer's trusted-keys format and
   behaviour. It could be a separate key-set spec, with no new certificate field.
2. How does revocation reach consumers: a signed key-set document they fetch (which needs a network
   call this library never makes), or configuration they are given?
3. Should certificates signed by a compromised key fail closed (refused) or fail to a person (refer)?
   For a decision boundary, refusing the certificate already sends every case to a person.
4. Should the key id be longer than 64 bits? The verifier checks that the trusted key hashes to
   its id, so a collision makes the lookup ambiguous but cannot forge a signature.
5. Should a duplicated key id in a trusted-keys file be refused (the proposal), and does that need
   the spec or only the verifiers?

### C1. Bind the per-case `cannot_tell` values

**Problem.** The `cannot_tell` cut is bound: `rule.cannot_tell_above` is a signed field, and a
consumer refuses a certificate whose cut differs from the one in force (spec v1.2 §1, §4). The
per-case values are **not** bound. The tuple hashed into `data_hash` is
`[case_id, label_index, raw_scores, decided_at, segment, propensity]`, as spec v1.2 §2 (the
`data_hash` row) defines it and the issuer writes it
(`python/src/decision_cert/issue/certify.py:427`). The gap is in the frozen spec, not only the
issuer. A case's `cannot_tell` value decides whether it
is answered (`certify.py:236`), but it is not in that tuple. Two runs on the same labelled cases
and raw scores, with different `cannot_tell` values, give the same `data_hash` but different
answered sets, thresholds and counts. So `data_hash` does not identify the measurement, and a
re-run cannot show which values were used.

**Proposed shape.** The v1.3 tuple appends each case's `cannot_tell` value (null when absent). The
source of the values (which model and version produced them) is bound by F1's `selector`.

**Open questions.**

1. Should the tuple be versioned as a whole (a new tuple per spec value), or become an object with
   named members, so that later additions (U1) do not each need a new tuple?
2. C1 can ship without F1: it binds the values, and F1's `selector` would later bind their
   source. Should it?

### U1. A typed uncertainty field for abstention

**Problem.** v1.2 has one model-side abstention signal, `cannot_tell`: a score per case, with a cut.
A model that reports another uncertainty measure (a posterior variance, or the disagreement of an
ensemble) has no place to put it. Reusing `cannot_tell` for it would change what `cannot_tell`
means between certificates.

**Proposed shape.** `rule.selectors`: a list of `{kind, above}`, where `kind` names a registered
measure (for example `posterior_variance`) and a case abstains when its value is above `above`.
`rule.cannot_tell_above` keeps its v1.2 meaning unchanged. A case abstains when any selector or the
`cannot_tell` cut says so, and those cases count as abstentions, as unscored cases do. Each value
used is bound in the hashed tuple (C1), and the source by F1's `selector`.

**Open questions.**

1. A fixed registry of kinds in the spec, or free-form kinds that a consumer refuses unless it
   knows them (as v1.2 does for `calibration_map.kind`)?
2. Only "abstain above a cut", or also "abstain below" and two-sided rules?
3. Does the confidence histogram (v1.2 §1.5) count selector-abstained cases as `unscored`, as it
   counts cannot-tell cases? Consistency says yes; then a shift in the uncertainty measure shows only
   as a change in the unscored count.
4. Who chooses each selector's `above`, and on which data? Choosing it on the threshold split
   would break the test. Is it fixed in the domain config, as `cannot_tell_above` is?
5. Should §4 refuse a certificate whose selectors differ from the ones in force, as it does for
   `cannot_tell_above`?

### P1. An error bound for the automated options only

**Problem.** The `ltt` statement (spec v1.2 §1) is about P(error | answered) over all answered
cases, whatever option the answer is. A consumer may automate only some options, for example
approvals, and send every other answer to a person. The certificate then states no error for the
cases it actually decides: errors can be concentrated in the automated option and diluted by the
answers that are referred, so the measured rate over all answered cases says nothing about the
automated subset.

**Possible shape.** A test on the automated subset alone: the cases whose top option is in a
declared `automate_options` list, with confidence at or above the threshold, and a field naming
that list. A per-option bound (one test per option) is the general case.

**Open questions.**

1. Should v1.3 carry this at all, or should a consumer that automates a subset certify that subset
   as its decision (an issuer option that tests only the cases it would automate)?
2. The subset has fewer cases, so it needs more labels at the same `alpha` (`docs/certificates.md`,
   "The arithmetic floor"). Is that acceptable, or is it a reason to keep one test?
3. Per option, or per automated subset? Per option multiplies the tests and needs a correction
   across them, as segments do (S1).
4. The subset is chosen by the model's own top option, so the threshold is tested on the cases the
   rule selects. Does fixed-sequence testing on that subset stay valid as v1.2's argument does, with
   the subset defined before the threshold split is seen?
5. How does a consumer refuse a certificate whose automated options differ from the ones in force,
   and how does it monitor the subset's answered share and histogram?

### S1 (optional). Segment correction beyond Bonferroni

**Problem.** `ltt` tests run at `delta / (1 + k)` for `k` certified segments (spec v1.2 §1.1 step 7).
Each added segment lowers every test's level, so the cases needed per test rise
([`docs/certificates.md`](../../docs/certificates.md), "The arithmetic floor").

**Options.**

- **Holm across the families.** Holm recycles a family's level only when that family's hypotheses
  are all rejected. A family's fixed sequence runs down the grid to cut 0.0, so Holm gains only when a
  family's error with every case answered is credibly below `alpha`. That happens for a strong model
  with a loose `alpha`, and not otherwise. This needs a study before it is proposed.
- **Šidák, Hochberg or Hommel.** The tests run on disjoint case sets (spec v1.2 §1.1 step 4), so
  they are independent, and these are valid. Šidák's level `1 − (1 − delta)^(1/(1+k))` is a little
  above Bonferroni's (0.0102 against 0.0100 at `delta` 0.05 and k = 4): exact, but a tiny gain.
- **Fixed sequence across families** (the top-level test first, segments in a declared order) has
  the same limit: a later family is tested only after an earlier one rejects everything.
- **Weighted Bonferroni**: levels `w_i · delta` with weights summing to 1, declared before issuing
  (for example in proportion to each segment's expected share). This keeps family-wise control and
  can help the largest tests. The weights would be a new field.
- **No simultaneity.** Each test at `delta`, with a per-test statement instead of one simultaneous
  one. A weaker claim, shown so the trade-off is visible.

**Open questions.** Which of these is worth a study? Should the weights be declared in the domain
config, where they cannot be chosen after seeing the data? What happens to a declared segment's
weight when it falls below `floor` and is not certified? Redistributing it is acceptable only
because certification depends on segment counts, not labels, the argument spec v1.2 §1.1 step 3
makes for `k`.

### M1 (optional). The drift alarm's false-alarm rate

**Problem.** The shift score (spec v1.2 §4) is a test at one level per window, and spec v1.2 §5
already notes that checking many windows raises false alarms. A deployment that checks every day
at p < 0.01 expects about one false alarm every 100 days on an unchanged population, more when it
checks several segments. Successive windows share the same stored histogram and often overlap, so
their p-values are correlated. The expected count still follows the per-day level, but the chance
of at least one alarm over a horizon, and how alarms cluster, do not. Two more effects:

- every window is compared with the same baseline. A baseline that is atypical by chance raises the
  alarm rate of that deployment above nominal, for as long as the certificate is used; the nominal
  rate holds only on average over calibration draws;
- the 1% figure assumes the chi-square p-value is calibrated at 0.01. The
  [H1 study](h1-histogram-study.md) checked the false-alarm rate near 5%, and the approximation is
  weakest in the tail when bins hold few cases.

**Options.** A section that states the per-window false-alarm rate and how it compounds, with
guidance on the level for a target number of alarms a year. Or a sequential test (CUSUM, or an
e-process that controls the false-alarm rate over an unbounded horizon) defined next to the shift
score.

**Open questions.** Guidance only (docs, no spec change), or a normative sequential score? If
sequential, what evidence does it need, along the lines of the H1 study, and how does it account for
the baseline being itself a finite sample?

## Not in this draft

Held by the owner: publishing the method write-up (#26), consumption by other systems (#27), a
transparency log (#28) and an independent countersignature (#29). R1 and K1 refer to #28 where a
log would anchor them.

## Decision log

| Date | Item | Decision |
|---|---|---|
| 2026-11-10 | draft | Opened as a design draft (owner go relayed 2026-11-10). Nothing approved for implementation. |
