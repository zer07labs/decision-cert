> Design draft. It scopes a possible addition; the owner decides. Nothing here is implemented, and no
> spec, schema, verifier or fixture changes with it.

# Cost-weighted abstention: scope (2026-11-12)

**The idea.** A consumer states asymmetric error costs, for example "a wrong approval costs five
times a wrong denial". The certificate then bounds the **expected cost** of the answered cases,
instead of their error rate, and the threshold is chosen against that bound.

**What it is not.** It bounds a measured expected cost on cases exchangeable with the calibration
cases. As with every certificate (v1 §5), it describes a measured process and makes no promise about the loss of
any decision or any period.

## 1. The risk and why `ltt` still holds

**Costs.** The consumer gives a cost matrix `C` over the decision's options:
- `C[y][o]` is the cost of answering option `o` when the label is `y`;
- the diagonal is 0, every entry is in `[0, c_max]`, and `c_max` is the largest entry, > 0.

A case answered with top option `o` and label `y` has the **normalised loss** `L = C[y][o] / c_max`,
in `[0, 1]`. An error is a case with `L > 0`. With every off-diagonal entry equal, `L` is v1's error
indicator.

**`selective_cost`** (with `ltt`):
- `R(λ) = E[L | confidence ≥ λ]`, the mean normalised loss of the answered cases at cut `λ`.
- **The statement:** with probability at least `1 − delta` over the calibration draw, `R` at the
  chosen threshold is at most `alpha`, for the top-level test and every certified segment at once.
- **In the consumer's units:** the expected cost per answered case is at most `alpha · c_max`.

**Why the procedure stays valid.** v1 §1.1 is unchanged except for the p-value:
1. **The grid comes from the temperature split only.** The hypotheses `H_λ: R(λ) > alpha` are then
   ordered independently of the threshold split, and fixed-sequence testing controls the
   family-wise error at level `d` given valid p-values. This is Learn-then-Test (Angelopoulos,
   Bates, Candès, Jordan, Lei, 2021, "Learn then Test: Calibrating Predictive Algorithms to Achieve
   Risk Control", its fixed-sequence procedure). That argument does not use the loss's form.
2. **Valid p-values per cut.** For a fixed `λ`, the answered cases are the first condition. Given
   that `n_λ = m`, their losses are `m` i.i.d. draws in `[0, 1]` with mean `R(λ)`, under
   exchangeability. Any valid p-value for "the mean of a bounded variable exceeds `alpha`" is
   therefore valid conditionally on `m`, and so marginally. This is the same conditioning v1 uses for
   its binomial test.
3. **The p-value: Hoeffding–Bentkus** for bounded losses.
   - Bates, Angelopoulos, Lei, Malik, Jordan, 2021, "Distribution-Free, Risk-Controlling Prediction
     Sets", JACM, the Hoeffding–Bentkus bound. Learn-then-Test recommends the same p-value for bounded losses.
   - With `R̂` the mean loss of the `n_λ` cases: `p = min( exp(−n_λ · h(min(R̂, alpha), alpha)), e · P(Binomial(n_λ, alpha) ≤ ⌈n_λ R̂⌉) )`,
     where `h(a, b) = a ln(a/b) + (1 − a) ln((1 − a)/(1 − b))`. `p` is 1 when `n_λ = 0`.
   - A tighter alternative is the betting confidence sequence of Waudby-Smith and Ramdas (2024,
     "Estimating means of bounded random variables by betting", JRSS-B). It has no closed form, so
     the reference issuer would need a pinned numerical routine. Recommended later, not first.
4. **Bonferroni over segments**, `d = delta / (1 + k)`, is unchanged: it needs only a level-`d` test
   per family.

**Equal costs keep v1's test.** An issuer must write `risk: selective_error` with v1's exact
binomial p-value when every off-diagonal cost is equal. It refuses `selective_cost` there, because
Hoeffding–Bentkus is more conservative than the exact binomial on a 0/1 loss, and the consumer would
pay in labels for nothing.

**`joint_cost`** (with `crc`). *Out of v1.4 (owner, 2026-11-12); recorded here for a later version if a consumer asks.*
- `E[1{answered} · L]` is non-increasing as `λ` rises and is bounded by 1.
- So conformal risk control applies with loss bound `B = 1` (Angelopoulos, Bates, Fisch, Lei,
  Schuster, 2022, "Conformal Risk Control", its main theorem). The chosen cut is the last one before
  `(Σ_answered L + 1)/(n + 1) > alpha`.
- The statement is in expectation over the calibration draw, as v1's `crc`, and `delta` is null.

## 2. Spec and verifier changes (a new spec value; frozen specs unchanged)

A new spec value, `decision-certificate.v1.4` (owner, 2026-11-12). v1.3 is in use and stays as it is, so no consumer of
v1.3 sees new fields. Every addition is a new field or a new enum value. v1.4 adds `selective_cost` only; `joint_cost` is
not in it.

| Field | Type | Meaning |
|---|---|---|
| `risk` | adds `"selective_cost"` (with `ltt`) | §1 |
| `cost` | `{matrix, c_max, unit}` \| null | `matrix`: number[][], options × options, row = label, column = answered option, in `options` order. `c_max`: its largest entry. `unit`: a free label such as `"USD"` or null; informational only. Null for the error risks. |
| `pvalue` | `"binomial"` \| `"hoeffding_bentkus"` \| null | The `ltt` p-value used. `binomial` for `selective_error`, `hoeffding_bentkus` for `selective_cost`, null for `crc`. A betting p-value would be a later, separately versioned value. |
| `realized_cost` | number \| null | Each test's mean normalised loss of its answered cases at the chosen threshold. Descriptive, like `realized_band`. Null for the error risks. |

- **`ucb`:** for `selective_cost`, the Hoeffding–Bentkus upper bound at level `1 − d`, on the mean
  normalised loss. It is descriptive after selection, as in v1 §1.2.
- **`realized_band`:** stays the Clopper–Pearson band on the error count. It still shows how many
  answered cases were wrong.
- **`automated` (v1.3 §1.6):** gains `realized_cost`. It is still not a bound.
- **`data_hash`:** unchanged. The losses follow from the labels, the scores and `cost`, which the
  certificate states.

**New checks beyond the schema (verifier, Rust and Python):**
- **`matrix`:** square of side `len(options)`, every diagonal entry 0, every entry in `[0, c_max]`,
  and `c_max` equal to the largest entry and > 0.
- **Pairing:** `risk` and `method` pair as above, and `cost` is non-null exactly for the cost risks.
  `pvalue` matches `risk`.
- **Equal costs:** a cost risk with every off-diagonal entry equal is refused (§1).
- **Ranges:** `ucb` is in `[0, 1]` or null, as before. `realized_cost` is in `[0, 1]`, and is null
  exactly where the test answered no case.
- As with every measured field, a verifier cannot check that `ucb` or `realized_cost` was computed
  from the cases. A re-run from the data does that.

**Consumer (§4):**
- It refuses a certificate whose `cost.matrix` differs from the costs it is configured with.
  Changing the costs is re-certification, like changing `automate_options`.
- It reports `alpha · c_max` in its own units when it shows the bound.

**Fixtures:** new positive fixtures from the reference issuer (`gen_positive_fixtures.py`). They
cover a two-option and a three-option matrix and one segment. New negatives cover a bad diagonal, an
entry above `c_max`, a wrong `c_max`, equal costs under a cost risk, and a pairing mismatch.

**Equal-cost test (required).** With every off-diagonal cost equal, the issuer must write `selective_error` and choose
exactly v1's threshold with v1's `ucb`, byte for byte, on the existing positive fixtures' inputs. It must refuse
`selective_cost` there.

## 3. How many labels (to be measured; design of the study)

Two effects move the label count at a fixed `alpha` and `delta`:

1. **The p-value.** Hoeffding–Bentkus is looser than the exact binomial on the same loss, so a cost
   certificate needs more labels than an error certificate whenever the losses are nearly 0/1.
2. **The mix of errors.** The bound is on mean normalised loss. Suppose errors of the cheap kind are
   common, as when costs are 5:1 and most errors are wrong denials. Then `R` is well below the error
   rate, and the same `alpha` is easier to meet. If the errors are mostly the expensive kind, `R` is
   close to the error rate, and only effect 1 remains.

**Study.** It extends the O4 budget study (`python/tools/study_budget.py`, [o4-budget-study.md](o4-budget-study.md)):
- **The model:** O4's synthetic model. Each error is of the expensive kind with probability `s`.
- **Costs:** the ratio `r = c_expensive / c_cheap`, with `r` ∈ {1, 2, 5, 10} and `s` ∈ {0.2, 0.5, 0.8}.
- **Grid:** `alpha` ∈ {0.05, 0.10} in normalised units, `delta` 0.1, `k*` ∈ {0.75, 0.5, 0.25}, and
  O4's `n_cal` grid.
- **Reported per cell:**
  - the certified share of draws and mean coverage as a share of the best possible, for
    `selective_cost` against `selective_error` at the matched error target;
  - the violation rate, which must stay ≤ `delta` within Monte Carlo error.
- **Draws:** 1,000 per cell, and 10,000 for the four worst cells, as in O4.
- **The result would go in `docs/certificates.md`** as planning guidance next to O4's table, not as a
  normative minimum (O4's recommendation stands).

## 4. Validation plan

- **Synthetic.** The study of §3 on one rented CPU machine, pinned seeds, byte-identical rerun.
  It has about 24 times O4's cell count (4 ratios × 3 mixes × 2 risks). The runtime is to be measured on
  a short pilot first; at a guess, a few CPU-hours on 8 vCPU.
- **One public set.** One state's public HMDA train split, with scores from an open model fitted on
  a disjoint public pool. Labels are the lenders' recorded decisions.
  - Issue `selective_cost` (5:1) and `selective_error` certificates over 200 random
    temperature/threshold splits.
  - Report coverage, `realized_cost`, and the empirical rate at which the held-out mean loss exceeds
    `alpha`.
  - The data, scores and run live outside this repo, which holds no data. Only the summary table
    comes back here.
- **Cost estimate:** about $1–3 of CPU at current rented rates, with a $5 cap. No GPU, no vendor
  calls.
- **Order:** the study and its table first. Then the issuer and verifier code behind the new spec
  value, then fixtures. Each is a separate change after the owner's go.

## 5. Claim limits

- The certificate bounds a **measured expected cost** of answered cases, on cases exchangeable with
  the calibration cases, at the stated `delta`. It says nothing about any single decision. It is not
  a promised loss, a loss cap or an insured amount.
- `alpha · c_max` is in the consumer's stated units. The certificate does not check that those costs
  are right; they are the consumer's input.
- `automated.realized_cost`, like v1.3's `automated` numbers, is descriptive and not a bound.
- Abstained cases carry no cost here. Total expected cost, including review cost, is a different
  objective that this scope does not cover.

## Owner answers (2026-11-12)

1. **Version:** a new `v1.4`, not folded into v1.3, which is in use.
2. **p-value:** Hoeffding–Bentkus first. Betting is a later, separately versioned option. v1's exact binomial stays
   whenever costs are equal, proved by the equal-cost test in §2.
3. **`joint_cost`:** out of v1.4. `selective_cost` ships alone; `crc` may follow if a consumer asks.
4. **Status:** a draft. No code until the founder's go.
