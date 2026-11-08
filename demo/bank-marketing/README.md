# Demo: bank marketing, Learn-then-Test

A demo certificate issued with the released **decision-cert 0.2.0** issuer and the demo key
(`ed25519:ddfedf92da8d6790`). No live domain trusts the demo key; this certificate exists for
reading and verifying. It describes one measured process and never guarantees an outcome.

```bash
uvx decision-cert verify certificate.json --keys trusted-keys.json --now 2026-11-08T12:00:00Z
```

## What was measured

| | |
|---|---|
| Dataset | UCI Bank Marketing (S. Moro, P. Rita, P. Cortez, 2014), file `bank-full.csv` (45,211 rows, SHA-256 `d1513ec6…ed32d`), [doi:10.24432/C5K306](https://doi.org/10.24432/C5K306), licence CC BY 4.0. Rows are not stored here. |
| Decision | `subscribed`: did the client subscribe to a term deposit after the campaign call (options `yes`, `no`; 11.5% `yes` in the held-out half). |
| Model | `demo/logistic-l2@1`: L2-regularised logistic regression on 6 numeric and 9 categorical columns, without `duration` (known only after the call). [`model.json`](model.json) holds its features, scaling and coefficients; its SHA-256 is the certificate's `manifest_hash`. |
| Split | A seeded permutation (seed 2012) of the rows: half trains the model, and the other 22,606 rows go to the issuer. The issuer splits those again (seed 0): 11,303 rows fit the temperature and build the candidate thresholds, and 11,303 rows test them. |
| Procedure | `method: ltt`, `risk: selective_error`, `alpha` 0.05, `delta` 0.1, `audit: full-label` (every row of the public set is labelled). |

How it was made: [`python/tools/demo_bank_marketing.py`](../../python/tools/demo_bank_marketing.py)
writes the predictions, labelled cases, domain file and `model.json` deterministically from the CSV,
and the certificate was issued with `pip install 'decision-cert[issue]==0.2.0'` (the command is in
the script's docstring).

## The result

- **Threshold.** Answer when the calibrated confidence is at least `abstain_below` = 0.9122;
  abstain otherwise.
- **The test split at that threshold.** 6,030 of 11,303 cases answered (`coverage` 0.533), 279 of
  them wrong (4.6%).
- **The claim.** Under exchangeability of these cases and future ones, with probability at least
  0.9 over the draw of the test split, the selective error at this threshold is at most 0.05.
- **Descriptive numbers.** `ucb` 0.0499 and `realized_band` [0.0411, 0.0519] (95%) describe the
  uncertainty at the selected threshold. They are not confidence statements (spec §1.2).
- **Expiry.** Fitted 2026-11-08, `expires_at` 2027-11-08.

## What this does not claim

Spec §5 applies in full:

- Nothing about any single client, or about clients unlike these: another bank, another country,
  another year (the data are from 2008–2010) or another kind of campaign.
- The expiry is a prompt to measure again, not a statement that the bound holds until then.
- `ucb` and `realized_band` are descriptive.
- The bound covers only the population the dataset was drawn from.
- Nothing about fairness, legality or the quality of the labels.
