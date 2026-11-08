# Demo: bank marketing, conformal risk control

The same data, model and split as [`../bank-marketing/`](../bank-marketing/), certified with
conformal risk control instead of Learn-then-Test. Issued with the released **decision-cert 0.2.0**
issuer and the demo key (`ed25519:ddfedf92da8d6790`), which no live domain trusts. It describes one
measured process and never guarantees an outcome.

```bash
uvx decision-cert verify certificate.json --keys trusted-keys.json --now 2026-11-08T12:00:00Z
```

## What was measured

| | |
|---|---|
| Dataset | UCI Bank Marketing, `bank-full.csv` (SHA-256 `d1513ec6…ed32d`), [doi:10.24432/C5K306](https://doi.org/10.24432/C5K306), CC BY 4.0. Rows are not stored here. |
| Decision | `subscribed` (options `yes`, `no`). |
| Model | `demo/logistic-l2@1`; [`model.json`](model.json) is its manifest (`manifest_hash`). |
| Split | As in `../bank-marketing/`: 11,303 rows fit the temperature and build the candidate thresholds, 11,303 rows test them. |
| Procedure | `method: crc`, `risk: joint_error`, `alpha` 0.05, `delta` null, `audit: full-label`. |

## The result

- **Threshold.** `abstain_below` = 0.8627.
- **The test split at that threshold.** 9,004 of 11,303 cases answered (`coverage` 0.797), 564
  answered and wrong.
- **What `crc` bounds.** The *joint* error, the share of all cases that are answered and wrong:
  (564 + 1) / (11,303 + 1) is at most 0.05. It is an average over draws of the test split, not a
  high-probability bound, so `delta` and `ucb` are null.
- **Joint is not selective.** Among the answered cases the error is 564 / 9,004 = 6.3%, above 0.05.
  A consumer who needs the error among answered cases bounded needs an `ltt` certificate, such as
  `../bank-marketing/`, which answers fewer cases.
- **Descriptive.** `realized_band` [0.0577, 0.0678] (95%) describes the selective error at the
  threshold (spec §1.2).
- **Expiry.** Fitted 2026-11-08, `expires_at` 2027-11-08.

## What this does not claim

Spec §5 applies in full. In particular, `crc` certifies an average, not a high-probability bound.
It says nothing about a single client or about clients unlike these (another bank, country, year
or campaign), nothing about fairness, legality or label quality, and the expiry is a prompt to
measure again.
