# Demo certificates

Material for trying a verifier, not for trusting a live decision.

## `example/`: the quickstart

`fixtures/valid_basic.json` split into the two files the command-line verifier takes: the
certificate exactly as signed, and its trusted keys. It is signed with the public **test** key that
signs the conformance fixtures, and its hashes and model id are placeholders. Use it to see a
verifier work; it says nothing about any real model. It expires on 2027-01-23, after which the CLI
reports it as expired (exit 1), as it should.

```bash
uvx decision-cert verify <(curl -sL https://raw.githubusercontent.com/zer07labs/decision-cert/main/demo/example/certificate.json) --keys <(curl -sL https://raw.githubusercontent.com/zer07labs/decision-cert/main/demo/example/trusted-keys.json)
```

## The demo signing key

[`demo-keys.json`](demo-keys.json) holds the public half of the **demo key**,
`ed25519:ddfedf92da8d6790`. Its private half is kept outside this repository. It signs demo
certificates only: no live domain trusts it, and nothing should.

## Demo certificates on public datasets

Issued with the released 0.2.0 issuer and the demo key. Each `demo/<name>/` holds the signed
certificate, its trusted keys, the model's manifest (`model.json`, whose SHA-256 is the
certificate's `manifest_hash`) and a README naming the dataset, the model, the split, `alpha` and
`delta`, the result, and what the certificate does not claim (spec §5). A certificate carries only
hashes and aggregate numbers, never rows.

| Demo | Dataset | Method | Threshold | Coverage |
|---|---|---|---|---|
| [`bank-marketing/`](bank-marketing/) | UCI Bank Marketing (CC BY 4.0) | `ltt`, selective error ≤ 0.05 at `delta` 0.1 | 0.9122 | 53.3% |
| [`bank-marketing-crc/`](bank-marketing-crc/) | the same | `crc`, joint error ≤ 0.05 on average | 0.8627 | 79.7% |

The inputs are rebuilt by
[`python/tools/demo_bank_marketing.py`](../python/tools/demo_bank_marketing.py) from the public CSV.

## Rules

Signed files are never hand-edited. `demo/DEMOS.sha256` lists every JSON file here and CI checks
it, and both verifiers (Rust and Python) verify every certificate in CI.
`python/tools/gen_demos.py` rewrites `example/` and the manifest.
