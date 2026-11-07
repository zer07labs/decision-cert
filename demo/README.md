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

## Demo certificates on public datasets (coming)

Each will live in `demo/<name>/`: the signed certificate, a README naming the dataset (source,
version, licence), the model that was measured, the split, `alpha` and `delta`, the result, and the
list of what the certificate does not claim (spec §5). A certificate carries only hashes and
aggregate numbers, never rows.

## Rules

Signed files are never hand-edited. `demo/DEMOS.sha256` lists every JSON file here and CI checks
it, and both verifiers (Rust and Python) verify every certificate in CI.
`python/tools/gen_demos.py` rewrites `example/` and the manifest.
