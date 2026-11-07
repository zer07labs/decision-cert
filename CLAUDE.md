# decision-cert

The open `decision-certificate.v1` spec, the Rust verifier crate (`rust/`), the Python verifier
(`python/`), and the conformance fixtures. See [`README.md`](README.md).

decision-cert depends on nothing else of ours. Consumers pin a released version (crates.io and
PyPI, both `decision-cert`) or a git revision. It holds no data and never calls a network service.

## Repo rules

- **Certificates describe a measured process, never guarantee an outcome.** No names, docs or
  messages that promise an outcome; the CI `wording` job enforces this on the public docs.
- **`spec/decision-certificate.v1.*` is frozen.** Any change to a field or its meaning is v2.
  Corrections and clarifications go in `spec/ERRATA.md` as dated entries, never edits of the
  frozen text.
- **Fixtures are never hand-edited.** The positive fixtures and `mutations/` come from the
  reference issuer and are copied unchanged; the negatives come from
  `python/tools/gen_negative_fixtures.py`. Any change updates `fixtures/FIXTURES.sha256` and every
  vendored copy in the same change.
- **The Rust crate is the oracle.** Never argue a verdict; run the crate. The Python verifier must
  agree with it on every fixture and in the differential test.
- **No data here.** No customer data, no model outputs beyond test material, no private keys.
  Fixtures carry public keys and deterministic test signatures only.
- **Public-facing.** Every file, commit message and PR is public; no internal project names.
- **Merge commits, never squash.** Releases: the owner pushes tag `vX.Y.Z` on `main`;
  `.github/workflows/release.yml` publishes. Never tag or publish from a session unasked.

## Commands

| | |
|---|---|
| `cd rust && cargo fmt --check && cargo clippy --all-targets --all-features -- -D warnings && cargo test --all-features` | what CI runs |
| `cd rust && cargo run --features cli -- verify <cert> --keys <keys>` | the command-line verifier (`python -m decision_cert verify` is the same) |
| `cd rust && cargo deny check` | licence/advisory/source policy (`rust/deny.toml`) |
| `cd python && uv run ruff check && uv run mypy && uv run pytest` | the Python verifier (its oracle test needs cargo) |
| `cd python && uv run python tools/gen_negative_fixtures.py` | regenerate the negative fixtures and `fixtures/FIXTURES.sha256` |
| `cd python && uv run python tools/gen_demos.py` | rewrite `demo/example/` and `demo/DEMOS.sha256` |
