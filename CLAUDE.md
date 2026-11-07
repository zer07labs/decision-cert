# decision-cert

The open `decision-certificate.v1` spec, the Rust verifier crate (`rust/`), and the conformance
fixtures. Split from `zer07labs/decisiond`; see [`README.md`](README.md).

Cross-repo context (Seam services, contracts):

@../seam/CLAUDE.md

decision-cert depends on nothing of ours. Consumers pin it by git rev: decision-api (apply),
decisiond (KG0 gates), and later `seam-sdk/verify` and `seam-learning`. It never reads or writes
Seam state.

## Repo rules

- **Certificates describe a measured process, never guarantee an outcome.** No assure, guarantee
  or underwrite claims in names, docs or messages; decisiond's banned-word list applies here.
- **`spec/decision-certificate.v1.*` is frozen.** Any change to a field or its meaning is v2. Typo
  fixes go through a dated note, not an edit of the frozen text.
- **Fixtures are shared byte for byte** with the issuer (decisiond's
  `py/tests/test_cert_conformance.py` until the issuer moves here after Q14). Never hand-edit a
  fixture; regenerate and update both copies in one change.
- **No data here.** No customer or tenant data, no closed-model outputs, no vendor scores, no
  private keys. Fixtures carry public keys and deterministic test signatures only.
- **Public-facing.** Treat every commit message as public.
- Not published to crates.io (`publish = false`) until the founder decides.

## Commands

| | |
|---|---|
| `cd rust && cargo fmt --check && cargo clippy --all-targets --all-features -- -D warnings && cargo test --all-features` | what CI runs |
| `cd rust && cargo run --features cli -- verify <cert> --keys <keys>` | the command-line verifier (`python -m decision_cert verify` is the same) |
| `cd rust && cargo deny check` | licence/advisory/source policy (`rust/deny.toml`) |
| `cd python && uv run ruff check && uv run mypy && uv run pytest` | the Python verifier (its oracle test needs cargo) |
| `cd python && uv run python tools/gen_negative_fixtures.py` | regenerate the negative fixtures and `fixtures/FIXTURES.sha256` |
