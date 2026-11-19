#!/usr/bin/env bash
# Build the npm package `decision-cert` into wasm/dist/: wasm-pack's Node.js build of this crate (release,
# no wasm-opt) with the committed npm/package.json, npm/README.md and npm/LICENSE. Prints the .wasm's
# SHA-256. The wasm-pack and wasm-bindgen versions are pinned in the CI and release workflows.
set -euo pipefail
cd "$(dirname "$0")"
rm -rf pkg dist
wasm-pack build --target nodejs --release --no-pack --out-dir pkg --out-name decision_cert -- --locked
mkdir dist
cp pkg/decision_cert.js pkg/decision_cert.d.ts pkg/decision_cert_bg.wasm pkg/decision_cert_bg.wasm.d.ts dist/
cp npm/package.json npm/README.md npm/LICENSE dist/
if command -v sha256sum >/dev/null; then
  (cd dist && sha256sum decision_cert_bg.wasm)
else
  (cd dist && shasum -a 256 decision_cert_bg.wasm)
fi
