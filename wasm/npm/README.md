# decision-cert (npm)

Verify [decision certificates](https://github.com/zer07labs/decision-cert) (`decision-certificate.v1`
to `v1.5`) and their transparency-log inclusion proofs (`decision-cert-inclusion.v1`) in Node.js. The
package is the Rust `decision-cert` crate compiled to WebAssembly: the same code makes every check, so
a verdict here is the crate's verdict. CI runs every conformance fixture of the repository through
this package and compares each verdict with the crate's.

It needs no network and reads no clock. You pass the document, the keys and the time to check expiry
at, so anyone with the same three inputs, an auditor offline included, gets the same answer.

A certificate describes a measured process. It never guarantees an outcome.

```bash
npm install decision-cert
```

## Verify a certificate

```js
const { verifyDocument } = require("decision-cert");
const fs = require("node:fs");

const r = verifyDocument(
  fs.readFileSync("cert.json", "utf8"),         // the certificate, as JSON text
  "acme-bank",                                  // the tenant you expect it to be for
  fs.readFileSync("trusted-keys.json", "utf8"), // that tenant's trusted keys, as JSON text
  new Date().toISOString(),                     // now: any RFC 3339 time
);

r.certificate_id;          // "sha256:…", recomputed from the document whatever the verdict
r.verification.verdict;    // "accepted" or "refused"
r.verification.error;      // when refused: "Invalid", "UntrustedKey", "BadKey", "BadSignature",
                           // "WrongTenant" or "KeyMode"
r.expiry;                  // when accepted: { now, expires_at, expired }; otherwise null
```

`verifyDocument` does exactly what the crate's `verify_for_tenant` does (the form, tenant, key, key
mode and signature checks of spec v1.5 §4; a v1 to v1.4 certificate binds no tenant and verifies
under an `operator` key), then checks expiry at the `now` you pass. The three results are separate:
read `verification` and `expiry` each, never just one of them. An expired certificate still verifies;
it is due to be measured again.

Pass the certificate as the text you stored or received, not a re-serialised object:
`JSON.stringify` can rewrite numbers, and the signature covers the canonical form of the numbers as
written.

### Errors

A refused document's `error` is the crate's `CertError` variant name, and `message` is its message.
**Relay the name** to whoever acts on the refusal, and log the message where only the tenant's own
operators read it: the `WrongTenant` message names the tenant the certificate is for.

A document's verdict is always returned, never thrown. Only an unusable argument throws, as an
`Error` whose `name` is the error name: keys that are not JSON or not well formed (`Invalid`,
`BadKey`), or a `now` that is not an RFC 3339 time (`Invalid`).

### The certificate id

```js
const { certificateId } = require("decision-cert");
certificateId(fs.readFileSync("cert.json", "utf8")); // "sha256:…" of its JCS bytes (RFC 8785)
```

## Inclusion proofs

```js
const { verifyBundle, verifyConsistency, applyPolicy, readTrust } = require("decision-cert");
const trust = fs.readFileSync("log-trust.json", "utf8");

verifyBundle(fs.readFileSync("bundle.json", "utf8"), trust);
// { verdict: "accepted", log_id, tree_size, leaf_index, certificate_id, witnesses, t_proven, … }
// or { verdict: "refused", error: "bad_proof", detail: "…" }
verifyConsistency(fs.readFileSync("consistency.json", "utf8"), trust);
applyPolicy(trust, bundleTextOrNull); // { outcome: "load" | "load_with_warning" | "refuse", … }
```

These return the same verdict lines as `decision-cert verify-bundle` and `verify-consistency`, with the
spec's error names (`decision-cert-inclusion.v1` §14). `verifyBundle` does not verify the bundle's
certificate; `verifyDocument` does. Also exported: `readTrust`, `checkTenants`, `leafHash`, and the
RFC 9162 primitives `hashLeafBytes`, `verifyInclusionPath` and `verifyConsistencyPath` (hashes as hex).

## Checking the package itself

The release workflow records the SHA-256 of `decision_cert_bg.wasm` in its job summary and log, at
publishing and again after installing the published version from npm, so you can pin the digest you
audited:

```bash
sha256sum node_modules/decision-cert/decision_cert_bg.wasm
```

The package is published from the repository's release workflow with npm provenance. To run the
repository's conformance fixtures through an installed copy:

```bash
git clone https://github.com/zer07labs/decision-cert && cd decision-cert
node wasm/conformance.cjs /path/to/node_modules/decision-cert fixtures
```

## Licence

Apache-2.0.
