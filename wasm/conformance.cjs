#!/usr/bin/env node
// Runs every conformance fixture through the npm package `decision-cert` (the WebAssembly build) and
// checks each verdict against the expected verdict the Rust crate's tests use (rust/tests/conformance.rs
// and rust/tests/inclusion_fixtures.rs). The Rust crate is the oracle: a disagreement is a bug here,
// never a reason to change a fixture.
//
//   node wasm/conformance.cjs <package-dir> <fixtures-dir> [set ...]
//
// <package-dir> is the built package (wasm/dist) or an installed one (node_modules/decision-cert).
// The sets are v1 (the top level of fixtures/), v1.1, v1.2, v1.3, v1.4, v1.5 and inclusion-v1; all of
// them by default. Prints a count per set and the .wasm's SHA-256; exits 1 on any disagreement.
"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const [pkgDir, fixturesDir, ...wanted] = process.argv.slice(2);
if (!pkgDir || !fixturesDir) {
  console.error("usage: node conformance.cjs <package-dir> <fixtures-dir> [set ...]");
  process.exit(2);
}
const dc = require(path.resolve(pkgDir));
const pkg = JSON.parse(fs.readFileSync(path.join(pkgDir, "package.json"), "utf8"));

// The least number of documents per set, as the Rust CI step checks.
const SETS = { v1: 14, "v1.1": 9, "v1.2": 25, "v1.3": 43, "v1.4": 84, "v1.5": 108 };
const INCLUSION_MIN_CASES = 300;
const sets = wanted.length ? wanted : [...Object.keys(SETS), "inclusion-v1"];
// A document without an expected tenant (v1 to v1.4, which bind none) is checked under this one.
const NO_TENANT = "conformance";
// The check time for a document whose own timestamps are not in the spec's form.
const FIXED_NOW = "2026-01-01T00:00:00Z";
const SPEC_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const CERT_ERRORS = new Set(["Invalid", "UntrustedKey", "BadKey", "BadSignature", "WrongTenant", "KeyMode"]);

const failures = [];
const fail = (where, msg) => failures.push(`${where}: ${msg}`);

// The text of every JSON value in `text`, as written, so a certificate reaches the verifier byte for
// byte (JSON.parse and JSON.stringify would rewrite its numbers). Returns a tree of
// { text, members?: Map, items?: [] }.
function spans(text) {
  let i = 0;
  const ws = () => {
    while (i < text.length && " \t\n\r".includes(text[i])) i++;
  };
  const expect = (c) => {
    if (text[i] !== c) throw new Error(`expected ${c} at ${i}`);
    i++;
  };
  const string = () => {
    expect('"');
    while (text[i] !== '"') {
      if (i >= text.length) throw new Error("unterminated string");
      i += text[i] === "\\" ? 2 : 1;
    }
    i++;
  };
  const value = () => {
    ws();
    const start = i;
    const node = {};
    if (text[i] === "{") {
      i++;
      node.members = new Map();
      ws();
      if (text[i] === "}") i++;
      else
        for (;;) {
          ws();
          const k0 = i;
          string();
          const key = JSON.parse(text.slice(k0, i));
          ws();
          expect(":");
          node.members.set(key, value());
          ws();
          if (text[i] === ",") {
            i++;
            continue;
          }
          expect("}");
          break;
        }
    } else if (text[i] === "[") {
      i++;
      node.items = [];
      ws();
      if (text[i] === "]") i++;
      else
        for (;;) {
          node.items.push(value());
          ws();
          if (text[i] === ",") {
            i++;
            continue;
          }
          expect("]");
          break;
        }
    } else if (text[i] === '"') {
      string();
    } else {
      while (i < text.length && !",}] \t\n\r".includes(text[i])) i++;
    }
    node.text = text.slice(start, i);
    return node;
  };
  const root = value();
  ws();
  if (i !== text.length) throw new Error("trailing text");
  return root;
}

// JSON with sorted keys, for comparing outcomes whatever their member order.
function stable(v) {
  if (Array.isArray(v)) return `[${v.map(stable).join(",")}]`;
  if (v && typeof v === "object")
    return `{${Object.keys(v)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${stable(v[k])}`)
      .join(",")}}`;
  return JSON.stringify(v);
}

function rawCertificate(node, where, parsed) {
  const raw = node.members.get("certificate").text;
  if (stable(JSON.parse(raw)) !== stable(parsed)) fail(where, "certificate span does not match the file");
  return raw;
}

function documentsOf(set) {
  const dir = set === "v1" ? fixturesDir : path.join(fixturesDir, set);
  return fs
    .readdirSync(dir)
    .filter((n) => n.endsWith(".json"))
    .sort()
    .map((n) => {
      const text = fs.readFileSync(path.join(dir, n), "utf8");
      return { name: n.slice(0, -5), file: JSON.parse(text), tree: spans(text) };
    });
}

function checkDocument(set, { name, file: f, tree }) {
  const where = `${set}/${name}`;
  const raw = rawCertificate(tree, where, f.certificate);
  const tenant = typeof f.tenant === "string" ? f.tenant : NO_TENANT;
  const keys = JSON.stringify(f.keys);
  const cert = f.certificate && typeof f.certificate === "object" ? f.certificate : {};
  let id;
  try {
    id = dc.certificateId(raw);
  } catch (e) {
    id = `${e.name}: ${e.message}`;
  }
  if (id !== f.certificate_id) fail(where, `certificateId ${id}, expected ${f.certificate_id}`);

  let runs = 0;
  let expiryChecks = 0;
  const nows = ["fitted_at", "expires_at"].filter((k) => SPEC_TIME.test(cert[k] ?? ""));
  const at = (now, label) => {
    let r;
    try {
      r = dc.verifyDocument(raw, tenant, keys, now);
    } catch (e) {
      if (e.message.startsWith("now ")) return false; // not a real date: try the next time
      fail(where, `verifyDocument threw ${e.name}: ${e.message}`);
      return true;
    }
    runs++;
    if (r.certificate_id !== f.certificate_id) fail(where, `certificate_id ${r.certificate_id}`);
    const v = r.verification;
    if (f.valid) {
      if (v.verdict !== "accepted") return fail(where, `refused: ${v.error}: ${v.message}`), true;
      if (v.certificate_id !== f.certificate_id) fail(where, `accepted with id ${v.certificate_id}`);
      const x = r.expiry;
      if (!x) return fail(where, "accepted without an expiry"), true;
      if (x.expires_at !== cert.expires_at) fail(where, `expiry.expires_at ${x.expires_at}`);
      if (!cert.expires_at.endsWith(":60Z") && !now.endsWith(":60Z")) {
        if (x.now !== now) fail(where, `expiry.now ${x.now}, passed ${now}`);
        // both in the spec's form, so the strings order as the times do
        if (x.expired !== now >= cert.expires_at) fail(where, `expired ${x.expired} at ${now}`);
        if (label === "expires_at" && !x.expired) fail(where, "not expired at its expires_at");
        expiryChecks++;
      }
    } else {
      if (v.verdict !== "refused") return fail(where, `accepted, expected the error ${f.error}`), true;
      if (!CERT_ERRORS.has(v.error)) fail(where, `unknown error name ${v.error}`);
      if (!v.message.includes(f.error)) fail(where, `error ${JSON.stringify(v.message)} does not mention ${JSON.stringify(f.error)}`);
      if (r.expiry !== null) fail(where, "refused with an expiry");
    }
    return true;
  };
  for (const k of nows) at(cert[k], k);
  if (runs === 0) at(FIXED_NOW, "fixed");
  return { valid: !!f.valid, expiryChecks };
}

function checkMutations(set) {
  const rel = set === "v1" ? "mutations/schema_invalid.json" : `${set}/mutations/schema_invalid.json`;
  const text = fs.readFileSync(path.join(fixturesDir, rel), "utf8");
  const f = JSON.parse(text);
  const tree = spans(text);
  const tenant = typeof f.tenant === "string" ? f.tenant : NO_TENANT;
  const keys = JSON.stringify(f.keys);
  const items = tree.members.get("cases").items;
  f.cases.forEach((c, k) => {
    const where = `${rel} case ${k} (${c.path} ${c.edit})`;
    const raw = rawCertificate(items[k], where, c.certificate);
    const r = dc.verifyDocument(raw, tenant, keys, FIXED_NOW);
    if (r.verification.verdict !== "refused") fail(where, "accepted a schema-invalid certificate");
    else if (!CERT_ERRORS.has(r.verification.error)) fail(where, `unknown error name ${r.verification.error}`);
  });
  return f.cases.length;
}

function withoutDetail(v) {
  if (v && typeof v === "object" && !Array.isArray(v)) {
    const { detail, ...rest } = v;
    return rest;
  }
  return v;
}

function inclusionOutcome(dir, c) {
  const read = (rel) => fs.readFileSync(path.join(dir, rel), "utf8");
  switch (c.check) {
    case "bundle":
      return withoutDetail(dc.verifyBundle(read(c.doc), read(c.trust)));
    case "consistency":
      return withoutDetail(dc.verifyConsistency(read(c.doc), read(c.trust)));
    case "trust":
      return withoutDetail(dc.readTrust(read(c.trust)));
    case "tenants":
      return withoutDetail(dc.checkTenants(c.trusts.map(read)));
    case "policy":
      return withoutDetail(dc.applyPolicy(read(c.trust), c.doc === null ? null : read(c.doc)));
    case "leaf_hash":
      return { leaf_hash: dc.leafHash(read(c.leaf)) };
    case "rfc9162_inclusion":
      return dc.verifyInclusionPath(c.leaf_index, c.tree_size, dc.hashLeafBytes(c.leaf_input), c.path, c.root);
    case "rfc9162_consistency":
      return dc.verifyConsistencyPath(c.older, c.newer, c.older_root, c.newer_root, c.path);
    default:
      throw new Error(`unknown check ${c.check}`);
  }
}

function checkInclusion() {
  const dir = path.join(fixturesDir, "inclusion-v1");
  const manifest = JSON.parse(fs.readFileSync(path.join(dir, "manifest.json"), "utf8"));
  const byCheck = {};
  for (const c of manifest.cases) {
    byCheck[c.check] = (byCheck[c.check] ?? 0) + 1;
    let got;
    try {
      got = inclusionOutcome(dir, c);
    } catch (e) {
      got = `threw ${e.name}: ${e.message}`;
    }
    if (stable(got) !== stable(c.expect))
      fail(`inclusion-v1/${c.name}`, `expected ${stable(c.expect)}, got ${stable(got)}`);
  }
  if (manifest.cases.length < INCLUSION_MIN_CASES)
    fail("inclusion-v1", `${manifest.cases.length} cases, expected at least ${INCLUSION_MIN_CASES}`);
  return { cases: manifest.cases.length, byCheck };
}

const wasmPath = path.join(pkgDir, "decision_cert_bg.wasm");
const digest = crypto.createHash("sha256").update(fs.readFileSync(wasmPath)).digest("hex");
console.log(`decision-cert ${pkg.version} (wasm ${dc.version()}), decision_cert_bg.wasm sha256 ${digest}`);
if (dc.version() !== pkg.version) fail("package", `wasm version ${dc.version()}, package.json ${pkg.version}`);

const summary = [];
for (const set of sets) {
  const before = failures.length;
  if (set === "inclusion-v1") {
    const { cases, byCheck } = checkInclusion();
    const parts = Object.entries(byCheck)
      .sort()
      .map(([k, n]) => `${k} ${n}`)
      .join(", ");
    summary.push(`${set}: ${cases} cases (${parts}), ${failures.length - before} disagreements`);
    continue;
  }
  if (!(set in SETS)) {
    console.error(`unknown set ${set}`);
    process.exit(2);
  }
  const docs = documentsOf(set);
  if (docs.length < SETS[set]) fail(set, `${docs.length} documents, expected at least ${SETS[set]}`);
  let valid = 0;
  let expiry = 0;
  for (const d of docs) {
    const r = checkDocument(set, d);
    valid += r.valid ? 1 : 0;
    expiry += r.expiryChecks;
  }
  const mutations = checkMutations(set);
  summary.push(
    `${set}: ${docs.length} documents (${valid} accepted, ${docs.length - valid} refused), ` +
      `${mutations} schema-invalid mutations refused, ${expiry} expiry checks, ` +
      `${failures.length - before} disagreements`,
  );
}

for (const line of summary) console.log(line);
if (failures.length) {
  console.error(`\n${failures.length} disagreements with the expected verdicts:`);
  for (const f of failures) console.error(`  ${f}`);
  process.exit(1);
}
console.log(`all ${sets.length} sets agree with the expected verdicts`);
