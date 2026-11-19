//! The `decision-cert` verifier for JavaScript: a thin wasm-bindgen layer over the Rust crate, which
//! does every check. Published to npm as `decision-cert` (see `npm/README.md`).
//!
//! Documents, keys and configurations are passed as JSON text and parsed here, exactly as the
//! crate's command-line verifier parses them, so a certificate's numbers reach the canonicaliser as
//! written. Results come back as plain objects. A document's verdict is always returned, never
//! thrown; only an argument that is not usable (keys that do not parse, a `now` that is not an
//! RFC 3339 time, a hex string that is not hex) throws, as an `Error` whose `name` is the error's
//! name.

use decision_cert::inclusion::{
    self, apply_policy, check_tenants, ErrorName, Hash, InclusionError, Leaf, LogTrust,
    PolicyOutcome,
};
use decision_cert::{CertError, UtcDateTime};
use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(typescript_custom_section)]
const TYPES: &'static str = r#"
/** The name of a certificate error: the Rust crate's `CertError` variant. */
export type CertErrorName = "Invalid" | "UntrustedKey" | "BadKey" | "BadSignature" | "WrongTenant" | "KeyMode";

/** The result of the form, tenant, key, key mode and signature checks. */
export type Verification =
  | { verdict: "accepted"; certificate_id: string; spec: string; tenant: string | null }
  | { verdict: "refused"; error: CertErrorName; message: string };

/** A verified certificate's expiry at the caller's `now`. */
export interface Expiry {
  /** The `now` the check used, in UTC, RFC 3339. */
  now: string;
  /** The certificate's `expires_at`, as written. */
  expires_at: string;
  /** Whether `now` is not before `expires_at`. */
  expired: boolean;
}

/** The separate results of `verifyDocument`; read each, they are never folded into one. */
export interface DocumentVerdict {
  /** The id recomputed from the document (`sha256:<hex>` of its JCS bytes), whatever the verdict. */
  certificate_id: string | null;
  verification: Verification;
  /** Present only when the verification was accepted. */
  expiry: Expiry | null;
}

/** An inclusion check's verdict line, as `decision-cert verify-bundle` / `verify-consistency` print it. */
export type InclusionLine =
  | ({ verdict: "accepted" } & Record<string, unknown>)
  | { verdict: "refused"; error: string; detail: string };

/** A log trust configuration's reading. */
export type TrustLine =
  | { verdict: "accepted"; tenant: string; m: number; policy: "off" | "warn" | "refuse" }
  | { verdict: "refused"; error: string; detail: string };

/** What a consumer does with a certificate under its log trust configuration's policy. */
export type PolicyLine =
  | { outcome: "load"; verdict?: Record<string, unknown> }
  | { outcome: "load_with_warning" | "refuse"; error: string; detail: string };
"#;

/// The crate's version, which is the package's.
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// The `CertError` variant's name. Relay this, not only the message: `WrongTenant`'s message
/// carries the certificate's own tenant.
fn cert_error_name(e: &CertError) -> &'static str {
    match e {
        CertError::Invalid(_) => "Invalid",
        CertError::UntrustedKey(_) => "UntrustedKey",
        CertError::BadKey(_) => "BadKey",
        CertError::BadSignature => "BadSignature",
        CertError::WrongTenant(_) => "WrongTenant",
        CertError::KeyMode(_) => "KeyMode",
    }
}

/// A thrown error: a JavaScript `Error` with `name` set.
fn thrown(name: &str, message: impl AsRef<str>) -> JsValue {
    let e = js_sys::Error::new(message.as_ref());
    e.set_name(name);
    e.into()
}

fn thrown_cert(e: &CertError) -> JsValue {
    thrown(cert_error_name(e), e.to_string())
}

fn to_js(v: &Value) -> Result<JsValue, JsValue> {
    js_sys::JSON::parse(&v.to_string())
}

/// The certificate text as the command-line verifier reads it.
fn read_certificate(text: &str) -> Result<Value, CertError> {
    serde_json::from_str(text).map_err(|e| CertError::Invalid(format!("not JSON: {e}")))
}

/// `now`: the spec's timestamp form, read as the crate reads it, or any other RFC 3339 time.
fn read_now(s: &str) -> Result<UtcDateTime, JsValue> {
    decision_cert::timestamp(s)
        .ok()
        .or_else(|| OffsetDateTime::parse(s, &Rfc3339).ok().map(|t| t.to_utc()))
        .ok_or_else(|| thrown("Invalid", format!("now {s:?} is not an RFC 3339 time")))
}

/// RFC 3339 in UTC, with a fraction only when the time has one.
fn rfc3339(t: UtcDateTime) -> String {
    let base = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    );
    match t.nanosecond() {
        0 => format!("{base}Z"),
        n => format!("{base}.{}Z", format!("{n:09}").trim_end_matches('0')),
    }
}

/// Verify a certificate for the expected tenant against that tenant's trusted keys, exactly as the
/// crate's `verify_for_tenant`, check its expiry at `now`, and recompute its id.
///
/// `certificate`: the certificate's JSON text. `keys`: the JSON text of the tenant's trusted keys,
/// key id to a base64url public key or a `{"key", "mode", "host"}` entry. `now`: an RFC 3339 time;
/// the package reads no clock. Throws only when `keys` or `now` cannot be read.
#[wasm_bindgen(js_name = verifyDocument, unchecked_return_type = "DocumentVerdict")]
pub fn verify_document(
    certificate: &str,
    tenant: &str,
    keys: &str,
    now: &str,
) -> Result<JsValue, JsValue> {
    let keys: Value = serde_json::from_str(keys)
        .map_err(|e| thrown("Invalid", format!("trusted keys are not JSON: {e}")))?;
    let keys = decision_cert::tenant_keys_from_json(&keys).map_err(|e| thrown_cert(&e))?;
    let now = read_now(now)?;
    let out = match read_certificate(certificate) {
        Err(e) => json!({
            "certificate_id": null,
            "verification": refused_cert(&e),
            "expiry": null,
        }),
        Ok(doc) => {
            let d = decision_cert::verify_document(&doc, tenant, &keys, now);
            let verification = match &d.verification {
                Ok(v) => json!({
                    "verdict": "accepted",
                    "certificate_id": v.id,
                    "spec": v.cert.spec,
                    "tenant": v.tenant(),
                }),
                Err(e) => refused_cert(e),
            };
            let expiry = match (&d.verification, d.expiry) {
                (Ok(v), Some(x)) => json!({
                    "now": rfc3339(x.now),
                    "expires_at": v.cert.expires_at,
                    "expired": x.expired,
                }),
                _ => Value::Null,
            };
            json!({
                "certificate_id": d.certificate_id,
                "verification": verification,
                "expiry": expiry,
            })
        }
    };
    to_js(&out)
}

fn refused_cert(e: &CertError) -> Value {
    json!({"verdict": "refused", "error": cert_error_name(e), "message": e.to_string()})
}

/// A certificate's id, `sha256:<hex>` of its JCS bytes, recomputed from its JSON text. Throws
/// (`Invalid`) when the text is not JSON.
#[wasm_bindgen(js_name = certificateId)]
pub fn certificate_id(certificate: &str) -> Result<String, JsValue> {
    read_certificate(certificate)
        .and_then(|v| decision_cert::certificate_id(&v))
        .map_err(|e| thrown_cert(&e))
}

fn refused(e: &InclusionError) -> Value {
    json!({"verdict": "refused", "error": e.name.as_str(), "detail": e.detail})
}

fn read_ijson(text: &str, form: ErrorName) -> Result<Value, InclusionError> {
    inclusion::parse_ijson(text).map_err(|e| InclusionError::new(form, format!("not I-JSON: {e}")))
}

fn read_trust(text: &str) -> Result<LogTrust, InclusionError> {
    inclusion::parse_ijson(text)
        .map_err(|e| InclusionError::new(ErrorName::TrustForm, e))
        .and_then(|v| LogTrust::from_json(&v))
}

fn line(result: Result<Value, InclusionError>) -> Result<JsValue, JsValue> {
    to_js(&match result {
        Ok(mut v) => {
            v["verdict"] = "accepted".into();
            v
        }
        Err(e) => refused(&e),
    })
}

/// Check an inclusion bundle (`decision-cert-inclusion.v1`) against a tenant's log trust
/// configuration, both JSON text. Returns the verdict line `decision-cert verify-bundle` prints; a
/// configuration that is not well formed is refused as `trust_form`. This does not verify the
/// bundle's certificate itself: `verifyDocument` does.
#[wasm_bindgen(js_name = verifyBundle, unchecked_return_type = "InclusionLine")]
pub fn verify_bundle(bundle: &str, trust: &str) -> Result<JsValue, JsValue> {
    line(read_trust(trust).and_then(|t| {
        let b = read_ijson(bundle, ErrorName::BundleForm)?;
        inclusion::verify_bundle(&b, &t).map(|v| v.to_json())
    }))
}

/// Check a consistency proof document against a tenant's log trust configuration, both JSON text.
/// Returns the verdict line `decision-cert verify-consistency` prints.
#[wasm_bindgen(js_name = verifyConsistency, unchecked_return_type = "InclusionLine")]
pub fn verify_consistency(doc: &str, trust: &str) -> Result<JsValue, JsValue> {
    line(read_trust(trust).and_then(|t| {
        let d = read_ijson(doc, ErrorName::ConsistencyForm)?;
        inclusion::verify_consistency(&d, &t).map(|v| v.to_json())
    }))
}

/// Read and check a log trust configuration (JSON text): its tenant, `m` and policy, or `trust_form`.
#[wasm_bindgen(js_name = readTrust, unchecked_return_type = "TrustLine")]
pub fn read_trust_line(trust: &str) -> Result<JsValue, JsValue> {
    to_js(&match read_trust(trust) {
        Ok(t) => json!({
            "verdict": "accepted",
            "tenant": t.tenant(),
            "m": t.m(),
            "policy": t.policy().as_str(),
        }),
        Err(e) => refused(&e),
    })
}

/// Check a consumer's log trust configurations (JSON text each) held together: refused as
/// `trust_cross_tenant` when one `log_id` or log key appears under two tenants, and as `trust_form`
/// when a configuration is not well formed.
#[wasm_bindgen(js_name = checkTenants, unchecked_return_type = "InclusionLine")]
pub fn check_tenants_line(trusts: Vec<String>) -> Result<JsValue, JsValue> {
    let configs: Result<Vec<LogTrust>, InclusionError> =
        trusts.iter().map(|t| read_trust(t)).collect();
    line(configs.and_then(|c| check_tenants(&c).map(|()| json!({}))))
}

/// Apply a log trust configuration's policy to a certificate's bundle (JSON text), or to its absence
/// (`bundle` undefined or null).
#[wasm_bindgen(js_name = applyPolicy, unchecked_return_type = "PolicyLine")]
pub fn apply_policy_line(trust: &str, bundle: Option<String>) -> Result<JsValue, JsValue> {
    let t = match read_trust(trust) {
        Ok(t) => t,
        Err(e) => {
            return to_js(
                &json!({"outcome": "refuse", "error": e.name.as_str(), "detail": e.detail}),
            )
        }
    };
    let result = bundle.map(|b| {
        read_ijson(&b, ErrorName::BundleForm).and_then(|v| inclusion::verify_bundle(&v, &t))
    });
    let with = |outcome: &str, e: &InclusionError| json!({"outcome": outcome, "error": e.name.as_str(), "detail": e.detail});
    to_js(&match apply_policy(result, t.policy()) {
        PolicyOutcome::Load(None) => json!({"outcome": "load"}),
        PolicyOutcome::Load(Some(v)) => json!({"outcome": "load", "verdict": v.to_json()}),
        PolicyOutcome::LoadWithWarning(e) => with("load_with_warning", &e),
        PolicyOutcome::Refuse(e) => with("refuse", &e),
    })
}

/// A leaf's hash (JSON text of the leaf), base64. Throws `leaf_form` for a leaf that is not well
/// formed.
#[wasm_bindgen(js_name = leafHash)]
pub fn leaf_hash(leaf: &str) -> Result<String, JsValue> {
    read_ijson(leaf, ErrorName::LeafForm)
        .and_then(|v| Leaf::from_json(&v))
        .map(|l| {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(inclusion::leaf_hash(&l))
        })
        .map_err(|e| thrown(e.name.as_str(), e.detail))
}

fn unhex(s: &str) -> Result<Vec<u8>, JsValue> {
    let bad = || thrown("Invalid", format!("{s:?} is not hex"));
    if !s.len().is_multiple_of(2) || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(bad());
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|_| bad()))
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn hash(s: &str) -> Result<Hash, JsValue> {
    unhex(s)?
        .try_into()
        .map_err(|_| thrown("Invalid", format!("{s:?} is not a 32-byte hash")))
}

fn hashes(v: &[String]) -> Result<Vec<Hash>, JsValue> {
    v.iter().map(|s| hash(s)).collect()
}

fn size(n: f64) -> Result<u64, JsValue> {
    if n.fract() == 0.0 && (0.0..=inclusion::MAX_INT as f64).contains(&n) {
        Ok(n as u64)
    } else {
        Err(thrown(
            "Invalid",
            format!("{n} is not an integer in 0 to 2^53 - 1"),
        ))
    }
}

/// RFC 9162's leaf hash of raw leaf input bytes (hex in, hex out).
#[wasm_bindgen(js_name = hashLeafBytes)]
pub fn hash_leaf_bytes(data: &str) -> Result<String, JsValue> {
    Ok(hex(&inclusion::hash_leaf_bytes(&unhex(data)?)))
}

/// RFC 9162 §2.1.3.2: whether `path` (hex hashes) proves the leaf hash at `leafIndex` in a tree of
/// `treeSize` with root `root`.
#[wasm_bindgen(js_name = verifyInclusionPath)]
pub fn verify_inclusion_path(
    leaf_index: f64,
    tree_size: f64,
    leaf_hash: &str,
    path: Vec<String>,
    root: &str,
) -> Result<bool, JsValue> {
    Ok(inclusion::verify_inclusion_path(
        size(leaf_index)?,
        size(tree_size)?,
        &hash(leaf_hash)?,
        &hashes(&path)?,
        &hash(root)?,
    ))
}

/// RFC 9162 §2.1.4.2: whether `path` (hex hashes) proves the tree of `older` leaves with root
/// `olderRoot` a prefix of the tree of `newer` leaves with root `newerRoot`.
#[wasm_bindgen(js_name = verifyConsistencyPath)]
pub fn verify_consistency_path(
    older: f64,
    newer: f64,
    older_root: &str,
    newer_root: &str,
    path: Vec<String>,
) -> Result<bool, JsValue> {
    Ok(inclusion::verify_consistency_path(
        size(older)?,
        size(newer)?,
        &hash(older_root)?,
        &hash(newer_root)?,
        &hashes(&path)?,
    ))
}
