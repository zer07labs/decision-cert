//! Load, verify and apply `decision-certificate.v1` (spec/decision-certificate.v1.md).
//!
//! Verification canonicalises the JSON value exactly as received (RFC 8785, JCS), never a
//! re-serialised struct, so number formatting can't drift from the issuer's. The typed
//! [`Certificate`] is read from the same value afterwards, rejecting unknown fields.

use std::collections::BTreeMap;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};

pub const SPEC: &str = "decision-certificate.v1";
/// `abstain_below` that abstains on every case (as `dk calibrate` writes it).
pub const ABSTAIN_ALL: f64 = 1.01;

#[derive(Debug, thiserror::Error)]
pub enum CertError {
    #[error("certificate is not a valid {SPEC}: {0}")]
    Invalid(String),
    #[error("certificate signed by {0}, which is not a trusted key")]
    UntrustedKey(String),
    #[error("trusted key {0} is malformed or does not hash to its id")]
    BadKey(String),
    #[error("certificate signature does not verify")]
    BadSignature,
}

#[derive(Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Band {
    pub level: f64,
    pub low: f64,
    pub high: f64,
}

#[derive(Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Segment {
    pub field: String,
    pub value: String,
    pub n: u64,
    pub abstain_below: f64,
    pub coverage: f64,
    #[serde(deserialize_with = "nullable")]
    pub ucb: Option<f64>,
    #[serde(deserialize_with = "nullable")]
    pub realized_band: Option<Band>,
    pub inherited: bool,
}

#[derive(Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Split {
    pub method: String,
    #[serde(deserialize_with = "nullable")]
    pub seed: Option<i64>,
}

#[derive(Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CalibrationMap {
    pub kind: String,
    pub params: BTreeMap<String, f64>,
    #[serde(deserialize_with = "nullable")]
    pub label_budget: Option<u64>,
}

#[derive(Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    #[serde(deserialize_with = "nullable")]
    pub cannot_tell_above: Option<f64>,
    pub unscored: String,
}

#[derive(Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Window {
    pub start: String,
    pub end: String,
}

#[derive(Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Audit {
    pub mode: String,
    pub rate: f64,
    pub n: u64,
    pub propensity_logged: bool,
}

#[derive(Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Issuer {
    pub tool: String,
    pub version: String,
}

/// Every field is required; `Option` fields must be present (as null) — see [`nullable`].
#[derive(Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Certificate {
    pub spec: String,
    pub domain: String,
    pub decision: String,
    pub options: Vec<String>,
    pub model_id: String,
    #[serde(deserialize_with = "nullable")]
    pub manifest_hash: Option<String>,
    pub data_hash: String,
    pub n_cal: u64,
    pub n_temperature: u64,
    pub split: Split,
    pub calibration_map: CalibrationMap,
    pub rule: Rule,
    pub alpha: f64,
    #[serde(deserialize_with = "nullable")]
    pub delta: Option<f64>,
    pub method: String,
    pub risk: String,
    pub n: u64,
    pub abstain_below: f64,
    pub coverage: f64,
    #[serde(deserialize_with = "nullable")]
    pub ucb: Option<f64>,
    pub realized_band: Band,
    pub segments: Vec<Segment>,
    #[serde(deserialize_with = "nullable")]
    pub window: Option<Window>,
    pub fitted_at: String,
    pub expires_at: String,
    pub audit: Audit,
    pub issuer: Issuer,
    pub signer_key_id: String,
    pub signature: String,
}

/// A present field that may be null. serde reads a missing `Option` as null, the spec does not:
/// with `deserialize_with` and no `default`, a missing field is an error at every level.
fn nullable<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<T>, D::Error> {
    Option::deserialize(d)
}

/// A certificate whose signature verified against a trusted key.
#[derive(Clone, Debug, PartialEq)]
pub struct Verified {
    /// `sha256:<hex>` of the signed certificate's JCS bytes.
    pub id: String,
    pub cert: Certificate,
    pub expires_at: DateTime<Utc>,
}

impl Verified {
    /// The threshold for a case in `segment`: a certified segment's own, else the top-level one.
    pub fn threshold_for(&self, segment: Option<&str>) -> f64 {
        segment
            .and_then(|v| {
                self.cert
                    .segments
                    .iter()
                    .find(|s| !s.inherited && s.value == v)
            })
            .map_or(self.cert.abstain_below, |s| s.abstain_below)
    }

    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        now >= self.expires_at
    }

    /// The temperature of a `kind: temperature` calibration map; None for other kinds.
    pub fn temperature(&self) -> Option<f64> {
        (self.cert.calibration_map.kind == "temperature")
            .then(|| self.cert.calibration_map.params.get("temperature").copied())
            .flatten()
    }
}

/// The JCS bytes of a JSON value.
pub fn canonical(v: &serde_json::Value) -> Result<Vec<u8>, CertError> {
    serde_jcs::to_vec(v).map_err(|e| CertError::Invalid(format!("not canonicalisable: {e}")))
}

pub fn certificate_id(v: &serde_json::Value) -> Result<String, CertError> {
    Ok(format!("sha256:{}", hex(&Sha256::digest(canonical(v)?))))
}

/// `ed25519:` + the first 16 hex chars of SHA-256 of the raw public key.
pub fn key_id(key: &VerifyingKey) -> String {
    format!("ed25519:{}", &hex(&Sha256::digest(key.as_bytes()))[..16])
}

/// Verify `v` against `keys` (key id → base64url raw public key) and read it.
pub fn verify(
    v: &serde_json::Value,
    keys: &BTreeMap<String, String>,
) -> Result<Verified, CertError> {
    let obj = v
        .as_object()
        .ok_or_else(|| CertError::Invalid("not a JSON object".into()))?;
    let cert: Certificate =
        serde_json::from_value(v.clone()).map_err(|e| CertError::Invalid(e.to_string()))?;
    check(&cert)?;

    let raw = keys
        .get(&cert.signer_key_id)
        .ok_or_else(|| CertError::UntrustedKey(cert.signer_key_id.clone()))?;
    let key = URL_SAFE_NO_PAD
        .decode(raw)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .and_then(|b| VerifyingKey::from_bytes(&b).ok())
        .filter(|k| key_id(k) == cert.signer_key_id)
        .ok_or_else(|| CertError::BadKey(cert.signer_key_id.clone()))?;
    let sig = URL_SAFE_NO_PAD
        .decode(&cert.signature)
        .ok()
        .and_then(|b| Signature::from_slice(&b).ok())
        .ok_or(CertError::BadSignature)?;
    let mut body = obj.clone();
    body.remove("signature");
    key.verify_strict(&canonical(&serde_json::Value::Object(body))?, &sig)
        .map_err(|_| CertError::BadSignature)?;

    Ok(Verified {
        id: certificate_id(v)?,
        expires_at: timestamp(&cert.expires_at)?,
        cert,
    })
}

/// The schema's constraints (spec/decision-certificate.v1.schema.json) that a typed read
/// doesn't already enforce, so this verifier accepts exactly what the schema accepts.
fn check(c: &Certificate) -> Result<(), CertError> {
    let bad = |m: &str| Err(CertError::Invalid(m.to_string()));
    let unit = |x: f64| (0.0..=1.0).contains(&x);
    let open = |x: f64| x > 0.0 && x < 1.0;
    let threshold = |x: f64| (0.0..=ABSTAIN_ALL).contains(&x);
    if c.spec != SPEC {
        return bad("spec is not decision-certificate.v1");
    }
    let mut seen = std::collections::BTreeSet::new();
    if c.options.len() < 2 || !c.options.iter().all(|o| !o.is_empty() && seen.insert(o)) {
        return bad("options needs at least 2 distinct non-empty ids");
    }
    if [
        &c.domain,
        &c.decision,
        &c.calibration_map.kind,
        &c.issuer.tool,
        &c.issuer.version,
    ]
    .iter()
    .any(|s| s.is_empty())
    {
        return bad("domain, decision, calibration_map.kind and issuer must be non-empty");
    }
    match (c.method.as_str(), c.risk.as_str(), c.delta, c.ucb) {
        ("ltt", "selective_error", Some(d), _) if open(d) => {}
        ("crc", "joint_error", None, None) => {}
        _ => return bad("method, risk, delta and ucb disagree"),
    }
    if !open(c.alpha) || !threshold(c.abstain_below) || !unit(c.coverage) {
        return bad("alpha, abstain_below or coverage out of range");
    }
    if c.ucb.is_some_and(|u| !unit(u)) || !band_ok(&c.realized_band) {
        return bad("ucb or realized_band out of range");
    }
    for s in &c.segments {
        if s.field.is_empty()
            || !threshold(s.abstain_below)
            || !unit(s.coverage)
            || s.ucb.is_some_and(|u| !unit(u))
            || s.realized_band.as_ref().is_some_and(|b| !band_ok(b))
        {
            return bad("a segment is out of range");
        }
    }
    if !matches!(
        (c.split.method.as_str(), c.split.seed),
        ("time", None) | ("seeded", Some(_))
    ) {
        return bad("split.method and split.seed disagree");
    }
    if c.rule.unscored != "abstain" || c.rule.cannot_tell_above.is_some_and(|x| !unit(x)) {
        return bad("rule out of range");
    }
    if !matches!(c.audit.mode.as_str(), "sample" | "full-label")
        || !(c.audit.rate > 0.0 && c.audit.rate <= 1.0)
    {
        return bad("audit out of range");
    }
    if !model_id_ok(&c.model_id) {
        return bad("model_id must be <backend>/<model>@<version>");
    }
    if !sha256_ok(&c.data_hash) || c.manifest_hash.as_deref().is_some_and(|h| !sha256_ok(h)) {
        return bad("data_hash and manifest_hash must be sha256:<64 hex>");
    }
    let key_hex = c.signer_key_id.strip_prefix("ed25519:");
    if !key_hex.is_some_and(|h| h.len() == 16 && lower_hex(h)) {
        return bad("signer_key_id must be ed25519:<16 hex>");
    }
    if c.signature.len() != 86
        || !c
            .signature
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return bad("signature must be 86 base64url characters");
    }
    timestamp(&c.fitted_at)?;
    timestamp(&c.expires_at)?;
    if let Some(w) = &c.window {
        timestamp(&w.start)?;
        timestamp(&w.end)?;
    }
    Ok(())
}

/// `^[^/]+/.+@.+$`, and not ending in `@?` (an unknown version).
fn model_id_ok(m: &str) -> bool {
    // The pattern's `.` matches no line terminator.
    if m.chars()
        .any(|c| matches!(c, '\n' | '\r' | '\u{2028}' | '\u{2029}'))
    {
        return false;
    }
    let Some((backend, rest)) = m.split_once('/') else {
        return false;
    };
    let at = rest
        .char_indices()
        .skip(1)
        .any(|(i, ch)| ch == '@' && i + 1 < rest.len());
    !backend.is_empty() && at && !m.ends_with("@?")
}

fn sha256_ok(h: &str) -> bool {
    h.strip_prefix("sha256:")
        .is_some_and(|x| x.len() == 64 && lower_hex(x))
}

fn lower_hex(s: &str) -> bool {
    s.bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn band_ok(b: &Band) -> bool {
    b.level > 0.0 && b.level < 1.0 && (0.0..=1.0).contains(&b.low) && (0.0..=1.0).contains(&b.high)
}

fn timestamp(s: &str) -> Result<DateTime<Utc>, CertError> {
    // The schema's `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$` exactly: chrono also takes `t` or a space.
    let b = s.as_bytes();
    let ok = b.len() == 20
        && b.iter().enumerate().all(|(i, &c)| match i {
            4 | 7 => c == b'-',
            10 => c == b'T',
            13 | 16 => c == b':',
            19 => c == b'Z',
            _ => c.is_ascii_digit(),
        });
    DateTime::parse_from_rfc3339(s)
        .ok()
        .filter(|_| ok)
        .map(|t| t.with_timezone(&Utc))
        .ok_or_else(|| CertError::Invalid(format!("timestamp {s:?} is not YYYY-MM-DDTHH:MM:SSZ")))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> serde_json::Value {
        let f: serde_json::Value =
            serde_json::from_str(include_str!("../../fixtures/valid_segments_unicode.json"))
                .unwrap();
        f["certificate"].clone()
    }

    #[test]
    fn check_rejects_what_the_schema_rejects() {
        let typed =
            |v: &serde_json::Value| serde_json::from_value::<Certificate>(v.clone()).unwrap();
        assert!(check(&typed(&valid())).is_ok());
        let edits: [(&str, serde_json::Value); 15] = [
            ("data_hash", serde_json::json!("sha256:XYZ")),
            ("manifest_hash", serde_json::json!("md5:00")),
            ("signer_key_id", serde_json::json!("ed25519:short")),
            ("model_id", serde_json::json!("/x@y")),
            ("model_id", serde_json::json!("b/m@?")),
            (
                "window",
                serde_json::json!({"start": "2023-01-02", "end": "2023-12-29T23:59:59Z"}),
            ),
            ("expires_at", serde_json::json!("2027-01-23T12:00:00+00:00")),
            ("expires_at", serde_json::json!("2027-01-23 12:00:00Z")),
            ("fitted_at", serde_json::json!("2026-10-25t12:00:00Z")),
            ("domain", serde_json::json!("")),
            ("options", serde_json::json!(["yes", "yes"])),
            ("split", serde_json::json!({"method": "time", "seed": 3})),
            ("alpha", serde_json::json!(1.0)),
            ("signature", serde_json::json!("abc")),
            ("model_id", serde_json::json!("a/b\n@c")),
        ];
        for (field, value) in edits {
            let mut v = valid();
            v[field] = value.clone();
            assert!(check(&typed(&v)).is_err(), "{field} = {value}");
        }
    }

    #[test]
    fn nested_nullable_fields_must_be_present() {
        let paths: [(&str, &str); 5] = [
            ("segments", "ucb"),
            ("segments", "realized_band"),
            ("split", "seed"),
            ("calibration_map", "label_budget"),
            ("rule", "cannot_tell_above"),
        ];
        for (outer, inner) in paths {
            let mut v = valid();
            let o = if outer == "segments" {
                &mut v[outer][0]
            } else {
                &mut v[outer]
            };
            o.as_object_mut().unwrap().remove(inner);
            let e = serde_json::from_value::<Certificate>(v).err();
            assert!(
                e.is_some_and(|e| e.to_string().contains(inner)),
                "{outer}.{inner}"
            );
        }
    }

    #[test]
    fn certified_segments_set_the_threshold_and_inherited_ones_do_not() {
        let cert: Certificate = serde_json::from_value(valid()).unwrap();
        let v = Verified {
            id: String::new(),
            expires_at: timestamp(&cert.expires_at).unwrap(),
            cert,
        };
        assert_eq!(v.threshold_for(Some("east")), 0.9);
        assert_eq!(
            v.threshold_for(Some("z\u{fc}rich \u{2603}")),
            v.cert.abstain_below
        );
        assert_eq!(v.threshold_for(None), v.cert.abstain_below);
        assert!(
            v.is_expired(v.expires_at)
                && !v.is_expired(v.expires_at - chrono::Duration::seconds(1))
        );
    }
}
