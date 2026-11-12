//! Load, verify and apply decision certificates: `decision-certificate.v1`
//! (spec/decision-certificate.v1.md), `decision-certificate.v1.1` (spec/decision-certificate.v1.1.md)
//! `decision-certificate.v1.2` (spec/decision-certificate.v1.2.md) and `decision-certificate.v1.3`
//! (spec/decision-certificate.v1.3.md).
//!
//! Verification canonicalises the JSON value exactly as received (RFC 8785, JCS), never a
//! re-serialised struct, so number formatting can't drift from the issuer's. The typed
//! [`Certificate`] is read from the same value afterwards, rejecting unknown fields.
//!
//! A v1.2 certificate also stores the confidence histogram of its threshold split, so a consumer can
//! monitor without labels: [`Histogram::of`] bins a window of use-time confidences and
//! [`shift_score`] compares it with the stored one. The score is descriptive, a prompt to measure
//! again; it never shows that the bound holds or has failed.
//!
//! [`probabilities`] applies a certificate's calibration map to a case's raw scores, for the map
//! kinds v1.2 defines (`temperature` and `dr`, [`MAP_KINDS`]).
//!
//! A v1.3 certificate also names the options a consumer automates (`automate_options`) and reports,
//! per test, the share and error of the answered cases whose answer is one of them ([`Automated`]).

mod map;
mod monitor;

pub use map::{confidence, probabilities, MAP_KINDS};
pub use monitor::{bin_of, chi2_sf, shift_score, ShiftScore};

use std::collections::BTreeMap;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// The `spec` of a certificate produced by the v1 procedure.
pub const SPEC: &str = "decision-certificate.v1";
/// The `spec` of a certificate produced by the v1.1 procedure (the per-test grid start).
pub const SPEC_V1_1: &str = "decision-certificate.v1.1";
/// The `spec` of a v1.2 certificate: v1.1's procedure, plus the stored confidence histogram.
pub const SPEC_V1_2: &str = "decision-certificate.v1.2";
/// The `spec` of a v1.3 certificate: v1.2, plus the automated options and their answered share and
/// error per test.
pub const SPEC_V1_3: &str = "decision-certificate.v1.3";
/// The `spec` of a v1.4 certificate: v1.3, plus the cost risk `selective_cost`.
pub const SPEC_V1_4: &str = "decision-certificate.v1.4";
/// Every `spec` this verifier accepts. v1 and v1.1 have the same fields; v1.2 adds some, v1.3 more,
/// v1.4 more again.
pub const SPECS: [&str; 5] = [SPEC, SPEC_V1_1, SPEC_V1_2, SPEC_V1_3, SPEC_V1_4];
/// Most bins a `confidence_bins` may define.
pub const MAX_BINS: usize = 100;
/// `abstain_below` that abstains on every case (as `dk calibrate` writes it).
pub const ABSTAIN_ALL: f64 = 1.01;

#[derive(Debug, thiserror::Error)]
pub enum CertError {
    #[error("certificate is not a valid decision certificate: {0}")]
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

/// A test's threshold-split cases per bin of `confidence_bins`, and the cases the rule abstains on
/// whatever the threshold (unscored, or above the `cannot_tell` cut). v1.2.
#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Histogram {
    pub counts: Vec<u64>,
    pub unscored: u64,
}

/// A test's answered cases whose answer is one of `automate_options` (v1.3): their share of the
/// test's `n` cases, and `ucb` and `realized_band` of their error, as the test's own (descriptive,
/// spec v1.2 §1.2). Null exactly where the test's are.
#[derive(Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Automated {
    pub coverage: f64,
    #[serde(deserialize_with = "nullable")]
    pub ucb: Option<f64>,
    #[serde(deserialize_with = "nullable")]
    pub realized_band: Option<Band>,
    /// v1.4 only (absent before v1.4): the automated cases' mean normalised cost under
    /// `selective_cost`; present and null otherwise.
    #[serde(default, deserialize_with = "present")]
    pub realized_cost: Option<Option<f64>>,
}

/// A v1.4 `selective_cost` certificate's costs: `matrix[label][answered option]`, in the options'
/// order, its largest entry `c_max`, and a free `unit` label (informational).
#[derive(Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Cost {
    pub matrix: Vec<Vec<f64>>,
    pub c_max: f64,
    #[serde(deserialize_with = "nullable")]
    pub unit: Option<String>,
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
    /// v1.2 only: absent (None) before v1.2; present and null (Some(None)) when withheld.
    #[serde(default, deserialize_with = "present")]
    pub confidence_histogram: Option<Option<Histogram>>,
    /// v1.3 only: absent (None) before v1.3.
    #[serde(default, deserialize_with = "present")]
    pub automated: Option<Automated>,
    /// v1.4 only: absent (None) before v1.4.
    #[serde(default, deserialize_with = "present")]
    pub realized_cost: Option<Option<f64>>,
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

/// Every field is required; `Option` fields must be present (as null): a missing field is an error.
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
    /// v1.2 only (absent, so None, before v1.2): the histogram bin edges, rising from 0 to 1.
    #[serde(default, deserialize_with = "present")]
    pub confidence_bins: Option<Vec<f64>>,
    /// v1.2 only: the remainder's histogram; present and null (Some(None)) when withheld.
    #[serde(default, deserialize_with = "present")]
    pub confidence_histogram: Option<Option<Histogram>>,
    /// v1.3 only (absent before v1.3): the options a consumer decides automatically; a case answered
    /// with another option goes to a person.
    #[serde(default, deserialize_with = "present")]
    pub automate_options: Option<Vec<String>>,
    /// v1.3 only: the remainder's automated cases.
    #[serde(default, deserialize_with = "present")]
    pub automated: Option<Automated>,
    /// v1.4 only (absent before v1.4): the costs of a `selective_cost` certificate; present and null
    /// for the error risks.
    #[serde(default, deserialize_with = "present")]
    pub cost: Option<Option<Cost>>,
    /// v1.4 only: the `ltt` p-value, `binomial` or `hoeffding_bentkus`; null for `crc`.
    #[serde(default, deserialize_with = "present")]
    pub pvalue: Option<Option<String>>,
    /// v1.4 only: the remainder's mean normalised cost of its answered cases (descriptive).
    #[serde(default, deserialize_with = "present")]
    pub realized_cost: Option<Option<f64>>,
}

/// A field that may be absent (with `default`, as None) but, when present, is read as `T`: so a
/// present null reads as `Some(None)` for `T = Option<_>`, and is an error for any other `T`.
fn present<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<T>, D::Error> {
    T::deserialize(d).map(Some)
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

    /// The bin edges of a v1.2 certificate's confidence histograms; None before v1.2.
    pub fn confidence_bins(&self) -> Option<&[f64]> {
        self.cert.confidence_bins.as_deref()
    }

    /// The stored confidence histogram of the cases decided by the same threshold as a case in
    /// `segment`: a certified segment's own, else the top level's. None before v1.2, or when the
    /// issuer withheld it.
    pub fn histogram_for(&self, segment: Option<&str>) -> Option<&Histogram> {
        let own = segment.and_then(|v| {
            self.cert
                .segments
                .iter()
                .find(|s| !s.inherited && s.value == v)
        });
        match own {
            Some(s) => s.confidence_histogram.as_ref()?.as_ref(),
            None => self.cert.confidence_histogram.as_ref()?.as_ref(),
        }
    }

    /// The options a v1.3 certificate's consumer automates; None before v1.3. A consumer refuses a
    /// certificate whose list differs from the options it automates (spec v1.3 §4).
    pub fn automate_options(&self) -> Option<&[String]> {
        self.cert.automate_options.as_deref()
    }

    /// The automated cases of the test that decides a case in `segment` (a certified segment's own,
    /// else the top level's): their share and error. None before v1.3.
    pub fn automated_for(&self, segment: Option<&str>) -> Option<&Automated> {
        let own = segment.and_then(|v| {
            self.cert
                .segments
                .iter()
                .find(|s| !s.inherited && s.value == v)
        });
        match own {
            Some(s) => s.automated.as_ref(),
            None => self.cert.automated.as_ref(),
        }
    }

    /// A v1.4 `selective_cost` certificate's costs; None otherwise. A consumer refuses a certificate
    /// whose matrix differs from the costs it is configured with (spec v1.4 §4), and reports the
    /// bound as `alpha * c_max` in `unit`.
    pub fn cost(&self) -> Option<&Cost> {
        self.cert.cost.as_ref().and_then(|c| c.as_ref())
    }

    /// The probabilities the certificate's calibration map gives a case's raw scores, one per
    /// option (spec v1.2 §1, [`probabilities`]). None when the map's kind is not one this crate
    /// applies ([`MAP_KINDS`]), its params do not fit that kind, or `scores` does not have one score
    /// per option, or the map is `dr` in a certificate before v1.2, which did not define it. A
    /// consumer refuses a certificate whose map it does not apply (spec v1.2 §4).
    pub fn probabilities(&self, scores: &[f64]) -> Option<Vec<f64>> {
        let defined = self.cert.calibration_map.kind == "temperature"
            || self.cert.spec == SPEC_V1_2
            || self.cert.spec == SPEC_V1_3
            || self.cert.spec == SPEC_V1_4;
        (defined && scores.len() == self.cert.options.len())
            .then(|| probabilities(&self.cert.calibration_map, scores))
            .flatten()
    }

    /// A case's confidence: the largest of its [`Verified::probabilities`]. A case is answered when
    /// this is at least [`Verified::threshold_for`] its segment (and the rule does not abstain on it).
    pub fn confidence(&self, scores: &[f64]) -> Option<f64> {
        self.probabilities(scores)
            .map(|p| p.into_iter().fold(f64::NEG_INFINITY, f64::max))
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

/// The schema's constraints (spec/decision-certificate.v1.schema.json, the v1.1 schema, which
/// differs only in `spec`, and the v1.2 schema) that a typed read doesn't already enforce, so this
/// verifier accepts exactly what the schemas accept; and for v1.2, the histogram and calibration map
/// checks the schema cannot express (spec v1.2 §2).
fn check(c: &Certificate) -> Result<(), CertError> {
    let bad = |m: &str| Err(CertError::Invalid(m.to_string()));
    let unit = |x: f64| (0.0..=1.0).contains(&x);
    let open = |x: f64| x > 0.0 && x < 1.0;
    let threshold = |x: f64| (0.0..=ABSTAIN_ALL).contains(&x);
    if !SPECS.contains(&c.spec.as_str()) {
        return bad("spec is not decision-certificate.v1, decision-certificate.v1.1, decision-certificate.v1.2, decision-certificate.v1.3 or decision-certificate.v1.4");
    }
    fields_for_spec(c)?;
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
    let v14 = c.spec == SPEC_V1_4;
    match (c.method.as_str(), c.risk.as_str(), c.delta, c.ucb) {
        ("ltt", "selective_error", Some(d), _) if open(d) => {}
        ("ltt", "selective_cost", Some(d), _) if v14 && open(d) => {}
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
    if c.spec == SPEC_V1_2 || c.spec == SPEC_V1_3 || v14 {
        histograms(c)?;
        map::check(&c.calibration_map, c.options.len())?;
    }
    if c.spec == SPEC_V1_3 || v14 {
        automated(c)?;
    }
    if v14 {
        cost(c)?;
    }
    Ok(())
}

/// A v1.2 certificate has every v1.2 field, a v1.3 certificate every v1.2 and v1.3 field, and an
/// earlier certificate none of them, at the top level and in every segment. A certificate whose
/// fields belong to another spec is refused as a spec it is not, so a v1.1-shaped certificate naming
/// v1.2, or a v1.2-shaped one naming v1.3, is still refused as an unknown spec.
fn fields_for_spec(c: &Certificate) -> Result<(), CertError> {
    let v14 = c.spec == SPEC_V1_4;
    let v13 = c.spec == SPEC_V1_3 || v14;
    let v12 = c.spec == SPEC_V1_2 || v13;
    // (name, present, required by this spec): the v1.2 fields first, then the v1.3 ones.
    let mut present = vec![
        ("confidence_bins", c.confidence_bins.is_some(), v12),
        (
            "confidence_histogram",
            c.confidence_histogram.is_some(),
            v12,
        ),
        ("automate_options", c.automate_options.is_some(), v13),
        ("automated", c.automated.is_some(), v13),
        ("cost", c.cost.is_some(), v14),
        ("pvalue", c.pvalue.is_some(), v14),
        ("realized_cost", c.realized_cost.is_some(), v14),
    ];
    for s in &c.segments {
        present.push((
            "segments[].confidence_histogram",
            s.confidence_histogram.is_some(),
            v12,
        ));
        present.push(("segments[].automated", s.automated.is_some(), v13));
        present.push(("segments[].realized_cost", s.realized_cost.is_some(), v14));
    }
    if let Some(a) = &c.automated {
        present.push(("automated.realized_cost", a.realized_cost.is_some(), v14));
    }
    for s in &c.segments {
        if let Some(a) = &s.automated {
            present.push((
                "segments[].automated.realized_cost",
                a.realized_cost.is_some(),
                v14,
            ));
        }
    }
    for (name, here, required) in present {
        if required && !here {
            return Err(CertError::Invalid(format!(
                "spec is not consistent with the fields: {} requires `{name}`",
                c.spec
            )));
        }
        if !required && here {
            return Err(CertError::Invalid(format!(
                "unknown field `{name}` in a {} certificate",
                c.spec
            )));
        }
    }
    Ok(())
}

/// v1.2's checks beyond the schema: the bins rise strictly from 0 to 1, and each histogram has one
/// count per bin and counts exactly its test's `n` cases.
fn histograms(c: &Certificate) -> Result<(), CertError> {
    let bins = c.confidence_bins.as_deref().unwrap_or_default();
    let rising = bins.windows(2).all(|w| w[0] < w[1]);
    if !(2..=MAX_BINS + 1).contains(&bins.len())
        || bins[0] != 0.0
        || bins[bins.len() - 1] != 1.0
        || !rising
    {
        return Err(CertError::Invalid(format!(
            "confidence_bins must rise strictly from 0 to 1, with 1 to {MAX_BINS} bins"
        )));
    }
    let tests = std::iter::once((&c.confidence_histogram, c.n))
        .chain(c.segments.iter().map(|s| (&s.confidence_histogram, s.n)));
    for (h, n) in tests {
        if let Some(Some(h)) = h {
            let total: u128 =
                h.counts.iter().map(|&x| u128::from(x)).sum::<u128>() + u128::from(h.unscored);
            if h.counts.len() != bins.len() - 1 || total != u128::from(n) {
                return Err(CertError::Invalid(
                    "a confidence_histogram needs one count per bin, and its counts and unscored must sum to n".into(),
                ));
            }
        }
    }
    Ok(())
}

/// v1.3's checks beyond the schema: `automate_options` names options of the certificate, once each
/// and in their order; each test's `automated` share is at most its `coverage`, its numbers are in
/// range, and its `ucb` and `realized_band` are null exactly where the test's are.
fn automated(c: &Certificate) -> Result<(), CertError> {
    let auto = c.automate_options.as_deref().unwrap_or_default();
    let mut at = c.options.iter();
    if auto.is_empty() || !auto.iter().all(|o| at.any(|x| x == o)) {
        return Err(CertError::Invalid(
            "automate_options must name one or more of the options, once each and in their order"
                .into(),
        ));
    }
    let unit = |x: f64| (0.0..=1.0).contains(&x);
    let tests = std::iter::once((
        &c.automated,
        c.coverage,
        c.ucb.is_some(),
        true, // the top level's realized_band is never null
    ))
    .chain(c.segments.iter().map(|s| {
        (
            &s.automated,
            s.coverage,
            s.ucb.is_some(),
            s.realized_band.is_some(),
        )
    }));
    for (a, coverage, ucb, band) in tests {
        let Some(a) = a else { continue };
        if !unit(a.coverage)
            || a.coverage > coverage
            || a.ucb.is_some_and(|u| !unit(u))
            || a.realized_band.as_ref().is_some_and(|b| !band_ok(b))
            || a.ucb.is_some() != ucb
            || a.realized_band.is_some() != band
        {
            return Err(CertError::Invalid(
                "automated must agree with its test: coverage at most the test's, and ucb and realized_band null exactly where the test's are".into(),
            ));
        }
    }
    // Every option automated: the automated cases are the answered cases, so each block is its
    // test's own numbers.
    if auto.len() == c.options.len() {
        let same = |a: &Option<Automated>, coverage: f64, ucb: Option<f64>, band: Option<&Band>| {
            a.as_ref().is_none_or(|a| {
                a.coverage == coverage && a.ucb == ucb && a.realized_band.as_ref() == band
            })
        };
        // v1.4: the realized costs agree too (both absent before v1.4)
        let same_cost = |a: &Option<Automated>, rc: Option<Option<f64>>| {
            a.as_ref().is_none_or(|a| a.realized_cost == rc)
        };
        if !same(&c.automated, c.coverage, c.ucb, Some(&c.realized_band))
            || !same_cost(&c.automated, c.realized_cost)
            || !c
                .segments
                .iter()
                .all(|s| same(&s.automated, s.coverage, s.ucb, s.realized_band.as_ref()))
            || !c
                .segments
                .iter()
                .all(|s| same_cost(&s.automated, s.realized_cost))
        {
            return Err(CertError::Invalid(
                "automated must equal its test's coverage, ucb and realized_band when every option is automated".into(),
            ));
        }
    }
    Ok(())
}

/// v1.4's checks beyond the schema (spec v1.4 §2): `cost` and `pvalue` pair with `risk`; the cost
/// matrix is options x options with a zero diagonal, every entry in [0, c_max], `c_max` its largest
/// entry and above 0, and its off-diagonal entries not all equal; `realized_cost` is in [0, 1], null
/// for the error risks, for an inherited segment and wherever its test answered no case.
fn cost(c: &Certificate) -> Result<(), CertError> {
    let bad = |m: &str| Err(CertError::Invalid(m.to_string()));
    let cost = c.cost.clone().flatten();
    let pvalue = c.pvalue.clone().flatten();
    let want = match c.risk.as_str() {
        "selective_error" => Some("binomial"),
        "selective_cost" => Some("hoeffding_bentkus"),
        _ => None,
    };
    if cost.is_some() != (c.risk == "selective_cost") || pvalue.as_deref() != want {
        return bad("cost, pvalue and risk disagree");
    }
    if let Some(k) = &cost {
        let n = c.options.len();
        let m = &k.matrix;
        let all = || m.iter().flatten().copied();
        let ok = m.len() == n
            && m.iter().all(|r| r.len() == n)
            && (0..n).all(|i| m[i][i] == 0.0)
            && all().all(|x| (0.0..=k.c_max).contains(&x))
            && k.c_max > 0.0
            && all().fold(f64::NEG_INFINITY, f64::max) == k.c_max
            && k.unit.as_deref() != Some("");
        if !ok {
            return bad("cost.matrix must be options x options with a zero diagonal and entries in [0, c_max], c_max its largest entry and above 0");
        }
        let off: Vec<f64> = (0..n)
            .flat_map(|i| (0..n).filter(move |&j| j != i).map(move |j| (i, j)))
            .map(|(i, j)| m[i][j])
            .collect();
        if off.iter().all(|&x| x == off[0]) {
            return bad("a cost risk needs unequal off-diagonal costs; with equal costs it is selective_error");
        }
    }
    let unit = |x: f64| (0.0..=1.0).contains(&x);
    let auto = |a: &Option<Automated>| {
        a.as_ref()
            .map(|a| (a.realized_cost.flatten(), a.coverage))
            .unwrap_or((None, 0.0))
    };
    let mut tests = vec![(c.realized_cost.flatten(), c.coverage, true)];
    tests.extend(
        c.segments
            .iter()
            .map(|s| (s.realized_cost.flatten(), s.coverage, !s.inherited)),
    );
    let (rc, cov) = auto(&c.automated);
    tests.push((rc, cov, true));
    tests.extend(c.segments.iter().map(|s| {
        let (rc, cov) = auto(&s.automated);
        (rc, cov, !s.inherited)
    }));
    for (rc, coverage, own) in tests {
        let expect = cost.is_some() && own && coverage > 0.0;
        if rc.is_some() != expect || rc.is_some_and(|x| !unit(x)) {
            return bad("realized_cost must be in [0, 1], and null for the error risks, an inherited segment and a test that answered no case");
        }
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

/// Parse the spec's timestamp form, `YYYY-MM-DDTHH:MM:SSZ`, and nothing else.
pub fn timestamp(s: &str) -> Result<DateTime<Utc>, CertError> {
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

    /// v1 and v1.1 define only `temperature`, so a `dr` map in one of them gives no probabilities,
    /// though the certificate verifies as it always did.
    #[test]
    fn dr_maps_are_applied_in_v1_2_certificates_only() {
        let mut cert: Certificate = serde_json::from_value(valid()).unwrap();
        cert.calibration_map = CalibrationMap {
            kind: "dr".into(),
            params: [("a", 1.0), ("b0", 0.0), ("b1", 0.0)]
                .iter()
                .map(|(k, v)| (k.to_string(), *v))
                .collect(),
            label_budget: None,
        };
        let v = Verified {
            id: String::new(),
            cert,
            expires_at: Utc::now(),
        };
        assert!(v.probabilities(&[1.0, 0.0]).is_none() && v.confidence(&[1.0, 0.0]).is_none());
        let mut v12 = v.clone();
        v12.cert.spec = SPEC_V1_2.into();
        assert!(v12.confidence(&[1.0, 0.0]).unwrap() > 0.73);
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

    /// The same table as python/tests/test_ed25519.py: every small-order encoding is a key
    /// `verify_strict` refuses (the Python verifier must refuse the same ones).
    #[test]
    fn small_order_keys_are_weak() {
        let table = [
            "0100000000000000000000000000000000000000000000000000000000000000",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000080",
            "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
            "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
            "0100000000000000000000000000000000000000000000000000000000000080",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ];
        for h in table {
            let b: [u8; 32] = (0..32)
                .map(|i| u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap())
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();
            let k = VerifyingKey::from_bytes(&b).unwrap_or_else(|e| panic!("{h}: {e}"));
            assert!(k.is_weak(), "{h}");
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
