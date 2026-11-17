//! `decision-cert-inclusion.v1`: a tenant's transparency log, checked offline
//! (spec/decision-cert-inclusion.v1.md).
//!
//! A log is an RFC 9162 Merkle tree over JCS-encoded leaves ([`Leaf`], [`leaf_hash`]). Its
//! checkpoints are C2SP signed notes ([`parse_checkpoint`]) signed by the log's Ed25519 key and
//! cosigned by witnesses (`cosignature/v1`). A bundle carries a leaf, its audit path and a cosigned
//! checkpoint, and a consumer checks it against its log trust configuration ([`LogTrust`]) with
//! [`verify_bundle`], in the order of the spec's §10, refusing at the first failure with that
//! check's error name ([`ErrorName`]). [`verify_consistency`] checks a consistency proof document
//! between two checkpoints of one log, and [`apply_policy`] applies the configuration's `policy` to
//! a certificate with or without a bundle.
//!
//! A bundle does not replace the certificate's own verification: for a certificate leaf, verify the
//! bundle's certificate with [`crate::verify_for_tenant`] (or [`crate::verify`]) as well.
//!
//! The functions here take parsed JSON. A JSON document's I-JSON rules (no member named twice)
//! cannot be checked once it is parsed into a [`serde_json::Value`], so read documents from text
//! with [`parse_ijson`].

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// The `spec` of a bundle (§8).
pub const SPEC_BUNDLE: &str = "decision-cert-inclusion.v1";
/// The `spec` of a consistency proof document (§7.2).
pub const SPEC_CONSISTENCY: &str = "decision-cert-consistency.v1";
/// The `spec` of a log trust configuration (§9).
pub const SPEC_LOG_TRUST: &str = "decision-cert-log-trust.v1";
/// The five leaf kinds of v1 (§3.2).
pub const LEAF_KINDS: [&str; 5] = [
    "certificate",
    "ledger_entry",
    "keyset",
    "attestation",
    "audit_head",
];
/// The C2SP signed-note signature type of an Ed25519 log signature (§5.2).
pub const SIG_TYPE_ED25519: u8 = 0x01;
/// The C2SP signed-note signature type of an Ed25519 `cosignature/v1` (§5.3).
pub const SIG_TYPE_COSIGNATURE_V1: u8 = 0x04;
/// The latest cosignature timestamp v1 accepts, 9999-12-31T23:59:59Z (§5.3).
pub const MAX_COSIGNATURE_TIME: u64 = 253_402_300_799;
/// The most signature lines a checkpoint may carry (§5.1).
pub const MAX_SIGNATURE_LINES: usize = 100;
/// The most node hashes an audit or consistency path may carry (§6, §7).
pub const MAX_PATH: usize = 64;
/// The largest integer a document may carry, 2^53 − 1 (§0).
pub const MAX_INT: u64 = (1 << 53) - 1;

/// A 32-byte SHA-256 hash: a leaf hash, a node hash or a root.
pub type Hash = [u8; 32];

// ---------------------------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------------------------

/// The spec's error names (§14), one per check.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ErrorName {
    TrustForm,
    TrustCrossTenant,
    BundleForm,
    LeafForm,
    LeafMismatch,
    TenantMismatch,
    UnknownLog,
    CheckpointForm,
    OriginMismatch,
    BadProof,
    LogSignatureMissing,
    BadLogSignature,
    BadCosignature,
    TooFewCosignatures,
    ConsistencyForm,
    SizeRegression,
    SplitView,
    BadConsistencyProof,
    InclusionMissing,
}

impl ErrorName {
    /// Every error name, in §14's order.
    pub const ALL: [ErrorName; 19] = [
        Self::TrustForm,
        Self::TrustCrossTenant,
        Self::BundleForm,
        Self::LeafForm,
        Self::LeafMismatch,
        Self::TenantMismatch,
        Self::UnknownLog,
        Self::CheckpointForm,
        Self::OriginMismatch,
        Self::BadProof,
        Self::LogSignatureMissing,
        Self::BadLogSignature,
        Self::BadCosignature,
        Self::TooFewCosignatures,
        Self::ConsistencyForm,
        Self::SizeRegression,
        Self::SplitView,
        Self::BadConsistencyProof,
        Self::InclusionMissing,
    ];

    /// The name as §14 writes it, for example `bad_proof`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TrustForm => "trust_form",
            Self::TrustCrossTenant => "trust_cross_tenant",
            Self::BundleForm => "bundle_form",
            Self::LeafForm => "leaf_form",
            Self::LeafMismatch => "leaf_mismatch",
            Self::TenantMismatch => "tenant_mismatch",
            Self::UnknownLog => "unknown_log",
            Self::CheckpointForm => "checkpoint_form",
            Self::OriginMismatch => "origin_mismatch",
            Self::BadProof => "bad_proof",
            Self::LogSignatureMissing => "log_signature_missing",
            Self::BadLogSignature => "bad_log_signature",
            Self::BadCosignature => "bad_cosignature",
            Self::TooFewCosignatures => "too_few_cosignatures",
            Self::ConsistencyForm => "consistency_form",
            Self::SizeRegression => "size_regression",
            Self::SplitView => "split_view",
            Self::BadConsistencyProof => "bad_consistency_proof",
            Self::InclusionMissing => "inclusion_missing",
        }
    }
}

impl fmt::Display for ErrorName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A refusal: the failing check's error name (§14) and a message for people.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{name}: {detail}")]
pub struct InclusionError {
    pub name: ErrorName,
    pub detail: String,
}

impl InclusionError {
    pub fn new(name: ErrorName, detail: impl Into<String>) -> Self {
        Self {
            name,
            detail: detail.into(),
        }
    }
}

fn fail<T>(name: ErrorName, detail: impl Into<String>) -> Result<T, InclusionError> {
    Err(InclusionError::new(name, detail))
}

// ---------------------------------------------------------------------------------------------
// I-JSON
// ---------------------------------------------------------------------------------------------

/// Parse JSON text as I-JSON (§0): as [`serde_json::from_str`], and also refusing an object with
/// two members of one name, which a [`Value`] would silently collapse. Integers that are written
/// with a fraction or an exponent parse as floats, and the checks here refuse them where an integer
/// is due.
pub fn parse_ijson(text: &str) -> Result<Value, String> {
    serde_json::from_str::<Strict>(text)
        .map(|s| s.0)
        .map_err(|e| e.to_string())
}

struct Strict(Value);

impl<'de> serde::Deserialize<'de> for Strict {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(StrictVisitor)
    }
}

struct StrictVisitor;

impl<'de> serde::de::Visitor<'de> for StrictVisitor {
    type Value = Strict;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }
    fn visit_bool<E>(self, v: bool) -> Result<Strict, E> {
        Ok(Strict(Value::Bool(v)))
    }
    fn visit_i64<E>(self, v: i64) -> Result<Strict, E> {
        Ok(Strict(Value::from(v)))
    }
    fn visit_u64<E>(self, v: u64) -> Result<Strict, E> {
        Ok(Strict(Value::from(v)))
    }
    fn visit_f64<E>(self, v: f64) -> Result<Strict, E> {
        Ok(Strict(
            serde_json::Number::from_f64(v).map_or(Value::Null, Value::Number),
        ))
    }
    fn visit_str<E>(self, v: &str) -> Result<Strict, E> {
        Ok(Strict(Value::String(v.to_string())))
    }
    fn visit_string<E>(self, v: String) -> Result<Strict, E> {
        Ok(Strict(Value::String(v)))
    }
    fn visit_unit<E>(self) -> Result<Strict, E> {
        Ok(Strict(Value::Null))
    }
    fn visit_none<E>(self) -> Result<Strict, E> {
        Ok(Strict(Value::Null))
    }
    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Strict, A::Error> {
        let mut out = Vec::new();
        while let Some(Strict(v)) = seq.next_element()? {
            out.push(v);
        }
        Ok(Strict(Value::Array(out)))
    }
    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Strict, A::Error> {
        let mut out = Map::new();
        while let Some(k) = map.next_key::<String>()? {
            if out.contains_key(&k) {
                return Err(serde::de::Error::custom(format!(
                    "member {k:?} appears twice in one object (not I-JSON)"
                )));
            }
            let Strict(v) = map.next_value()?;
            out.insert(k, v);
        }
        Ok(Strict(Value::Object(out)))
    }
}

// ---------------------------------------------------------------------------------------------
// The tree (§4, §6, §7.1): RFC 9162 §2.1
// ---------------------------------------------------------------------------------------------

/// RFC 9162 §2.1.1's leaf hash of raw leaf bytes: SHA-256(0x00 || data). [`leaf_hash`] applies it
/// to a leaf's JCS bytes.
pub fn hash_leaf_bytes(data: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(data);
    h.finalize().into()
}

/// An inner node: SHA-256(0x01 || left || right).
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// The largest power of two smaller than `n` (n ≥ 2).
fn split_point(n: usize) -> usize {
    let mut k = 1;
    while k << 1 < n {
        k <<= 1;
    }
    k
}

/// RFC 9162 §2.1.1's MTH over leaf hashes; None for no leaves (the spec defines no empty tree).
pub fn root_hash(leaf_hashes: &[Hash]) -> Option<Hash> {
    match leaf_hashes.len() {
        0 => None,
        1 => Some(leaf_hashes[0]),
        n => {
            let k = split_point(n);
            Some(node_hash(
                &root_hash(&leaf_hashes[..k])?,
                &root_hash(&leaf_hashes[k..])?,
            ))
        }
    }
}

/// RFC 9162 §2.1.3.1's audit path for the leaf at `index` in the tree over `leaf_hashes`, from the
/// leaf's sibling upward; None when `index` is out of range. A log computes these; a verifier only
/// checks them ([`verify_inclusion_path`]).
pub fn audit_path(leaf_hashes: &[Hash], index: usize) -> Option<Vec<Hash>> {
    let n = leaf_hashes.len();
    if index >= n {
        return None;
    }
    if n == 1 {
        return Some(Vec::new());
    }
    let k = split_point(n);
    let (mut path, other) = if index < k {
        (
            audit_path(&leaf_hashes[..k], index)?,
            root_hash(&leaf_hashes[k..])?,
        )
    } else {
        (
            audit_path(&leaf_hashes[k..], index - k)?,
            root_hash(&leaf_hashes[..k])?,
        )
    };
    path.push(other);
    Some(path)
}

/// RFC 9162 §2.1.4.1's consistency path from the tree of the first `older` leaves to the tree over
/// all of `leaf_hashes`; None unless 1 ≤ `older` ≤ the number of leaves.
pub fn consistency_path(leaf_hashes: &[Hash], older: usize) -> Option<Vec<Hash>> {
    fn sub(m: usize, d: &[Hash], whole: bool) -> Option<Vec<Hash>> {
        let n = d.len();
        if m == n {
            return Some(if whole {
                Vec::new()
            } else {
                vec![root_hash(d)?]
            });
        }
        let k = split_point(n);
        let (mut path, other) = if m <= k {
            (sub(m, &d[..k], whole)?, root_hash(&d[k..])?)
        } else {
            (sub(m - k, &d[k..], false)?, root_hash(&d[..k])?)
        };
        path.push(other);
        Some(path)
    }
    if older == 0 || older > leaf_hashes.len() {
        return None;
    }
    sub(older, leaf_hashes, true)
}

/// RFC 9162 §2.1.3.2 (the spec's §6): does `path` lead from `leaf_hash` at `index` to `root` in a
/// tree of `size` leaves?
pub fn verify_inclusion_path(
    index: u64,
    size: u64,
    leaf_hash: &Hash,
    path: &[Hash],
    root: &Hash,
) -> bool {
    if index >= size {
        return false;
    }
    let (mut fnode, mut snode, mut r) = (index, size - 1, *leaf_hash);
    for p in path {
        if snode == 0 {
            return false;
        }
        if fnode & 1 == 1 || fnode == snode {
            r = node_hash(p, &r);
            if fnode & 1 == 0 {
                while fnode & 1 == 0 && fnode != 0 {
                    fnode >>= 1;
                    snode >>= 1;
                }
            }
        } else {
            r = node_hash(&r, p);
        }
        fnode >>= 1;
        snode >>= 1;
    }
    snode == 0 && r == *root
}

/// RFC 9162 §2.1.4.2 (the spec's §7.1): is the tree of `older` leaves with `older_root` a prefix of
/// the tree of `newer` leaves with `newer_root`, by `path`? For `older` = `newer`, only an empty
/// path between equal roots; `older` = 0 or `older` > `newer` never.
pub fn verify_consistency_path(
    older: u64,
    newer: u64,
    older_root: &Hash,
    newer_root: &Hash,
    path: &[Hash],
) -> bool {
    if older == 0 || older > newer {
        return false;
    }
    if older == newer {
        return path.is_empty() && older_root == newer_root;
    }
    if path.is_empty() {
        return false;
    }
    let mut nodes: Vec<Hash> = Vec::with_capacity(path.len() + 1);
    if older.is_power_of_two() {
        nodes.push(*older_root);
    }
    nodes.extend_from_slice(path);
    let (mut fnode, mut snode) = (older - 1, newer - 1);
    if fnode & 1 == 1 {
        while fnode & 1 == 1 {
            fnode >>= 1;
            snode >>= 1;
        }
    }
    let (mut fr, mut sr) = (nodes[0], nodes[0]);
    for c in &nodes[1..] {
        if snode == 0 {
            return false;
        }
        if fnode & 1 == 1 || fnode == snode {
            fr = node_hash(c, &fr);
            sr = node_hash(c, &sr);
            if fnode & 1 == 0 {
                while fnode & 1 == 0 && fnode != 0 {
                    fnode >>= 1;
                    snode >>= 1;
                }
            }
        } else {
            sr = node_hash(&sr, c);
        }
        fnode >>= 1;
        snode >>= 1;
    }
    fr == *older_root && sr == *newer_root && snode == 0
}

// ---------------------------------------------------------------------------------------------
// Leaves (§3)
// ---------------------------------------------------------------------------------------------

/// A leaf (§3) whose form has been checked: one of [`LEAF_KINDS`] with exactly its members, each in
/// its form.
#[derive(Clone, Debug, PartialEq)]
pub struct Leaf(Map<String, Value>);

impl Leaf {
    /// Check a leaf's form (§3), refusing it as `leaf_form`.
    pub fn from_json(v: &Value) -> Result<Leaf, InclusionError> {
        let bad = |m: String| fail(ErrorName::LeafForm, m);
        let Some(obj) = v.as_object() else {
            return bad("a leaf is a JSON object".into());
        };
        let Some(kind) = obj.get("kind").and_then(Value::as_str) else {
            return bad("a leaf needs a string kind".into());
        };
        type Check = fn(&Value) -> bool;
        let members: &[(&str, Check)] = match kind {
            "certificate" => &[
                ("certificate_id", |v| str_is(v, doc_hash_ok)),
                ("signer_key_id", |v| str_is(v, crate::key_id_form)),
                ("spec", |v| str_is(v, |s| crate::SPECS.contains(&s))),
                ("fitted_at", |v| str_is(v, time_ok)),
                ("tenant", |v| str_is(v, crate::tenant_ok)),
            ],
            "ledger_entry" => &[
                ("ledger_id", |v| {
                    str_is(v, |s| prefixed_hex(s, "ledger:", 32))
                }),
                ("seq", |v| uint(v).is_some()),
                ("entry", |v| str_is(v, doc_hash_ok)),
            ],
            "keyset" => &[
                ("keyset_id", |v| {
                    str_is(v, |s| prefixed_hex(s, "keyset:", 32))
                }),
                ("seq", |v| uint(v).is_some()),
                ("keyset", |v| str_is(v, doc_hash_ok)),
            ],
            "attestation" => &[
                ("attestation", |v| str_is(v, doc_hash_ok)),
                ("certificate_id", |v| str_is(v, doc_hash_ok)),
            ],
            "audit_head" => &[
                ("tenant", |v| str_is(v, crate::tenant_ok)),
                ("chain", |v| str_is(v, crate::tenant_ok)),
                ("seq", |v| uint(v).is_some_and(|n| n >= 1)),
                ("digest", |v| str_is(v, doc_hash_ok)),
                ("observed_at", |v| str_is(v, time_ok)),
            ],
            other => return bad(format!("unknown leaf kind {other:?}")),
        };
        // `tenant` is a certificate leaf's member exactly for a v1.5 certificate (§3.2).
        let v15 = kind == "certificate"
            && obj.get("spec").and_then(Value::as_str) == Some(crate::SPEC_V1_5);
        let required = |name: &str| !(kind == "certificate" && name == "tenant") || v15;
        for k in obj.keys() {
            if k != "kind" && !members.iter().any(|(m, _)| m == k) {
                return bad(format!("unknown member {k:?} in a {kind} leaf"));
            }
        }
        for (name, ok) in members {
            match obj.get(*name) {
                None if required(name) => {
                    return bad(format!("a {kind} leaf needs {name:?}"));
                }
                None => {}
                Some(_) if !required(name) => {
                    return bad(format!(
                        "a certificate leaf carries tenant only for a {} certificate",
                        crate::SPEC_V1_5
                    ));
                }
                Some(v) if !ok(v) => {
                    return bad(format!("{name:?} of a {kind} leaf is out of its form"));
                }
                Some(_) => {}
            }
        }
        Ok(Leaf(obj.clone()))
    }

    /// The leaf's kind, one of [`LEAF_KINDS`].
    pub fn kind(&self) -> &str {
        self.0["kind"].as_str().unwrap_or_default()
    }

    /// A member's string value (None for an absent or non-string member).
    pub fn get_str(&self, member: &str) -> Option<&str> {
        self.0.get(member).and_then(Value::as_str)
    }

    /// The leaf as JSON.
    pub fn to_json(&self) -> Value {
        Value::Object(self.0.clone())
    }

    /// The leaf's canonical bytes, its JCS bytes (§3.1).
    pub fn canonical(&self) -> Vec<u8> {
        // every member is a string or an integer at most 2^53 − 1: JCS cannot fail
        crate::canonical(&self.to_json()).unwrap_or_default()
    }
}

/// The leaf hash of a leaf (§4): SHA-256(0x00 || JCS(leaf)).
pub fn leaf_hash(leaf: &Leaf) -> Hash {
    hash_leaf_bytes(&leaf.canonical())
}

fn str_is(v: &Value, f: impl Fn(&str) -> bool) -> bool {
    v.as_str().is_some_and(f)
}

/// An integer written as one, 0 to 2^53 − 1 (§0).
fn uint(v: &Value) -> Option<u64> {
    v.as_u64().filter(|&n| n <= MAX_INT)
}

fn prefixed_hex(s: &str, prefix: &str, len: usize) -> bool {
    s.strip_prefix(prefix)
        .is_some_and(|h| h.len() == len && crate::lower_hex(h))
}

fn doc_hash_ok(s: &str) -> bool {
    prefixed_hex(s, "sha256:", 64)
}

/// §0's time: `YYYY-MM-DDTHH:MM:SSZ` naming a real date, seconds 00 to 59.
fn time_ok(s: &str) -> bool {
    crate::timestamp(s).is_ok() && s.get(17..19).is_some_and(|ss| ss <= "59")
}

/// The latest POSIX second [`time_of`] writes, 262142-12-31T23:59:59Z; after it, the empty string.
const LAST_TIME_OF: u64 = 8_210_266_876_799;

/// §0's time of POSIX seconds. A counted cosignature time is at most [`MAX_COSIGNATURE_TIME`], so
/// four digits of year; for the public fields' larger values, the year is written with its sign
/// (`+10000-01-01T00:00:00Z`) up to [`LAST_TIME_OF`], and a later time is the empty string.
fn time_of(secs: u64) -> String {
    if secs > LAST_TIME_OF {
        return String::new();
    }
    // Days since 1970-01-01 to a proleptic Gregorian date (H. Hinnant's civil_from_days).
    let (days, rem) = (secs / 86_400, secs % 86_400);
    let z = days + 719_468;
    let (era, doe) = (z / 146_097, z % 146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    let year = if year <= 9_999 {
        format!("{year:04}")
    } else {
        format!("+{year}")
    };
    format!(
        "{year}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3_600,
        rem / 60 % 60,
        rem % 60
    )
}

// ---------------------------------------------------------------------------------------------
// Checkpoints (§5)
// ---------------------------------------------------------------------------------------------

/// One signature line of a signed note: the key name, the 4-byte C2SP key ID, and the bytes after
/// the key ID (a log signature, or a cosignature's timestamp and signature).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignatureLine {
    pub key_name: String,
    pub key_hash: [u8; 4],
    pub value: Vec<u8>,
}

/// A checkpoint parsed from its signed note (§5.1). Nothing in it is trusted yet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub origin: String,
    pub tree_size: u64,
    pub root_hash: Hash,
    /// The note text: the three lines, each with its newline. The log signs these bytes.
    pub note_text: String,
    pub signatures: Vec<SignatureLine>,
}

/// Parse a checkpoint's full signed-note text (§5.1), without trusting it: refused as
/// `checkpoint_form` when it breaks any rule of §5.1, two signature lines from one key included.
pub fn parse_checkpoint(note: &str) -> Result<Checkpoint, InclusionError> {
    let bad = |m: &str| fail(ErrorName::CheckpointForm, m.to_string());
    if note.chars().any(|c| c.is_control() && c != '\n') {
        return bad("a checkpoint has no control character other than a newline");
    }
    let Some(body) = note.strip_suffix('\n') else {
        return bad("a checkpoint ends with a newline");
    };
    let lines: Vec<&str> = body.split('\n').collect();
    if lines.len() < 5 || !lines[3].is_empty() {
        return bad(
            "a checkpoint is three text lines, an empty line, then one or more signature lines",
        );
    }
    let (origin, size, root) = (lines[0], lines[1], lines[2]);
    if origin.is_empty() {
        return bad("the origin line is empty");
    }
    let tree_size =
        (size.len() <= 20 && size.bytes().all(|b| b.is_ascii_digit()) && !size.starts_with('0'))
            .then(|| size.parse::<u64>().ok())
            .flatten()
            .filter(|&n| n >= 1);
    let Some(tree_size) = tree_size else {
        return bad("the tree size is 1 to 2^64 − 1 in decimal, without leading zeros");
    };
    let Some(root_hash) = b64_hash(root) else {
        return bad("the root hash is 32 bytes in canonical base64");
    };
    let sig_lines = &lines[4..];
    if sig_lines.len() > MAX_SIGNATURE_LINES {
        return bad("a checkpoint has at most 100 signature lines");
    }
    let mut signatures = Vec::with_capacity(sig_lines.len());
    let mut seen = BTreeSet::new();
    for line in sig_lines {
        let Some((name, value)) = line
            .strip_prefix("\u{2014} ")
            .and_then(|r| r.split_once(' '))
        else {
            return bad(
                "a signature line is an em dash, a space, a key name, a space and a base64 value",
            );
        };
        if !key_name_ok(name) {
            return bad("a key name is 1 to 255 printable ASCII characters other than +");
        }
        let Some(bytes) = b64(value).filter(|b| b.len() >= 5) else {
            return bad("a signature value is canonical base64 of at least 5 bytes");
        };
        let key_hash: [u8; 4] = [bytes[0], bytes[1], bytes[2], bytes[3]];
        if !seen.insert((name, key_hash)) {
            return bad("two signature lines from one key (the same key name and key ID)");
        }
        signatures.push(SignatureLine {
            key_name: name.to_string(),
            key_hash,
            value: bytes[4..].to_vec(),
        });
    }
    Ok(Checkpoint {
        origin: origin.to_string(),
        tree_size,
        root_hash,
        note_text: format!("{origin}\n{size}\n{root}\n"),
        signatures,
    })
}

/// A C2SP key name or cosigner name: 1 to 255 printable ASCII characters other than `+` (§5.1).
fn key_name_ok(s: &str) -> bool {
    (1..=255).contains(&s.len()) && s.bytes().all(|b| (0x21..=0x7e).contains(&b) && b != b'+')
}

/// Canonical standard base64 (RFC 4648 §4 with padding, §3.5): decodes and re-encodes to itself.
fn b64(s: &str) -> Option<Vec<u8>> {
    STANDARD.decode(s).ok().filter(|b| STANDARD.encode(b) == s)
}

fn b64_hash(s: &str) -> Option<Hash> {
    b64(s).and_then(|b| b.try_into().ok())
}

/// The C2SP key ID (§5.2, §5.3): the first 4 bytes of SHA-256(key name || 0x0A || type || public key).
pub fn c2sp_key_hash(key_name: &str, sig_type: u8, key: &VerifyingKey) -> [u8; 4] {
    let mut h = Sha256::new();
    h.update(key_name.as_bytes());
    h.update([0x0a, sig_type]);
    h.update(key.as_bytes());
    let d = h.finalize();
    [d[0], d[1], d[2], d[3]]
}

/// The message a `cosignature/v1` signs (§5.3): `"cosignature/v1\ntime <timestamp>\n"` then the
/// checkpoint's note text.
pub fn cosignature_message(note_text: &str, timestamp: u64) -> Vec<u8> {
    format!("cosignature/v1\ntime {timestamp}\n{note_text}").into_bytes()
}

fn verify_sig(key: &VerifyingKey, msg: &[u8], sig: &[u8]) -> bool {
    Signature::from_slice(sig).is_ok_and(|s| key.verify_strict(msg, &s).is_ok())
}

// ---------------------------------------------------------------------------------------------
// The log trust configuration (§9)
// ---------------------------------------------------------------------------------------------

/// The consumer's `policy` for a certificate without a bundle (§11).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Policy {
    Off,
    Warn,
    Refuse,
}

impl Policy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Warn => "warn",
            Self::Refuse => "refuse",
        }
    }
}

/// A trusted log: its id, its C2SP key name, and its key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedLog {
    pub log_id: String,
    pub key_name: String,
    /// The key's id in this repository's form, `ed25519:<16 hex>`.
    pub key_id: String,
    pub key: VerifyingKey,
    /// The time of the log's first entry (§9), if the configuration gives it: a certificate whose
    /// `fitted_at` is earlier is marked backfilled (§10, "Backfilled").
    pub started_at: Option<String>,
}

/// A trusted witness: its C2SP cosigner name, and its key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedWitness {
    pub name: String,
    pub key_id: String,
    pub key: VerifyingKey,
}

/// One tenant's log trust configuration (§9), checked as a whole by [`LogTrust::from_json`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogTrust {
    tenant: String,
    logs: Vec<TrustedLog>,
    witnesses: Vec<TrustedWitness>,
    m: usize,
    policy: Policy,
}

impl LogTrust {
    /// Read and check a log trust configuration (§9), refusing it as `trust_form`.
    pub fn from_json(v: &Value) -> Result<LogTrust, InclusionError> {
        let bad = |m: &str| fail(ErrorName::TrustForm, m.to_string());
        let Some(obj) = v.as_object() else {
            return bad("the log trust configuration is a JSON object");
        };
        if !only(
            obj,
            &["spec", "tenant", "logs", "witnesses"],
            &["m", "policy"],
        ) {
            return bad("the log trust configuration has exactly spec, tenant, logs, witnesses and optionally m and policy");
        }
        if obj["spec"] != SPEC_LOG_TRUST {
            return bad("spec is not decision-cert-log-trust.v1");
        }
        let Some(tenant) = obj["tenant"].as_str().filter(|t| crate::tenant_ok(t)) else {
            return bad("tenant is 1 to 128 characters of A-Z a-z 0-9 . _ : -");
        };
        let (Some(logs_in), Some(witnesses_in)) =
            (obj["logs"].as_array(), obj["witnesses"].as_array())
        else {
            return bad("logs and witnesses are arrays");
        };
        if logs_in.is_empty() || witnesses_in.is_empty() {
            return bad("logs and witnesses each have at least one entry");
        }
        let mut logs = Vec::new();
        for l in logs_in {
            let e = l
                .as_object()
                .filter(|e| only(e, &["log_id", "key_name", "key_id", "key"], &["started_at"]));
            let Some(e) = e else {
                return bad(
                    "a log entry has exactly log_id, key_name, key_id, key and optionally started_at",
                );
            };
            let Some(log_id) = e["log_id"].as_str().filter(|s| prefixed_hex(s, "log:", 32)) else {
                return bad("a log_id is log: and 32 lowercase hex characters");
            };
            let Some(key_name) = e["key_name"].as_str().filter(|s| key_name_ok(s)) else {
                return bad("a key_name is 1 to 255 printable ASCII characters other than +");
            };
            let started_at = match e.get("started_at") {
                None => None,
                Some(v) => match v.as_str().filter(|s| time_ok(s)) {
                    Some(s) => Some(s.to_string()),
                    None => return bad("started_at is a time YYYY-MM-DDTHH:MM:SSZ"),
                },
            };
            let (key_id, key) = trusted_key(e)?;
            logs.push(TrustedLog {
                log_id: log_id.to_string(),
                key_name: key_name.to_string(),
                key_id,
                key,
                started_at,
            });
        }
        let mut witnesses = Vec::new();
        for w in witnesses_in {
            let e = w
                .as_object()
                .filter(|e| only(e, &["name", "key_id", "key"], &[]));
            let Some(e) = e else {
                return bad("a witness entry has exactly name, key_id and key");
            };
            let Some(name) = e["name"].as_str().filter(|s| key_name_ok(s)) else {
                return bad("a witness name is 1 to 255 printable ASCII characters other than +");
            };
            let (key_id, key) = trusted_key(e)?;
            witnesses.push(TrustedWitness {
                name: name.to_string(),
                key_id,
                key,
            });
        }
        let m = match obj.get("m") {
            None => 1,
            Some(v) => match uint(v) {
                Some(n) if n >= 1 && n <= witnesses.len() as u64 => n as usize,
                _ => return bad("m is an integer from 1 to the number of witnesses"),
            },
        };
        let policy = match obj.get("policy").map(Value::as_str) {
            None => Policy::Warn,
            Some(Some("off")) => Policy::Off,
            Some(Some("warn")) => Policy::Warn,
            Some(Some("refuse")) => Policy::Refuse,
            Some(_) => return bad("policy is off, warn or refuse"),
        };
        let distinct = |xs: Vec<&[u8]>| xs.iter().collect::<BTreeSet<_>>().len() == xs.len();
        if !distinct(logs.iter().map(|l| l.log_id.as_bytes()).collect())
            || !distinct(logs.iter().map(|l| l.key.as_bytes().as_slice()).collect())
        {
            return bad("two logs share a log_id or a key");
        }
        if !distinct(witnesses.iter().map(|w| w.name.as_bytes()).collect())
            || !distinct(
                witnesses
                    .iter()
                    .map(|w| w.key.as_bytes().as_slice())
                    .collect(),
            )
        {
            return bad("two witnesses share a name or a key");
        }
        if witnesses
            .iter()
            .any(|w| logs.iter().any(|l| l.key == w.key))
        {
            return bad("a witness's key is also a log's key");
        }
        Ok(LogTrust {
            tenant: tenant.to_string(),
            logs,
            witnesses,
            m,
            policy,
        })
    }

    /// The expected tenant.
    pub fn tenant(&self) -> &str {
        &self.tenant
    }
    pub fn logs(&self) -> &[TrustedLog] {
        &self.logs
    }
    pub fn witnesses(&self) -> &[TrustedWitness] {
        &self.witnesses
    }
    /// The number of distinct trusted witnesses a checkpoint needs (default 1).
    pub fn m(&self) -> usize {
        self.m
    }
    /// The policy for a certificate without a bundle (default `warn`).
    pub fn policy(&self) -> Policy {
        self.policy
    }

    fn log(&self, log_id: &str) -> Result<&TrustedLog, InclusionError> {
        self.logs
            .iter()
            .find(|l| l.log_id == log_id)
            .ok_or_else(|| {
                InclusionError::new(
                    ErrorName::UnknownLog,
                    format!("{log_id} is not one of tenant {}'s logs", self.tenant),
                )
            })
    }
}

/// The required members, and optional ones, and nothing else.
fn only(obj: &Map<String, Value>, required: &[&str], optional: &[&str]) -> bool {
    required.iter().all(|k| obj.contains_key(*k))
        && obj
            .keys()
            .all(|k| required.contains(&k.as_str()) || optional.contains(&k.as_str()))
}

/// An entry's `key` (base64url, a valid Ed25519 key under strict verification) and its `key_id`,
/// which must be the key's id.
fn trusted_key(e: &Map<String, Value>) -> Result<(String, VerifyingKey), InclusionError> {
    let key = e["key"]
        .as_str()
        .and_then(|s| {
            URL_SAFE_NO_PAD
                .decode(s)
                .ok()
                .filter(|b| URL_SAFE_NO_PAD.encode(b) == s)
        })
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .and_then(|b| VerifyingKey::from_bytes(&b).ok())
        .filter(|k| !k.is_weak());
    let Some(key) = key else {
        return fail(
            ErrorName::TrustForm,
            "a key is a valid Ed25519 public key in base64url (43 characters), not of small order",
        );
    };
    let id = crate::key_id(&key);
    if e["key_id"].as_str() != Some(id.as_str()) {
        return fail(
            ErrorName::TrustForm,
            format!("key_id is not the key id of its key ({id})"),
        );
    }
    Ok((id, key))
}

/// Several tenants' configurations held together (§2, §9): refused as `trust_cross_tenant` when one
/// `log_id`, or one log key, appears under two tenants. Witnesses may serve several tenants.
pub fn check_tenants(configs: &[LogTrust]) -> Result<(), InclusionError> {
    let mut ids: BTreeMap<&str, &str> = BTreeMap::new();
    let mut keys: BTreeMap<&[u8; 32], &str> = BTreeMap::new();
    for c in configs {
        for l in &c.logs {
            for owner in [
                *ids.entry(&l.log_id).or_insert(&c.tenant),
                *keys.entry(l.key.as_bytes()).or_insert(&c.tenant),
            ] {
                if owner != c.tenant {
                    return fail(
                        ErrorName::TrustCrossTenant,
                        format!(
                            "log {} (or its key) appears under tenants {owner} and {}",
                            l.log_id, c.tenant
                        ),
                    );
                }
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// The bundle (§8) and the consumer's checks (§10)
// ---------------------------------------------------------------------------------------------

/// A witness counted for a checkpoint: a trusted witness whose cosignature verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CountedWitness {
    pub name: String,
    pub key_id: String,
    /// The cosignature time, POSIX seconds.
    pub time: u64,
}

/// What a verified bundle shows (§10, "The verdict").
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InclusionVerdict {
    pub log_id: String,
    pub tree_size: u64,
    pub root_hash: Hash,
    pub leaf_index: u64,
    pub kind: String,
    /// For a certificate leaf, the certificate's id.
    pub certificate_id: Option<String>,
    /// For a certificate leaf, the bases on which it is marked backfilled, in this order: `bundle`
    /// (the bundle's `backfilled`, the bundler's statement) and `started_at` (its `fitted_at` is
    /// earlier than the configuration's `started_at` for the log). Empty when it is not marked.
    pub backfilled_by: Option<Vec<&'static str>>,
    /// The counted witnesses, by cosignature time, then name.
    pub witnesses: Vec<CountedWitness>,
    /// The `m`-th earliest counted cosignature time, POSIX seconds.
    pub t_proven: u64,
}

impl InclusionVerdict {
    /// `t_proven` as a time (§0).
    pub fn t_proven_time(&self) -> String {
        time_of(self.t_proven)
    }

    /// For a certificate leaf, whether it is marked backfilled (§10, "Backfilled"): a mark, never a
    /// reason to refuse.
    pub fn backfilled(&self) -> Option<bool> {
        self.backfilled_by.as_ref().map(|by| !by.is_empty())
    }

    /// The verdict as JSON: hashes in base64, times in §0's form.
    pub fn to_json(&self) -> Value {
        let mut v = serde_json::json!({
            "log_id": self.log_id,
            "tree_size": self.tree_size,
            "root_hash": STANDARD.encode(self.root_hash),
            "leaf_index": self.leaf_index,
            "kind": self.kind,
            "witnesses": self.witnesses.iter().map(|w| serde_json::json!({
                "name": w.name,
                "key_id": w.key_id,
                "time": time_of(w.time),
            })).collect::<Vec<_>>(),
            "t_proven": self.t_proven_time(),
        });
        if let Some(id) = &self.certificate_id {
            v["certificate_id"] = Value::String(id.clone());
        }
        if let Some(by) = &self.backfilled_by {
            v["backfilled"] = Value::Bool(!by.is_empty());
            v["backfilled_by"] = serde_json::json!(by);
        }
        v
    }
}

/// Check a bundle against the expected tenant's configuration, in §10's order (checks 2 to 12; check
/// 1 is [`LogTrust::from_json`]), refusing at the first failure with that check's error name.
///
/// For a certificate leaf this does not verify the certificate itself: verify it under its own spec
/// as well ([`crate::verify_for_tenant`] with `trust.tenant()`).
pub fn verify_bundle(bundle: &Value, trust: &LogTrust) -> Result<InclusionVerdict, InclusionError> {
    // 2. the bundle's form
    let bad = |m: &str| fail(ErrorName::BundleForm, m.to_string());
    let Some(obj) = bundle.as_object() else {
        return bad("a bundle is a JSON object");
    };
    let members = [
        "spec",
        "log_id",
        "leaf_index",
        "leaf",
        "proof",
        "checkpoint",
    ];
    if !only(obj, &members, &["certificate", "backfilled"]) {
        return bad("a bundle has exactly spec, log_id, leaf_index, leaf, proof, checkpoint, and certificate (and optionally backfilled) for a certificate leaf");
    }
    if obj["spec"] != SPEC_BUNDLE {
        return bad("spec is not decision-cert-inclusion.v1");
    }
    let Some(log_id) = obj["log_id"]
        .as_str()
        .filter(|s| prefixed_hex(s, "log:", 32))
    else {
        return bad("log_id is log: and 32 lowercase hex characters");
    };
    let Some(leaf_index) = uint(&obj["leaf_index"]) else {
        return bad("leaf_index is an integer from 0 to 2^53 − 1");
    };
    let Some(leaf_value) = obj["leaf"].as_object() else {
        return bad("leaf is a JSON object");
    };
    let Some(proof) = path_of(&obj["proof"]) else {
        return bad("proof is an array of at most 64 base64 32-byte hashes");
    };
    let Some(checkpoint_text) = obj["checkpoint"].as_str() else {
        return bad("checkpoint is a string, the checkpoint's signed note");
    };
    let is_cert = leaf_value.get("kind").and_then(Value::as_str) == Some("certificate");
    let certificate = match (is_cert, obj.get("certificate")) {
        (true, Some(c)) if c.is_object() => Some(c),
        (false, None) => None,
        _ => {
            return bad(
                "certificate is a JSON object, present if and only if leaf.kind is certificate",
            )
        }
    };
    let bundle_backfilled = match obj.get("backfilled") {
        None => false,
        Some(Value::Bool(true)) if is_cert => true,
        _ => return bad("backfilled is true, and present only beside a certificate leaf"),
    };

    // 3. the leaf's form
    let leaf = Leaf::from_json(&obj["leaf"])?;

    // 4. a certificate leaf matches its certificate
    let mut certificate_id = None;
    if let Some(cert) = certificate {
        let id = crate::certificate_id(cert)
            .map_err(|e| InclusionError::new(ErrorName::LeafMismatch, e.to_string()))?;
        if leaf.get_str("certificate_id") != Some(id.as_str()) {
            return fail(
                ErrorName::LeafMismatch,
                format!("the leaf's certificate_id is not the certificate's id {id}"),
            );
        }
        for m in ["signer_key_id", "spec", "fitted_at", "tenant"] {
            if leaf.0.get(m) != cert.get(m) {
                return fail(
                    ErrorName::LeafMismatch,
                    format!("the leaf's {m} is not the certificate's"),
                );
            }
        }
        certificate_id = Some(id);
    }

    // 5. the leaf's tenant (a v1.5 certificate leaf's, an audit_head's) is the expected tenant
    if let Some(t) = leaf.get_str("tenant") {
        if t != trust.tenant {
            return fail(
                ErrorName::TenantMismatch,
                format!("the leaf is for tenant {t}, not {}", trust.tenant),
            );
        }
    }

    // 6. a log of the expected tenant
    let log = trust.log(log_id)?;

    // 7, 8. the checkpoint's form and origin
    let cp = parse_checkpoint(checkpoint_text)?;
    if cp.origin != log_id {
        return fail(
            ErrorName::OriginMismatch,
            format!("the checkpoint's origin is not {log_id}"),
        );
    }

    // 9. the audit path
    if !verify_inclusion_path(
        leaf_index,
        cp.tree_size,
        &leaf_hash(&leaf),
        &proof,
        &cp.root_hash,
    ) {
        return fail(
            ErrorName::BadProof,
            format!(
                "the audit path does not lead from the leaf at {leaf_index} to the root of the tree of {} leaves",
                cp.tree_size
            ),
        );
    }

    // 10. the log's signature
    check_log_signature(&cp, log)?;

    // 11, 12. the witnesses' cosignatures
    let witnesses = cosigners(&cp, trust)?;
    if witnesses.len() < trust.m {
        return fail(
            ErrorName::TooFewCosignatures,
            format!(
                "{} trusted witnesses cosigned, the configuration needs {}",
                witnesses.len(),
                trust.m
            ),
        );
    }
    let t_proven = witnesses[trust.m - 1].time;

    // the backfilled mark (§10, "Backfilled"): reported, never refused
    let backfilled_by = certificate_id.as_ref().map(|_| {
        let mut by = Vec::new();
        if bundle_backfilled {
            by.push("bundle");
        }
        if let (Some(start), Some(fitted)) = (&log.started_at, leaf.get_str("fitted_at")) {
            if fitted < start.as_str() {
                by.push("started_at");
            }
        }
        by
    });
    Ok(InclusionVerdict {
        log_id: log_id.to_string(),
        tree_size: cp.tree_size,
        root_hash: cp.root_hash,
        leaf_index,
        kind: leaf.kind().to_string(),
        certificate_id,
        backfilled_by,
        witnesses,
        t_proven,
    })
}

/// A JSON array of at most 64 canonical base64 32-byte hashes.
fn path_of(v: &Value) -> Option<Vec<Hash>> {
    let a = v.as_array().filter(|a| a.len() <= MAX_PATH)?;
    a.iter().map(|h| h.as_str().and_then(b64_hash)).collect()
}

/// Check 10 (§5.2, §5.4): a line matches the log's key, and it verifies.
fn check_log_signature(cp: &Checkpoint, log: &TrustedLog) -> Result<(), InclusionError> {
    let want = c2sp_key_hash(&log.key_name, SIG_TYPE_ED25519, &log.key);
    let mut matched = false;
    for s in &cp.signatures {
        if s.key_name == log.key_name && s.key_hash == want {
            matched = true;
            if s.value.len() != 64 || !verify_sig(&log.key, cp.note_text.as_bytes(), &s.value) {
                return fail(
                    ErrorName::BadLogSignature,
                    format!("the log signature of {} does not verify", log.log_id),
                );
            }
        }
    }
    if !matched {
        return fail(
            ErrorName::LogSignatureMissing,
            format!("no signature line matches the key of log {}", log.log_id),
        );
    }
    Ok(())
}

/// Check 11 (§5.3, §5.4): every line matching a trusted witness verifies, with a timestamp at most
/// [`MAX_COSIGNATURE_TIME`]. The counted witnesses, by time then name. Each trusted witness has at
/// most one line (§5.1, [`parse_checkpoint`]).
fn cosigners(cp: &Checkpoint, trust: &LogTrust) -> Result<Vec<CountedWitness>, InclusionError> {
    let mut out = Vec::new();
    for w in &trust.witnesses {
        let want = c2sp_key_hash(&w.name, SIG_TYPE_COSIGNATURE_V1, &w.key);
        for s in &cp.signatures {
            if s.key_name != w.name || s.key_hash != want {
                continue;
            }
            let time = (s.value.len() == 72)
                .then(|| s.value[..8].try_into().ok().map(u64::from_be_bytes))
                .flatten()
                .filter(|&t| t <= MAX_COSIGNATURE_TIME);
            let verified = time.filter(|&t| {
                verify_sig(
                    &w.key,
                    &cosignature_message(&cp.note_text, t),
                    &s.value[8..],
                )
            });
            let Some(time) = verified else {
                return fail(
                    ErrorName::BadCosignature,
                    format!(
                        "the cosignature of witness {} does not verify, or its time is out of range",
                        w.name
                    ),
                );
            };
            out.push(CountedWitness {
                name: w.name.clone(),
                key_id: w.key_id.clone(),
                time,
            });
        }
    }
    out.sort_by(|a, b| (a.time, &a.name).cmp(&(b.time, &b.name)));
    Ok(out)
}

// ---------------------------------------------------------------------------------------------
// The consistency proof document (§7)
// ---------------------------------------------------------------------------------------------

/// What a verified consistency proof document shows (§7.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsistencyVerdict {
    pub log_id: String,
    pub older_size: u64,
    pub newer_size: u64,
}

impl ConsistencyVerdict {
    pub fn to_json(&self) -> Value {
        serde_json::json!({
            "log_id": self.log_id,
            "older_size": self.older_size,
            "newer_size": self.newer_size,
        })
    }
}

/// Check a consistency proof document against the expected tenant's configuration, in §7.2's order:
/// its form, its log, each checkpoint's form and origin, each checkpoint's log signature, then the
/// sizes and the path. Cosignatures are not required, and witness lines are not checked.
pub fn verify_consistency(
    doc: &Value,
    trust: &LogTrust,
) -> Result<ConsistencyVerdict, InclusionError> {
    let bad = |m: &str| fail(ErrorName::ConsistencyForm, m.to_string());
    let Some(obj) = doc.as_object() else {
        return bad("a consistency proof document is a JSON object");
    };
    if !only(obj, &["spec", "log_id", "older", "newer", "proof"], &[]) {
        return bad(
            "a consistency proof document has exactly spec, log_id, older, newer and proof",
        );
    }
    if obj["spec"] != SPEC_CONSISTENCY {
        return bad("spec is not decision-cert-consistency.v1");
    }
    let Some(log_id) = obj["log_id"]
        .as_str()
        .filter(|s| prefixed_hex(s, "log:", 32))
    else {
        return bad("log_id is log: and 32 lowercase hex characters");
    };
    let (Some(older_text), Some(newer_text)) = (obj["older"].as_str(), obj["newer"].as_str())
    else {
        return bad("older and newer are strings, checkpoints' signed notes");
    };
    let Some(proof) = path_of(&obj["proof"]) else {
        return bad("proof is an array of at most 64 base64 32-byte hashes");
    };
    let log = trust.log(log_id)?;
    let mut cps = Vec::with_capacity(2);
    for text in [older_text, newer_text] {
        let cp = parse_checkpoint(text)?;
        if cp.origin != log_id {
            return fail(
                ErrorName::OriginMismatch,
                format!("a checkpoint's origin is not {log_id}"),
            );
        }
        cps.push(cp);
    }
    for cp in &cps {
        check_log_signature(cp, log)?;
    }
    let (older, newer) = (&cps[0], &cps[1]);
    if newer.tree_size < older.tree_size {
        return fail(
            ErrorName::SizeRegression,
            format!(
                "the newer checkpoint ({}) is smaller than the older ({})",
                newer.tree_size, older.tree_size
            ),
        );
    }
    if newer.tree_size == older.tree_size && newer.root_hash != older.root_hash {
        return fail(
            ErrorName::SplitView,
            format!(
                "two checkpoints of log {log_id} with size {} and different roots",
                older.tree_size
            ),
        );
    }
    if !verify_consistency_path(
        older.tree_size,
        newer.tree_size,
        &older.root_hash,
        &newer.root_hash,
        &proof,
    ) {
        return fail(
            ErrorName::BadConsistencyProof,
            format!(
                "the consistency path does not connect sizes {} and {}",
                older.tree_size, newer.tree_size
            ),
        );
    }
    Ok(ConsistencyVerdict {
        log_id: log_id.to_string(),
        older_size: older.tree_size,
        newer_size: newer.tree_size,
    })
}

// ---------------------------------------------------------------------------------------------
// Policy (§11)
// ---------------------------------------------------------------------------------------------

/// What a consumer does with a certificate, under its policy (§11). The certificate must pass its
/// own verification in every case.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyOutcome {
    /// Load it; the verdict when a bundle was checked (`warn` and `refuse`), None under `off`.
    Load(Option<InclusionVerdict>),
    /// Load it, with the warning `inclusion_missing` (`warn`, no bundle).
    LoadWithWarning(InclusionError),
    /// Refuse it: `inclusion_missing` under `refuse`, or the failing check's error.
    Refuse(InclusionError),
}

/// Apply `policy` to a certificate's bundle check: None when it has no bundle, else the result of
/// [`verify_bundle`]. `warn` softens only a missing bundle; a bundle that fails is refused under
/// `warn` and `refuse` alike. Under `off` nothing is checked and any result is ignored.
pub fn apply_policy(
    result: Option<Result<InclusionVerdict, InclusionError>>,
    policy: Policy,
) -> PolicyOutcome {
    let missing = || {
        InclusionError::new(
            ErrorName::InclusionMissing,
            "the certificate has no inclusion bundle",
        )
    };
    match (policy, result) {
        (Policy::Off, _) => PolicyOutcome::Load(None),
        (Policy::Warn, None) => PolicyOutcome::LoadWithWarning(missing()),
        (Policy::Refuse, None) => PolicyOutcome::Refuse(missing()),
        (_, Some(Ok(v))) => PolicyOutcome::Load(Some(v)),
        (_, Some(Err(e))) => PolicyOutcome::Refuse(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }
    fn h(s: &str) -> Hash {
        unhex(s).try_into().unwrap()
    }

    // RFC 6962 / RFC 9162 reference test data, from transparency-dev/merkle at tag v0.0.2 (commit
    // 036047b5d2f7faf3b1ee643d391e60fe5b1defcf): testonly/constants.go (LeafInputs, NodeHashes,
    // RootHashes) and proof/verify_test.go (inclusionProofs, consistencyProofs). The same values are
    // in google/certificate-transparency's merkle tree tests. These vectors hash the raw leaf
    // inputs, so they test the RFC 9162 layer ([`hash_leaf_bytes`]) beneath the JCS leaf encoding.
    const INPUTS: [&str; 8] = [
        "",
        "00",
        "10",
        "2021",
        "3031",
        "40414243",
        "5051525354555657",
        "606162636465666768696a6b6c6d6e6f",
    ];
    /// NodeHashes: level 0 (the leaf hashes) to level 3 (the root of all eight).
    const LEVELS: [&[&str]; 4] = [
        &[
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
            "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
            "0298d122906dcfc10892cb53a73992fc5b9f493ea4c9badb27b791b4127a7fe7",
            "07506a85fd9dd2f120eb694f86011e5bb4662e5c415a62917033d4a9624487e7",
            "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
            "4271a26be0d8a84f0bd54c8c302e7cb3a3b5d1fa6780a40bcce2873477dab658",
            "b08693ec2e721597130641e8211e7eedccb4c26413963eee6c1e2ed16ffb1a5f",
            "46f6ffadd3d06a09ff3c5860d2755c8b9819db7df44251788c7d8e3180de8eb1",
        ],
        &[
            "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
            "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
            "0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a",
            "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
        ],
        &[
            "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
            "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
        ],
        &["5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328"],
    ];
    /// RootHashes: the MTH of the first 1 to 8 leaves.
    const ROOTS: [&str; 8] = [
        "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
        "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
        "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
        "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
        "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
        "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
        "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
        "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
    ];
    /// inclusionProofs: (0-based leaf index, tree size, audit path). The source numbers leaves from
    /// 1; its {0, 0, nil} entry is an invalid probe, not a vector.
    const INCLUSION: [(u64, u64, &[&str]); 5] = [
        (0, 1, &[]),
        (
            0,
            8,
            &[
                "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
                "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
                "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
            ],
        ),
        (
            5,
            8,
            &[
                "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
                "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
                "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
            ],
        ),
        (
            2,
            3,
            &["fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125"],
        ),
        (
            1,
            5,
            &[
                "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
                "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
                "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
            ],
        ),
    ];
    /// consistencyProofs: (older size, newer size, consistency path).
    const CONSISTENCY: [(u64, u64, &[&str]); 5] = [
        (1, 1, &[]),
        (
            1,
            8,
            &[
                "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
                "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
                "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
            ],
        ),
        (
            6,
            8,
            &[
                "0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a",
                "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
                "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
            ],
        ),
        (
            2,
            5,
            &[
                "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
                "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
            ],
        ),
        (
            6,
            7,
            &[
                "0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a",
                "b08693ec2e721597130641e8211e7eedccb4c26413963eee6c1e2ed16ffb1a5f",
                "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
            ],
        ),
    ];

    fn reference_leaves() -> Vec<Hash> {
        INPUTS.iter().map(|x| hash_leaf_bytes(&unhex(x))).collect()
    }

    #[test]
    fn rfc6962_leaf_and_node_hashes() {
        let leaves = reference_leaves();
        for (level, hashes) in LEVELS.iter().enumerate() {
            let width = 1 << level;
            for (i, want) in hashes.iter().enumerate() {
                let got = root_hash(&leaves[i * width..(i + 1) * width]).unwrap();
                assert_eq!(got, h(want), "level {level} node {i}");
            }
        }
        assert_eq!(
            node_hash(&leaves[0], &leaves[1]),
            h(LEVELS[1][0]),
            "node_hash"
        );
    }

    #[test]
    fn rfc6962_roots_for_every_size() {
        let leaves = reference_leaves();
        for (n, want) in ROOTS.iter().enumerate() {
            assert_eq!(root_hash(&leaves[..=n]), Some(h(want)), "size {}", n + 1);
        }
        assert_eq!(root_hash(&[]), None);
    }

    #[test]
    fn rfc6962_inclusion_vectors() {
        let leaves = reference_leaves();
        for (index, size, path) in INCLUSION {
            let path: Vec<Hash> = path.iter().map(|x| h(x)).collect();
            let root = h(ROOTS[size as usize - 1]);
            assert!(
                verify_inclusion_path(index, size, &leaves[index as usize], &path, &root),
                "{index} in {size}"
            );
            assert_eq!(
                audit_path(&leaves[..size as usize], index as usize).unwrap(),
                path,
                "audit_path {index} in {size}"
            );
        }
    }

    #[test]
    fn rfc6962_consistency_vectors() {
        let leaves = reference_leaves();
        for (older, newer, path) in CONSISTENCY {
            let path: Vec<Hash> = path.iter().map(|x| h(x)).collect();
            let (r1, r2) = (h(ROOTS[older as usize - 1]), h(ROOTS[newer as usize - 1]));
            assert!(
                verify_consistency_path(older, newer, &r1, &r2, &path),
                "{older} -> {newer}"
            );
            assert_eq!(
                consistency_path(&leaves[..newer as usize], older as usize).unwrap(),
                path,
                "consistency_path {older} -> {newer}"
            );
        }
    }

    /// Hand-built small trees, sizes 1 to 9, every index and every pair of sizes: the paths this
    /// module computes verify, and every short, long, altered or misplaced one fails.
    #[test]
    fn small_trees_every_index_and_every_pair() {
        let mut leaves = reference_leaves();
        leaves.push(hash_leaf_bytes(&[0x70]));
        let flip = |p: &mut Vec<Hash>, i: usize| p[i][0] ^= 1;
        for n in 1..=9usize {
            let d = &leaves[..n];
            let root = root_hash(d).unwrap();
            let size = n as u64;
            for i in 0..n {
                let path = audit_path(d, i).unwrap();
                let ok = |idx: u64, sz: u64, p: &[Hash], r: &Hash| {
                    verify_inclusion_path(idx, sz, &d[i], p, r)
                };
                assert!(ok(i as u64, size, &path, &root), "{i} in {n}");
                for j in (0..n).filter(|&j| j != i) {
                    assert!(!ok(j as u64, size, &path, &root), "{i} as {j} in {n}");
                }
                // a path for another tree size, against that tree's root: it fails unless the
                // two trees give that leaf the same path
                for m in (i + 1..=9).filter(|&m| m != n) {
                    let theirs = audit_path(&leaves[..m], i).unwrap();
                    let their_root = root_hash(&leaves[..m]).unwrap();
                    let fits = verify_inclusion_path(i as u64, m as u64, &d[i], &path, &their_root);
                    assert_eq!(fits, theirs == path, "{i} in {n} as {m}");
                }
                assert!(!ok(i as u64, i as u64, &path, &root), "index = size");
                let mut long = path.clone();
                long.push(root);
                assert!(!ok(i as u64, size, &long, &root), "long {i} in {n}");
                if !path.is_empty() {
                    let short = &path[..path.len() - 1];
                    assert!(!ok(i as u64, size, short, &root), "short {i} in {n}");
                    for k in 0..path.len() {
                        let mut bad = path.clone();
                        flip(&mut bad, k);
                        assert!(!ok(i as u64, size, &bad, &root), "altered {k}");
                    }
                }
                let mut other = root;
                other[31] ^= 1;
                assert!(!ok(i as u64, size, &path, &other), "other root");
            }
            for m in 1..=n {
                let r1 = root_hash(&d[..m]).unwrap();
                let path = consistency_path(d, m).unwrap();
                let (m64, n64) = (m as u64, n as u64);
                assert!(
                    verify_consistency_path(m64, n64, &r1, &root, &path),
                    "{m} -> {n}"
                );
                assert!(!verify_consistency_path(n64, m64, &root, &r1, &path) || m == n);
                let mut wrong = r1;
                wrong[0] ^= 1;
                assert!(!verify_consistency_path(m64, n64, &wrong, &root, &path));
                assert!(!verify_consistency_path(m64, n64, &r1, &wrong, &path));
                let mut long = path.clone();
                long.push(root);
                assert!(
                    !verify_consistency_path(m64, n64, &r1, &root, &long),
                    "long {m} -> {n}"
                );
                if !path.is_empty() {
                    let short = &path[..path.len() - 1];
                    assert!(
                        !verify_consistency_path(m64, n64, &r1, &root, short),
                        "short"
                    );
                    for k in 0..path.len() {
                        let mut bad = path.clone();
                        flip(&mut bad, k);
                        assert!(
                            !verify_consistency_path(m64, n64, &r1, &root, &bad),
                            "altered"
                        );
                    }
                }
                if m < n {
                    assert!(!verify_consistency_path(m64, n64, &r1, &root, &[]));
                }
                // a path to another newer size, against that tree's root
                for k in (m..=9).filter(|&k| k != n) {
                    let theirs = consistency_path(&leaves[..k], m).unwrap();
                    let their_root = root_hash(&leaves[..k]).unwrap();
                    let fits = verify_consistency_path(m64, k as u64, &r1, &their_root, &path);
                    assert_eq!(fits, theirs == path, "{m} -> {n} as {m} -> {k}");
                }
            }
        }
        assert!(!verify_consistency_path(0, 1, &leaves[0], &leaves[0], &[]));
    }

    // -----------------------------------------------------------------------------------------
    // A test log: deterministic keys from fixed seeds, never fixture files.
    // -----------------------------------------------------------------------------------------

    type Edit = Box<dyn Fn(&mut Value)>;

    const LOG: &str = "log:00112233445566778899aabbccddeeff";
    const OTHER_LOG: &str = "log:ffeeddccbbaa99887766554433221100";
    const TENANT: &str = "acme-eu";

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }
    fn log_key() -> SigningKey {
        key(1)
    }
    fn witness_name(i: u8) -> String {
        format!("witness.example/w{i}")
    }
    fn witness_key(i: u8) -> SigningKey {
        key(10 + i)
    }
    fn b64url(k: &SigningKey) -> String {
        URL_SAFE_NO_PAD.encode(k.verifying_key().as_bytes())
    }

    fn trust_json(witnesses: u8, m: u64) -> Value {
        json!({
            "spec": SPEC_LOG_TRUST,
            "tenant": TENANT,
            "logs": [{
                "log_id": LOG,
                "key_name": LOG,
                "key_id": crate::key_id(&log_key().verifying_key()),
                "key": b64url(&log_key()),
            }],
            "witnesses": (0..witnesses).map(|i| json!({
                "name": witness_name(i),
                "key_id": crate::key_id(&witness_key(i).verifying_key()),
                "key": b64url(&witness_key(i)),
            })).collect::<Vec<_>>(),
            "m": m,
        })
    }
    fn trust(witnesses: u8, m: u64) -> LogTrust {
        LogTrust::from_json(&trust_json(witnesses, m)).unwrap()
    }

    fn note(origin: &str, size: u64, root: &Hash) -> String {
        format!("{origin}\n{size}\n{}\n", STANDARD.encode(root))
    }
    fn log_line(name: &str, k: &SigningKey, note_text: &str) -> String {
        let mut v = c2sp_key_hash(name, SIG_TYPE_ED25519, &k.verifying_key()).to_vec();
        v.extend(k.sign(note_text.as_bytes()).to_bytes());
        format!("\u{2014} {name} {}\n", STANDARD.encode(v))
    }
    fn cosig_line(name: &str, k: &SigningKey, note_text: &str, time: u64) -> String {
        let mut v = c2sp_key_hash(name, SIG_TYPE_COSIGNATURE_V1, &k.verifying_key()).to_vec();
        v.extend(time.to_be_bytes());
        v.extend(k.sign(&cosignature_message(note_text, time)).to_bytes());
        format!("\u{2014} {name} {}\n", STANDARD.encode(v))
    }
    /// A checkpoint signed by the log, cosigned by trusted witnesses `(index, time)`.
    fn checkpoint(note_text: &str, cosigs: &[(u8, u64)]) -> String {
        let mut s = format!("{note_text}\n{}", log_line(LOG, &log_key(), note_text));
        for &(i, t) in cosigs {
            s += &cosig_line(&witness_name(i), &witness_key(i), note_text, t);
        }
        s
    }

    fn certificate() -> Value {
        json!({
            "spec": "decision-certificate.v1.5",
            "signer_key_id": "ed25519:0c6e5b7d2a913f84",
            "fitted_at": "2026-11-16T09:31:10Z",
            "tenant": TENANT,
            "signature": "test",
        })
    }
    fn certificate_leaf(c: &Value) -> Value {
        let mut l = json!({
            "kind": "certificate",
            "certificate_id": crate::certificate_id(c).unwrap(),
            "signer_key_id": c["signer_key_id"],
            "spec": c["spec"],
            "fitted_at": c["fitted_at"],
        });
        if c.get("tenant").is_some() {
            l["tenant"] = c["tenant"].clone();
        }
        l
    }
    fn ledger_leaf(seq: u64) -> Value {
        json!({
            "kind": "ledger_entry",
            "ledger_id": format!("ledger:{}", "ab".repeat(16)),
            "seq": seq,
            "entry": format!("sha256:{seq:064x}"),
        })
    }

    /// A seven-leaf log whose leaf `at` is `leaf`, and a bundle for it cosigned as `cosigs`.
    fn bundle_for(leaf: Value, cert: Option<Value>, at: usize, cosigs: &[(u8, u64)]) -> Value {
        let mut leaves: Vec<Value> = (0..7).map(ledger_leaf).collect();
        leaves[at] = leaf;
        let hashes: Vec<Hash> = leaves
            .iter()
            .map(|l| leaf_hash(&Leaf::from_json(l).unwrap()))
            .collect();
        let root = root_hash(&hashes).unwrap();
        let mut b = json!({
            "spec": SPEC_BUNDLE,
            "log_id": LOG,
            "leaf_index": at,
            "leaf": leaves[at],
            "proof": audit_path(&hashes, at).unwrap().iter().map(|p| STANDARD.encode(p)).collect::<Vec<_>>(),
            "checkpoint": checkpoint(&note(LOG, 7, &root), cosigs),
        });
        if let Some(c) = cert {
            b["certificate"] = c;
        }
        b
    }
    fn bundle() -> Value {
        let c = certificate();
        bundle_for(certificate_leaf(&c), Some(c), 3, &[(0, 1_800_000_000)])
    }
    fn note_of(b: &Value) -> String {
        let cp = parse_checkpoint(b["checkpoint"].as_str().unwrap()).unwrap();
        cp.note_text
    }

    fn refused(b: &Value, t: &LogTrust) -> ErrorName {
        verify_bundle(b, t).expect_err("expected a refusal").name
    }

    /// The times written are the ones the 0.7.0 crate wrote (`chrono`'s `%Y-%m-%dT%H:%M:%SZ`).
    #[test]
    fn times_are_written_in_the_spec_form() {
        let cases: [(u64, &str); 9] = [
            (0, "1970-01-01T00:00:00Z"),
            (951_782_400, "2000-02-29T00:00:00Z"),
            (1_709_164_800, "2024-02-29T00:00:00Z"),
            (1_800_000_000, "2027-01-15T08:00:00Z"),
            (4_107_542_400, "2100-03-01T00:00:00Z"),
            (MAX_COSIGNATURE_TIME, "9999-12-31T23:59:59Z"),
            (MAX_COSIGNATURE_TIME + 1, "+10000-01-01T00:00:00Z"),
            (LAST_TIME_OF, "+262142-12-31T23:59:59Z"),
            (86_399, "1970-01-01T23:59:59Z"),
        ];
        for (secs, want) in cases {
            assert_eq!(time_of(secs), want, "{secs}");
        }
        for secs in [
            LAST_TIME_OF + 1,
            i64::MAX as u64,
            i64::MAX as u64 + 1,
            u64::MAX,
        ] {
            assert_eq!(time_of(secs), "", "{secs}");
        }
        // every written time up to the cosignature limit reads back as itself
        let mut secs = 0;
        while secs <= MAX_COSIGNATURE_TIME {
            let t = time_of(secs);
            assert!(time_ok(&t), "{t}");
            let back = crate::timestamp(&t).unwrap().unix_timestamp();
            assert_eq!(u64::try_from(back).unwrap(), secs, "{t}");
            secs += 9_876_543;
        }
    }

    #[test]
    fn times_are_the_certificate_form_with_seconds_to_59() {
        assert!(time_ok("2026-12-31T23:59:59Z"));
        assert!(time_ok("0000-02-29T00:00:00Z"));
        for s in [
            "2026-12-31T23:59:60Z",
            "2026-12-31T23:59:61Z",
            "2023-02-29T00:00:00Z",
            "2026-12-31t23:59:59Z",
            "2026-12-31T23:59:59z",
            "2026-12-31T23:59:59+00:00",
            "2026-12-31T23:59:59.0Z",
            "",
        ] {
            assert!(!time_ok(s), "{s}");
        }
    }

    #[test]
    fn a_good_bundle_verifies() {
        let v = verify_bundle(&bundle(), &trust(1, 1)).unwrap();
        assert_eq!(v.log_id, LOG);
        assert_eq!((v.tree_size, v.leaf_index), (7, 3));
        assert_eq!(v.kind, "certificate");
        assert_eq!(
            v.certificate_id,
            Some(crate::certificate_id(&certificate()).unwrap())
        );
        assert_eq!(v.witnesses.len(), 1);
        assert_eq!(v.t_proven, 1_800_000_000);
        assert_eq!(v.t_proven_time(), "2027-01-15T08:00:00Z");
        assert_eq!(v.backfilled(), Some(false));
        let j = v.to_json();
        assert_eq!(j["t_proven"], "2027-01-15T08:00:00Z");
        assert_eq!(
            (&j["backfilled"], &j["backfilled_by"]),
            (&json!(false), &json!([]))
        );
        assert_eq!(j["witnesses"][0]["name"], witness_name(0));
        // every index of the tree, other leaf kinds, and the bundle's JSON text round trip
        for at in 0..7 {
            let b = bundle_for(ledger_leaf(at as u64), None, at, &[(0, 5)]);
            let text = serde_json::to_string(&b).unwrap();
            let v = verify_bundle(&parse_ijson(&text).unwrap(), &trust(1, 1)).unwrap();
            assert_eq!(v.backfilled(), None);
            assert!(v.to_json().get("backfilled").is_none());
            assert_eq!((v.leaf_index, v.certificate_id), (at as u64, None));
        }
        let head = json!({"kind": "audit_head", "tenant": TENANT, "chain": "audit", "seq": 1,
            "digest": format!("sha256:{}", "0".repeat(64)), "observed_at": "2026-11-16T09:31:10Z"});
        assert!(verify_bundle(&bundle_for(head, None, 6, &[(0, 5)]), &trust(1, 1)).is_ok());
        let c14 = json!({"spec": "decision-certificate.v1.4", "signer_key_id": "ed25519:0c6e5b7d2a913f84",
            "fitted_at": "2026-11-16T09:31:10Z", "signature": "x"});
        let b = bundle_for(certificate_leaf(&c14), Some(c14), 0, &[(0, 5)]);
        assert!(verify_bundle(&b, &trust(1, 1)).is_ok());
    }

    #[test]
    fn leaf_hash_is_rfc9162_over_the_jcs_bytes() {
        let leaf = Leaf::from_json(&ledger_leaf(7)).unwrap();
        let jcs = format!(
            "{{\"entry\":\"sha256:{:064x}\",\"kind\":\"ledger_entry\",\"ledger_id\":\"ledger:{}\",\"seq\":7}}",
            7,
            "ab".repeat(16)
        );
        assert_eq!(leaf.canonical(), jcs.as_bytes());
        let mut pre = vec![0u8];
        pre.extend(jcs.as_bytes());
        assert_eq!(leaf_hash(&leaf), <[u8; 32]>::from(Sha256::digest(&pre)));
        assert_ne!(
            leaf_hash(&leaf),
            <[u8; 32]>::from(Sha256::digest(jcs.as_bytes()))
        );
    }

    #[test]
    fn trust_form() {
        assert_eq!(trust(3, 2).m(), 2);
        assert_eq!(trust(1, 1).policy(), Policy::Warn);
        let edits: Vec<Edit> = vec![
            Box::new(|t| t["spec"] = json!("decision-cert-inclusion.v1")),
            Box::new(|t| t["extra"] = json!(1)),
            Box::new(|t| t["m"] = json!(3)),
            Box::new(|t| t["m"] = json!(0)),
            Box::new(|t| t["m"] = json!(1.0)),
            Box::new(|t| t["policy"] = json!("loud")),
            Box::new(|t| t["tenant"] = json!("acme eu")),
            Box::new(|t| t["logs"] = json!([])),
            Box::new(|t| t["witnesses"] = json!([])),
            Box::new(|t| t["logs"][0]["key_id"] = json!("ed25519:0000000000000000")),
            Box::new(|t| t["logs"][0]["key_name"] = json!("a+b")),
            Box::new(|t| t["logs"][0]["log_id"] = json!("log:XYZ")),
            Box::new(|t| t["witnesses"][0]["extra"] = json!(1)),
            Box::new(|t| {
                // a small-order key (and its own id)
                let weak = [1u8]
                    .iter()
                    .chain([0u8; 31].iter())
                    .copied()
                    .collect::<Vec<_>>();
                t["witnesses"][0]["key"] = json!(URL_SAFE_NO_PAD.encode(&weak));
                t["witnesses"][0]["key_id"] = json!(format!(
                    "ed25519:{}",
                    &crate::hex(&Sha256::digest(&weak))[..16]
                ));
            }),
            Box::new(|t| {
                let w = t["witnesses"][0].clone();
                t["witnesses"].as_array_mut().unwrap().push(w);
            }),
            Box::new(|t| {
                let mut w = t["witnesses"][1].clone();
                w["name"] = t["witnesses"][0]["name"].clone();
                t["witnesses"][0] = w.clone();
            }),
            Box::new(|t| {
                t["witnesses"][0]["key"] = t["logs"][0]["key"].clone();
                t["witnesses"][0]["key_id"] = t["logs"][0]["key_id"].clone();
            }),
            Box::new(|t| {
                let mut l = t["logs"][0].clone();
                l["log_id"] = json!(OTHER_LOG);
                t["logs"].as_array_mut().unwrap().push(l);
            }),
        ];
        for (i, edit) in edits.iter().enumerate() {
            let mut t = trust_json(2, 1);
            edit(&mut t);
            let e = LogTrust::from_json(&t).expect_err(&format!("edit {i}"));
            assert_eq!(e.name, ErrorName::TrustForm, "edit {i}: {e}");
        }
    }

    #[test]
    fn trust_cross_tenant() {
        let a = trust(1, 1);
        let mut other = trust_json(1, 1);
        other["tenant"] = json!("beta");
        let b = LogTrust::from_json(&other).unwrap();
        assert_eq!(
            check_tenants(&[a.clone(), b]).unwrap_err().name,
            ErrorName::TrustCrossTenant
        );
        // the same key under another log_id is still one log under two tenants
        other["logs"][0]["log_id"] = json!(OTHER_LOG);
        let b = LogTrust::from_json(&other).unwrap();
        assert_eq!(
            check_tenants(&[a.clone(), b]).unwrap_err().name,
            ErrorName::TrustCrossTenant
        );
        // a witness may serve several tenants
        let mut c = trust_json(1, 1);
        c["tenant"] = json!("gamma");
        c["logs"][0]["log_id"] = json!(OTHER_LOG);
        c["logs"][0]["key"] = json!(b64url(&key(2)));
        c["logs"][0]["key_id"] = json!(crate::key_id(&key(2).verifying_key()));
        assert!(check_tenants(&[a, LogTrust::from_json(&c).unwrap()]).is_ok());
    }

    #[test]
    fn bundle_form() {
        let t = trust(1, 1);
        let edits: Vec<Edit> = vec![
            Box::new(|b| b["spec"] = json!("decision-cert-consistency.v1")),
            Box::new(|b| b["extra"] = json!(1)),
            Box::new(|b| {
                b.as_object_mut().unwrap().remove("proof");
            }),
            Box::new(|b| {
                b.as_object_mut().unwrap().remove("certificate");
            }),
            Box::new(|b| b["certificate"] = json!("not an object")),
            Box::new(|b| b["leaf_index"] = json!(3.0)),
            Box::new(|b| b["leaf_index"] = json!(-1)),
            Box::new(|b| b["leaf_index"] = json!(1u64 << 53)),
            Box::new(|b| b["log_id"] = json!("log:1")),
            Box::new(|b| b["leaf"] = json!("a leaf")),
            Box::new(|b| b["checkpoint"] = json!(7)),
            Box::new(|b| b["proof"] = json!(["AAAA"])),
            Box::new(|b| b["proof"] = json!(vec![STANDARD.encode([0u8; 32]); 65])),
            // a non-canonical base64 node hash: the last character's unused bits set
            Box::new(|b| {
                let mut s = STANDARD.encode([0u8; 32]);
                s.replace_range(42..43, "B");
                b["proof"][0] = json!(s);
            }),
        ];
        for (i, edit) in edits.iter().enumerate() {
            let mut b = bundle();
            edit(&mut b);
            assert_eq!(refused(&b, &t), ErrorName::BundleForm, "edit {i}");
        }
        // a certificate with a leaf of another kind
        let mut b = bundle_for(ledger_leaf(3), None, 3, &[(0, 5)]);
        b["certificate"] = certificate();
        assert_eq!(refused(&b, &t), ErrorName::BundleForm);
        // backfilled: true only, and only beside a certificate leaf
        for v in [json!(false), json!("true"), json!(1), json!(null)] {
            let mut b = bundle();
            b["backfilled"] = v;
            assert_eq!(refused(&b, &t), ErrorName::BundleForm);
        }
        let mut b = bundle_for(ledger_leaf(3), None, 3, &[(0, 5)]);
        b["backfilled"] = json!(true);
        assert_eq!(refused(&b, &t), ErrorName::BundleForm);
    }

    #[test]
    fn backfilled_mark() {
        // the certificate's fitted_at is 2026-11-16T09:31:10Z
        let with_start = |start: Option<&str>| {
            let mut t = trust_json(1, 1);
            if let Some(s) = start {
                t["logs"][0]["started_at"] = json!(s);
            }
            LogTrust::from_json(&t).unwrap()
        };
        let mut marked = bundle();
        marked["backfilled"] = json!(true);
        for (b, start, by) in [
            (bundle(), None, vec![]),
            (marked.clone(), None, vec!["bundle"]),
            (bundle(), Some("2026-11-17T00:00:00Z"), vec!["started_at"]),
            (bundle(), Some("2026-11-16T09:31:10Z"), vec![]),
            (bundle(), Some("2026-11-01T00:00:00Z"), vec![]),
            (
                marked.clone(),
                Some("2026-11-17T00:00:00Z"),
                vec!["bundle", "started_at"],
            ),
            (marked, Some("2026-11-01T00:00:00Z"), vec!["bundle"]),
        ] {
            let v = verify_bundle(&b, &with_start(start)).unwrap();
            assert_eq!(v.backfilled(), Some(!by.is_empty()), "{start:?}");
            assert_eq!(v.backfilled_by, Some(by));
        }
        for bad in [
            json!("2026-11-17"),
            json!("2026-11-17T00:00:60Z"),
            json!(null),
            json!(1),
        ] {
            let mut t = trust_json(1, 1);
            t["logs"][0]["started_at"] = bad;
            assert_eq!(
                LogTrust::from_json(&t).unwrap_err().name,
                ErrorName::TrustForm
            );
        }
    }

    #[test]
    fn leaf_form() {
        let t = trust(1, 1);
        let mut b = bundle_for(ledger_leaf(3), None, 3, &[(0, 5)]);
        b["leaf"]["kind"] = json!("receipt");
        assert_eq!(refused(&b, &t), ErrorName::LeafForm, "unknown kind");
        let edits: Vec<Edit> = vec![
            Box::new(|l| l["extra"] = json!(1)),
            Box::new(|l| {
                l.as_object_mut().unwrap().remove("fitted_at");
            }),
            Box::new(|l| {
                l.as_object_mut().unwrap().remove("tenant");
            }),
            Box::new(|l| l["spec"] = json!("decision-certificate.v1.4")),
            Box::new(|l| l["spec"] = json!("decision-certificate.v2")),
            Box::new(|l| l["fitted_at"] = json!("2026-11-16T09:31:60Z")),
            Box::new(|l| l["fitted_at"] = json!("2026-02-30T09:31:10Z")),
            Box::new(|l| l["certificate_id"] = json!("sha256:ABC")),
            Box::new(|l| l["signer_key_id"] = json!("ed25519:short")),
            Box::new(|l| l["tenant"] = json!("")),
        ];
        for (i, edit) in edits.iter().enumerate() {
            let mut b = bundle();
            edit(&mut b["leaf"]);
            assert_eq!(refused(&b, &t), ErrorName::LeafForm, "edit {i}");
        }
        for bad in [
            json!({"kind": "ledger_entry", "ledger_id": "ledger:x", "seq": 0, "entry": format!("sha256:{}", "0".repeat(64))}),
            json!({"kind": "keyset", "keyset_id": format!("keyset:{}", "0".repeat(32)), "seq": 1.5, "keyset": format!("sha256:{}", "0".repeat(64))}),
            json!({"kind": "attestation", "attestation": format!("sha256:{}", "0".repeat(64))}),
            json!({"kind": "audit_head", "tenant": TENANT, "chain": "a", "seq": 0, "digest": format!("sha256:{}", "0".repeat(64)), "observed_at": "2026-11-16T09:31:10Z"}),
        ] {
            assert_eq!(
                Leaf::from_json(&bad).unwrap_err().name,
                ErrorName::LeafForm,
                "{bad}"
            );
        }
    }

    #[test]
    fn leaf_mismatch() {
        let t = trust(1, 1);
        // another certificate's leaf
        let mut other = certificate();
        other["fitted_at"] = json!("2026-11-16T09:31:11Z");
        let mut b = bundle();
        b["leaf"] = certificate_leaf(&other);
        assert_eq!(refused(&b, &t), ErrorName::LeafMismatch);
        // a member that does not match its certificate (with the right id)
        for (m, v) in [
            ("signer_key_id", json!("ed25519:0000000000000000")),
            ("fitted_at", json!("2026-01-01T00:00:00Z")),
            ("tenant", json!("beta")),
        ] {
            let mut b = bundle();
            b["leaf"][m] = v;
            assert_eq!(refused(&b, &t), ErrorName::LeafMismatch, "{m}");
        }
    }

    #[test]
    fn tenant_mismatch() {
        let t = trust(1, 1);
        let mut c = certificate();
        c["tenant"] = json!("beta");
        let b = bundle_for(certificate_leaf(&c), Some(c), 3, &[(0, 5)]);
        assert_eq!(refused(&b, &t), ErrorName::TenantMismatch);
        let head = json!({"kind": "audit_head", "tenant": "beta", "chain": "audit", "seq": 1,
            "digest": format!("sha256:{}", "0".repeat(64)), "observed_at": "2026-11-16T09:31:10Z"});
        assert_eq!(
            refused(&bundle_for(head, None, 0, &[(0, 5)]), &t),
            ErrorName::TenantMismatch
        );
    }

    #[test]
    fn unknown_log_and_origin_mismatch() {
        let t = trust(1, 1);
        let mut b = bundle();
        b["log_id"] = json!(OTHER_LOG);
        assert_eq!(refused(&b, &t), ErrorName::UnknownLog);
        // the checkpoint of another log under this bundle's log_id
        let mut b = bundle();
        let text = b["checkpoint"].as_str().unwrap().replace(LOG, OTHER_LOG);
        b["checkpoint"] = json!(text);
        assert_eq!(refused(&b, &t), ErrorName::OriginMismatch);
    }

    #[test]
    fn checkpoint_form() {
        let good = bundle()["checkpoint"].as_str().unwrap().to_string();
        let cp = parse_checkpoint(&good).unwrap();
        assert_eq!((cp.origin.as_str(), cp.tree_size), (LOG, 7));
        let sig_lines: Vec<&str> = good.split_inclusive('\n').skip(4).collect();
        let note_text = cp.note_text.clone();
        let root = note_text.lines().nth(2).unwrap().to_string();
        let mut noncanonical = root.clone();
        let last = noncanonical.len() - 2;
        let c = noncanonical.as_bytes()[last];
        let bumped = if c == b'/' { '+' } else { (c + 1) as char };
        noncanonical.replace_range(last..last + 1, &bumped.to_string());
        let cases: Vec<String> = vec![
            good.strip_suffix('\n').unwrap().to_string(), // no final newline
            good.replacen('\n', "\nextra\n", 1),          // an extra text line
            good.replacen(&format!("{root}\n\n"), &format!("{root}\n"), 1), // no blank line
            good.replace(&root, &noncanonical),           // non-canonical base64 root
            good.replacen("\n7\n", "\n07\n", 1),          // a leading zero
            good.replacen("\n7\n", "\n0\n", 1),           // size 0
            good.replacen("\n7\n", "\n18446744073709551616\n", 1), // over 2^64 - 1
            good.replacen("\n7\n", "\n+7\n", 1),
            good.replace('\n', "\r\n"),                 // carriage returns
            good.replacen(LOG, &format!("{LOG}\t"), 1), // a tab
            note_text.clone() + "\n",                   // no signature line
            good.replacen('\u{2014}', "-", 1),          // not an em dash
            good.replacen(&format!("\u{2014} {LOG} "), "\u{2014} a+b ", 1), // + in a key name
            good.clone() + "\n",                        // a trailing blank line
            good.clone() + sig_lines[0],                // the log's line twice
            good.clone() + sig_lines[1],                // one witness's line twice
            format!("{note_text}\n{}", "\u{2014} x AAAA\n"), // a value under 5 bytes
            format!("{note_text}\n{}", "\u{2014} x AAAAAAAA\n".repeat(101)),
        ];
        for (i, c) in cases.iter().enumerate() {
            let e = parse_checkpoint(c).expect_err(&format!("case {i}: {c:?}"));
            assert_eq!(e.name, ErrorName::CheckpointForm, "case {i}");
            let mut b = bundle();
            b["checkpoint"] = json!(c);
            assert_eq!(
                refused(&b, &trust(1, 1)),
                ErrorName::CheckpointForm,
                "case {i}"
            );
        }
        // two lines with one name and different key IDs are two keys
        let mut b = bundle();
        let other = cosig_line(&witness_name(0), &key(99), &note_text, 5);
        b["checkpoint"] = json!(good.clone() + &other);
        assert!(verify_bundle(&b, &trust(1, 1)).is_ok());
    }

    #[test]
    fn bad_proof() {
        let t = trust(1, 1);
        let mut b = bundle();
        b["leaf_index"] = json!(4);
        assert_eq!(refused(&b, &t), ErrorName::BadProof);
        let mut b = bundle();
        b["leaf_index"] = json!(7);
        assert_eq!(refused(&b, &t), ErrorName::BadProof);
        let mut b = bundle();
        b["proof"].as_array_mut().unwrap().pop();
        assert_eq!(refused(&b, &t), ErrorName::BadProof);
        let mut b = bundle();
        b["proof"]
            .as_array_mut()
            .unwrap()
            .push(json!(STANDARD.encode([7u8; 32])));
        assert_eq!(refused(&b, &t), ErrorName::BadProof);
        // a path for another tree size: the seven-leaf path, an eight-leaf checkpoint
        let mut b = bundle();
        let mut leaves: Vec<Value> = (0..8).map(ledger_leaf).collect();
        leaves[3] = b["leaf"].clone();
        let hashes: Vec<Hash> = leaves
            .iter()
            .map(|l| leaf_hash(&Leaf::from_json(l).unwrap()))
            .collect();
        let root8 = root_hash(&hashes).unwrap();
        b["checkpoint"] = json!(checkpoint(&note(LOG, 8, &root8), &[(0, 5)]));
        assert_eq!(refused(&b, &t), ErrorName::BadProof);
        b["proof"] = json!(audit_path(&hashes, 3)
            .unwrap()
            .iter()
            .map(|p| STANDARD.encode(p))
            .collect::<Vec<_>>());
        assert!(verify_bundle(&b, &t).is_ok());
    }

    #[test]
    fn log_signatures() {
        let t = trust(1, 1);
        let b = bundle();
        let n = note_of(&b);
        let w = cosig_line(&witness_name(0), &witness_key(0), &n, 5);
        let with = |log: String| json!(format!("{n}\n{log}{w}"));
        let mut b2 = b.clone();
        // no line from the log's key: one from another key under its name, none at all
        b2["checkpoint"] = with(log_line(LOG, &key(42), &n));
        assert_eq!(refused(&b2, &t), ErrorName::LogSignatureMissing);
        b2["checkpoint"] = json!(format!("{n}\n{w}"));
        assert_eq!(refused(&b2, &t), ErrorName::LogSignatureMissing);
        // the log's line over another note
        b2["checkpoint"] = with(log_line(LOG, &log_key(), &note(LOG, 7, &[0; 32])));
        assert_eq!(refused(&b2, &t), ErrorName::BadLogSignature);
        // the log's key ID with a value of the wrong length
        let mut v = c2sp_key_hash(LOG, SIG_TYPE_ED25519, &log_key().verifying_key()).to_vec();
        v.extend([0u8; 10]);
        b2["checkpoint"] = with(format!("\u{2014} {LOG} {}\n", STANDARD.encode(v)));
        assert_eq!(refused(&b2, &t), ErrorName::BadLogSignature);
    }

    #[test]
    fn cosignatures() {
        let b = bundle();
        let n = note_of(&b);
        let log = log_line(LOG, &log_key(), &n);
        let with = |lines: &[String]| json!(format!("{n}\n{log}{}", lines.concat()));
        let mut b2 = b.clone();
        // a cosignature over another checkpoint
        let other = note(LOG, 7, &[0; 32]);
        b2["checkpoint"] = with(&[cosig_line(&witness_name(0), &witness_key(0), &other, 5)]);
        assert_eq!(refused(&b2, &trust(1, 1)), ErrorName::BadCosignature);
        // a time past 9999-12-31T23:59:59Z
        b2["checkpoint"] = with(&[cosig_line(
            &witness_name(0),
            &witness_key(0),
            &n,
            MAX_COSIGNATURE_TIME + 1,
        )]);
        assert_eq!(refused(&b2, &trust(1, 1)), ErrorName::BadCosignature);
        b2["checkpoint"] = with(&[cosig_line(
            &witness_name(0),
            &witness_key(0),
            &n,
            MAX_COSIGNATURE_TIME,
        )]);
        assert_eq!(
            verify_bundle(&b2, &trust(1, 1)).unwrap().t_proven_time(),
            "9999-12-31T23:59:59Z"
        );
        // a trusted witness's line that fails is refused even when m others verify
        b2["checkpoint"] = with(&[
            cosig_line(&witness_name(0), &witness_key(0), &n, 5),
            cosig_line(&witness_name(1), &witness_key(1), &other, 5),
        ]);
        assert_eq!(refused(&b2, &trust(2, 1)), ErrorName::BadCosignature);
    }

    #[test]
    fn too_few_cosignatures_and_untrusted_witnesses() {
        let b = bundle();
        let n = note_of(&b);
        let log = log_line(LOG, &log_key(), &n);
        let with = |lines: &[String]| json!(format!("{n}\n{log}{}", lines.concat()));
        let untrusted = cosig_line("witness.example/other", &key(77), &n, 1);
        let w0 = cosig_line(&witness_name(0), &witness_key(0), &n, 9);
        let mut b2 = b.clone();
        // no cosignature; only an untrusted witness's (ignored, so none)
        b2["checkpoint"] = with(&[]);
        assert_eq!(refused(&b2, &trust(1, 1)), ErrorName::TooFewCosignatures);
        b2["checkpoint"] = with(std::slice::from_ref(&untrusted));
        assert_eq!(refused(&b2, &trust(1, 1)), ErrorName::TooFewCosignatures);
        // an untrusted line beside a trusted one is ignored: one counted, at its own time
        b2["checkpoint"] = with(&[untrusted.clone(), w0.clone()]);
        let v = verify_bundle(&b2, &trust(1, 1)).unwrap();
        assert_eq!((v.witnesses.len(), v.t_proven), (1, 9));
        // m = 2 with one trusted cosignature and one untrusted
        assert_eq!(refused(&b2, &trust(2, 2)), ErrorName::TooFewCosignatures);
        // a trusted witness's name with another key, and its key under another name: ignored
        b2["checkpoint"] = with(&[
            w0,
            cosig_line(&witness_name(1), &key(78), &n, 1),
            cosig_line("witness.example/renamed", &witness_key(1), &n, 1),
        ]);
        assert_eq!(refused(&b2, &trust(2, 2)), ErrorName::TooFewCosignatures);
    }

    #[test]
    fn t_proven_is_the_mth_earliest_counted_time() {
        let c = certificate();
        let b = bundle_for(
            certificate_leaf(&c),
            Some(c),
            3,
            &[(0, 300), (1, 100), (2, 200)],
        );
        let at = |m| verify_bundle(&b, &trust(3, m)).unwrap();
        assert_eq!(at(1).t_proven, 100);
        assert_eq!(at(2).t_proven, 200);
        assert_eq!(at(3).t_proven, 300);
        let names: Vec<_> = at(2).witnesses.into_iter().map(|w| w.time).collect();
        assert_eq!(names, [100, 200, 300]);
        // two of three cosign, m = 2: the later of the two
        let c = certificate();
        let b = bundle_for(certificate_leaf(&c), Some(c), 3, &[(0, 300), (2, 200)]);
        assert_eq!(verify_bundle(&b, &trust(3, 2)).unwrap().t_proven, 300);
        assert_eq!(refused(&b, &trust(3, 3)), ErrorName::TooFewCosignatures);
    }

    #[test]
    fn checks_run_in_order() {
        // a bundle broken at checks 5 and 9: check 5's error
        let t = trust(1, 1);
        let mut c = certificate();
        c["tenant"] = json!("beta");
        let mut b = bundle_for(certificate_leaf(&c), Some(c), 3, &[(0, 5)]);
        b["leaf_index"] = json!(2);
        assert_eq!(refused(&b, &t), ErrorName::TenantMismatch);
        // broken at checks 9 and 10: bad_proof
        let mut b = bundle();
        let n = note_of(&b);
        b["leaf_index"] = json!(2);
        b["checkpoint"] = json!(format!(
            "{n}\n{}",
            cosig_line(&witness_name(0), &witness_key(0), &n, 5)
        ));
        assert_eq!(refused(&b, &t), ErrorName::BadProof);
    }

    fn consistency_doc(older: usize, newer: usize) -> Value {
        let leaves: Vec<Hash> = (0..9)
            .map(|i| leaf_hash(&Leaf::from_json(&ledger_leaf(i)).unwrap()))
            .collect();
        let r = |n: usize| root_hash(&leaves[..n]).unwrap();
        json!({
            "spec": SPEC_CONSISTENCY,
            "log_id": LOG,
            "older": checkpoint(&note(LOG, older as u64, &r(older)), &[]),
            "newer": checkpoint(&note(LOG, newer as u64, &r(newer)), &[(0, 5)]),
            "proof": consistency_path(&leaves[..newer], older).unwrap().iter().map(|p| STANDARD.encode(p)).collect::<Vec<_>>(),
        })
    }

    #[test]
    fn consistency() {
        let t = trust(1, 1);
        for (m, n) in [(1, 2), (3, 7), (7, 8), (4, 4), (1, 9)] {
            let v = verify_consistency(&consistency_doc(m, n), &t).unwrap();
            assert_eq!(
                (v.log_id.as_str(), v.older_size, v.newer_size),
                (LOG, m as u64, n as u64)
            );
        }
        let err = |d: &Value| verify_consistency(d, &t).unwrap_err().name;
        // newer smaller than older
        let mut d = consistency_doc(3, 7);
        let older = d["older"].clone();
        d["older"] = d["newer"].clone();
        d["newer"] = older;
        assert_eq!(err(&d), ErrorName::SizeRegression);
        // one size, two roots
        let mut d = consistency_doc(4, 4);
        d["newer"] = json!(checkpoint(&note(LOG, 4, &[9; 32]), &[]));
        d["proof"] = json!([]);
        assert_eq!(err(&d), ErrorName::SplitView);
        // one size, one root, a path
        let mut d = consistency_doc(4, 4);
        d["proof"] = json!([STANDARD.encode([1u8; 32])]);
        assert_eq!(err(&d), ErrorName::BadConsistencyProof);
        // a newer tree that does not extend the older
        let mut d = consistency_doc(3, 7);
        d["newer"] = json!(checkpoint(&note(LOG, 7, &[9; 32]), &[]));
        assert_eq!(err(&d), ErrorName::BadConsistencyProof);
        let mut d = consistency_doc(3, 7);
        d["proof"].as_array_mut().unwrap().pop();
        assert_eq!(err(&d), ErrorName::BadConsistencyProof);
        // form, log, checkpoint and signature
        let mut d = consistency_doc(3, 7);
        d["spec"] = json!(SPEC_BUNDLE);
        assert_eq!(err(&d), ErrorName::ConsistencyForm);
        let mut d = consistency_doc(3, 7);
        d["extra"] = json!(1);
        assert_eq!(err(&d), ErrorName::ConsistencyForm);
        let mut d = consistency_doc(3, 7);
        d["log_id"] = json!(OTHER_LOG);
        assert_eq!(err(&d), ErrorName::UnknownLog);
        let mut d = consistency_doc(3, 7);
        d["older"] = json!(d["older"].as_str().unwrap().trim_end());
        assert_eq!(err(&d), ErrorName::CheckpointForm);
        let mut d = consistency_doc(3, 7);
        d["newer"] = json!(d["newer"].as_str().unwrap().replace(LOG, OTHER_LOG));
        assert_eq!(err(&d), ErrorName::OriginMismatch);
        let mut d = consistency_doc(3, 7);
        let n = note(LOG, 3, &[1; 32]);
        d["older"] = json!(format!("{n}\n{}", log_line(LOG, &key(42), &n)));
        assert_eq!(err(&d), ErrorName::LogSignatureMissing);
        let mut d = consistency_doc(3, 7);
        let n = parse_checkpoint(d["older"].as_str().unwrap())
            .unwrap()
            .note_text;
        d["older"] = json!(format!(
            "{n}\n{}",
            log_line(LOG, &log_key(), "another note\n1\nAA==\n")
        ));
        assert_eq!(err(&d), ErrorName::BadLogSignature);
    }

    #[test]
    fn policy() {
        let ok = || Some(Ok(verify_bundle(&bundle(), &trust(1, 1)).unwrap()));
        let failed = || Some(Err(InclusionError::new(ErrorName::BadProof, "x")));
        use PolicyOutcome::*;
        assert_eq!(apply_policy(None, Policy::Off), Load(None));
        assert_eq!(apply_policy(ok(), Policy::Off), Load(None));
        assert_eq!(apply_policy(failed(), Policy::Off), Load(None));
        assert!(
            matches!(apply_policy(None, Policy::Warn), LoadWithWarning(e) if e.name == ErrorName::InclusionMissing)
        );
        assert!(matches!(apply_policy(ok(), Policy::Warn), Load(Some(_))));
        assert!(
            matches!(apply_policy(failed(), Policy::Warn), Refuse(e) if e.name == ErrorName::BadProof)
        );
        assert!(
            matches!(apply_policy(None, Policy::Refuse), Refuse(e) if e.name == ErrorName::InclusionMissing)
        );
        assert!(matches!(apply_policy(ok(), Policy::Refuse), Load(Some(_))));
        assert!(
            matches!(apply_policy(failed(), Policy::Refuse), Refuse(e) if e.name == ErrorName::BadProof)
        );
    }

    #[test]
    fn ijson() {
        assert!(parse_ijson(r#"{"a": 1, "b": {"c": [1, 2.5, null, true, "x"]}}"#).is_ok());
        assert!(parse_ijson(r#"{"a": 1, "a": 1}"#).is_err());
        assert!(parse_ijson(r#"{"a": [{"b": 1, "b": 2}]}"#).is_err());
        assert!(parse_ijson(r#""\ud800""#).is_err());
        assert!(parse_ijson(r#"{"leaf_index": 1e0}"#).unwrap()["leaf_index"]
            .as_u64()
            .is_none());
        let names: BTreeSet<_> = ErrorName::ALL.iter().map(|e| e.as_str()).collect();
        assert_eq!(names.len(), 19);
    }
}
