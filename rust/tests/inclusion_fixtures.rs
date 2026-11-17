//! The crate's inclusion verifier (`decision-cert-inclusion.v1`) on every case of
//! `fixtures/inclusion-v1/manifest.json`, written by `python/tools/gen_inclusion_fixtures.py`: each
//! case's outcome, in the manifest's shape, equals its `expect` exactly. The Python verifier is held to
//! the same manifest by `python/tests/test_inclusion.py`, which also runs both command-line verifiers on
//! every document and compares their output lines.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use base64::{engine::general_purpose::STANDARD, Engine};
use decision_cert::inclusion::{
    apply_policy, check_tenants, hash_leaf_bytes, leaf_hash, parse_ijson, verify_bundle,
    verify_consistency, verify_consistency_path, verify_inclusion_path, ErrorName, Hash,
    InclusionError, Leaf, LogTrust, PolicyOutcome,
};
use serde_json::{json, Value};

fn set_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../fixtures/inclusion-v1")
}

fn text(rel: &str) -> String {
    let p = set_dir().join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

fn read_trust(rel: &str) -> Result<LogTrust, InclusionError> {
    parse_ijson(&text(rel))
        .map_err(|e| InclusionError::new(ErrorName::TrustForm, e))
        .and_then(|v| LogTrust::from_json(&v))
}

fn trust(rel: &str) -> LogTrust {
    read_trust(rel).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

fn refused(e: &InclusionError) -> Value {
    json!({"verdict": "refused", "error": e.name.as_str()})
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn hash(s: &Value) -> Hash {
    unhex(s.as_str().unwrap()).try_into().unwrap()
}

fn hashes(v: &Value) -> Vec<Hash> {
    v.as_array().unwrap().iter().map(hash).collect()
}

/// The verdict line `verify-bundle` / `verify-consistency` prints, without `detail`.
fn line_of(check: &str, doc: &str, trust_rel: &str) -> Value {
    let t = trust(trust_rel);
    let form = if check == "bundle" {
        ErrorName::BundleForm
    } else {
        ErrorName::ConsistencyForm
    };
    let got = parse_ijson(&text(doc))
        .map_err(|e| InclusionError::new(form, format!("not I-JSON: {e}")))
        .and_then(|v| {
            if check == "bundle" {
                verify_bundle(&v, &t).map(|x| x.to_json())
            } else {
                verify_consistency(&v, &t).map(|x| x.to_json())
            }
        });
    match got {
        Ok(mut v) => {
            v["verdict"] = "accepted".into();
            v
        }
        Err(e) => refused(&e),
    }
}

/// What the crate says on one manifest case, in the manifest's `expect` shape.
fn outcome(case: &Value) -> Value {
    let s = |k: &str| case[k].as_str().unwrap();
    match s("check") {
        c @ ("bundle" | "consistency") => line_of(c, s("doc"), s("trust")),
        "trust" => match read_trust(s("trust")) {
            Ok(t) => {
                json!({"verdict": "accepted", "tenant": t.tenant(), "m": t.m(), "policy": t.policy().as_str()})
            }
            Err(e) => refused(&e),
        },
        "tenants" => {
            let configs: Vec<LogTrust> = case["trusts"]
                .as_array()
                .unwrap()
                .iter()
                .map(|t| trust(t.as_str().unwrap()))
                .collect();
            match check_tenants(&configs) {
                Ok(()) => json!({"verdict": "accepted"}),
                Err(e) => refused(&e),
            }
        }
        "policy" => {
            let t = trust(s("trust"));
            let result = case["doc"].as_str().map(|d| {
                let v = parse_ijson(&text(d)).unwrap();
                verify_bundle(&v, &t)
            });
            match apply_policy(result, t.policy()) {
                PolicyOutcome::Load(None) => json!({"outcome": "load"}),
                PolicyOutcome::Load(Some(v)) => json!({"outcome": "load", "verdict": v.to_json()}),
                PolicyOutcome::LoadWithWarning(e) => {
                    json!({"outcome": "load_with_warning", "error": e.name.as_str()})
                }
                PolicyOutcome::Refuse(e) => json!({"outcome": "refuse", "error": e.name.as_str()}),
            }
        }
        "leaf_hash" => {
            let leaf = Leaf::from_json(&parse_ijson(&text(s("leaf"))).unwrap()).unwrap();
            json!({"leaf_hash": STANDARD.encode(leaf_hash(&leaf))})
        }
        "rfc9162_inclusion" => {
            let h = hash_leaf_bytes(&unhex(s("leaf_input")));
            Value::Bool(verify_inclusion_path(
                case["leaf_index"].as_u64().unwrap(),
                case["tree_size"].as_u64().unwrap(),
                &h,
                &hashes(&case["path"]),
                &hash(&case["root"]),
            ))
        }
        "rfc9162_consistency" => Value::Bool(verify_consistency_path(
            case["older"].as_u64().unwrap(),
            case["newer"].as_u64().unwrap(),
            &hash(&case["older_root"]),
            &hash(&case["newer_root"]),
            &hashes(&case["path"]),
        )),
        other => panic!("unknown check {other}"),
    }
}

fn manifest() -> Vec<Value> {
    let m: Value = serde_json::from_str(&text("manifest.json")).unwrap();
    m["cases"].as_array().unwrap().clone()
}

#[test]
fn rust_agrees_with_every_inclusion_v1_case() {
    let cases = manifest();
    let mut checks: BTreeMap<String, usize> = BTreeMap::new();
    let mut wrong = Vec::new();
    for case in &cases {
        *checks
            .entry(case["check"].as_str().unwrap().to_string())
            .or_default() += 1;
        let got = outcome(case);
        if got != case["expect"] {
            wrong.push(format!(
                "{}: expected {}, got {got}",
                case["name"], case["expect"]
            ));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    assert!(
        cases.len() >= 290 && checks["bundle"] >= 140 && checks["consistency"] >= 40,
        "expected the inclusion-v1 cases, found {checks:?}"
    );
}

#[test]
fn every_inclusion_error_name_has_a_case() {
    let seen: BTreeSet<String> = manifest()
        .iter()
        .filter_map(|c| c["expect"]["error"].as_str().map(str::to_string))
        .collect();
    for name in ErrorName::ALL {
        assert!(seen.contains(name.as_str()), "no case refuses with {name}");
    }
}

/// The hash list covers exactly the set's files, and every hash matches.
#[test]
fn the_inclusion_v1_hash_list_is_whole() {
    use sha2::{Digest, Sha256};
    let listed: BTreeMap<String, String> = text("INCLUSION.sha256")
        .lines()
        .map(|l| {
            let (h, p) = l.split_once("  ").unwrap();
            (p.to_string(), h.to_string())
        })
        .collect();
    let mut on_disk = BTreeSet::new();
    let mut stack = vec![set_dir()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "json") {
                let rel = p.strip_prefix(set_dir()).unwrap();
                on_disk.insert(rel.to_string_lossy().replace('\\', "/"));
            }
        }
    }
    assert_eq!(listed.keys().cloned().collect::<BTreeSet<_>>(), on_disk);
    for (p, h) in &listed {
        let bytes = std::fs::read(set_dir().join(p)).unwrap();
        let got: String = Sha256::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(&got, h, "{p}");
    }
}
