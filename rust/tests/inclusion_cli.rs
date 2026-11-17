//! `decision-cert verify-bundle` and `verify-consistency`: one JSON verdict line on stdout, exit 0
//! accepted, 1 refused, 2 unreadable or a configuration that is not well formed. The bundle and the
//! documents are built here from deterministic test keys (fixed seeds); nothing is read from
//! fixtures/.
#![cfg(feature = "cli")]

use std::path::PathBuf;
use std::process::Command;

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use decision_cert::inclusion::{
    audit_path, c2sp_key_hash, consistency_path, cosignature_message, leaf_hash, root_hash, Hash,
    Leaf, SIG_TYPE_COSIGNATURE_V1, SIG_TYPE_ED25519,
};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};

const LOG: &str = "log:0123456789abcdef0123456789abcdef";
const WITNESS: &str = "witness.example/w1";

fn log_key() -> SigningKey {
    SigningKey::from_bytes(&[3; 32])
}
fn witness_key() -> SigningKey {
    SigningKey::from_bytes(&[4; 32])
}

fn trust() -> Value {
    let entry = |k: &SigningKey| {
        (
            decision_cert::key_id(&k.verifying_key()),
            URL_SAFE_NO_PAD.encode(k.verifying_key().as_bytes()),
        )
    };
    let (log_id, log_pk) = entry(&log_key());
    let (w_id, w_pk) = entry(&witness_key());
    json!({
        "spec": "decision-cert-log-trust.v1",
        "tenant": "acme-eu",
        "logs": [{"log_id": LOG, "key_name": LOG, "key_id": log_id, "key": log_pk}],
        "witnesses": [{"name": WITNESS, "key_id": w_id, "key": w_pk}],
        "policy": "refuse",
    })
}

fn leaves() -> Vec<Value> {
    (0..5)
        .map(|i| {
            json!({
                "kind": "keyset",
                "keyset_id": format!("keyset:{}", "c".repeat(32)),
                "seq": i,
                "keyset": format!("sha256:{i:064x}"),
            })
        })
        .collect()
}
fn hashes(n: usize) -> Vec<Hash> {
    leaves()[..n]
        .iter()
        .map(|l| leaf_hash(&Leaf::from_json(l).unwrap()))
        .collect()
}

fn checkpoint(size: usize) -> String {
    let root = root_hash(&hashes(size)).unwrap();
    let note = format!("{LOG}\n{size}\n{}\n", STANDARD.encode(root));
    let mut log = c2sp_key_hash(LOG, SIG_TYPE_ED25519, &log_key().verifying_key()).to_vec();
    log.extend(log_key().sign(note.as_bytes()).to_bytes());
    let time: u64 = 1_800_000_000;
    let mut w = c2sp_key_hash(
        WITNESS,
        SIG_TYPE_COSIGNATURE_V1,
        &witness_key().verifying_key(),
    )
    .to_vec();
    w.extend(time.to_be_bytes());
    w.extend(
        witness_key()
            .sign(&cosignature_message(&note, time))
            .to_bytes(),
    );
    format!(
        "{note}\n\u{2014} {LOG} {}\n\u{2014} {WITNESS} {}\n",
        STANDARD.encode(log),
        STANDARD.encode(w)
    )
}

fn b64s(hs: &[Hash]) -> Vec<String> {
    hs.iter().map(|h| STANDARD.encode(h)).collect()
}

fn bundle() -> Value {
    json!({
        "spec": "decision-cert-inclusion.v1",
        "log_id": LOG,
        "leaf_index": 2,
        "leaf": leaves()[2],
        "proof": b64s(&audit_path(&hashes(5), 2).unwrap()),
        "checkpoint": checkpoint(5),
    })
}

fn consistency() -> Value {
    json!({
        "spec": "decision-cert-consistency.v1",
        "log_id": LOG,
        "older": checkpoint(3),
        "newer": checkpoint(5),
        "proof": b64s(&consistency_path(&hashes(5), 3).unwrap()),
    })
}

fn write(name: &str, text: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("inclusion_cli");
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join(name);
    std::fs::write(&p, text).unwrap();
    p
}

/// Run the CLI: its exit code and its stdout lines.
fn run(cmd: &str, doc: &PathBuf, trust: &PathBuf) -> (i32, Vec<String>) {
    let out = Command::new(env!("CARGO_BIN_EXE_decision-cert"))
        .arg(cmd)
        .arg(doc)
        .arg("--trust")
        .arg(trust)
        .output()
        .unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();
    (
        out.status.code().unwrap(),
        stdout.lines().map(str::to_string).collect(),
    )
}

fn verdict(lines: &[String]) -> Value {
    assert_eq!(lines.len(), 1, "one verdict line: {lines:?}");
    serde_json::from_str(&lines[0]).unwrap()
}

#[test]
fn verify_bundle_cli() {
    let t = write("bundle-trust.json", &trust().to_string());
    let (code, out) = run(
        "verify-bundle",
        &write("bundle.json", &bundle().to_string()),
        &t,
    );
    let v = verdict(&out);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["verdict"], "accepted");
    assert_eq!(v["leaf_index"], 2);
    assert_eq!(v["kind"], "keyset");
    assert_eq!(v["t_proven"], "2027-01-15T08:00:00Z");
    assert_eq!(v["witnesses"][0]["name"], WITNESS);

    // refused: the wrong leaf index
    let mut b = bundle();
    b["leaf_index"] = json!(3);
    let (code, out) = run(
        "verify-bundle",
        &write("bad-proof.json", &b.to_string()),
        &t,
    );
    let v = verdict(&out);
    assert_eq!(
        (code, v["verdict"].as_str(), v["error"].as_str()),
        (1, Some("refused"), Some("bad_proof"))
    );

    // refused: a member named twice is not I-JSON
    let text = bundle().to_string().replacen('{', "{\"spec\":\"x\",", 1);
    let (code, out) = run("verify-bundle", &write("dup.json", &text), &t);
    assert_eq!(
        (code, verdict(&out)["error"].clone()),
        (1, json!("bundle_form"))
    );

    // exit 2: an unreadable bundle, a malformed configuration
    let (code, out) = run(
        "verify-bundle",
        &PathBuf::from("/nonexistent/bundle.json"),
        &t,
    );
    assert_eq!((code, out.len()), (2, 0));
    let mut bad = trust();
    bad["m"] = json!(2);
    let bt = write("bad-trust.json", &bad.to_string());
    let (code, out) = run(
        "verify-bundle",
        &write("bundle2.json", &bundle().to_string()),
        &bt,
    );
    assert_eq!((code, out.len()), (2, 0));
}

#[test]
fn verify_consistency_cli() {
    let t = write("consistency-trust.json", &trust().to_string());
    let (code, out) = run(
        "verify-consistency",
        &write("consistency.json", &consistency().to_string()),
        &t,
    );
    let v = verdict(&out);
    assert_eq!(code, 0, "{v}");
    assert_eq!(
        v,
        json!({"verdict": "accepted", "log_id": LOG, "older_size": 3, "newer_size": 5})
    );

    // refused: newer smaller than older
    let mut d = consistency();
    d["older"] = json!(checkpoint(5));
    d["newer"] = json!(checkpoint(3));
    let (code, out) = run(
        "verify-consistency",
        &write("regression.json", &d.to_string()),
        &t,
    );
    assert_eq!(
        (code, verdict(&out)["error"].clone()),
        (1, json!("size_regression"))
    );

    // a bundle given as a consistency proof document
    let (code, out) = run(
        "verify-consistency",
        &write("wrong-kind.json", &bundle().to_string()),
        &t,
    );
    assert_eq!(
        (code, verdict(&out)["error"].clone()),
        (1, json!("consistency_form"))
    );
}
