//! The Rust verifier agrees with the issuer on the JCS bytes, the certificate id and the
//! verdict of every fixture in fixtures/ (v1), fixtures/v1.1/, fixtures/v1.2/, fixtures/v1.3/ and fixtures/v1.4/
//! (see fixtures/README.md for which program wrote each). The v1, v1.1 and v1.2 sets are frozen: a
//! newer verifier gives every one of their files the same verdict, id and bytes.

use std::{collections::BTreeMap, path::PathBuf};

use base64::{engine::general_purpose::STANDARD, Engine};
use decision_cert::{canonical, certificate_id, verify};

fn fixtures(set: &str, min: usize) -> Vec<(String, serde_json::Value)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../fixtures")
        .join(set);
    let mut out: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .map(|p| {
            let v = serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
            (p.file_stem().unwrap().to_string_lossy().to_string(), v)
        })
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    assert!(
        out.len() >= min,
        "expected the conformance fixtures in {}, found {}",
        dir.display(),
        out.len()
    );
    out
}

#[test]
fn rust_and_python_agree_on_every_fixture() {
    agree_on(fixtures("", 14));
}

#[test]
fn rust_and_python_agree_on_every_v1_1_fixture() {
    let set = fixtures("v1.1", 9);
    assert!(set.iter().any(|(_, f)| f["valid"].as_bool().unwrap()
        && f["certificate"]["spec"] == "decision-certificate.v1.1"));
    agree_on(set);
}

#[test]
fn rust_and_python_agree_on_every_v1_2_fixture() {
    let set = fixtures("v1.2", 25);
    assert!(set.iter().any(|(_, f)| f["valid"].as_bool().unwrap()
        && f["certificate"]["spec"] == "decision-certificate.v1.2"
        && f["certificate"]["confidence_histogram"].is_object()));
    agree_on(set);
}

#[test]
fn rust_and_python_agree_on_every_v1_3_fixture() {
    let set = fixtures("v1.3", 43);
    assert!(set.iter().any(|(_, f)| f["valid"].as_bool().unwrap()
        && f["certificate"]["spec"] == "decision-certificate.v1.3"
        && f["certificate"]["automate_options"] == serde_json::json!(["yes"])));
    agree_on(set);
}

#[test]
fn rust_and_python_agree_on_every_v1_4_fixture() {
    let set = fixtures("v1.4", 70);
    assert!(set.iter().any(|(_, f)| f["valid"].as_bool().unwrap()
        && f["certificate"]["spec"] == "decision-certificate.v1.4"
        && f["certificate"]["risk"] == "selective_cost"
        && f["certificate"]["options"].as_array().unwrap().len() == 3));
    agree_on(set);
}

/// A v1.4 verifier reads a `selective_cost` certificate's costs, and finds none in an error-risk or
/// earlier certificate.
#[test]
fn costs_are_read_from_v1_4_cost_certificates_only() {
    let read = |set: &str, name: &str| {
        let (_, f) = fixtures(set, 1)
            .into_iter()
            .find(|(n, _)| n == name)
            .unwrap();
        let keys: BTreeMap<String, String> = serde_json::from_value(f["keys"].clone()).unwrap();
        verify(&f["certificate"], &keys).unwrap()
    };
    for (set, name) in [
        ("v1.3", "valid_basic"),
        ("v1.4", "valid_basic"),
        ("v1.4", "valid_crc_abstain_all"),
    ] {
        assert!(read(set, name).cost().is_none(), "{set}/{name}");
    }
    let v = read("v1.4", "valid_cost_three_options");
    let c = v.cost().unwrap();
    assert_eq!(c.c_max, 8.0);
    assert_eq!(c.matrix[1][0], 8.0);
    assert!(c.unit.is_none());
    assert_eq!(
        read("v1.4", "valid_cost_basic")
            .cost()
            .unwrap()
            .unit
            .as_deref(),
        Some("usd")
    );
}

/// A v1.3 verifier reads the automated options and each test's automated cases, and finds none in
/// an earlier certificate.
#[test]
fn automated_cases_are_read_from_v1_3_certificates_only() {
    let read = |set: &str, name: &str| {
        let (_, f) = fixtures(set, 1)
            .into_iter()
            .find(|(n, _)| n == name)
            .unwrap();
        let keys: BTreeMap<String, String> = serde_json::from_value(f["keys"].clone()).unwrap();
        verify(&f["certificate"], &keys).unwrap()
    };
    for set in ["", "v1.1", "v1.2"] {
        let v = read(set, "valid_segments_unicode");
        assert!(v.automate_options().is_none() && v.automated_for(None).is_none());
    }
    let all = read("v1.3", "valid_basic");
    assert_eq!(all.automate_options().unwrap(), ["yes", "no"]);
    assert_eq!(all.automated_for(None).unwrap().coverage, all.cert.coverage);
    let v = read("v1.3", "valid_automated_subset");
    assert_eq!(v.automate_options().unwrap(), ["yes"]);
    assert_eq!(v.automated_for(None).unwrap().coverage, 0.3);
    assert_eq!(v.automated_for(Some("east")).unwrap().coverage, 0.2);
    // The inherited segment is decided with the remainder, so its cases read the top-level block.
    assert_eq!(
        v.automated_for(Some("z\u{fc}rich \u{2603}")),
        v.automated_for(None)
    );
}

/// A v1.2 verifier reads a v1.2 certificate's histograms, and finds none in a v1 or v1.1 one.
#[test]
fn histograms_are_read_from_v1_2_certificates_only() {
    let read = |set: &str, name: &str| {
        let (_, f) = fixtures(set, 1)
            .into_iter()
            .find(|(n, _)| n == name)
            .unwrap();
        let keys: BTreeMap<String, String> = serde_json::from_value(f["keys"].clone()).unwrap();
        verify(&f["certificate"], &keys).unwrap()
    };
    for set in ["", "v1.1"] {
        let v = read(set, "valid_segments_unicode");
        assert!(v.confidence_bins().is_none() && v.histogram_for(None).is_none());
    }
    let v = read("v1.2", "valid_segments_unicode");
    assert_eq!(v.confidence_bins().unwrap().len(), 10);
    assert_eq!(v.histogram_for(None).unwrap().total(), v.cert.n);
    assert_eq!(v.histogram_for(Some("east")).unwrap().total(), 600);
    // The inherited segment is decided, and so monitored, with the remainder.
    assert_eq!(
        v.histogram_for(Some("z\u{fc}rich \u{2603}")),
        v.histogram_for(None)
    );
    assert!(read("v1.2", "valid_histogram_withheld")
        .histogram_for(None)
        .is_none());
}

/// A v1.2 verifier applies the map kinds v1.2 defines, and gives no probabilities for another kind.
#[test]
fn maps_are_applied_for_the_kinds_v1_2_defines() {
    let read = |name: &str| {
        let (_, f) = fixtures("v1.2", 1)
            .into_iter()
            .find(|(n, _)| n == name)
            .unwrap();
        let keys: BTreeMap<String, String> = serde_json::from_value(f["keys"].clone()).unwrap();
        verify(&f["certificate"], &keys).unwrap()
    };
    // dr: softmax(a · s + b) with a 0.8125, b (0.375, -0.375); scores (1, -1) give logits ±1.1875.
    let dr = read("valid_dr_map");
    let p = dr.probabilities(&[1.0, -1.0]).unwrap();
    let want = 1.0 / (1.0 + (-2.375f64).exp());
    assert!((p[0] - want).abs() < 1e-15 && (p[0] + p[1] - 1.0).abs() < 1e-15);
    assert_eq!(dr.confidence(&[1.0, -1.0]), Some(p[0]));
    assert!(
        dr.probabilities(&[1.0, -1.0, 0.0]).is_none(),
        "one score per option"
    );
    assert!(dr.temperature().is_none());
    let t = read("valid_basic");
    assert!(t.probabilities(&[0.0, 0.0]).unwrap() == vec![0.5, 0.5]);
    assert!(read("valid_other_map_kind")
        .probabilities(&[1.0, 0.0])
        .is_none());
}

fn agree_on(set: Vec<(String, serde_json::Value)>) {
    for (name, f) in set {
        let cert = &f["certificate"];
        let mut body = cert.as_object().unwrap().clone();
        body.remove("signature");
        let jcs = canonical(&serde_json::Value::Object(body)).unwrap();
        assert_eq!(
            STANDARD.encode(&jcs),
            f["body_jcs_b64"].as_str().unwrap(),
            "{name}: JCS bytes differ:\n{}",
            String::from_utf8_lossy(&jcs)
        );
        assert_eq!(
            certificate_id(cert).unwrap(),
            f["certificate_id"].as_str().unwrap(),
            "{name}"
        );
        let keys: BTreeMap<String, String> = serde_json::from_value(f["keys"].clone()).unwrap();
        let got = verify(cert, &keys);
        if f["valid"].as_bool().unwrap() {
            let v = got.unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(v.id, f["certificate_id"].as_str().unwrap(), "{name}");
        } else {
            let e = got.expect_err(&name).to_string();
            let want = f["error"].as_str().unwrap();
            assert!(
                e.contains(want),
                "{name}: error {e:?} does not mention {want:?}"
            );
        }
    }
}

/// Signed certificates the schema rejects (one per field and edit, generated by the reference
/// issuer): this verifier must reject every one too.
#[test]
fn every_schema_invalid_mutation_is_rejected() {
    rejects_every_mutation("mutations/schema_invalid.json");
}

#[test]
fn every_v1_1_schema_invalid_mutation_is_rejected() {
    rejects_every_mutation("v1.1/mutations/schema_invalid.json");
}

#[test]
fn every_v1_2_schema_invalid_mutation_is_rejected() {
    rejects_every_mutation("v1.2/mutations/schema_invalid.json");
}

#[test]
fn every_v1_3_schema_invalid_mutation_is_rejected() {
    rejects_every_mutation("v1.3/mutations/schema_invalid.json");
}

#[test]
fn every_v1_4_schema_invalid_mutation_is_rejected() {
    rejects_every_mutation("v1.4/mutations/schema_invalid.json");
}

fn rejects_every_mutation(rel: &str) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../fixtures")
        .join(rel);
    let f: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let keys: BTreeMap<String, String> = serde_json::from_value(f["keys"].clone()).unwrap();
    let accepted: Vec<String> = f["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| verify(&c["certificate"], &keys).is_ok())
        .map(|c| format!("{} {}", c["path"], c["edit"]))
        .collect();
    assert!(accepted.is_empty(), "accepted: {accepted:?}");
}
