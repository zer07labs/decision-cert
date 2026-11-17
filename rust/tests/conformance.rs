//! The Rust verifier agrees with the issuer on the JCS bytes, the certificate id and the
//! verdict of every fixture in fixtures/ (v1), fixtures/v1.1/, fixtures/v1.2/, fixtures/v1.3/,
//! fixtures/v1.4/ and fixtures/v1.5/ (see fixtures/README.md for which program wrote each). The v1 to
//! v1.4 sets are frozen: a newer verifier gives every one of their files the same verdict, id and
//! bytes. A v1.5 file carries the expected `tenant` and moded `keys`, and is verified with
//! `verify_for_tenant`.

use std::{collections::BTreeMap, path::PathBuf};

use base64::{engine::general_purpose::STANDARD, Engine};
use decision_cert::{
    canonical, certificate_id, tenant_keys_from_json, verify, verify_for_tenant, CertError,
    Verified,
};

/// A fixture's verdict: for its expected tenant when it has one (v1.5), else with `verify`.
fn verdict(f: &serde_json::Value, cert: &serde_json::Value) -> Result<Verified, CertError> {
    match f["tenant"].as_str() {
        Some(tenant) => verify_for_tenant(cert, tenant, &tenant_keys_from_json(&f["keys"])?),
        None => {
            let keys: BTreeMap<String, String> = serde_json::from_value(f["keys"].clone()).unwrap();
            verify(cert, &keys)
        }
    }
}

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

#[test]
fn rust_and_python_agree_on_every_v1_5_fixture() {
    let set = fixtures("v1.5", 100);
    assert!(set.iter().all(|(_, f)| f["tenant"].is_string()));
    assert!(set.iter().any(|(_, f)| f["valid"].as_bool().unwrap()
        && f["certificate"]["spec"] == "decision-certificate.v1.5"
        && f["certificate"]["signer"]["mode"] == "hosted"));
    assert!(set.iter().any(|(_, f)| f["valid"].as_bool().unwrap()
        && f["certificate"]["spec"] == "decision-certificate.v1.4"));
    agree_on(set);
}

/// `verify` keeps its meaning for v1 to v1.4 and refuses a v1.5 certificate, which binds a tenant;
/// `verify_for_tenant` reads its tenant and signer.
#[test]
fn verify_refuses_a_v1_5_certificate_and_verify_for_tenant_reads_it() {
    for name in ["valid_operator", "valid_hosted"] {
        let (_, f) = fixtures("v1.5", 1)
            .into_iter()
            .find(|(n, _)| n == name)
            .unwrap();
        let flat: BTreeMap<String, String> = f["keys"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v["key"].as_str().unwrap().to_string()))
            .collect();
        let e = verify(&f["certificate"], &flat).unwrap_err().to_string();
        assert!(
            e.contains(
                "a v1.5 certificate is verified with its expected tenant (verify_for_tenant)"
            ),
            "{name}: {e}"
        );
        let v = verdict(&f, &f["certificate"]).unwrap();
        assert_eq!(v.tenant(), f["tenant"].as_str());
        assert_eq!(
            v.signer().unwrap().mode,
            f["certificate"]["signer"]["mode"].as_str().unwrap()
        );
        // another expected tenant: the field check refuses it
        let e = verify_for_tenant(
            &f["certificate"],
            "another-tenant",
            &tenant_keys_from_json(&f["keys"]).unwrap(),
        )
        .unwrap_err();
        assert!(matches!(e, CertError::WrongTenant(_)), "{name}: {e}");
        // an expected tenant outside the character set
        let e = verify_for_tenant(
            &f["certificate"],
            "a b",
            &tenant_keys_from_json(&f["keys"]).unwrap(),
        )
        .unwrap_err();
        assert!(
            e.to_string().contains("expected tenant must be"),
            "{name}: {e}"
        );
    }
    let (_, f) = fixtures("v1.4", 1)
        .into_iter()
        .find(|(n, _)| n == "valid_basic")
        .unwrap();
    let keys: BTreeMap<String, String> = serde_json::from_value(f["keys"].clone()).unwrap();
    assert!(verify(&f["certificate"], &keys).unwrap().tenant().is_none());
}

/// Key entries: a bare string is an operator key; a moded entry with an unknown field, a mode
/// without its host (or the reverse), or a host that is not a key id is refused.
#[test]
fn tenant_keys_are_read_strictly() {
    use decision_cert::KeyMode;
    let host = "ed25519:0123456789abcdef";
    let ok = tenant_keys_from_json(&serde_json::json!({
        "ed25519:aaaaaaaaaaaaaaaa": "AAAA",
        "ed25519:bbbbbbbbbbbbbbbb": {"key": "BBBB", "mode": "operator"},
        "ed25519:cccccccccccccccc": {"key": "CCCC", "mode": "hosted", "host": host},
    }))
    .unwrap();
    assert_eq!(ok["ed25519:aaaaaaaaaaaaaaaa"].mode, KeyMode::Operator);
    assert_eq!(ok["ed25519:bbbbbbbbbbbbbbbb"].key, "BBBB");
    assert_eq!(
        ok["ed25519:cccccccccccccccc"].mode,
        KeyMode::Hosted { host: host.into() }
    );
    for bad in [
        serde_json::json!({"key": "K", "mode": "operator", "host": host}),
        serde_json::json!({"key": "K", "mode": "hosted"}),
        serde_json::json!({"key": "K", "mode": "hosted", "host": "hosting.example"}),
        serde_json::json!({"key": "K", "mode": "hosted", "host": "ed25519:0123456789ABCDEF"}),
        serde_json::json!({"key": "K", "mode": "delegated"}),
        serde_json::json!({"key": "K", "mode": "operator", "extra": 1}),
        serde_json::json!({"mode": "operator"}),
        serde_json::json!(7),
    ] {
        let e = tenant_keys_from_json(&serde_json::json!({"ed25519:aaaaaaaaaaaaaaaa": bad}));
        assert!(matches!(e, Err(CertError::BadKey(_))), "{bad}");
    }
    assert!(tenant_keys_from_json(&serde_json::json!(["k"])).is_err());
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
    assert_eq!(c.c_max, 16);
    assert_eq!(c.matrix[1][0], 16);
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
        let got = verdict(&f, cert);
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

#[test]
fn every_v1_5_schema_invalid_mutation_is_rejected() {
    rejects_every_mutation("v1.5/mutations/schema_invalid.json");
}

fn rejects_every_mutation(rel: &str) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../fixtures")
        .join(rel);
    let f: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let accepted: Vec<String> = f["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| verdict(&f, &c["certificate"]).is_ok())
        .map(|c| format!("{} {}", c["path"], c["edit"]))
        .collect();
    assert!(accepted.is_empty(), "accepted: {accepted:?}");
}
