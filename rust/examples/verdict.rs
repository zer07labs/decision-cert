//! Print the crate's verdict on fixture files, one JSON line each. Used by
//! `python/tools/gen_negative_fixtures.py` to record verdicts from the reference verifier, and by
//! `python/tests/test_rust_oracle.py`. A file with a `tenant` (the v1.5 sets) is verified for that
//! expected tenant, its `keys` read as a tenant's moded keys.
//!
//! cargo run --example verdict -- <fixture.json>...

use std::collections::BTreeMap;

fn main() {
    for path in std::env::args().skip(1) {
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
        let f: serde_json::Value =
            serde_json::from_str(&text).unwrap_or_else(|e| panic!("{path}: {e}"));
        let got = match f["tenant"].as_str() {
            Some(tenant) => decision_cert::tenant_keys_from_json(&f["keys"]).and_then(|keys| {
                decision_cert::verify_for_tenant(&f["certificate"], tenant, &keys)
            }),
            None => {
                let keys: BTreeMap<String, String> = serde_json::from_value(f["keys"].clone())
                    .unwrap_or_else(|e| panic!("{path}: {e}"));
                decision_cert::verify(&f["certificate"], &keys)
            }
        };
        let line = match got {
            Ok(v) => serde_json::json!({"file": path, "valid": true, "error": null, "id": v.id}),
            Err(e) => serde_json::json!({"file": path, "valid": false, "error": e.to_string()}),
        };
        println!("{line}");
    }
}
