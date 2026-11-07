//! Print the crate's verdict on fixture files, one JSON line each. Used by
//! `python/tools/gen_negative_fixtures.py` to record verdicts from the reference verifier.
//!
//! cargo run --example verdict -- <fixture.json>...

use std::collections::BTreeMap;

fn main() {
    for path in std::env::args().skip(1) {
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
        let f: serde_json::Value =
            serde_json::from_str(&text).unwrap_or_else(|e| panic!("{path}: {e}"));
        let keys: BTreeMap<String, String> =
            serde_json::from_value(f["keys"].clone()).unwrap_or_else(|e| panic!("{path}: {e}"));
        let line = match decision_cert::verify(&f["certificate"], &keys) {
            Ok(v) => serde_json::json!({"file": path, "valid": true, "error": null, "id": v.id}),
            Err(e) => serde_json::json!({"file": path, "valid": false, "error": e.to_string()}),
        };
        println!("{line}");
    }
}
