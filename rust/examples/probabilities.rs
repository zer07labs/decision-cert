//! Apply calibration maps to raw scores, one JSON line per case. Used by
//! python/tests/test_rust_oracle.py to check the Python port of `probabilities`.
//!
//! cargo run --example probabilities -- <cases.json>
//!
//! Each case: `{"map": {"kind", "params", "label_budget"}, "scores": [..]}`.
//! Output: `{"probabilities": [..] | null, "confidence": c | null}`.

use decision_cert::{confidence, probabilities, CalibrationMap};

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: probabilities <cases.json>");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let cases: Vec<serde_json::Value> = serde_json::from_str(&text).expect("a JSON array");
    for c in cases {
        let map: CalibrationMap = serde_json::from_value(c["map"].clone()).unwrap();
        let scores: Vec<f64> = serde_json::from_value(c["scores"].clone()).unwrap();
        let line = serde_json::json!({
            "probabilities": probabilities(&map, &scores),
            "confidence": confidence(&map, &scores),
        });
        println!("{line}");
    }
}
