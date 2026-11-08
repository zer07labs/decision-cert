//! Bin windows of confidences and score them against a baseline histogram, one JSON line per case.
//! Used by python/tests/test_rust_oracle.py to check the Python port of the monitoring functions.
//!
//! cargo run --example monitor -- <cases.json>
//!
//! Each case: `{"bins": [..], "baseline": {"counts": [..], "unscored": n}, "confidences": [c | null, ..]}`.
//! Output: `{"window": {"counts", "unscored"} | null, "score": {"statistic", "df", "p_value"} | null}`.

use decision_cert::{shift_score, Histogram};

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: monitor <cases.json>");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let cases: Vec<serde_json::Value> = serde_json::from_str(&text).expect("a JSON array");
    for c in cases {
        let bins: Vec<f64> = serde_json::from_value(c["bins"].clone()).unwrap();
        let base: Histogram = serde_json::from_value(c["baseline"].clone()).unwrap();
        let conf: Vec<Option<f64>> = serde_json::from_value(c["confidences"].clone()).unwrap();
        let window = Histogram::of(&bins, conf);
        let score = window.as_ref().and_then(|w| shift_score(&base, w));
        let line = serde_json::json!({
            "window": window.map(|w| serde_json::json!({"counts": w.counts, "unscored": w.unscored})),
            "score": score.map(|s| serde_json::json!({"statistic": s.statistic, "df": s.df, "p_value": s.p_value})),
        });
        println!("{line}");
    }
}
