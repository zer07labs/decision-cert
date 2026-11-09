//! Calibration maps (spec v1.2 §1 and §2): the parameter shape of each kind v1.2 defines, and the
//! probabilities a map gives a case's raw scores.

use std::collections::BTreeMap;

use crate::{CalibrationMap, CertError};

/// The kinds of calibration map v1.2 defines. A certificate may name another kind; it still
/// verifies, and a consumer that does not apply that kind refuses it (spec v1.2 §4).
pub const MAP_KINDS: [&str; 2] = ["temperature", "dr"];

/// `params.temperature` of a `temperature` map, when the params have exactly that shape.
fn temperature(params: &BTreeMap<String, f64>) -> Option<f64> {
    let t = *params.get("temperature")?;
    (params.len() == 1 && t > 0.0).then_some(t)
}

/// `(a, [b0, .., b{k-1}])` of a `dr` map over `k` options, when the params have exactly that shape.
fn dr(params: &BTreeMap<String, f64>, k: usize) -> Option<(f64, Vec<f64>)> {
    let a = *params.get("a")?;
    let b = (0..k)
        .map(|i| params.get(&format!("b{i}")).copied())
        .collect::<Option<Vec<f64>>>()?;
    (params.len() == k + 1 && a > 0.0).then_some((a, b))
}

/// v1.2's checks of the map's parameters (spec v1.2 §2), for a certificate with `k` options. A kind
/// v1.2 does not define is not checked.
pub(crate) fn check(m: &CalibrationMap, k: usize) -> Result<(), CertError> {
    let bad = |s: &str| Err(CertError::Invalid(s.to_string()));
    match m.kind.as_str() {
        "temperature" if temperature(&m.params).is_none() => {
            bad("a `temperature` calibration_map needs exactly the param `temperature`, above 0")
        }
        "dr" if dr(&m.params, k).is_none() || !m.label_budget.is_some_and(|n| n >= 1) => bad(
            "a `dr` calibration_map needs exactly the params `a`, above 0, and `b0` to `b{k-1}` for its k options, and a label_budget of at least 1",
        ),
        _ => Ok(()),
    }
}

/// The probabilities `map` gives a case's raw scores, one per option in score order (spec v1.2 §1):
/// - `temperature`: softmax(scores / temperature);
/// - `dr`: softmax(a · scores + b), with `b` the params `b0` to `b{k-1}`.
///
/// None when the kind is not one of [`MAP_KINDS`], its params do not have that kind's shape for
/// `scores.len()` options, there are fewer than 2 scores, or a score or logit is not finite. The
/// case's confidence is the largest probability ([`confidence`]).
pub fn probabilities(map: &CalibrationMap, scores: &[f64]) -> Option<Vec<f64>> {
    if scores.len() < 2 {
        return None;
    }
    let logits: Vec<f64> = match map.kind.as_str() {
        "temperature" => {
            let t = temperature(&map.params)?;
            scores.iter().map(|s| s / t).collect()
        }
        "dr" => {
            let (a, b) = dr(&map.params, scores.len())?;
            scores.iter().zip(&b).map(|(s, b)| a * s + b).collect()
        }
        _ => return None,
    };
    if !logits.iter().all(|z| z.is_finite()) {
        return None;
    }
    let top = logits.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    let e: Vec<f64> = logits.iter().map(|z| (z - top).exp()).collect();
    let mut total = 0.0;
    for x in &e {
        total += x;
    }
    Some(e.iter().map(|x| x / total).collect())
}

/// A case's confidence under `map`: the largest of its [`probabilities`]. None when those are.
pub fn confidence(map: &CalibrationMap, scores: &[f64]) -> Option<f64> {
    probabilities(map, scores).map(|p| p.into_iter().fold(f64::NEG_INFINITY, f64::max))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(kind: &str, params: &[(&str, f64)], label_budget: Option<u64>) -> CalibrationMap {
        CalibrationMap {
            kind: kind.into(),
            params: params.iter().map(|(k, v)| (k.to_string(), *v)).collect(),
            label_budget,
        }
    }

    #[test]
    fn temperature_divides_the_scores() {
        let m = map("temperature", &[("temperature", 2.0)], None);
        let p = probabilities(&m, &[2.0, 0.0]).unwrap();
        let want = 1.0 / (1.0 + (-1.0f64).exp());
        assert!((p[0] - want).abs() < 1e-15 && (p[0] + p[1] - 1.0).abs() < 1e-15);
        assert!(probabilities(
            &map("temperature", &[("temperature", 0.0)], None),
            &[1.0, 0.0]
        )
        .is_none());
        assert!(probabilities(&m, &[1.0]).is_none());
    }

    #[test]
    fn dr_scales_and_shifts_the_scores() {
        let m = map(
            "dr",
            &[("a", 0.5), ("b0", 1.0), ("b1", 0.0), ("b2", -1.0)],
            Some(50),
        );
        let p = probabilities(&m, &[0.0, 0.0, 4.0]).unwrap();
        let z = [1.0f64, 0.0, 1.0];
        let s: f64 = z.iter().map(|x| x.exp()).sum();
        for (got, z) in p.iter().zip(z) {
            assert!((got - z.exp() / s).abs() < 1e-15);
        }
        assert_eq!(confidence(&m, &[0.0, 0.0, 4.0]), Some(p[0].max(p[2])));
        // The params name the number of options: 3 here, so 2 or 4 scores do not fit.
        assert!(probabilities(&m, &[0.0, 1.0]).is_none());
        assert!(probabilities(&m, &[0.0, 1.0, 2.0, 3.0]).is_none());
        assert!(probabilities(&map("isotonic", &[], None), &[0.0, 1.0]).is_none());
        assert!(probabilities(&m, &[0.0, f64::MAX, 1e308]).is_some());
        assert!(probabilities(
            &map("dr", &[("a", 4.0), ("b0", 0.0), ("b1", 0.0)], Some(1)),
            &[f64::MAX, 0.0]
        )
        .is_none());
    }

    #[test]
    fn check_holds_each_kind_to_its_shape() {
        let ok = |m: &CalibrationMap| check(m, 2).is_ok();
        assert!(ok(&map("temperature", &[("temperature", 1.3)], None)));
        assert!(ok(&map("temperature", &[("temperature", 1.3)], Some(200))));
        assert!(!ok(&map("temperature", &[("temperature", -1.0)], None)));
        assert!(!ok(&map(
            "temperature",
            &[("temperature", 1.3), ("x", 1.0)],
            None
        )));
        assert!(!ok(&map("temperature", &[], None)));
        let dr2 = [("a", 0.9), ("b0", 0.1), ("b1", -0.1)];
        assert!(ok(&map("dr", &dr2, Some(1))));
        assert!(!ok(&map("dr", &dr2, None)));
        assert!(!ok(&map("dr", &dr2, Some(0))));
        assert!(!ok(&map(
            "dr",
            &[("a", 0.0), ("b0", 0.1), ("b1", -0.1)],
            Some(9)
        )));
        assert!(!ok(&map("dr", &[("a", 0.9), ("b0", 0.1)], Some(9))));
        assert!(!ok(&map(
            "dr",
            &[("a", 0.9), ("b0", 0.1), ("b2", 0.1)],
            Some(9)
        )));
        assert!(!ok(&map(
            "dr",
            &[("a", 0.9), ("b0", 0.1), ("b1", 0.1), ("b2", 0.1)],
            Some(9)
        )));
        assert!(ok(&map("isotonic", &[("knots", 3.0)], None)));
    }
}
