//! Monitoring without labels against a v1.2 certificate's stored confidence histogram
//! (spec/decision-certificate.v1.2.md §4). The Python verifier's `decision_cert._monitor` is a port
//! with the same arithmetic in the same order.

use crate::Histogram;

/// Pearson's chi-square test of homogeneity between the stored histogram and a window's.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ShiftScore {
    pub statistic: f64,
    pub df: u64,
    pub p_value: f64,
}

impl Histogram {
    /// The histogram of `confidences` on `bins`. Pass None for a case the rule abstains on whatever
    /// the threshold (unscored, or above `rule.cannot_tell_above`), as the issuer counts it. None when a confidence is
    /// outside [0, 1] or `bins` has fewer than two edges.
    pub fn of(bins: &[f64], confidences: impl IntoIterator<Item = Option<f64>>) -> Option<Self> {
        let mut counts = vec![0u64; bins.len().checked_sub(1).filter(|&k| k > 0)?];
        let mut unscored = 0u64;
        for c in confidences {
            match c {
                None => unscored += 1,
                Some(c) => counts[bin_of(bins, c)?] += 1,
            }
        }
        Some(Self { counts, unscored })
    }

    /// The cases it counts: the bins and the unscored.
    pub fn total(&self) -> u64 {
        self.counts
            .iter()
            .fold(self.unscored, |t, &c| t.saturating_add(c))
    }
}

/// The bin of `confidence`: `i` with `bins[i] <= confidence < bins[i + 1]`; the last bin also holds
/// 1. None for a confidence outside [0, 1] (or NaN), or fewer than two edges.
pub fn bin_of(bins: &[f64], confidence: f64) -> Option<usize> {
    if !(0.0..=1.0).contains(&confidence) || bins.len() < 2 {
        return None;
    }
    let i = bins.partition_point(|&e| e <= confidence);
    Some(i.saturating_sub(1).min(bins.len() - 2))
}

/// Compare a window's histogram with the certificate's (spec §4). The columns are the bins and the
/// unscored count; columns empty in both are dropped. With an empty side or one column left there
/// is nothing to compare: statistic 0, df 0, p-value 1. None when the bin counts differ.
pub fn shift_score(baseline: &Histogram, window: &Histogram) -> Option<ShiftScore> {
    if baseline.counts.len() != window.counts.len() {
        return None;
    }
    let row = |h: &Histogram| {
        let mut r = h.counts.clone();
        r.push(h.unscored);
        r
    };
    let (r1, r2) = (row(baseline), row(window));
    let n1 = r1.iter().map(|&x| x as f64).sum::<f64>();
    let n2 = r2.iter().map(|&x| x as f64).sum::<f64>();
    let kept: Vec<(u64, u64)> = r1
        .into_iter()
        .zip(r2)
        .filter(|&(a, b)| a > 0 || b > 0)
        .collect();
    if n1 == 0.0 || n2 == 0.0 || kept.len() < 2 {
        return Some(ShiftScore {
            statistic: 0.0,
            df: 0,
            p_value: 1.0,
        });
    }
    let n = n1 + n2;
    let mut stat = 0.0;
    for &(a, b) in &kept {
        let col = a as f64 + b as f64;
        let (e1, e2) = (n1 * col / n, n2 * col / n);
        stat += (a as f64 - e1).powi(2) / e1;
        stat += (b as f64 - e2).powi(2) / e2;
    }
    let df = kept.len() as u64 - 1;
    Some(ShiftScore {
        statistic: stat,
        df,
        p_value: chi2_sf(stat, df),
    })
}

const LANCZOS_G: f64 = 7.0;
const LANCZOS: [f64; 9] = [
    0.999_999_999_999_809_9,
    676.520_368_121_885_1,
    -1_259.139_216_722_402_8,
    771.323_428_777_653_1,
    -176.615_029_162_140_6,
    12.507_343_278_686_905,
    -0.138_571_095_265_720_12,
    9.984_369_578_019_572e-6,
    1.505_632_735_149_311_6e-7,
];
const EPS: f64 = 1e-15;
const TINY: f64 = 1e-300;
const MAX_ITER: usize = 10_000;

/// ln Γ(z) for z >= 0.5 (Lanczos, g = 7, nine coefficients).
fn ln_gamma(z: f64) -> f64 {
    let z = z - 1.0;
    let mut s = LANCZOS[0];
    for (i, c) in LANCZOS.iter().enumerate().skip(1) {
        s += c / (z + i as f64);
    }
    let t = z + LANCZOS_G + 0.5;
    0.5 * (2.0 * std::f64::consts::PI).ln() + (z + 0.5) * t.ln() - t + s.ln()
}

/// P(X >= x) for X ~ chi-square with `df` degrees of freedom: the regularised upper incomplete
/// gamma Q(df/2, x/2), by its series below a + 1 and its continued fraction above. 1 for df 0.
pub fn chi2_sf(x: f64, df: u64) -> f64 {
    if df == 0 || x.is_nan() || x <= 0.0 {
        return 1.0;
    }
    let (a, h) = (df as f64 / 2.0, x / 2.0);
    let front = -h + a * h.ln() - ln_gamma(a);
    if h < a + 1.0 {
        let (mut ap, mut term) = (a, 1.0 / a);
        let mut total = term;
        for _ in 0..MAX_ITER {
            ap += 1.0;
            term *= h / ap;
            total += term;
            if term.abs() < total.abs() * EPS {
                break;
            }
        }
        return (1.0 - total * front.exp()).max(0.0);
    }
    let mut b = h + 1.0 - a;
    let mut c = 1.0 / TINY;
    let mut d = 1.0 / b;
    let mut f = d;
    for i in 1..MAX_ITER {
        let i = i as f64;
        let an = -i * (i - a);
        b += 2.0;
        d = an * d + b;
        if d.abs() < TINY {
            d = TINY;
        }
        c = b + an / c;
        if c.abs() < TINY {
            c = TINY;
        }
        d = 1.0 / d;
        let step = d * c;
        f *= step;
        if (step - 1.0).abs() < EPS {
            break;
        }
    }
    (front.exp() * f).min(1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chi2_tail_matches_known_values() {
        // scipy.stats.chi2.sf, to 1e-12 relative
        let known = [
            (3.841_458_820_694_124, 1, 0.049_999_999_999_999_94),
            (5.991_464_547_107_979, 2, 0.050_000_000_000_000_08),
            (30.143_527_205_646_16, 19, 0.050_000_000_000_000_01),
            (10.0, 3, 0.018_566_135_463_043_23),
            (150.0, 100, 0.000_903_932_042_354_018_4),
        ];
        for (x, df, p) in known {
            let got = chi2_sf(x, df);
            assert!(
                (got - p).abs() <= 1e-12 * p.max(1e-300) + 1e-15,
                "{x} {df}: {got} vs {p}"
            );
        }
        assert_eq!(chi2_sf(0.0, 4), 1.0);
        assert_eq!(chi2_sf(1e5, 2), 0.0);
    }

    #[test]
    fn bins_are_half_open_and_the_last_holds_one() {
        let bins = [0.0, 0.5, 0.9, 1.0];
        assert_eq!(bin_of(&bins, 0.0), Some(0));
        assert_eq!(bin_of(&bins, 0.5), Some(1));
        assert_eq!(bin_of(&bins, 0.899_999), Some(1));
        assert_eq!(bin_of(&bins, 0.9), Some(2));
        assert_eq!(bin_of(&bins, 1.0), Some(2));
        assert_eq!(bin_of(&bins, 1.01), None);
        assert_eq!(bin_of(&bins, f64::NAN), None);
        let h = Histogram::of(&bins, [Some(0.95), None, Some(0.1), Some(1.0)]).unwrap();
        assert_eq!((h.counts, h.unscored), (vec![1, 0, 2], 1));
    }

    #[test]
    fn identical_histograms_do_not_shift_and_disjoint_ones_do() {
        let a = Histogram {
            counts: vec![10, 20, 30, 0],
            unscored: 5,
        };
        let same = shift_score(&a, &a).unwrap();
        assert_eq!((same.statistic, same.df, same.p_value), (0.0, 3, 1.0));
        let b = Histogram {
            counts: vec![0, 0, 0, 60],
            unscored: 0,
        };
        assert!(shift_score(&a, &b).unwrap().p_value < 1e-20);
        let empty = Histogram {
            counts: vec![0; 4],
            unscored: 0,
        };
        assert_eq!(shift_score(&a, &empty).unwrap().df, 0);
        let short = Histogram {
            counts: vec![1],
            unscored: 0,
        };
        assert!(shift_score(&a, &short).is_none());
    }
}
