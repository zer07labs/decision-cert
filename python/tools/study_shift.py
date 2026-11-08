"""Simulation study for open item O2 of the v1.1 draft: can a label-free score see the shifts that
break a certificate?

    cd python && uv run python tools/study_shift.py [--reps 500] [--json out.json]

Deterministic (pinned seeds). The calibration population is the O3 study's mixture: an easy group
(error with probability 0.3 * (1 - c)) and a hard group (0.8 * (1 - c)), 20% hard, with confidence
c ~ Uniform(0.5, 1) in both. A pooled `ltt` certificate (alpha 0.05, delta 0.1, n_cal 3,000 and a
temperature split of the same size, grid start as decided for O1) is issued on each draw. Then a
window of m use-time cases arrives from one of four populations:

- none: the calibration population (measures false alarms);
- mix: the hard share rises to 50%, and confidences look the same (the O3 case);
- confidence: confidences move toward the low end (c = 0.5 + 0.5 * B, B ~ Beta(1, 2)), and the
  error at each confidence is unchanged;
- concept: the error at every confidence is 1.5 times higher, and confidences are unchanged.

The true use-time selective error at the certified threshold is exact: for uniform confidences it
is beta * (1 - lam) / 2, and for the low-skewed ones 2 * beta * (1 - lam) / 3, mixed over groups by
their answered shares. Three label-free scores are tested at level 0.05 on each window:

- coverage: the window's answered share against the threshold split's (a two-sample test). The
  certificate already carries `coverage` and `n`, so a consumer can run this on v1;
- confidence: a two-sample Kolmogorov-Smirnov test of the window's confidences against the
  threshold split's. A consumer would need the calibration confidences, a new field;
- segment share: the window's hard share against the threshold split's (a two-sample test). This
  needs the group observed and its calibration share, a new field.

Reported per population and window size: breaks, the share of draws whose true use-time error at the
certified threshold is above alpha; and the share of draws each score flags.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

import numpy as np
from scipy import stats

from decision_cert.issue import stats as cs

ALPHA, DELTA, LEVEL = 0.05, 0.1, 0.05
EASY, HARD, CAL_HARD = 0.3, 0.8, 0.2
N_CAL = 3000
WINDOWS = [1000, 5000]
POPULATIONS = ["none", "mix", "confidence", "concept"]
SEED = 20261111


def population(name: str) -> tuple[float, bool, float]:
    """(hard share, low-skewed confidences, error multiplier)."""
    return {
        "none": (CAL_HARD, False, 1.0),
        "mix": (0.5, False, 1.0),
        "confidence": (CAL_HARD, True, 1.0),
        "concept": (CAL_HARD, False, 1.5),
    }[name]


def draw(rng: np.random.Generator, n: int, pop: str) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    share, skewed, mult = population(pop)
    hard = rng.random(n) < share
    conf = 0.5 + 0.5 * rng.beta(1.0, 2.0, n) if skewed else rng.uniform(0.5, 1.0, n)
    err = rng.random(n) < mult * np.where(hard, HARD, EASY) * (1 - conf)
    return conf, err, hard


def true_error(lam: float, pop: str) -> float:
    share, skewed, mult = population(pop)
    t = 1 - max(lam, 0.5)
    if t <= 0:
        return 0.0
    per = (2 / 3 if skewed else 1 / 2) * t  # error among answered, per unit of beta
    beta = mult * (share * HARD + (1 - share) * EASY)  # both groups answer the same share
    return beta * per


def two_sample(k1: int, n1: int, k2: int, n2: int) -> float:
    table = np.array([[k1, n1 - k1], [k2, n2 - k2]])
    if (table.sum(axis=0) == 0).any():
        return 1.0
    return float(stats.chi2_contingency(table, correction=False)[1])


def replicate(rep: int) -> dict[str, Any]:
    rng = np.random.default_rng([SEED, rep])
    ct, et, _ = draw(rng, N_CAL, "none")
    ca, ea, ha = draw(rng, N_CAL, "none")
    u = np.unique(ct)[::-1]
    cuts = np.array([cs._between(float(u[i + 1]), float(u[i])) for i in range(len(u) - 1)] + [0.0])
    n, e = cs.counts(ct, et, cuts)
    p = np.where(n > 0, stats.binom.cdf(e, np.maximum(n, 1), ALPHA), 1.0)
    lam = cs.ltt(ca, ea, cuts[int(np.argmin(p)) :], ALPHA, DELTA).abstain_below
    out: dict[str, Any] = {"certified": lam < cs.ABSTAIN_ALL}
    if not out["certified"]:
        return out
    cal_answered = int((ca >= lam).sum())
    for pop in POPULATIONS:
        out[pop] = {"breaks": true_error(lam, pop) > ALPHA}
        for m in WINDOWS:
            cw, _, hw = draw(rng, m, pop)
            out[pop][m] = {
                "coverage": two_sample(int((cw >= lam).sum()), m, cal_answered, N_CAL) <= LEVEL,
                "confidence": float(stats.ks_2samp(cw, ca).pvalue) <= LEVEL,
                "segment share": two_sample(int(hw.sum()), m, int(ha.sum()), N_CAL) <= LEVEL,
            }
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reps", type=int, default=500)
    ap.add_argument("--json", help="also write the rows as JSON to this path")
    args = ap.parse_args()
    reps = [replicate(r) for r in range(args.reps)]
    ok = [r for r in reps if r["certified"]]
    rows = []
    for pop in POPULATIONS:
        for m in WINDOWS:
            row: dict[str, Any] = {
                "population": pop,
                "window": m,
                "breaks": float(np.mean([r[pop]["breaks"] for r in ok])),
            }
            for score in ("coverage", "confidence", "segment share"):
                row[score] = float(np.mean([r[pop][m][score] for r in ok]))
            rows.append(row)
    print(f"alpha {ALPHA}, delta {DELTA}, n_cal {N_CAL}, test level {LEVEL}, seed {SEED}")
    print(f"{len(ok)} of {args.reps} draws certified; rates are over those\n")
    print(
        "| population | window | breaks the bound | flagged: coverage | flagged: confidence | flagged: segment share |"
    )
    print("|---|---|---|---|---|---|")
    for r in rows:
        print(
            f"| {r['population']} | {r['window']} | {r['breaks']:.2f} | {r['coverage']:.2f} "
            f"| {r['confidence']:.2f} | {r['segment share']:.2f} |"
        )
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump({"reps": args.reps, "certified": len(ok), "seed": SEED, "rows": rows}, f, indent=1)
            f.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
