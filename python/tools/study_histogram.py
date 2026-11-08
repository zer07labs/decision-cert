"""Simulation study for v1.2 item H1 (#25): what a stored confidence histogram lets a consumer see
without labels, beyond the answered share that v1 and v1.1 already allow.

    cd python && uv run python tools/study_histogram.py [--reps 500] [--json out.json]

Deterministic (pinned seeds). The calibration population is the O2 study's (`study_shift.py`): an
easy group (error with probability 0.3 * (1 - c)) and a hard group (0.8 * (1 - c)), 20% hard, with
confidence c ~ Uniform(0.5, 1). A pooled `ltt` certificate (alpha 0.05, delta 0.1, n_cal 3,000 and a
temperature split of the same size, the v1.1 grid start) is issued on each draw, with the threshold
split's confidence histogram on bins learned from the temperature split. Then a window of m use-time
cases arrives from one of five populations:

- none: the calibration population (measures false alarms);
- confidence: confidences move toward the low end (c = 0.5 + 0.5 * B, B ~ Beta(1, 2)), and the
  error at each confidence is unchanged (the O2 case);
- squeeze: the answered cases' confidences move toward the certified threshold lam
  (c' = lam + 0.7 * (c - lam) for c >= lam), and those cases' error follows their new confidence.
  The answered share is unchanged by construction;
- abstained: the abstained cases' confidences move toward 0.5 (c' = 0.5 + 0.8 * (c - 0.5) for
  c < lam). Nothing answered changes, so the bound is unaffected;
- concept: the error at every confidence is 1.5 times higher, and confidences are unchanged.

The true use-time selective error at the certified threshold is exact (it is a mean of
beta * (1 - c) over the answered confidences, each population's in closed form). Label-free scores,
each tested at level 0.05 on each window:

- coverage: the window's answered share against the certificate's `coverage` and `n` (v1, v1.1);
- KS: a two-sample Kolmogorov-Smirnov test against the threshold split's raw confidences (needs the
  issuer's data; the O2 study's reference point);
- histogram (q20, q10): the v1.2 shift score, `decision_cert.shift_score`, on bins at the 20 or 10
  quantiles of the temperature split's confidences, rounded to 4 decimals (the reference issuer's
  choice is q20);
- histogram (fixed20): the same score on 20 equal-width bins of [0, 1], fixed in advance.

A second table repeats `none` with small calibration sets, where the chi-square approximation is
weakest, to check that the score's false-alarm rate stays near its level.

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

from decision_cert import Histogram, shift_score
from decision_cert.issue import stats as cs

ALPHA, DELTA, LEVEL = 0.05, 0.1, 0.05
EASY, HARD, CAL_HARD = 0.3, 0.8, 0.2
BETA = CAL_HARD * HARD + (1 - CAL_HARD) * EASY  # both groups share the same confidences
N_CAL = 3000
WINDOWS = [1000, 5000]
POPULATIONS = ["none", "confidence", "squeeze", "abstained", "concept"]
SCORES = ["coverage", "KS", "histogram q20", "histogram q10", "histogram fixed20"]
SMALL = [(300, 300), (300, 1000), (1000, 300)]  # (n_cal, window) for the false-alarm check
SQUEEZE, SHRINK = 0.7, 0.8
SEED = 20261112


def quantile_bins(conf_t: np.ndarray, k: int) -> list[float]:
    """The reference issuer's bins: 0, the k-quantiles of the temperature split's confidences rounded
    to 4 decimals (strictly inside (0, 1), duplicates dropped), 1."""
    q = np.quantile(conf_t, np.arange(1, k) / k)
    inner = sorted({round(float(x), 4) for x in q} - {0.0, 1.0})
    return [0.0, *[x for x in inner if 0.0 < x < 1.0], 1.0]


FIXED20 = [round(i / 20, 2) for i in range(21)]


def draw(rng: np.random.Generator, n: int, pop: str, lam: float) -> tuple[np.ndarray, np.ndarray]:
    """(confidences, errors) of n cases from population `pop`; `lam` is the certified threshold."""
    hard = rng.random(n) < CAL_HARD
    if pop == "confidence":
        conf = 0.5 + 0.5 * rng.beta(1.0, 2.0, n)
    else:
        conf = rng.uniform(0.5, 1.0, n)
    if pop == "squeeze":
        conf = np.where(conf >= lam, lam + SQUEEZE * (conf - lam), conf)
    elif pop == "abstained":
        conf = np.where(conf < lam, 0.5 + SHRINK * (conf - 0.5), conf)
    mult = 1.5 if pop == "concept" else 1.0
    err = rng.random(n) < mult * np.where(hard, HARD, EASY) * (1 - conf)
    return conf, err


def true_error(lam: float, pop: str) -> float:
    """Exact selective error at threshold lam for each population."""
    t = 1 - max(lam, 0.5)
    if t <= 0:
        return 0.0
    if pop == "confidence":
        return BETA * 2 * t / 3
    if pop == "squeeze":
        return BETA * t * (1 - SQUEEZE / 2)
    mult = 1.5 if pop == "concept" else 1.0
    return mult * BETA * t / 2  # none, abstained: answered cases are unchanged


def two_sample(k1: int, n1: int, k2: int, n2: int) -> float:
    table = np.array([[k1, n1 - k1], [k2, n2 - k2]])
    if (table.sum(axis=0) == 0).any():
        return 1.0
    return float(stats.chi2_contingency(table, correction=False)[1])


def certify(rng: np.random.Generator, n_cal: int) -> tuple[float, np.ndarray, np.ndarray]:
    """(lam, temperature-split confidences, threshold-split confidences); lam is 1.01 when nothing
    is certified."""
    ct, et = draw(rng, n_cal, "none", 1.0)
    ca, ea = draw(rng, n_cal, "none", 1.0)
    cuts = cs.cuts_of(ct)
    lam = cs.ltt(ca, ea, cuts[cs.start(cuts, ct, et, ALPHA) :], ALPHA, DELTA).abstain_below
    return lam, ct, ca


def flags(lam: float, ct: np.ndarray, ca: np.ndarray, cw: np.ndarray) -> dict[str, bool]:
    n, m = len(ca), len(cw)
    out = {
        "coverage": two_sample(int((cw >= lam).sum()), m, int((ca >= lam).sum()), n) <= LEVEL,
        "KS": float(stats.ks_2samp(cw, ca).pvalue) <= LEVEL,
    }
    for name, bins in (
        ("histogram q20", quantile_bins(ct, 20)),
        ("histogram q10", quantile_bins(ct, 10)),
        ("histogram fixed20", FIXED20),
    ):
        base = Histogram.of(bins, ca.tolist())
        out[name] = shift_score(base, Histogram.of(bins, cw.tolist())).p_value <= LEVEL
    return out


def replicate(rep: int) -> dict[str, Any]:
    rng = np.random.default_rng([SEED, rep])
    lam, ct, ca = certify(rng, N_CAL)
    if lam >= cs.ABSTAIN_ALL:
        return {"certified": False}
    out: dict[str, Any] = {"certified": True}
    for pop in POPULATIONS:
        out[pop] = {"breaks": true_error(lam, pop) > ALPHA}
        for m in WINDOWS:
            cw, _ = draw(rng, m, pop, lam)
            out[pop][m] = flags(lam, ct, ca, cw)
    return out


def small_replicate(rep: int, n_cal: int, m: int) -> dict[str, bool]:
    """False alarms do not depend on certifying: every draw counts (coverage at 1.01 never flags)."""
    rng = np.random.default_rng([SEED, n_cal, m, rep])
    lam, ct, ca = certify(rng, n_cal)
    cw, _ = draw(rng, m, "none", lam)
    return flags(lam, ct, ca, cw)


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
            for s in SCORES:
                row[s] = float(np.mean([r[pop][m][s] for r in ok]))
            rows.append(row)
    small = []
    for n_cal, m in SMALL:
        got = [small_replicate(r, n_cal, m) for r in range(args.reps)]
        small.append({"n_cal": n_cal, "window": m, **{s: float(np.mean([f[s] for f in got])) for s in SCORES}})
    print(f"alpha {ALPHA}, delta {DELTA}, n_cal {N_CAL}, test level {LEVEL}, seed {SEED}")
    print(f"{len(ok)} of {args.reps} draws certified; rates are over those\n")
    print("| population | window | breaks the bound | " + " | ".join(f"flagged: {s}" for s in SCORES) + " |")
    print("|---|---|---|" + "---|" * len(SCORES))
    for r in rows:
        cells = " | ".join(f"{r[s]:.2f}" for s in SCORES)
        print(f"| {r['population']} | {r['window']} | {r['breaks']:.2f} | {cells} |")
    print("\nFalse alarms (population none) with small calibration sets")
    print(f"Every one of {args.reps} draws counts, certified or not.\n")
    print("| n_cal | window | " + " | ".join(f"flagged: {s}" for s in SCORES) + " |")
    print("|---|---|" + "---|" * len(SCORES))
    for r in small:
        print(f"| {r['n_cal']} | {r['window']} | " + " | ".join(f"{r[s]:.2f}" for s in SCORES) + " |")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            out = {"reps": args.reps, "certified": len(ok), "seed": SEED, "rows": rows, "small": small}
            json.dump(out, f, indent=1)
            f.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
