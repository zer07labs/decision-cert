"""Simulation study for open item O3 of the v1.1 draft: thresholds when the segment mix shifts.

    cd python && uv run python tools/study_mix.py [--reps 1000] [--json out.json]

Deterministic (pinned seeds). Two groups whose confidences look alike (c ~ Uniform(0.5, 1) in both),
but whose errors differ: an easy group (error with probability 0.3 * (1 - c)) and a hard group
(0.8 * (1 - c)). The model's confidence does not tell them apart, which is exactly when a change in
the mix can break a pooled bound. At calibration the hard group is 20% of cases; at use it is 20%,
35% or 50%.

Rules (alpha 0.05, delta 0.1), on threshold splits of n_cal cases (and temperature splits of the same
size):
- pooled: no segment declared; one test on all cases at level delta (v1, and v1.1 alike);
- conditional: the group declared as a segment, both groups certified, each tested on its own cases
  at delta / 3 (v1's Bonferroni over 1 + 2 families) with the grid start decided for O1.

The true selective error at use is computed exactly from the chosen thresholds and the use-time mix:
the answered share of a group at a cut lam is 2 * (1 - lam), and its error among answered is
beta * (1 - lam) / 2. Reported per n_cal and use-time hard share:
- violations: the share of draws whose use-time selective error over all answered cases is above
  alpha (<= delta for validity);
- coverage: the mean use-time share of cases answered.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

import numpy as np
from scipy import stats

from decision_cert.issue import stats as cs

ALPHA, DELTA = 0.05, 0.1
EASY, HARD = 0.3, 0.8
CAL_HARD = 0.2
USE_HARD = [0.2, 0.35, 0.5]
SIZES = [1000, 3000, 10000]
SEED = 20261110


def cuts_of(conf_t: np.ndarray) -> np.ndarray:
    u = np.unique(conf_t)[::-1]
    return np.array([cs._between(float(u[i + 1]), float(u[i])) for i in range(len(u) - 1)] + [0.0])


def test(cuts: np.ndarray, t: tuple[np.ndarray, np.ndarray], a: tuple[np.ndarray, np.ndarray], d: float) -> float:
    n, e = cs.counts(t[0], t[1], cuts)
    p = np.where(n > 0, stats.binom.cdf(e, np.maximum(n, 1), ALPHA), 1.0)
    return cs.ltt(a[0], a[1], cuts[int(np.argmin(p)) :], ALPHA, d).abstain_below


def draw(rng: np.random.Generator, n: int) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    hard = rng.random(n) < CAL_HARD
    conf = rng.uniform(0.5, 1.0, n)
    err = rng.random(n) < np.where(hard, HARD, EASY) * (1 - conf)
    return conf, err, hard


def answered(lam: float) -> float:
    return 0.0 if lam >= 1.0 else 2 * (1 - max(lam, 0.5))


def use_time(lam_easy: float, lam_hard: float, hard_share: float) -> tuple[float, float]:
    """(selective error over all answered cases, share answered) at use, for per-group thresholds."""
    ae, ah = (1 - hard_share) * answered(lam_easy), hard_share * answered(lam_hard)
    if ae + ah == 0:
        return 0.0, 0.0
    errs = ae * EASY * (1 - max(lam_easy, 0.5)) / 2 + ah * HARD * (1 - max(lam_hard, 0.5)) / 2
    return errs / (ae + ah), ae + ah


def replicate(n: int, rep: int) -> dict[str, tuple[float, float]]:
    rng = np.random.default_rng([SEED, SIZES.index(n), rep])
    ct, et, ht = draw(rng, n)
    ca, ea, ha = draw(rng, n)
    cuts = cuts_of(ct)  # one list of cuts from the whole temperature split
    pooled = test(cuts, (ct, et), (ca, ea), DELTA)
    easy = test(cuts, (ct[~ht], et[~ht]), (ca[~ha], ea[~ha]), DELTA / 3)
    hard = test(cuts, (ct[ht], et[ht]), (ca[ha], ea[ha]), DELTA / 3)
    return {"pooled": (pooled, pooled), "conditional": (easy, hard)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reps", type=int, default=1000)
    ap.add_argument("--json", help="also write the rows as JSON to this path")
    args = ap.parse_args()
    rows: list[dict[str, Any]] = []
    for n in SIZES:
        reps = [replicate(n, r) for r in range(args.reps)]
        for rule in ("pooled", "conditional"):
            for share in USE_HARD:
                res = np.array([use_time(*r[rule], share) for r in reps])
                rows.append(
                    {
                        "n_cal": n,
                        "rule": rule,
                        "use_hard_share": share,
                        "violations": float(np.mean(res[:, 0] > ALPHA)),
                        "coverage": float(res[:, 1].mean()),
                    }
                )
    print(
        f"alpha {ALPHA}, delta {DELTA}, {args.reps} draws per row, seed {SEED}, hard share at calibration {CAL_HARD}\n"
    )
    print("| n_cal | rule | hard share at use | violations | coverage at use |\n|---|---|---|---|---|")
    for r in rows:
        print(f"| {r['n_cal']} | {r['rule']} | {r['use_hard_share']} | {r['violations']:.3f} | {r['coverage']:.3f} |")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump({"alpha": ALPHA, "delta": DELTA, "reps": args.reps, "seed": SEED, "rows": rows}, f, indent=1)
            f.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
