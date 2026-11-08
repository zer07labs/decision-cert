"""Simulation study for open item O4 of the v1.1 draft: how many labelled cases an `ltt` certificate needs.

    cd python && uv run python tools/study_budget.py [--reps 1000] [--json out.json]

Deterministic (pinned seeds). The same synthetic model as `study_grid.py`: confidence
c ~ Uniform(0.5, 1), error with probability beta * (1 - c), so the true selective error at a cut
answering a share k of cases is beta * k / 4. Model quality is set by **k\\***, the largest share of
cases the model can answer with true error at alpha (beta = 4 * alpha / k\\*): 0.75 is a strong model
for that alpha, 0.25 a weak one.

For each alpha (0.05, 0.10; delta 0.1), k\\* and n_cal (the threshold split; the temperature split is
the same size, so the issuer needs 2 * n_cal labelled cases), the reference issuer's grid and `ltt`
test run on 1,000 independent draws, with the grid start decided for v1.1 (O1). For a single test it
is the same as v1's. Reported:

- certified: the share of draws with a threshold below 1.01;
- coverage / k\\*: the mean true coverage as a share of the best possible (0 when abstaining);
- violations: the share of draws whose true error at the chosen threshold is above alpha (<= delta
  for validity).
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

import numpy as np
from scipy import stats

from decision_cert.issue import stats as cs

DELTA = 0.1
ALPHAS = [0.05, 0.10]
BEST = [0.75, 0.5, 0.25]
SIZES = [100, 200, 300, 500, 1000, 2000, 3000, 5000, 10000]
SEED = 20261109


def run(alpha: float, best: float, n: int, rep: int) -> float:
    rng = np.random.default_rng([SEED, ALPHAS.index(alpha), BEST.index(best), SIZES.index(n), rep])
    beta = 4 * alpha / best
    ct, ca = rng.uniform(0.5, 1.0, n), rng.uniform(0.5, 1.0, n)
    et, ea = rng.random(n) < beta * (1 - ct), rng.random(n) < beta * (1 - ca)
    u = np.unique(ct)[::-1]
    cuts = np.array([cs._between(float(u[i + 1]), float(u[i])) for i in range(len(u) - 1)] + [0.0])
    nt, kt = cs.counts(ct, et, cuts)
    p = np.where(nt > 0, stats.binom.cdf(kt, np.maximum(nt, 1), alpha), 1.0)
    return cs.ltt(ca, ea, cuts[int(np.argmin(p)) :], alpha, DELTA).abstain_below


def summarise(alpha: float, best: float, n: int, reps: int) -> dict[str, Any]:
    beta = 4 * alpha / best
    lams = np.array([run(alpha, best, n, r) for r in range(reps)])
    answered = lams < cs.ABSTAIN_ALL
    cov = np.where(answered, 2 * (1 - np.maximum(lams, 0.5)), 0.0)
    err = np.where(answered, beta * cov / 4, 0.0)
    return {
        "alpha": alpha,
        "best_coverage": best,
        "n_cal": n,
        "certified": float(answered.mean()),
        "coverage_share": float(cov.mean() / best),
        "violations": float(np.mean(err > alpha)),
    }


def table(rows: list[dict[str, Any]]) -> str:
    out = []
    for alpha in ALPHAS:
        out.append(f"\n**alpha {alpha}** — certified share of draws / mean coverage as a share of k\\*\n")
        out.append("| k\\* | " + " | ".join(f"n_cal {n}" for n in SIZES) + " | max violations |")
        out.append("|---" * (len(SIZES) + 2) + "|")
        for best in BEST:
            rs = [r for r in rows if r["alpha"] == alpha and r["best_coverage"] == best]
            cells = " | ".join(f"{r['certified']:.2f} / {r['coverage_share']:.2f}" for r in rs)
            out.append(f"| {best} | {cells} | {max(r['violations'] for r in rs):.3f} |")
    return "\n".join(out) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reps", type=int, default=1000)
    ap.add_argument("--json", help="also write the rows as JSON to this path")
    args = ap.parse_args()
    rows = [summarise(a, b, n, args.reps) for a in ALPHAS for b in BEST for n in SIZES]
    print(f"delta {DELTA}, {args.reps} draws per cell, seed {SEED}")
    print(table(rows), end="")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump({"delta": DELTA, "reps": args.reps, "seed": SEED, "rows": rows}, f, indent=1)
            f.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
