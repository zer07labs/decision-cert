"""Simulation study for the v1.4 draft (spec/drafts/cost-weighted-abstention.md §3): how many labelled cases
a `selective_cost` certificate needs, against a `selective_error` one at the same alpha.

    cd python && uv run python tools/study_cost.py [--reps 1000] [--jobs 8] [--json out.json]
    cd python && uv run python tools/study_cost.py --worst 4 --reps 10000   # the validity rerun

Deterministic (pinned seeds, independent of --jobs). O4's synthetic model (`study_budget.py`): confidence
c ~ Uniform(0.5, 1), error with probability beta * (1 - c), beta = 4 * alpha / k\\*. Each error is of the
expensive kind with probability s, independently of c. The cost matrix has expensive errors at r and cheap
ones at 1, so c_max = r and the normalised losses are 1 and 1/r. At a cut answering a share k of the cases:

- the true selective error is beta * k / 4;
- the true mean normalised loss is beta * k / 4 * w, with w = s + (1 - s) / r.

For each cell (alpha, k\\*, r, s, n_cal) and draw, both tests run on the same temperature and threshold splits
of n_cal cases each, so the issuer used 2 * n_cal labelled cases:

- `selective_error`: v1's grid and exact binomial `ltt` on the 0/1 errors;
- `selective_cost`: `cost_grid` and Hoeffding-Bentkus `cost_ltt` on the normalised losses.

Reported per cell and test:

- certified: the share of draws with a threshold below 1.01;
- coverage / k\\*: the mean true coverage as a share of the error test's best possible, k\\*. The cost test's
  own best possible is min(1, k\\* / w), also reported;
- violations: the share of draws whose true risk at the chosen threshold (the error for `selective_error`,
  the mean loss for `selective_cost`) is above alpha; it must be <= delta within Monte Carlo error.

r = 1 is the equal-cost case. There the issuer refuses `selective_cost` (§1); its row shows what the
Hoeffding-Bentkus p-value alone costs against the exact binomial.
"""

from __future__ import annotations

import argparse
import json
import sys
from concurrent.futures import ProcessPoolExecutor
from typing import Any

import numpy as np

from decision_cert.issue import stats as cs

DELTA = 0.1
ALPHAS = [0.05, 0.10]
BEST = [0.75, 0.5, 0.25]
RATIOS = [1, 2, 5, 10]
MIXES = [0.2, 0.5, 0.8]
SIZES = [100, 200, 300, 500, 1000, 2000, 3000, 5000, 10000]
SEED = 20261112

Cell = tuple[float, float, int, float, int]  # alpha, k*, r, s, n_cal


def cells() -> list[Cell]:
    return [(a, b, r, s, n) for a in ALPHAS for b in BEST for r in RATIOS for s in MIXES for n in SIZES]


def draw(cell: Cell, rep: int) -> tuple[float, float]:
    """(selective_error threshold, selective_cost threshold) on one draw."""
    alpha, best, r, s, n = cell
    key = [SEED, ALPHAS.index(alpha), BEST.index(best), RATIOS.index(r), MIXES.index(s), SIZES.index(n), rep]
    rng = np.random.default_rng(key)
    beta = 4 * alpha / best
    ct, ca = rng.uniform(0.5, 1.0, n), rng.uniform(0.5, 1.0, n)
    et, ea = rng.random(n) < beta * (1 - ct), rng.random(n) < beta * (1 - ca)
    xt, xa = rng.random(n) < s, rng.random(n) < s  # expensive?
    lt = np.where(et, np.where(xt, 1.0, 1.0 / r), 0.0)
    la = np.where(ea, np.where(xa, 1.0, 1.0 / r), 0.0)
    err = cs.ltt(ca, ea, cs.grid(ct, et, alpha), alpha, DELTA).abstain_below
    cost = cs.cost_ltt(ca, la, cs.cost_grid(ct, lt, alpha), alpha, DELTA).abstain_below
    return err, cost


def summarise(cell: Cell, reps: int) -> dict[str, Any]:
    alpha, best, r, s, n = cell
    beta = 4 * alpha / best
    w = s + (1 - s) / r
    lams = np.array([draw(cell, rep) for rep in range(reps)])
    row: dict[str, Any] = {"alpha": alpha, "best_coverage": best, "ratio": r, "mix": s, "n_cal": n}
    row["best_cost_coverage"] = min(1.0, best / w)
    for j, name in enumerate(["error", "cost"]):
        lam = lams[:, j]
        answered = lam < cs.ABSTAIN_ALL
        cov = np.where(answered, 2 * (1 - np.maximum(lam, 0.5)), 0.0)
        risk = np.where(answered, beta * cov / 4 * (w if name == "cost" else 1.0), 0.0)
        row[f"{name}_certified"] = float(answered.mean())
        row[f"{name}_coverage_share"] = float(cov.mean() / best)
        row[f"{name}_violations"] = float(np.mean(risk > alpha))
    return row


def _one(args: tuple[Cell, int]) -> dict[str, Any]:
    return summarise(*args)


def table(rows: list[dict[str, Any]]) -> str:
    out = []
    for alpha in ALPHAS:
        for best in BEST:
            out.append(
                f"\n**alpha {alpha}, k\\* {best}**: certified share of draws / mean coverage as a share of k\\*"
                " (`selective_error` row first, then `selective_cost` per r and s)\n"
            )
            out.append("| test | r | s | " + " | ".join(f"n_cal {n}" for n in SIZES) + " | max violations |")
            out.append("|---" * (len(SIZES) + 4) + "|")
            rs = [x for x in rows if x["alpha"] == alpha and x["best_coverage"] == best]
            base = [x for x in rs if x["ratio"] == RATIOS[0] and x["mix"] == MIXES[0]]
            cells_ = " | ".join(f"{x['error_certified']:.2f} / {x['error_coverage_share']:.2f}" for x in base)
            worst = max(x["error_violations"] for x in rs)
            out.append(f"| error | | | {cells_} | {worst:.3f} |")
            for r in RATIOS:
                for s in MIXES:
                    line = [x for x in rs if x["ratio"] == r and x["mix"] == s]
                    cells_ = " | ".join(f"{x['cost_certified']:.2f} / {x['cost_coverage_share']:.2f}" for x in line)
                    worst = max(x["cost_violations"] for x in line)
                    out.append(f"| cost | {r} | {s} | {cells_} | {worst:.3f} |")
    return "\n".join(out) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reps", type=int, default=1000)
    ap.add_argument("--jobs", type=int, default=1)
    ap.add_argument("--json", help="also write the rows as JSON to this path")
    ap.add_argument("--worst", type=int, default=0, help="rerun the N cells with the highest violation rate in --rows")
    ap.add_argument("--rows", help="a --json file from a full run, for --worst")
    ap.add_argument("--only", help="comma-separated n_cal values to run (a timing pilot)")
    args = ap.parse_args()
    todo = cells()
    if args.only:
        keep = {int(x) for x in args.only.split(",")}
        todo = [c for c in todo if c[4] in keep]
    if args.worst:
        with open(args.rows, encoding="utf-8") as f:
            prev = json.load(f)["rows"]
        scored = []
        for x in prev:
            c = (x["alpha"], x["best_coverage"], x["ratio"], x["mix"], x["n_cal"])
            scored.append((max(x["error_violations"], x["cost_violations"]), c))
        todo = [c for _, c in sorted(scored, key=lambda t: (-t[0], t[1]))[: args.worst]]
    with ProcessPoolExecutor(max_workers=args.jobs) as ex:
        rows = list(ex.map(_one, [(c, args.reps) for c in todo], chunksize=1))
    print(f"delta {DELTA}, {args.reps} draws per cell, seed {SEED}")
    if args.worst or args.only:
        for x in rows:
            print(json.dumps(x))
    else:
        print(table(rows), end="")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump({"delta": DELTA, "reps": args.reps, "seed": SEED, "rows": rows}, f, indent=1)
            f.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
