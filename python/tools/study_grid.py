"""Simulation study for open item O1 of the v1.1 draft: how the threshold grid behaves on small tests.

    cd python && uv run python tools/study_grid.py [--reps 1000] [--json out.json]

Deterministic: every replicate draws from its own pinned seed, so the same arguments give the same
table. The test itself is the reference issuer's (`decision_cert.issue.stats.ltt`); only the grid
(the list of cuts and where the sequence starts) changes between rules.

Synthetic cases: confidence c ~ Uniform(0.5, 1), and a case is an error with probability
beta * (1 - c). Then the true selective error at a cut lam (in [0.5, 1)) is beta * (1 - lam) / 2,
and the true coverage is 2 * (1 - lam), so every chosen threshold is scored exactly, without a
second sample. The temperature split and the threshold split are independent draws of the same size.

Scenarios (alpha 0.05, delta 0.1):
- easy: beta 0.3 (7.5% error overall; the best threshold answers 67%);
- hard: beta 0.8 (20% error overall; the best threshold answers 25%);
- none: a constant 6% error at every confidence, so no threshold has true error <= alpha;
- segments: two certified segments tested at delta / 3, A easy and three times as large, B hard; the
  row reports segment B, the one a pooled start is tuned away from.

Rules:
- fine/pooled: v1. Cuts are midpoints between adjacent distinct temperature-split confidences, and
  the sequence starts at the cut with the smallest p-value on the whole temperature split;
- fine/own: the same cuts, starting at the best cut on the test's own temperature-split cases;
- coarse/pooled and coarse/own: cuts at the temperature split's confidence quantiles in steps of 5%
  (20 cuts, then 0.0), with the same two starts.
Without segments, pooled and own are the same test, so only the two pooled rules are reported.

Reported for each scenario, test size n (cases in the tested set's threshold split) and rule:
- certified: the share of replicates with a threshold below 1.01;
- coverage: the mean true coverage (0 when abstaining on everything), and the best possible;
- violations: the share of replicates whose true selective error at the chosen threshold is above
  alpha (abstaining on everything counts as no violation). Validity needs this <= delta;
- q90 and q95: those quantiles of the true selective error across all replicates (0 when abstaining
  on everything). Validity at delta 0.1 needs q90 <= alpha.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import numpy as np
from scipy import stats

from decision_cert.issue import stats as cs

ALPHA, DELTA = 0.05, 0.1
SIZES = [100, 300, 1000, 3000, 10000]
STEPS = 20
SEED = 20261108


@dataclass(frozen=True)
class Scenario:
    name: str
    beta: float | None  # None: the constant-error scenario
    segments: bool = False


SCENARIOS = [Scenario("easy", 0.3), Scenario("hard", 0.8), Scenario("none", None), Scenario("segments", 0.8, True)]
CONSTANT_ERROR = 0.06
EASY_BETA = 0.3


def draw(rng: np.random.Generator, n: int, beta: float | None) -> tuple[np.ndarray, np.ndarray]:
    conf = rng.uniform(0.5, 1.0, n)
    p = np.full(n, CONSTANT_ERROR) if beta is None else beta * (1.0 - conf)
    return conf, rng.random(n) < p


def true_error(lam: float, beta: float | None) -> float:
    if lam >= 1.0:
        return 0.0  # abstains on everything: nothing answered, nothing wrong
    if beta is None:
        return CONSTANT_ERROR
    return beta * (1.0 - max(lam, 0.5)) / 2


def true_coverage(lam: float) -> float:
    return 0.0 if lam >= 1.0 else 2.0 * (1.0 - max(lam, 0.5))


def best_coverage(beta: float | None) -> float:
    if beta is None:
        return 0.0
    return min(1.0, true_coverage(1.0 - 2 * ALPHA / beta))


def fine_cuts(conf_t: np.ndarray) -> np.ndarray:
    u = np.unique(conf_t)[::-1]
    return np.array([cs._between(float(u[i + 1]), float(u[i])) for i in range(len(u) - 1)] + [0.0])


def coarse_cuts(conf_t: np.ndarray) -> np.ndarray:
    q = np.quantile(conf_t, [1 - j / STEPS for j in range(1, STEPS)])
    return np.array([*np.unique(q)[::-1], 0.0])


def start(cuts: np.ndarray, conf_t: np.ndarray, err_t: np.ndarray) -> int:
    n, e = cs.counts(conf_t, err_t, cuts)
    p = np.where(n > 0, stats.binom.cdf(e, np.maximum(n, 1), ALPHA), 1.0)
    return int(np.argmin(p))


Rule = tuple[str, Callable[[np.ndarray], np.ndarray], bool]  # name, cuts, own start
RULES: list[Rule] = [
    ("fine/pooled", fine_cuts, False),
    ("fine/own", fine_cuts, True),
    ("coarse/pooled", coarse_cuts, False),
    ("coarse/own", coarse_cuts, True),
]


def replicate(sc: Scenario, n: int, rep: int) -> dict[str, float]:
    """The chosen threshold of every rule on one draw, for the tested set (segment B when segmented)."""
    rng = np.random.default_rng([SEED, SIZES.index(n), SCENARIOS.index(sc), rep])
    ct, et = draw(rng, n, sc.beta)
    ca, ea = draw(rng, n, sc.beta)
    pooled_t = (ct, et)
    d = DELTA
    if sc.segments:  # segment A: easy, three times as large; both certified
        at, aet = draw(rng, 3 * n, EASY_BETA)
        pooled_t = (np.concatenate([at, ct]), np.concatenate([aet, et]))
        d = DELTA / 3
    out = {}
    for name, make, own in RULES:
        if own and not sc.segments:
            continue
        cuts = make(pooled_t[0])  # one list of cuts from the whole temperature split, as in v1
        s = start(cuts, ct, et) if own else start(cuts, *pooled_t)
        out[name] = cs.ltt(ca, ea, cuts[s:], ALPHA, d).abstain_below
    return out


def summarise(sc: Scenario, n: int, reps: int) -> list[dict[str, Any]]:
    chosen: dict[str, list[float]] = {}
    for rep in range(reps):
        for name, lam in replicate(sc, n, rep).items():
            chosen.setdefault(name, []).append(lam)
    rows = []
    for name, lams in chosen.items():
        err = np.array([true_error(lam, sc.beta) for lam in lams])
        cov = np.array([true_coverage(lam) for lam in lams])
        rows.append(
            {
                "scenario": sc.name,
                "n": n,
                "rule": name,
                "certified": float(np.mean(np.array(lams) < cs.ABSTAIN_ALL)),
                "coverage": float(cov.mean()),
                "best_coverage": best_coverage(sc.beta),
                "violations": float(np.mean(err > ALPHA)),
                "q90": float(np.quantile(err, 0.9)),
                "q95": float(np.quantile(err, 0.95)),
            }
        )
    return rows


def table(rows: list[dict[str, Any]]) -> str:
    head = (
        "| scenario | n | rule | certified | coverage (best) | violations | q90 error | q95 error |\n"
        "|---|---|---|---|---|---|---|---|\n"
    )
    body = "".join(
        f"| {r['scenario']} | {r['n']} | {r['rule']} | {r['certified']:.2f} "
        f"| {r['coverage']:.3f} ({r['best_coverage']:.2f}) "
        f"| {r['violations']:.3f} | {r['q90']:.4f} | {r['q95']:.4f} |\n"
        for r in rows
    )
    return head + body


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reps", type=int, default=1000)
    ap.add_argument("--json", help="also write the rows as JSON to this path")
    args = ap.parse_args()
    rows = [r for sc in SCENARIOS for n in SIZES for r in summarise(sc, n, args.reps)]
    print(f"alpha {ALPHA}, delta {DELTA}, {args.reps} replicates per row, seed {SEED}\n")
    print(table(rows), end="")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump({"alpha": ALPHA, "delta": DELTA, "reps": args.reps, "seed": SEED, "rows": rows}, f, indent=1)
            f.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
