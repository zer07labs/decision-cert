"""Simulation study: where the `ltt` fixed sequence starts, and what that costs on small tests.

    cd python && uv run python tools/study_start.py [--reps 2000] [--json out.json]

Deterministic: every replicate draws from its own pinned seed, so the same arguments give the same
table, and every rule sees the same draw. The test is the reference issuer's
(`decision_cert.issue.stats.ltt`, `cuts_of`, `start`, `n_min`); only where the sequence starts, and
how many sequences are run, changes between rules.

Synthetic cases: confidence c ~ Uniform(0.5, 1), and a case is an error with probability f(c). The
true selective error at a cut lam is the mean of f over [lam, 1), and the true coverage is
2 * (1 - lam), so every chosen threshold is scored exactly, without a second sample. The temperature
split and the threshold split are independent draws of the same size n.

Worlds (alpha 0.1, delta 0.1):
- calibrated: f(c) = 1 - c. Error is at or below alpha only above c 0.8; the best threshold answers 40%;
- quarter: f(c) = (1 - c) / 4. Every threshold is at or below alpha; the best answers everything;
- near-alpha: f(c) = 0.13 below c 0.97 and 0 above. Error is near alpha through most of the confident
  range, with a small clean top; the best threshold (0.87) answers 26%;
- above: a constant 12% error, so no threshold is truly at or below alpha and any certificate is a
  violation.

Rules (cuts are always `cuts_of` on the temperature split, except `grid20`):
- argmin-p: the reference issuer (v1.1 on): one sequence at delta, starting at the cut with the smallest
  p-value on the temperature split;
- min-n: one sequence at delta, starting at the strictest cut that answers at least `n_min(alpha,
  delta)` temperature-split cases (22 at alpha = delta = 0.1), the fewest that could reject with no
  errors. It uses only the temperature split's confidences, not its labels;
- bonf4: four sequences at delta / 4, starting at argmin-p and at the strictest cuts answering at least
  10%, 25% and 50% of the temperature split, but never fewer than `n_min(alpha, delta / 4)` cases; the
  certificate takes the loosest cut any sequence reaches. Any false rejection is a false rejection in
  one of the four sequences, so the family-wise error is at most delta;
- grid20: no sequence; 20 cuts at the temperature split's confidence quantiles (answering 5%, 10%,
  ..., 100% of it), each tested on its own at delta / 20, taking the loosest that rejects (Bonferroni).

Reported for each world, test size n and rule:
- certified, and nothing (1 - certified): the share of replicates with, and without, a threshold below
  1.01;
- coverage: the mean true coverage (0 when abstaining on everything), and the best possible;
- violations: the share of replicates whose true selective error at the chosen threshold is above
  alpha (abstaining on everything counts as no violation). Validity needs this <= delta;
- mean error: the mean true selective error over the replicates that certify; q90 and worst: the 90%
  quantile and the largest true selective error across all replicates (0 when abstaining on
  everything). Validity at delta 0.1 needs q90 <= alpha.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import numpy as np
from scipy import stats

from decision_cert.issue import stats as cs

ALPHA, DELTA = 0.1, 0.1
SIZES = [250, 500, 1000]
SEED = 20261111
TOP = 0.97  # near-alpha: the clean top of the confidence range
NEAR = 0.13  # near-alpha: the error below TOP
ABOVE = 0.12  # above: the constant error
GRID = 20
FRACTIONS = (0.10, 0.25, 0.50)  # bonf4: the coverage of the temperature split at the three extra starts


@dataclass(frozen=True)
class World:
    name: str
    f: Callable[[np.ndarray], np.ndarray]  # error probability at confidence c
    err: Callable[[float], float]  # true selective error at a cut in [0.5, 1)
    best: float  # true coverage of the loosest threshold with error <= alpha


def _near_err(lam: float) -> float:
    return 0.0 if lam >= TOP else NEAR * (TOP - lam) / (1.0 - lam)


WORLDS = [
    World("calibrated", lambda c: 1.0 - c, lambda lam: (1.0 - lam) / 2, 0.4),
    World("quarter", lambda c: (1.0 - c) / 4, lambda lam: (1.0 - lam) / 8, 1.0),
    World(
        "near-alpha",
        lambda c: np.where(c < TOP, NEAR, 0.0),
        _near_err,
        2.0 * (1.0 - (NEAR * TOP - ALPHA) / (NEAR - ALPHA)),
    ),
    World("above", lambda c: np.full(len(c), ABOVE), lambda lam: ABOVE, 0.0),
]


def draw(rng: np.random.Generator, n: int, w: World) -> tuple[np.ndarray, np.ndarray]:
    conf = rng.uniform(0.5, 1.0, n)
    return conf, rng.random(n) < w.f(conf)


def true_error(lam: float, w: World) -> float:
    return 0.0 if lam >= 1.0 else w.err(max(lam, 0.5))


def true_coverage(lam: float) -> float:
    return 0.0 if lam >= 1.0 else 2.0 * (1.0 - max(lam, 0.5))


def first_with(cuts: np.ndarray, conf_t: np.ndarray, n_at_least: int) -> int:
    """The strictest cut answering at least `n_at_least` temperature-split cases (the last cut if none)."""
    n, _ = cs.counts(conf_t, np.zeros(len(conf_t), bool), cuts)
    hit = np.flatnonzero(n >= n_at_least)
    return int(hit[0]) if len(hit) else len(cuts) - 1


def argmin_p(ct: np.ndarray, et: np.ndarray, ca: np.ndarray, ea: np.ndarray) -> float:
    cuts = cs.cuts_of(ct)
    return cs.ltt(ca, ea, cuts[cs.start(cuts, ct, et, ALPHA) :], ALPHA, DELTA).abstain_below


def min_n(ct: np.ndarray, et: np.ndarray, ca: np.ndarray, ea: np.ndarray) -> float:
    cuts = cs.cuts_of(ct)
    return cs.ltt(ca, ea, cuts[first_with(cuts, ct, cs.n_min(ALPHA, DELTA)) :], ALPHA, DELTA).abstain_below


def bonf4(ct: np.ndarray, et: np.ndarray, ca: np.ndarray, ea: np.ndarray) -> float:
    cuts = cs.cuts_of(ct)
    d = DELTA / (1 + len(FRACTIONS))
    floor = cs.n_min(ALPHA, d)
    starts = [cs.start(cuts, ct, et, ALPHA)]
    starts += [first_with(cuts, ct, max(floor, math.ceil(q * len(ct)))) for q in FRACTIONS]
    return min(cs.ltt(ca, ea, cuts[s:], ALPHA, d).abstain_below for s in starts)


def grid20(ct: np.ndarray, et: np.ndarray, ca: np.ndarray, ea: np.ndarray) -> float:
    cuts = np.unique(np.quantile(ct, [1 - j / GRID for j in range(1, GRID + 1)]))[::-1]
    n, e = cs.counts(ca, ea, cuts)
    p = np.where(n > 0, stats.binom.cdf(e, np.maximum(n, 1), ALPHA), 1.0)
    ok = np.flatnonzero(p <= DELTA / GRID)
    return float(cuts[ok].min()) if len(ok) else cs.ABSTAIN_ALL


RULES: list[tuple[str, Callable[[np.ndarray, np.ndarray, np.ndarray, np.ndarray], float]]] = [
    ("argmin-p", argmin_p),
    ("min-n", min_n),
    ("bonf4", bonf4),
    ("grid20", grid20),
]


def replicate(w: World, n: int, rep: int) -> dict[str, float]:
    rng = np.random.default_rng([SEED, SIZES.index(n), WORLDS.index(w), rep])
    ct, et = draw(rng, n, w)
    ca, ea = draw(rng, n, w)
    return {name: rule(ct, et, ca, ea) for name, rule in RULES}


def summarise(w: World, n: int, reps: int) -> list[dict[str, Any]]:
    chosen: dict[str, list[float]] = {name: [] for name, _ in RULES}
    for rep in range(reps):
        for name, x in replicate(w, n, rep).items():
            chosen[name].append(x)
    rows = []
    for name, lams in chosen.items():
        lam = np.array(lams, float)
        err = np.array([true_error(x, w) for x in lams])
        cov = np.array([true_coverage(x) for x in lams])
        cert = np.asarray(lam < cs.ABSTAIN_ALL)
        rows.append(
            {
                "world": w.name,
                "n": n,
                "rule": name,
                "certified": float(cert.mean()),
                "nothing": float(1.0 - cert.mean()),
                "coverage": float(cov.mean()),
                "best_coverage": w.best,
                "violations": float(np.mean(err > ALPHA)),
                "mean_error_certified": float(err[cert].mean()) if cert.any() else None,
                "q90": float(np.quantile(err, 0.9)),
                "worst": float(err.max()),
            }
        )
    return rows


def table(rows: list[dict[str, Any]]) -> str:
    head = (
        "| world | n | rule | certified | nothing | coverage (best) | violations | mean error (certified) "
        "| q90 error | worst error |\n|---|---|---|---|---|---|---|---|---|---|\n"
    )
    body = "".join(
        f"| {r['world']} | {r['n']} | {r['rule']} | {r['certified']:.3f} | {r['nothing']:.3f} "
        f"| {r['coverage']:.3f} ({r['best_coverage']:.2f}) | {r['violations']:.3f} "
        f"| {'-' if r['mean_error_certified'] is None else format(r['mean_error_certified'], '.4f')} "
        f"| {r['q90']:.4f} | {r['worst']:.4f} |\n"
        for r in rows
    )
    return head + body


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reps", type=int, default=2000)
    ap.add_argument("--json", help="also write the rows as JSON to this path")
    args = ap.parse_args()
    rows = [r for w in WORLDS for n in SIZES for r in summarise(w, n, args.reps)]
    print(f"alpha {ALPHA}, delta {DELTA}, {args.reps} replicates per row, seed {SEED}\n")
    print(table(rows), end="")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump({"alpha": ALPHA, "delta": DELTA, "reps": args.reps, "seed": SEED, "rows": rows}, f, indent=1)
            f.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
