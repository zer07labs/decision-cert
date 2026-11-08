"""The statistics behind the issuer (spec/decision-certificate.v1.md §1): exact binomial p-values
and bounds, the Learn-then-Test threshold search, conformal risk control and the realized band.
Pure functions over numpy arrays.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

import numpy as np
from scipy import stats

# Confidence never exceeds 1.0, so this threshold abstains on every case.
ABSTAIN_ALL = 1.01


def n_min(alpha: float, delta: float) -> int:
    """Fewest answered cases that can reject `risk > alpha` at level delta with zero errors."""
    return math.ceil(math.log(delta) / math.log(1.0 - alpha))


def p_value(n: int, e: int, alpha: float) -> float:
    """Exact binomial p-value for H: risk > alpha, given e errors in n answered: P(Bin(n, alpha) ≤ e)."""
    return 1.0 if n == 0 else float(stats.binom.cdf(e, n, alpha))


def ucb(n: int, e: int, delta: float) -> float:
    """One-sided Clopper-Pearson upper bound at level 1 - delta; 1 when nothing is answered."""
    return 1.0 if n == 0 or e >= n else float(stats.beta.ppf(1.0 - delta, e + 1, n - e))


def band(n: int, e: int, level: float) -> tuple[float, float]:
    """Two-sided Clopper-Pearson interval at `level` (spec §1.2)."""
    if n == 0:
        return 0.0, 1.0
    low = 0.0 if e == 0 else float(stats.beta.ppf((1.0 - level) / 2, e, n - e + 1))
    high = 1.0 if e == n else float(stats.beta.ppf((1.0 + level) / 2, e + 1, n - e))
    return low, high


def _between(lo: float, hi: float) -> float:
    mid = (lo + hi) / 2
    return mid if mid > lo else float(np.nextafter(lo, np.inf))


def cuts_of(conf_temperature: np.ndarray) -> np.ndarray:
    """Every cut (spec §1.1 step 3), learned from the temperature split only: the midpoints between
    adjacent distinct confidences, descending, then 0.0 (answer everything)."""
    conf_temperature = np.asarray(conf_temperature, float)
    u = np.unique(conf_temperature[conf_temperature >= 0])[::-1]  # distinct, descending; unscored (< 0) never a cut
    return np.array([_between(float(u[i + 1]), float(u[i])) for i in range(len(u) - 1)] + [0.0])


def start(cuts: np.ndarray, conf: np.ndarray, err: np.ndarray, alpha: float) -> int:
    """Where a fixed sequence down `cuts` starts: the cut with the smallest `ltt` p-value on these
    temperature-split cases, the strictest on ties. Starting at the very top would stop the sequence
    on cuts that answer too few cases to reject anything."""
    n, e = counts(conf, err, cuts)
    p = np.where(n > 0, stats.binom.cdf(e, np.maximum(n, 1), alpha), 1.0)
    return int(np.argmin(p))  # argmin takes the first (strictest) cut on ties


def grid(conf_temperature: np.ndarray, err_temperature: np.ndarray, alpha: float) -> np.ndarray:
    """The cuts from `cuts_of`, starting where the whole temperature split's labels put the start:
    v1's grid for every test, and v1.1's for a single test."""
    cuts = cuts_of(conf_temperature)
    return cuts[start(cuts, np.asarray(conf_temperature, float), err_temperature, alpha) :]


@dataclass(frozen=True)
class Point:
    abstain_below: float
    n: int  # answered
    e: int  # errors among answered
    coverage: float


def counts(conf: np.ndarray, err: np.ndarray, cuts: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """(answered, errors) at each cut, answering confidence >= cut as a consumer does."""
    conf, err = np.asarray(conf, float), np.asarray(err, bool)
    order = np.argsort(conf, kind="stable")
    asc, err_asc = conf[order], err[order]
    first = np.searchsorted(asc, cuts, side="left")  # first answered position at each cut
    tail_err = np.concatenate([np.cumsum(err_asc[::-1])[::-1], [0]])  # errors from position i on
    return len(asc) - first, tail_err[first]


def ltt(conf: np.ndarray, err: np.ndarray, cuts: np.ndarray, alpha: float, delta: float) -> Point:
    """Fixed-sequence Learn-then-Test down `cuts`: the last cut whose p-value ≤ delta before the
    first non-rejection; abstain-all when the first cut is not rejected."""
    n, e = counts(conf, err, cuts)
    p = np.where(n > 0, stats.binom.cdf(e, np.maximum(n, 1), alpha), 1.0)
    failed = np.flatnonzero(p > delta)
    last = (failed[0] if len(failed) else len(cuts)) - 1
    return _point(cuts, n, e, int(last), len(conf))


def _point(cuts: np.ndarray, n: np.ndarray, e: np.ndarray, i: int, total: int) -> Point:
    if i < 0:
        return Point(ABSTAIN_ALL, 0, 0, 0.0)
    return Point(float(cuts[i]), int(n[i]), int(e[i]), int(n[i]) / total)


def crc(conf: np.ndarray, err: np.ndarray, cuts: np.ndarray, alpha: float) -> Point:
    """Conformal risk control on the joint loss 1[answered and wrong], monotone in the cut:
    the loosest cut with (n·R̂ + 1)/(n + 1) ≤ alpha (loss bound B = 1)."""
    n, e = counts(conf, err, cuts)
    total = len(conf)
    failed = np.flatnonzero((e + 1) / (total + 1) > alpha)  # joint loss only grows down the grid
    last = (failed[0] if len(failed) else len(cuts)) - 1
    return _point(cuts, n, e, int(last), total)


MONDRIAN_MIN = 19  # a class-conditional threshold is fitted only for a class with at least this many cases


def mondrian(
    conf: np.ndarray, err: np.ndarray, klass: np.ndarray, alpha: float, delta: float, min_per_class: int = MONDRIAN_MIN
) -> dict[int, Point | None]:
    """Class-conditional (Mondrian) Learn-then-Test: for each predicted class, `grid` and `ltt` over the cases predicted
    as that class. A class with fewer than `min_per_class` cases gets None, and the caller decides what that means."""
    conf, err, klass = np.asarray(conf, float), np.asarray(err, bool), np.asarray(klass)
    out: dict[int, Point | None] = {}
    for c in sorted(int(x) for x in np.unique(klass)):
        m = klass == c
        if int(m.sum()) < min_per_class:
            out[c] = None
            continue
        out[c] = ltt(conf[m], err[m], grid(conf[m], err[m], alpha), alpha, delta)
    return out
