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


def bins_of(conf_temperature: np.ndarray, k: int) -> list[float]:
    """v1.2 histogram bins, learned from the temperature split only (like the grid): 0, the
    k-quantiles of its scored confidences (not above the `cannot_tell` cut) rounded to 4 decimals
    (strictly inside (0, 1), repeats dropped), then 1. Rounding keeps the edges short and reveals
    no more than the quantiles do."""
    c = np.asarray(conf_temperature, float)
    c = c[c >= 0]
    inner = sorted({round(float(x), 4) for x in np.quantile(c, np.arange(1, k) / k)} if len(c) else set())
    return [0.0, *[x for x in inner if 0.0 < x < 1.0], 1.0]


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


# ---- Bounded losses (the v1.4 draft's `selective_cost`, spec/drafts/cost-weighted-abstention.md §1) ----
# Each answered case carries a normalised loss in [0, 1] instead of a 0/1 error. Nothing above changes: v1's
# binomial p-value stays the test for 0/1 errors, and every function below is new.

# A loss sum within this of an integer counts as that integer in the Hoeffding-Bentkus ceiling, so float
# summation noise (2.0000000000000004) cannot push ⌈n·R̂⌉ up by one. It is far below any real loss step.
_SUM_TOL = 1e-9


def _kl(a: float, b: float) -> float:
    """h(a, b) = a ln(a/b) + (1 - a) ln((1 - a)/(1 - b)), the Bernoulli relative entropy, for 0 ≤ a ≤ 1, 0 < b < 1."""
    out = 0.0
    if a > 0:
        out += a * math.log(a / b)
    if a < 1:
        out += (1 - a) * math.log((1 - a) / (1 - b))
    return out


def hb_p_value(n: int, loss_sum: float, alpha: float) -> float:
    """Hoeffding-Bentkus p-value for H: mean loss > alpha, given n answered cases with losses in [0, 1]
    summing to `loss_sum` (Bates, Angelopoulos, Lei, Malik, Jordan 2021, "Distribution-Free,
    Risk-Controlling Prediction Sets"):

        p = min( exp(-n · h(min(R̂, alpha), alpha)),  e · P(Bin(n, alpha) ≤ ⌈n R̂⌉) ),   1 when n = 0.
    """
    if n == 0:
        return 1.0
    r_hat = min(max(loss_sum / n, 0.0), 1.0)
    hoeffding = math.exp(-n * _kl(min(r_hat, alpha), alpha))
    k = math.ceil(loss_sum - _SUM_TOL)
    bentkus = math.e * float(stats.binom.cdf(k, n, alpha))
    return min(1.0, hoeffding, bentkus)


def hb_p_values(n: np.ndarray, loss_sum: np.ndarray, alpha: float) -> np.ndarray:
    """`hb_p_value` at every cut (vectorised; the same numbers)."""
    n = np.asarray(n, np.int64)
    loss_sum = np.asarray(loss_sum, float)
    safe = np.maximum(n, 1)
    r = np.clip(loss_sum / safe, 0.0, 1.0)
    a = np.minimum(r, alpha)
    with np.errstate(divide="ignore", invalid="ignore"):
        kl = np.where(a > 0, a * np.log(np.where(a > 0, a, 1.0) / alpha), 0.0) + np.where(
            a < 1, (1 - a) * np.log(np.where(a < 1, 1 - a, 1.0) / (1 - alpha)), 0.0
        )
    hoeffding = np.exp(-n * kl)
    k = np.ceil(loss_sum - _SUM_TOL)
    bentkus = math.e * stats.binom.cdf(k, safe, alpha)
    return np.where(n > 0, np.minimum(1.0, np.minimum(hoeffding, bentkus)), 1.0)


def hb_ucb(n: int, loss_sum: float, delta: float) -> float:
    """Hoeffding-Bentkus upper bound at level 1 - delta on the mean loss: the smallest alpha the
    p-value rejects at delta (bisection to 1e-12); 1 when nothing is answered or nothing below 1 is."""
    if n == 0 or hb_p_value(n, loss_sum, 1.0 - 1e-12) > delta:
        return 1.0
    lo, hi = min(max(loss_sum / n, 0.0), 1.0), 1.0 - 1e-12  # p(lo) = 1 > delta; p(hi) <= delta
    for _ in range(200):
        if hi - lo <= 1e-12:
            break
        mid = (lo + hi) / 2
        if hb_p_value(n, loss_sum, mid) <= delta:
            hi = mid
        else:
            lo = mid
    return hi


@dataclass(frozen=True)
class CostPoint:
    abstain_below: float
    n: int  # answered
    loss_sum: float  # sum of the answered cases' normalised losses
    coverage: float
    raw_sum: float = 0.0  # the same sum before dividing by `scale` (v1.4: exact, in whole cost units)


def loss_sums(conf: np.ndarray, loss: np.ndarray, cuts: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """(answered, loss sum) at each cut, answering confidence >= cut as a consumer does."""
    conf, loss = np.asarray(conf, float), np.asarray(loss, float)
    order = np.argsort(conf, kind="stable")
    asc, loss_asc = conf[order], loss[order]
    first = np.searchsorted(asc, cuts, side="left")
    tail = np.concatenate([np.cumsum(loss_asc[::-1])[::-1], [0.0]])
    return len(asc) - first, tail[first]


def cost_start(cuts: np.ndarray, conf: np.ndarray, loss: np.ndarray, alpha: float, scale: float = 1.0) -> int:
    """`start` with the Hoeffding-Bentkus p-value: the cut with the smallest p on the temperature split. With
    `scale`, `loss` is in cost units and each sum is divided by it once (spec v1.4: whole costs, summed exactly)."""
    n, s = loss_sums(conf, loss, cuts)
    return int(np.argmin(hb_p_values(n, s / scale, alpha)))


def cost_grid(conf_temperature: np.ndarray, loss_temperature: np.ndarray, alpha: float) -> np.ndarray:
    """`grid` for bounded losses: the same cuts, starting where the temperature split's losses put the start."""
    cuts = cuts_of(conf_temperature)
    return cuts[cost_start(cuts, np.asarray(conf_temperature, float), loss_temperature, alpha) :]


def cost_ltt(
    conf: np.ndarray, loss: np.ndarray, cuts: np.ndarray, alpha: float, delta: float, scale: float = 1.0
) -> CostPoint:
    """Fixed-sequence Learn-then-Test down `cuts` on mean normalised loss, with Hoeffding-Bentkus p-values. With
    `scale`, `loss` is in cost units and each sum is divided by it once."""
    n, raw = loss_sums(conf, loss, cuts)
    s = raw / scale
    failed = np.flatnonzero(hb_p_values(n, s, alpha) > delta)
    i = int((failed[0] if len(failed) else len(cuts)) - 1)
    if i < 0:
        return CostPoint(ABSTAIN_ALL, 0, 0.0, 0.0)
    return CostPoint(float(cuts[i]), int(n[i]), float(s[i]), int(n[i]) / len(conf), float(raw[i]))


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
