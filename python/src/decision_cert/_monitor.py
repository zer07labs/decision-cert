"""Monitoring without labels against a v1.2 certificate's stored confidence histogram
(spec/decision-certificate.v1.2.md §4): bin a window of use-time confidences on the certificate's
`confidence_bins`, and compare the window with the stored histogram.

A port of the Rust crate's `bin_of`, `Histogram::of` and `shift_score`, with the same arithmetic in
the same order, so the two agree up to floating-point rounding. The shift score is descriptive: a
significant change is a prompt to measure again, never a statement that the bound has failed, and no
change is never a statement that it holds.
"""

from __future__ import annotations

import math
import numbers
from bisect import bisect_right
from collections.abc import Iterable, Sequence
from dataclasses import dataclass


@dataclass(frozen=True)
class Histogram:
    """Cases per bin of `confidence_bins`, and the cases the rule abstains on whatever the threshold
    (unscored, or above the `cannot_tell` cut)."""

    counts: tuple[int, ...]
    unscored: int

    @classmethod
    def of(cls, bins: Sequence[float], confidences: Iterable[float | None]) -> Histogram:
        """The histogram of `confidences` on `bins`. Pass None for a case the rule abstains on
        whatever the threshold (unscored, or above `rule.cannot_tell_above`), as the issuer counts
        it. Raises ValueError for a confidence outside [0, 1] or fewer than two edges."""
        if len(bins) < 2:
            raise ValueError("bins need at least two edges")
        counts = [0] * (len(bins) - 1)
        unscored = 0
        for c in confidences:
            if c is None:
                unscored += 1
            else:
                counts[bin_of(bins, c)] += 1
        return cls(tuple(counts), unscored)

    @property
    def total(self) -> int:
        return sum(self.counts) + self.unscored


@dataclass(frozen=True)
class ShiftScore:
    """Pearson's chi-square test of homogeneity between the stored histogram and a window's."""

    statistic: float
    df: int
    p_value: float


def bin_of(bins: Sequence[float], confidence: float) -> int:
    """The bin of `confidence`: `i` with `bins[i] <= confidence < bins[i + 1]`; the last bin also
    holds 1. Raises ValueError for a confidence outside [0, 1] (or not a number) or fewer than two
    edges."""
    if isinstance(confidence, bool) or not isinstance(confidence, numbers.Real):
        raise ValueError(f"confidence {confidence!r} is not a number")
    confidence = float(confidence)
    if not 0.0 <= confidence <= 1.0:
        raise ValueError(f"confidence {confidence!r} is not in [0, 1]")
    if len(bins) < 2:
        raise ValueError("bins need at least two edges")
    return min(max(bisect_right(bins, confidence) - 1, 0), len(bins) - 2)


def shift_score(baseline: Histogram, window: Histogram) -> ShiftScore:
    """Compare a window's histogram with the certificate's (spec §4). The columns are the bins and
    the unscored count; columns empty in both are dropped. With an empty side or one column left
    there is nothing to compare: statistic 0, df 0, p-value 1."""
    if len(baseline.counts) != len(window.counts):
        raise ValueError(f"the window has {len(window.counts)} bins, the certificate {len(baseline.counts)}")
    rows = ([*baseline.counts, baseline.unscored], [*window.counts, window.unscored])
    n1, n2 = float(sum(rows[0])), float(sum(rows[1]))
    kept = [(a, b) for a, b in zip(*rows, strict=True) if a > 0 or b > 0]
    if n1 == 0.0 or n2 == 0.0 or len(kept) < 2:
        return ShiftScore(0.0, 0, 1.0)
    n = n1 + n2
    stat = 0.0
    for a, b in kept:
        col = float(a) + float(b)
        e1, e2 = n1 * col / n, n2 * col / n
        stat += (a - e1) ** 2 / e1
        stat += (b - e2) ** 2 / e2
    df = len(kept) - 1
    return ShiftScore(stat, df, chi2_sf(stat, df))


# ---------- the chi-square upper tail, Q(df/2, x/2) ----------

_LANCZOS_G = 7.0
_LANCZOS = (
    0.99999999999980993,
    676.5203681218851,
    -1259.1392167224028,
    771.32342877765313,
    -176.61502916214059,
    12.507343278686905,
    -0.13857109526572012,
    9.9843695780195716e-6,
    1.5056327351493116e-7,
)
_EPS = 1e-15
_TINY = 1e-300
_MAX_ITER = 10_000


def _ln_gamma(z: float) -> float:
    """ln Γ(z) for z >= 0.5 (Lanczos, g = 7, nine coefficients)."""
    z -= 1.0
    s = _LANCZOS[0]
    for i in range(1, 9):
        s += _LANCZOS[i] / (z + float(i))
    t = z + _LANCZOS_G + 0.5
    return 0.5 * math.log(2.0 * math.pi) + (z + 0.5) * math.log(t) - t + math.log(s)


def chi2_sf(x: float, df: int) -> float:
    """P(X >= x) for X ~ chi-square with `df` degrees of freedom (df >= 1): the regularised upper
    incomplete gamma Q(df/2, x/2), by its series below a + 1 and its continued fraction above.
    1 for df 0 (nothing compared), as in the Rust crate; ValueError for a negative df."""
    if df < 0:
        raise ValueError("df must not be negative")
    if df == 0 or not x > 0.0:
        return 1.0
    a, h = df / 2.0, x / 2.0
    front = -h + a * math.log(h) - _ln_gamma(a)
    if h < a + 1.0:
        ap, term = a, 1.0 / a
        total = term
        for _ in range(_MAX_ITER):
            ap += 1.0
            term *= h / ap
            total += term
            if abs(term) < abs(total) * _EPS:
                break
        return max(0.0, 1.0 - total * math.exp(front))
    b = h + 1.0 - a
    c = 1.0 / _TINY
    d = 1.0 / b
    f = d
    for i in range(1, _MAX_ITER):
        an = -float(i) * (float(i) - a)
        b += 2.0
        d = an * d + b
        if abs(d) < _TINY:
            d = _TINY
        c = b + an / c
        if abs(c) < _TINY:
            c = _TINY
        d = 1.0 / d
        step = d * c
        f *= step
        if abs(step - 1.0) < _EPS:
            break
    return min(1.0, math.exp(front) * f)
