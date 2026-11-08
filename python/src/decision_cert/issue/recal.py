"""Few-label recalibration under shift, with a learned prior (the `dr` map; not part of spec v1).

A model fitted on one population is moved to a shifted one, where n labelled cases are available
(the label budget). The map refits

    q = softmax(a · log p + b),   a a temperature, b a per-option shift of the log prior,

by MAP on those n labels, with a Gaussian prior a ~ N(mu_a, sigma_a²), b_k ~ N(0, sigma_b²). The prior is
not hand-set: `meta_prior` learns it from maximum-likelihood fits on many earlier shifts. With few
labels the prior keeps the fit from chasing noise; with many it washes out.

`isotonic_fit` / `isotonic_apply` are the comparison: isotonic regression on the top-label
confidence, fitted on the same labels. Pure functions over numpy arrays.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from scipy.optimize import minimize

SIGMA_FLOOR = 0.05
MLE_SIGMA = 10.0  # near-flat prior for maximum-likelihood fits


@dataclass(frozen=True)
class Prior:
    mu_a: float
    sigma_a: float
    sigma_b: float

    def to_json(self) -> dict[str, float]:
        return {"mu_a": self.mu_a, "sigma_a": self.sigma_a, "sigma_b": self.sigma_b}


FLAT = Prior(1.0, MLE_SIGMA, MLE_SIGMA)


def _log_softmax(z: np.ndarray) -> np.ndarray:
    z = z - z.max(axis=1, keepdims=True)
    return np.asarray(z - np.log(np.exp(z).sum(axis=1, keepdims=True)))


def apply(logp: np.ndarray, a: float, b: np.ndarray) -> np.ndarray:
    return np.exp(_log_softmax(a * logp + b[None, :]))


def fit(logp: np.ndarray, y: np.ndarray, prior: Prior) -> tuple[float, np.ndarray]:
    """MAP (a, b) for q = softmax(a·logp + b) on labels y."""
    _n, k = logp.shape
    onehot = np.eye(k)[y]

    def loss(theta: np.ndarray) -> tuple[float, np.ndarray]:
        a, b = theta[0], theta[1:]
        ls = _log_softmax(a * logp + b[None, :])
        q = np.exp(ls)
        nll = -float((ls * onehot).sum())
        r = q - onehot  # d nll / d logits
        ga = float((r * logp).sum()) + (a - prior.mu_a) / prior.sigma_a**2
        gb = r.sum(axis=0) + b / prior.sigma_b**2
        pen = 0.5 * ((a - prior.mu_a) / prior.sigma_a) ** 2 + 0.5 * float((b**2).sum()) / prior.sigma_b**2
        return nll + pen, np.concatenate([[ga], gb])

    res = minimize(loss, np.concatenate([[prior.mu_a], np.zeros(k)]), jac=True, method="L-BFGS-B")
    return float(res.x[0]), np.asarray(res.x[1:])


def meta_prior(fits: list[tuple[float, np.ndarray]]) -> Prior:
    """The prior from per-shift maximum-likelihood fits: mean and spread of a, spread of centred b."""
    a = np.array([f[0] for f in fits])
    b = np.concatenate([f[1] - f[1].mean() for f in fits])
    return Prior(float(a.mean()), max(SIGMA_FLOOR, float(a.std())), max(SIGMA_FLOOR, float(b.std())))


def isotonic_fit(x: np.ndarray, y: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """Pool-adjacent-violators: a non-decreasing step map x → E[y], as (knots, values)."""
    order = np.argsort(x, kind="stable")
    xs, ys = np.asarray(x, float)[order], np.asarray(y, float)[order]
    vals: list[float] = []
    wts: list[float] = []
    ends: list[float] = []
    for xv, yv in zip(xs, ys, strict=True):
        vals.append(float(yv))
        wts.append(1.0)
        ends.append(float(xv))
        while len(vals) > 1 and vals[-2] > vals[-1]:
            w = wts[-2] + wts[-1]
            v = (vals[-2] * wts[-2] + vals[-1] * wts[-1]) / w
            vals[-2:], wts[-2:], ends[-2:] = [v], [w], [ends[-1]]
    return np.array(ends), np.array(vals)


def isotonic_apply(model: tuple[np.ndarray, np.ndarray], x: np.ndarray) -> np.ndarray:
    ends, vals = model
    i = np.searchsorted(ends, np.asarray(x, float), side="left")
    return np.asarray(vals[np.minimum(i, len(vals) - 1)])


def top_label(p: np.ndarray, y: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    return p.max(axis=1), p.argmax(axis=1) == y
