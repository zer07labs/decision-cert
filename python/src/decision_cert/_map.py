"""Calibration maps (spec/decision-certificate.v1.2.md §1 and §2): the parameter shape of each kind
v1.2 defines, and the probabilities a map gives a case's raw scores.

A port of the Rust crate's `probabilities` and `confidence`, with the same arithmetic in the same
order, so the two agree up to floating-point rounding.
"""

from __future__ import annotations

import math
import numbers
from collections.abc import Mapping, Sequence
from typing import Any

#: The kinds of calibration map v1.2 defines. A certificate may name another kind; it still
#: verifies, and a consumer that does not apply that kind refuses it (spec v1.2 §4).
MAP_KINDS = ("temperature", "dr")

TEMPERATURE_SHAPE = "a `temperature` calibration_map needs exactly the param `temperature`, above 0"
DR_SHAPE = (
    "a `dr` calibration_map needs exactly the params `a`, above 0, and `b0` to `b{k-1}` for its k options, "
    "and a label_budget of at least 1"
)


def _real(x: Any) -> bool:
    return isinstance(x, numbers.Real) and not isinstance(x, bool)


def _float(x: Any) -> float | None:
    if not _real(x):
        return None
    try:
        f = float(x)
    except OverflowError:
        return None
    return f if math.isfinite(f) else None


def _temperature(params: Mapping[str, Any]) -> float | None:
    t = _float(params.get("temperature"))
    return t if len(params) == 1 and t is not None and t > 0 else None


def _dr(params: Mapping[str, Any], k: int) -> tuple[float, list[float]] | None:
    a = _float(params.get("a"))
    b = [_float(params.get(f"b{i}")) for i in range(k)]
    if len(params) != k + 1 or a is None or not a > 0 or any(x is None for x in b):
        return None
    return a, [x for x in b if x is not None]


def check(m: Mapping[str, Any], k: int) -> str | None:
    """v1.2's check of a map's parameters (spec v1.2 §2), for a certificate with `k` options: the
    message to refuse it with, or None. A kind v1.2 does not define is not checked."""
    if m["kind"] == "temperature" and _temperature(m["params"]) is None:
        return TEMPERATURE_SHAPE
    if m["kind"] == "dr":
        budget = m["label_budget"]
        if _dr(m["params"], k) is None or budget is None or budget < 1:
            return DR_SHAPE
    return None


def probabilities(calibration_map: Mapping[str, Any], scores: Sequence[float]) -> tuple[float, ...] | None:
    """The probabilities `calibration_map` (a certificate's `{kind, params, label_budget}`) gives a
    case's raw scores, one per option in score order (spec v1.2 §1):

    - `temperature`: softmax(scores / temperature);
    - `dr`: softmax(a · scores + b), with `b` the params `b0` to `b{k-1}`.

    None when the kind is not one of `MAP_KINDS`, its params do not have that kind's shape for
    `len(scores)` options, there are fewer than 2 scores, or a score or logit is not finite. The
    case's confidence is the largest probability (`confidence`).
    """
    params = calibration_map.get("params")
    if len(scores) < 2 or not isinstance(params, Mapping):
        return None
    read = [_float(x) for x in scores]
    s = [x for x in read if x is not None]
    if len(s) != len(read):
        return None
    kind = calibration_map.get("kind")
    if kind == "temperature":
        t = _temperature(params)
        if t is None:
            return None
        logits = [x / t for x in s]
    elif kind == "dr":
        fit = _dr(params, len(s))
        if fit is None:
            return None
        a, b = fit
        logits = [a * x + bi for x, bi in zip(s, b, strict=True)]
    else:
        return None
    if not all(math.isfinite(z) for z in logits):
        return None
    top = max(logits)
    e = [math.exp(z - top) for z in logits]
    total = 0.0
    for x in e:  # in order, as the crate sums (the builtin sum compensates, from Python 3.12)
        total += x
    return tuple(x / total for x in e)


def confidence(calibration_map: Mapping[str, Any], scores: Sequence[float]) -> float | None:
    """A case's confidence under `calibration_map`: the largest of its `probabilities`. None when
    those are."""
    p = probabilities(calibration_map, scores)
    return None if p is None else max(p)
