"""The issuer's inputs: temperature scaling, the seeded split, the labelled-cases format and the
domain file. numpy, PyYAML and the standard library only."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import math
import sys
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
import yaml

# ---------- temperature scaling ----------

T_MIN, T_MAX = 0.05, 20.0


def softmax(scores: np.ndarray, temperature: float = 1.0) -> np.ndarray:
    # Subtract the max before scaling: dividing first can overflow a huge finite score to inf, and
    # inf - inf is NaN.
    z = np.asarray(scores, dtype=float)
    e = np.exp((z - z.max(axis=-1, keepdims=True)) / temperature)
    return np.asarray(e / e.sum(axis=-1, keepdims=True))


def nll(score_rows: list[list[float]], labels: list[int], t: float) -> float:
    if score_rows and len({len(r) for r in score_rows}) == 1:
        # Same option count everywhere (the usual case): one vectorised softmax.
        p = softmax(np.asarray(score_rows, float), t)
        picked = p[np.arange(len(labels)), np.asarray(labels)]
        return float(-np.mean(np.log(np.maximum(picked, 1e-12))))
    ps = [softmax(np.asarray(s), t) for s in score_rows]  # rows can differ in length across decisions
    return float(-np.mean([np.log(max(p[y], 1e-12)) for p, y in zip(ps, labels, strict=False)]))


def fit_temperature(score_rows: list[list[float]], labels: list[int]) -> float:
    """Single temperature minimising NLL on held-out labels (grid + local refine)."""
    if not score_rows:
        raise ValueError("fit_temperature needs at least one labelled row")
    if len(score_rows) != len(labels):
        raise ValueError(f"{len(score_rows)} score rows but {len(labels)} labels")
    grid = np.exp(np.linspace(np.log(T_MIN), np.log(T_MAX), 241))
    losses = [nll(score_rows, labels, t) for t in grid]
    i = int(np.argmin(losses))
    lo, hi = grid[max(i - 1, 0)], grid[min(i + 1, len(grid) - 1)]
    fine = np.linspace(lo, hi, 101)
    j = int(np.argmin([nll(score_rows, labels, t) for t in fine]))
    return float(fine[j])


def split_halves(n: int, seed: int) -> tuple[np.ndarray, np.ndarray]:
    """Disjoint index sets for (temperature, threshold). Both non-empty when n >= 2."""
    order = np.random.default_rng(seed).permutation(n)
    half = n // 2
    return order[:half], order[half:]


# ---------- labelled cases (JSONL, one row per case) ----------
#
#     {"case_id": "<stable id>",                     required
#      "case": {...} | "text",                       required
#      "labels": {"<decision_id>": "<option_id>"},
#      "decided_at": "<ISO 8601>",                   when the real decision was made
#      "propensity": <float in (0, 1]>,              P(row was sent for labelling)
#      ...}
#
# A row without `case_id` gets the SHA-256 of its canonical case JSON, with one warning per file.

LABEL_SOURCES = frozenset({"human", "outcome", "teacher", "synthetic"})
DECIDERS = frozenset({"auto", "human"})
FIELDS = frozenset(
    {
        "case_id",
        "case",
        "labels",
        "decided_at",
        "decided_by",
        "outcome",
        "label_source",
        "segment",
        "propensity",
        "teacher",
        "source",
        "gym",
    }
)


class DataError(ValueError):
    """A row that doesn't match the cases format."""


def case_id_of(case: Any) -> str:
    """The fallback id: SHA-256 of the case as canonical JSON (sorted keys, no spaces)."""
    canon = json.dumps(case, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canon.encode()).hexdigest()


def normalize(row: dict[str, Any], where: str = "row") -> tuple[dict[str, Any], bool]:
    """Validate one row. Returns (row with `case_id`, whether the id was derived)."""
    unknown = set(row) - FIELDS
    if unknown:
        raise DataError(f"{where}: unknown fields {sorted(unknown)}")
    if "case" not in row or not isinstance(row["case"], dict | str):
        raise DataError(f"{where}: `case` must be an object or a string")
    labels = row.get("labels", {})
    if not isinstance(labels, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in labels.items()):
        raise DataError(f"{where}: `labels` must map decision ids to option ids")
    if (ls := row.get("label_source")) is not None and (not isinstance(ls, str) or ls not in LABEL_SOURCES):
        raise DataError(f"{where}: label_source {ls!r} is not one of {sorted(LABEL_SOURCES)}")
    if (seg := row.get("segment")) is not None and not isinstance(seg, str):
        raise DataError(f"{where}: `segment` must be a string")
    if (at := row.get("decided_at")) is not None:
        try:
            dt.datetime.fromisoformat(at)
        except (TypeError, ValueError):
            raise DataError(f"{where}: decided_at {at!r} is not ISO 8601") from None
    if (by := row.get("decided_by")) is not None and not (
        isinstance(by, dict) and all(isinstance(k, str) and isinstance(v, str) and v in DECIDERS for k, v in by.items())
    ):
        raise DataError(f"{where}: `decided_by` must map decision ids to one of {sorted(DECIDERS)}")
    if (p := row.get("propensity")) is not None:
        if isinstance(p, bool) or not isinstance(p, int | float) or not math.isfinite(p) or not 0 < p <= 1:
            raise DataError(f"{where}: propensity {p!r} must be a number in (0, 1]")
    if (g := row.get("gym")) is not None and not (
        isinstance(g, dict) and isinstance(g.get("generator"), str) and isinstance(g.get("seed"), int)
    ):
        raise DataError(f"{where}: `gym` must be an object with a string `generator` and an integer `seed`")
    if "case_id" in row:
        if not isinstance(row["case_id"], str) or not row["case_id"]:
            raise DataError(f"{where}: `case_id` must be a non-empty string")
        return row, False
    return {"case_id": case_id_of(row["case"]), **row}, True


def read_cases(path: str | Path, warn: Callable[[str], None] | None = None) -> list[dict[str, Any]]:
    """Rows of a cases file, validated, each with a `case_id`. Raises DataError on a bad row or a
    repeated `case_id` (a stable id must be unique)."""
    with open(path) as f:
        return parse_cases(f, str(path), warn)


def parse_cases(lines: Iterable[str], path: str, warn: Callable[[str], None] | None = None) -> list[dict[str, Any]]:
    """`read_cases` over lines already in memory."""
    rows: list[dict[str, Any]] = []
    derived = 0
    seen: dict[str, int] = {}
    for i, line in enumerate(lines, 1):
        if not line.strip():
            continue
        where = f"{path}:{i}"
        try:
            raw = json.loads(line)
        except ValueError as e:
            raise DataError(f"{where}: {e}") from None
        if not isinstance(raw, dict):
            raise DataError(f"{where}: expected a JSON object")
        row, was_derived = normalize(raw, where)
        derived += was_derived
        if (prev := seen.get(row["case_id"])) is not None:
            raise DataError(f"{where}: case_id {row['case_id']!r} repeats line {prev}")
        seen[row["case_id"]] = i
        rows.append(row)
    if derived:
        (warn or (lambda m: print(m, file=sys.stderr)))(
            f"warning: {path}: {derived} row(s) without case_id; using the SHA-256 of the case JSON"
        )
    return rows


def read_jsonl(path: str | Path) -> list[dict[str, Any]]:
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


def write_jsonl(path: str | Path, rows: Iterable[dict[str, Any]]) -> int:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with open(path, "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
            n += 1
    return n


# ---------- the domain file (domain.yaml): its decisions, options and cannot-tell bound ----------


@dataclass
class Decision:
    id: str
    kind: str  # choice | score | noul
    options: list[str]

    def option_ids(self) -> list[str]:
        return list(self.options)


@dataclass
class Domain:
    id: str
    decisions: list[Decision]
    cannot_tell_above: float | None = None

    def decision(self, decision_id: str) -> Decision:
        for d in self.decisions:
            if d.id == decision_id:
                return d
        raise KeyError(f"unknown decision '{decision_id}' in domain '{self.id}'")


def _options(kind: str, raw: list[dict[str, Any]] | None) -> list[str]:
    if kind == "noul" and not raw:
        return ["yes", "no"]
    return [o["id"] for o in (raw or [])]


def _unit_interval(v: Any, name: str, where: Path) -> float | None:
    """`None`, or a number in [0, 1]."""
    if v is None:
        return None
    if isinstance(v, bool) or not isinstance(v, int | float) or not 0.0 <= v <= 1.0:
        raise ValueError(f"{where}: {name} must be a number in [0, 1], got {v!r}")
    return float(v)


def load_domain(path: str | Path) -> Domain:
    """Load a domain directory (or a path to its domain.yaml)."""
    p = Path(path)
    if p.is_dir():
        p = p / "domain.yaml"
    raw = yaml.safe_load(p.read_text())
    decisions = [Decision(d["id"], d["kind"], _options(d["kind"], d.get("options"))) for d in raw["decisions"]]
    return Domain(raw["id"], decisions, _unit_interval(raw.get("cannot_tell_above"), "cannot_tell_above", p))
