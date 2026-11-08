"""Inputs for the `demo/bank-marketing*` certificates: a public dataset, a small model, its
predictions on held-out cases, and the domain file. Deterministic: the same CSV gives the same bytes.

    cd python && uv run python tools/demo_bank_marketing.py --csv bank-full.csv --out <dir>

The dataset is UCI Bank Marketing (Moro, Rita, Cortez, 2014; https://doi.org/10.24432/C5K306,
CC BY 4.0), file `bank-full.csv` from https://archive.ics.uci.edu/static/public/222/bank+marketing.zip.
It is not stored here; the script checks its SHA-256.

- Split: a seeded permutation (seed 2012). The first half trains the model, the second half is
  what the issuer sees (it splits that again into the temperature and threshold halves).
- Model: L2-regularised logistic regression on the standardised numeric columns and one-hot
  categorical columns. `duration` is left out: it is only known after the call, so the dataset's
  own notes say to drop it for a realistic model.
- Output in <dir>: `predictions.jsonl`, `cases.jsonl` (case id and label),
  `domain/domain.yaml`, and `model.json` (features, scaling and coefficients). `model.json` is the
  certificate's manifest: its SHA-256 is the certificate's `manifest_hash`.

The certificates are then issued with the released package, never this checkout:

    uv run --isolated --no-project --with 'decision-cert[issue]==0.2.0' python -m decision_cert.issue \\
        certify --predictions <dir>/predictions.jsonl --data <dir>/cases.jsonl --domain-dir <dir>/domain \\
        --backend demo --key <demo key> --manifest <dir>/model.json --audit full-label --in-environment
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
from typing import Any

import numpy as np
from scipy.optimize import minimize

CSV_SHA256 = "d1513ec63b385506f7cfce9f2c5caa9fe99e7ba4e8c3fa264b3aaf0f849ed32d"
SEED = 2012
L2 = 1.0
NUMERIC = ["age", "balance", "day", "campaign", "pdays", "previous"]
CATEGORICAL = ["job", "marital", "education", "default", "housing", "loan", "contact", "month", "poutcome"]
DOMAIN = """\
id: bank-marketing
decisions:
  - id: subscribed
    kind: noul
    question: Did the client subscribe to a term deposit after the campaign call?
certificate:
  ttl_days: 365
"""


def read(path: Path) -> list[dict[str, str]]:
    raw = path.read_bytes()
    got = hashlib.sha256(raw).hexdigest()
    if got != CSV_SHA256:
        raise SystemExit(f"{path}: sha256 {got}, expected {CSV_SHA256} (bank-full.csv from the UCI archive)")
    return list(csv.DictReader(raw.decode("utf-8").splitlines(), delimiter=";"))


def design(rows: list[dict[str, str]], spec: dict[str, Any]) -> np.ndarray:
    cols = [(np.array([float(r[c]) for r in rows]) - spec["mean"][c]) / spec["std"][c] for c in NUMERIC]
    for c in CATEGORICAL:
        cols += [np.array([1.0 if r[c] == v else 0.0 for r in rows]) for v in spec["levels"][c]]
    return np.column_stack([np.ones(len(rows)), *cols])


def fit(x: np.ndarray, y: np.ndarray) -> np.ndarray:
    def loss(w: np.ndarray) -> tuple[float, np.ndarray]:
        z = x @ w
        nll = float(np.sum(np.logaddexp(0.0, z) - y * z))
        p = 1.0 / (1.0 + np.exp(-z))
        reg = w.copy()
        reg[0] = 0.0
        return nll + 0.5 * L2 * float(reg @ reg), x.T @ (p - y) + L2 * reg

    res = minimize(loss, np.zeros(x.shape[1]), jac=True, method="L-BFGS-B", options={"maxiter": 2000, "gtol": 1e-9})
    if not res.success:
        raise SystemExit(f"model fit did not converge: {res.message}")
    return np.asarray(res.x)


def dump_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows), encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True, type=Path, help="bank-full.csv from the UCI archive")
    ap.add_argument("--out", required=True, type=Path)
    args = ap.parse_args()
    rows = read(args.csv)
    order = np.random.default_rng(SEED).permutation(len(rows))
    half = len(rows) // 2
    train = [rows[i] for i in order[:half]]
    held = sorted(int(i) for i in order[half:])
    spec: dict[str, Any] = {
        "mean": {c: float(np.mean([float(r[c]) for r in train])) for c in NUMERIC},
        "std": {c: float(np.std([float(r[c]) for r in train])) for c in NUMERIC},
        "levels": {c: sorted({r[c] for r in train}) for c in CATEGORICAL},
    }
    w = fit(design(train, spec), np.array([1.0 if r["y"] == "yes" else 0.0 for r in train]))
    z = design([rows[i] for i in held], spec) @ w

    out = args.out
    (out / "domain").mkdir(parents=True, exist_ok=True)
    (out / "domain" / "domain.yaml").write_text(DOMAIN, encoding="utf-8")
    preds: list[dict[str, Any]] = []
    cases: list[dict[str, Any]] = []
    for i, zi in zip(held, z, strict=True):
        cid = f"bank-full-{i + 1:05d}"  # the 1-based data row of bank-full.csv
        preds.append({"case_id": cid, "decision": "subscribed", "model": "logistic-l2", "version": "1",
                      "raw_scores": [float(zi) / 2, -float(zi) / 2]})  # fmt: skip
        cases.append({"case_id": cid, "case": {}, "labels": {"subscribed": rows[i]["y"]}})
    dump_jsonl(out / "predictions.jsonl", preds)
    dump_jsonl(out / "cases.jsonl", cases)
    model: dict[str, Any] = {
        "model": "logistic-l2",
        "version": "1",
        "dataset": {
            "name": "UCI Bank Marketing",
            "file": "bank-full.csv",
            "sha256": CSV_SHA256,
            "doi": "10.24432/C5K306",
            "licence": "CC BY 4.0",
        },
        "split": {"method": "seeded permutation", "seed": SEED, "train": half, "held_out": len(held)},
        "objective": {"loss": "logistic", "l2": L2, "intercept_penalised": False},
        "scores": "raw_scores = [z / 2, -z / 2] for options [yes, no], z the linear predictor",
        "features": ["intercept", *NUMERIC, *(f"{c}={v}" for c in CATEGORICAL for v in spec["levels"][c])],
        "scaling": {"mean": spec["mean"], "std": spec["std"]},
        "coefficients": [float(v) for v in w],
    }
    (out / "model.json").write_text(json.dumps(model, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    yes = sum(c["labels"]["subscribed"] == "yes" for c in cases)
    print(f"train {half}, held out {len(held)} ({yes} yes), {len(w)} coefficients")


if __name__ == "__main__":
    main()
