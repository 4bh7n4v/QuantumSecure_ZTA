"""
Train a RandomForest classifier on the synthetic (or real CIC-IDS) flow dataset.

Outputs:
  * ml/model.joblib          — the fitted pipeline (scaler + classifier)
  * ml/model_report.txt      — accuracy, F1, confusion matrix
  * ml/feature_names.json    — the column order the model expects

Run:
    python -m ml.train                       # uses ml/dataset.csv
    python -m ml.train --data path/to.csv    # to point at real CIC-IDS
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, classification_report,
                             confusion_matrix, f1_score)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from ml.generate_dataset import FEATURES

ROOT = Path(__file__).parent


def load_csv(path: Path):
    import csv
    X, y = [], []
    with path.open("r", encoding="utf-8") as f:
        r = csv.DictReader(f)
        for row in r:
            X.append([float(row[c]) for c in FEATURES])
            y.append(row["label"])
    return np.array(X, dtype=np.float32), np.array(y)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=str(ROOT / "dataset.csv"))
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    data_path = Path(args.data)
    if not data_path.exists():
        raise SystemExit(f"dataset not found: {data_path} — run `python -m ml.generate_dataset` first")

    print(f"loading {data_path} ...")
    X, y = load_csv(data_path)
    print(f"  {len(X)} rows, {len(FEATURES)} features, classes: {sorted(set(y))}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, stratify=y, random_state=args.seed
    )

    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", RandomForestClassifier(
            n_estimators=120, max_depth=None, n_jobs=-1, random_state=args.seed,
            class_weight="balanced",
        )),
    ])

    print("training RandomForest ...")
    pipeline.fit(X_train, y_train)

    y_pred = pipeline.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred, average="macro")

    labels_sorted = sorted(set(y))
    cm = confusion_matrix(y_test, y_pred, labels=labels_sorted)

    report_lines = [
        f"dataset: {data_path}",
        f"rows: {len(X)}  features: {len(FEATURES)}  classes: {labels_sorted}",
        "",
        f"accuracy:      {acc:.4f}",
        f"macro F1:      {f1:.4f}",
        "",
        "per-class report:",
        classification_report(y_test, y_pred, digits=3),
        "confusion matrix (rows=true, cols=pred):",
        "               " + "  ".join(f"{l:>11s}" for l in labels_sorted),
    ]
    for label, row in zip(labels_sorted, cm):
        report_lines.append(f"  {label:12s} " + "  ".join(f"{v:>11d}" for v in row))
    report = "\n".join(report_lines)

    print("\n" + report)

    (ROOT / "model_report.txt").write_text(report, encoding="utf-8")
    joblib.dump(pipeline, ROOT / "model.joblib")
    (ROOT / "feature_names.json").write_text(json.dumps(FEATURES, indent=2), encoding="utf-8")

    print(f"\nsaved: {ROOT/'model.joblib'}")
    print(f"saved: {ROOT/'model_report.txt'}")


if __name__ == "__main__":
    main()
