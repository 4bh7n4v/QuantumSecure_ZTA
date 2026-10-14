"""
ML Signal Extractor
-------------------
Loads the trained flow classifier and scores a set of flows. Produces a
per-device summary:

    { "10.0.0.9": {
        "flow_count":      4,
        "malicious_flows": 4,
        "anomaly_rate":    1.0,          # 0..1
        "top_class":       "port_scan",
        "class_counts":    {"port_scan": 3, "c2_beacon": 1}
      },
      ...
    }

Input flows come as JSON:
    { "flows": [ {"src_ip": "...", "features": { <15 CIC-IDS-style fields> }}, ... ] }

Later this will be replaced by an on-the-fly pcap → feature extractor
(scapy or nfstream). For the demo, we ship canned flow files.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import joblib
import numpy as np

from ml.generate_dataset import FEATURES

ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = ROOT / "ml" / "model.joblib"


_model = None


def _load_model():
    global _model
    if _model is None:
        if not MODEL_PATH.exists():
            raise SystemExit(
                f"model not found at {MODEL_PATH}. "
                "Run `python -m ml.generate_dataset && python -m ml.train` first."
            )
        _model = joblib.load(MODEL_PATH)
    return _model


def score_flows(flows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """
    flows: [{"src_ip": str, "features": {feature_name: value, ...}}, ...]
    Returns per-device aggregate.
    """
    if not flows:
        return {}

    model = _load_model()

    X = np.array(
        [[f["features"].get(name, 0.0) for name in FEATURES] for f in flows],
        dtype=np.float32,
    )
    predictions = model.predict(X)

    per_device: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"flow_count": 0, "malicious_flows": 0, "class_counts": Counter()}
    )
    for flow, pred in zip(flows, predictions):
        ip = flow["src_ip"]
        d = per_device[ip]
        d["flow_count"] += 1
        d["class_counts"][pred] += 1
        if pred != "benign":
            d["malicious_flows"] += 1

    out: dict[str, dict[str, Any]] = {}
    for ip, d in per_device.items():
        counts = dict(d["class_counts"])
        malicious_only = {k: v for k, v in counts.items() if k != "benign"}
        top_class = max(malicious_only, key=malicious_only.get) if malicious_only else "benign"
        out[ip] = {
            "flow_count":      d["flow_count"],
            "malicious_flows": d["malicious_flows"],
            "anomaly_rate":    d["malicious_flows"] / d["flow_count"],
            "top_class":       top_class,
            "class_counts":    counts,
        }
    return out


def extract(path: str | Path) -> dict[str, dict[str, Any]]:
    """Convenience: JSON file path → per-device ML signal."""
    with Path(path).open("r", encoding="utf-8") as f:
        doc = json.load(f)
    return score_flows(doc.get("flows", []))


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Score flows with the trained ML model")
    ap.add_argument("path", help="path to a flows.json file")
    args = ap.parse_args()
    result = extract(args.path)
    print(json.dumps(result, indent=2))
