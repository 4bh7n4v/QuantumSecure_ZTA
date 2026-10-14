"""
Suricata Signal Extractor
-------------------------
Parses a Suricata eve.json file (line-delimited JSON) and produces a per-device
alert summary.

    { "10.0.0.9": {
        "alert_count":   4,
        "max_severity":  1,          # 1 = highest, 3 = lowest (Suricata convention)
        "categories":    ["A Network Trojan was Detected", "Attempted Information Leak"],
        "signatures":    ["ET MALWARE Cobalt Strike Beacon Observed", ...]
      },
      ...
    }

Design notes:
  * Real Suricata writes one JSON object per line; we're robust to blank lines.
  * We only bucket the *source* IP (the presumed offender). In a real deployment
    you'd also want dest_ip for lateral-movement detection.
  * `severity` in Suricata: 1 = highest / critical, 3 = lowest. We keep that
    convention here so the shape matches real output.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any


# Suricata severity → human label (1 = worst, 3 = least severe)
SEVERITY_LABEL = {1: "critical", 2: "high", 3: "medium"}


def parse_eve(path: str | Path) -> list[dict[str, Any]]:
    """Read eve.json (one JSON object per line). Skips blank/bad lines."""
    events: list[dict[str, Any]] = []
    p = Path(path)
    if not p.exists():
        return events
    with p.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue  # tolerate partial writes / corrupt lines
    return events


def summarize_alerts(events: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Bucket every `alert` event by src_ip and aggregate."""
    per_device: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"alert_count": 0, "max_severity": 99, "categories": set(), "signatures": set()}
    )
    for e in events:
        if e.get("event_type") != "alert":
            continue
        src = e.get("src_ip")
        alert = e.get("alert") or {}
        if not src or not alert:
            continue
        agg = per_device[src]
        agg["alert_count"] += 1
        sev = int(alert.get("severity", 3))
        if sev < agg["max_severity"]:
            agg["max_severity"] = sev
        if alert.get("category"):
            agg["categories"].add(alert["category"])
        if alert.get("signature"):
            agg["signatures"].add(alert["signature"])
    # Convert sets → sorted lists for JSON friendliness, and clamp max_severity
    out: dict[str, dict[str, Any]] = {}
    for ip, agg in per_device.items():
        out[ip] = {
            "alert_count": agg["alert_count"],
            "max_severity": agg["max_severity"] if agg["max_severity"] < 99 else None,
            "severity_label": SEVERITY_LABEL.get(agg["max_severity"]),
            "categories": sorted(agg["categories"]),
            "signatures": sorted(agg["signatures"]),
        }
    return out


def extract(path: str | Path) -> dict[str, dict[str, Any]]:
    """Convenience wrapper: file path → per-device alert summary."""
    return summarize_alerts(parse_eve(path))


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Summarize a Suricata eve.json file")
    ap.add_argument("path", help="path to eve.json")
    args = ap.parse_args()
    summary = extract(args.path)
    print(json.dumps(summary, indent=2))
