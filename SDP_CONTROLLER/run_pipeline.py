#!/usr/bin/env python3
"""
Detection Pipeline Orchestrator
-------------------------------
Reads Suricata alerts + ML-scored flows, produces a single per-device telemetry
snapshot that the policy engine consumes.

    python run_pipeline.py --benign     # write telemetry_snapshot.json from benign inputs
    python run_pipeline.py --attack     # write telemetry_snapshot.json from attack inputs
    python run_pipeline.py --eve X.json --flows Y.json  # custom inputs

The snapshot format:
    {
      "10.0.0.9": {
        "suricata": { alert_count, max_severity, categories, signatures },
        "ml":       { flow_count, malicious_flows, anomaly_rate, top_class, class_counts }
      },
      ...
    }
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from rich.console import Console
from rich.table import Table

from detection.ml_signal import extract as extract_ml
from detection.suricata_signal import extract as extract_suricata

ROOT = Path(__file__).parent
DATA = ROOT / "data"
SNAPSHOT = ROOT / "telemetry_snapshot.json"

console = Console()


def build_snapshot(eve_path: Path, flows_path: Path) -> dict:
    suricata = extract_suricata(eve_path) if eve_path.exists() else {}
    ml = extract_ml(flows_path) if flows_path.exists() else {}
    ips = set(suricata) | set(ml)
    return {ip: {"suricata": suricata.get(ip), "ml": ml.get(ip)} for ip in sorted(ips)}


def render(snapshot: dict) -> None:
    if not snapshot:
        console.print("[dim](telemetry snapshot is empty)[/dim]")
        return
    t = Table(title="Per-device telemetry snapshot", header_style="bold", expand=True)
    t.add_column("device_ip", style="bold cyan", no_wrap=True)
    t.add_column("suricata alerts", no_wrap=True)
    t.add_column("max sev", justify="center", no_wrap=True)
    t.add_column("ml flows", justify="right", no_wrap=True)
    t.add_column("anomaly rate", justify="right", no_wrap=True)
    t.add_column("top class", no_wrap=True)
    t.add_column("signatures", overflow="ellipsis", no_wrap=True, ratio=1)
    for ip, entry in snapshot.items():
        s = entry.get("suricata") or {}
        m = entry.get("ml") or {}
        sev = s.get("severity_label") or "-"
        sev_color = {"critical": "red", "high": "yellow", "medium": "cyan"}.get(sev, "dim")
        t.add_row(
            ip,
            str(s.get("alert_count", 0)),
            f"[{sev_color}]{sev}[/{sev_color}]",
            str(m.get("flow_count", 0)),
            f"{m.get('anomaly_rate', 0):.2f}",
            m.get("top_class", "-"),
            ", ".join((s.get("signatures") or [])[:3]) or "-",
        )
    console.print(t)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--benign", action="store_true", help="use bundled benign inputs")
    ap.add_argument("--attack", action="store_true", help="use bundled attack inputs")
    ap.add_argument("--eve", help="path to Suricata eve.json")
    ap.add_argument("--flows", help="path to flows.json (for ML scoring)")
    ap.add_argument("--out", default=str(SNAPSHOT), help="output snapshot path")
    args = ap.parse_args()

    if args.attack:
        eve, flows = DATA / "eve_attack.json", DATA / "flows_attack.json"
    elif args.benign:
        eve, flows = DATA / "eve_benign.json", DATA / "flows_benign.json"
    else:
        eve = Path(args.eve) if args.eve else DATA / "eve_benign.json"
        flows = Path(args.flows) if args.flows else DATA / "flows_benign.json"

    console.print(f"[dim]suricata input: {eve}[/dim]")
    console.print(f"[dim]ml input:       {flows}[/dim]\n")

    snapshot = build_snapshot(eve, flows)
    render(snapshot)

    out = Path(args.out)
    out.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
    console.print(f"\n[green]wrote {out}[/green]")


if __name__ == "__main__":
    main()
