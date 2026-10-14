#!/usr/bin/env python3
"""
Zero Trust Policy Engine - Demo CLI
-----------------------------------
    python demo.py                    # evaluate all scenarios once
    python demo.py --scenario 3       # evaluate one scenario (1-indexed)
    python demo.py --watch            # re-evaluate on every file save
    python demo.py --request '{...}'  # evaluate an inline JSON request

Live demo tip: keep `--watch` running, edit `policies.yaml` in another pane,
save, and the whole board re-renders.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import time
from pathlib import Path

import yaml
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from engine import Decision, evaluate, load_policies
from trust_scorer import enrich_request, load_telemetry

ROOT = Path(__file__).parent
POLICIES_PATH = ROOT / "policies.yaml"
SCENARIOS_PATH = ROOT / "scenarios.yaml"
TELEMETRY_PATH = ROOT / "telemetry_snapshot.json"

# Auto-detect terminal width, floor at 140 so the tables never get squished
# when output is piped or the terminal is small.
_TERM_WIDTH = max(shutil.get_terminal_size((140, 40)).columns, 140)
console = Console(width=_TERM_WIDTH)


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def _verdict_style(verdict: str, obligations: list[str]) -> tuple[str, str]:
    if verdict == "DENY":
        return ("bold white on red", "DENY")
    if obligations:
        label = "ALLOW + " + " + ".join(o.upper() for o in obligations)
        return ("bold black on yellow", label)
    return ("bold white on green", "ALLOW")


def render_request(name: str, req: dict) -> Panel:
    u = req.get("user", {}) or {}
    d = req.get("device", {}) or {}
    r = req.get("resource", {}) or {}
    c = req.get("context", {}) or {}
    body = Text()
    body.append("USER   ", style="bold cyan")
    body.append(f"{u.get('id','?')}  role={u.get('role','?')}  "
                f"auth={u.get('authenticated')}  mfa={u.get('mfa_verified')}\n")
    body.append("DEVICE ", style="bold cyan")
    ts = d.get("trust_score")
    ts_color = "green" if (ts or 0) >= 70 else "yellow" if (ts or 0) >= 40 else "red"
    body.append(f"os={d.get('os','?')}  managed={d.get('managed')}  known={d.get('known')}  ")
    body.append(f"trust_score={ts}", style=f"bold {ts_color}")
    tb = d.get("trust_breakdown") or {}
    if tb:
        body.append(f"   (posture={tb.get('posture','?')}  "
                    f"suricata={tb.get('suricata','?')}  "
                    f"ml={tb.get('ml','?')})", style="dim")
    body.append("\n")
    body.append("RES    ", style="bold cyan")
    body.append(f"{r.get('name','?')}  classification={r.get('classification','?')}\n")
    body.append("CTX    ", style="bold cyan")
    body.append(f"hour={c.get('hour')}  country={c.get('country')}  action={c.get('action')}")
    return Panel(body, title=f"[bold]{name}[/bold]", border_style="cyan", padding=(0, 1))


def render_matches(decision: Decision) -> Table:
    t = Table(show_lines=False, header_style="bold", expand=True)
    t.add_column("prio",        justify="right", min_width=5,  no_wrap=True)
    t.add_column("policy id",                    min_width=32, no_wrap=True)
    t.add_column("effect",                       min_width=15, no_wrap=True)
    t.add_column("match",       justify="center", min_width=6, no_wrap=True)
    t.add_column("description", overflow="ellipsis", no_wrap=True, ratio=1)
    for m in decision.matched:
        prio = str(m.policy.priority)
        eff = m.policy.effect
        eff_style = {
            "deny": "bold red",
            "allow": "bold green",
            "require_mfa": "bold yellow",
            "require_stepup": "bold magenta",
            "log": "dim",
        }.get(eff, "")
        if m.error:
            mark = Text("ERR", style="red")
        elif m.matched:
            mark = Text("✔", style="bold green")
        else:
            mark = Text("·", style="dim")
        row_style = None if m.matched or m.error else "dim"
        t.add_row(prio, m.policy.id, Text(eff, style=eff_style), mark,
                  m.policy.description + (f"  [red]({m.error})[/red]" if m.error else ""),
                  style=row_style)
    return t


def render_decision(name: str, request: dict, decision: Decision) -> None:
    style, label = _verdict_style(decision.verdict, decision.obligations)
    console.print(render_request(name, request))
    console.print(render_matches(decision))
    reason_lines = "\n".join(f"  • {r}" for r in decision.reasons) or "  (no reasons)"
    console.print(Panel(f"[{style}] {label} [/{style}]\n\n{reason_lines}",
                        border_style="white", padding=(0, 1)))
    console.print()


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def load_scenarios() -> list[dict]:
    with open(SCENARIOS_PATH, "r", encoding="utf-8") as f:
        return (yaml.safe_load(f) or {}).get("scenarios", [])


def evaluate_all(only_index: int | None = None) -> None:
    console.clear()
    console.print(Rule("[bold cyan]ZERO TRUST POLICY ENGINE — LIVE EVALUATION[/bold cyan]"))
    telemetry = load_telemetry(TELEMETRY_PATH)
    telem_note = (f"telemetry: {TELEMETRY_PATH.name} ({len(telemetry)} devices)"
                  if telemetry else "telemetry: (none — using scenario defaults)")
    console.print(f"[dim]policies: {POLICIES_PATH.name}   scenarios: {SCENARIOS_PATH.name}   "
                  f"{telem_note}   time: {time.strftime('%H:%M:%S')}[/dim]\n")

    try:
        policies = load_policies(str(POLICIES_PATH))
    except Exception as e:
        console.print(Panel(f"[red]Failed to load policies:[/red] {e}", border_style="red"))
        return

    console.print(f"[dim]Loaded {len(policies)} policies.[/dim]\n")

    scenarios = load_scenarios()
    summary_rows: list[tuple[str, str, str]] = []
    for i, s in enumerate(scenarios, start=1):
        if only_index and i != only_index:
            continue
        request = enrich_request(s["request"], telemetry=telemetry)
        decision = evaluate(policies, request)
        console.print(Rule(f"[bold]#{i}  {s['name']}[/bold]", style="cyan"))
        render_decision(s["name"], request, decision)
        _, label = _verdict_style(decision.verdict, decision.obligations)
        summary_rows.append((str(i), s["name"], label))

    if len(summary_rows) > 1:
        console.print(Rule("[bold]SUMMARY[/bold]"))
        t = Table(header_style="bold", expand=True)
        t.add_column("#", justify="right", width=3)
        t.add_column("scenario")
        t.add_column("verdict")
        for row in summary_rows:
            style = "red" if "DENY" in row[2] else ("yellow" if "MFA" in row[2] or "STEPUP" in row[2] else "green")
            t.add_row(row[0], row[1], Text(row[2], style=f"bold {style}"))
        console.print(t)


def evaluate_inline(request_json: str) -> None:
    try:
        request = json.loads(request_json)
    except json.JSONDecodeError as e:
        console.print(f"[red]invalid JSON:[/red] {e}")
        sys.exit(2)
    policies = load_policies(str(POLICIES_PATH))
    request = enrich_request(request)
    decision = evaluate(policies, request)
    render_decision("inline request", request, decision)


def watch_and_run() -> None:
    watched = [POLICIES_PATH, SCENARIOS_PATH, TELEMETRY_PATH]
    last = {p: (p.stat().st_mtime if p.exists() else 0) for p in watched}
    evaluate_all()
    console.print("[dim]watching for changes... (Ctrl-C to stop)[/dim]")
    try:
        while True:
            time.sleep(0.5)
            changed = False
            for p in watched:
                m = p.stat().st_mtime if p.exists() else 0
                if m != last[p]:
                    last[p] = m
                    changed = True
            if changed:
                evaluate_all()
                console.print("[dim]watching for changes... (Ctrl-C to stop)[/dim]")
    except KeyboardInterrupt:
        console.print("\n[dim]bye.[/dim]")


def main() -> None:
    ap = argparse.ArgumentParser(description="Zero Trust policy engine demo")
    ap.add_argument("--scenario", type=int, help="evaluate a single scenario (1-indexed)")
    ap.add_argument("--watch", action="store_true", help="re-run on every file save")
    ap.add_argument("--request", help="evaluate one inline JSON request")
    args = ap.parse_args()

    if args.request:
        evaluate_inline(args.request)
    elif args.watch:
        watch_and_run()
    else:
        evaluate_all(only_index=args.scenario)


if __name__ == "__main__":
    main()
