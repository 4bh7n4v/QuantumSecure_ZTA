"""
Trust Score Calculator
----------------------
Fuses three sources of evidence into a 0..100 trust score:

  * Device posture   (60 pts)   — MDM signals: managed, patched, encrypted, ...
  * Suricata IDS     (25 pts)   — signature-based alerts on the device's flows
  * ML anomaly       (15 pts)   — RandomForest classifier over flow features

Interface: `enrich_request(request, telemetry=None)`
  * `request` is the ZT access request (as in scenarios.yaml).
  * `telemetry` is an optional per-device network snapshot produced by the
    detection pipeline. If absent, we fall back to the request's static
    `device.signals` (baseline zero-trust: unknown = untrusted).

Score contributions are always transparent — the breakdown is attached to
`device.trust_breakdown` so operators can explain any decision.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Weights (must sum to 100)
# ---------------------------------------------------------------------------

POSTURE_WEIGHTS = {
    "device_managed":     15,
    "disk_encrypted":      5,
    "os_patched":         15,
    "antivirus_running":   5,
    "known_device":       10,
    "location_expected":  10,
}
POSTURE_MAX = sum(POSTURE_WEIGHTS.values())      # 60

SURICATA_MAX = 25
ML_MAX = 15
TOTAL_MAX = POSTURE_MAX + SURICATA_MAX + ML_MAX  # 100
assert TOTAL_MAX == 100


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

@dataclass
class TrustBreakdown:
    score: int
    posture_score: int
    suricata_score: int
    ml_score: int
    contributions: dict[str, Any]
    notes: list[str]


def _posture_score(signals: dict) -> tuple[int, dict[str, int]]:
    contrib: dict[str, int] = {}
    total = 0
    for name, weight in POSTURE_WEIGHTS.items():
        val = signals.get(name)
        pts = weight if val is True else 0
        contrib[name] = pts
        total += pts
    return total, contrib


def _suricata_score(alerts: dict | None) -> tuple[int, str]:
    """
    Real Suricata severity: 1=critical, 2=high, 3=medium.
    Score is subtracted from SURICATA_MAX. Any critical → 0.
    """
    if alerts is None:
        # No telemetry available: give benefit of the doubt at half credit.
        return SURICATA_MAX // 2, "no telemetry, half-credit"
    count = alerts.get("alert_count", 0)
    if count == 0:
        return SURICATA_MAX, "no alerts"
    max_sev = alerts.get("max_severity", 3) or 3
    if max_sev <= 1:
        return 0, f"{count} alert(s) incl. critical"
    if max_sev == 2:
        # High severity: 4 pts, minus 2 per extra alert, floor 0
        return max(0, 8 - 2 * count), f"{count} high-severity alert(s)"
    # Medium severity only
    return max(0, SURICATA_MAX - 3 * count), f"{count} medium-severity alert(s)"


def _ml_score(ml_summary: dict | None) -> tuple[int, str]:
    """
    ML anomaly_rate ∈ [0,1]. 0 → full credit, 1 → zero.
    Linear penalty; heavier if any malicious class other than benign top-hits.
    """
    if ml_summary is None:
        return ML_MAX // 2, "no telemetry, half-credit"
    rate = ml_summary.get("anomaly_rate", 0.0) or 0.0
    top = ml_summary.get("top_class", "benign")
    pts = int(round(ML_MAX * (1.0 - rate)))
    note = f"anomaly_rate={rate:.2f}, top={top}"
    # Extra hit for known-bad top classes (C2 / DoS)
    if top in {"c2_beacon", "dos"}:
        pts = max(0, pts - 5)
        note += " (severe class → -5)"
    return pts, note


def compute_trust_score(
    signals: dict | None = None,
    suricata: dict | None = None,
    ml: dict | None = None,
) -> TrustBreakdown:
    signals = signals or {}
    p_score, p_contrib = _posture_score(signals)
    s_score, s_note = _suricata_score(suricata)
    m_score, m_note = _ml_score(ml)

    total = min(TOTAL_MAX, p_score + s_score + m_score)
    notes = [
        f"posture:  {p_score}/{POSTURE_MAX}",
        f"suricata: {s_score}/{SURICATA_MAX}   ({s_note})",
        f"ml:       {m_score}/{ML_MAX}   ({m_note})",
    ]
    contrib = {
        "posture": p_contrib,
        "suricata": {"score": s_score, "raw": suricata},
        "ml": {"score": m_score, "raw": ml},
    }
    return TrustBreakdown(total, p_score, s_score, m_score, contrib, notes)


# ---------------------------------------------------------------------------
# Telemetry snapshot (produced by run_pipeline.py)
# ---------------------------------------------------------------------------

def load_telemetry(path: str | Path) -> dict[str, dict]:
    """
    Snapshot shape:
      { "10.0.0.9": {"suricata": {...}, "ml": {...}}, ... }
    """
    p = Path(path)
    if not p.exists():
        return {}
    return json.loads(p.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Request enrichment
# ---------------------------------------------------------------------------

def enrich_request(request: dict, telemetry: dict[str, dict] | None = None) -> dict:
    """
    Attach a computed trust score to the request's device block.
      * If `device.trust_score` is explicitly set, respect it (test overrides).
      * Otherwise fuse posture + telemetry-derived Suricata/ML signals.
    """
    device = dict(request.get("device") or {})
    if "trust_score" in device:
        return request

    signals = device.get("signals") or {}
    telem_entry = None
    if telemetry:
        ip = (request.get("context") or {}).get("ip")
        if ip and ip in telemetry:
            telem_entry = telemetry[ip]

    # If telemetry has an entry for this device, treat missing sub-signals as
    # "the pipeline ran and saw nothing bad" (full credit), not "unknown" (half).
    if telem_entry is not None:
        suricata_info = telem_entry.get("suricata") or {"alert_count": 0}
        ml_info = telem_entry.get("ml") or {"anomaly_rate": 0.0, "top_class": "benign"}
    else:
        suricata_info = None
        ml_info = None

    # Fallback: if no telemetry snapshot, honor the boolean signals in the request
    # so scenarios still run standalone.
    if telem_entry is None:
        if "no_suricata_alerts" in signals:
            suricata_info = {"alert_count": 0} if signals["no_suricata_alerts"] else \
                            {"alert_count": 3, "max_severity": 2}
        if "ml_anomaly_score_ok" in signals:
            ml_info = {"anomaly_rate": 0.0, "top_class": "benign"} if signals["ml_anomaly_score_ok"] else \
                      {"anomaly_rate": 0.9, "top_class": "port_scan"}

    breakdown = compute_trust_score(signals, suricata_info, ml_info)

    device["trust_score"] = breakdown.score
    device["trust_breakdown"] = {
        "posture":  breakdown.posture_score,
        "suricata": breakdown.suricata_score,
        "ml":       breakdown.ml_score,
        "notes":    breakdown.notes,
        "detail":   breakdown.contributions,
    }
    new_req = dict(request)
    new_req["device"] = device
    return new_req
