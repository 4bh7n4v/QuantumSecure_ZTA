# Zero Trust Policy Engine + Dynamic Trust Score

A Rego-style policy engine for Zero Trust Network Access, driven by a live
trust score computed from three sources:

  * **Device posture** (60 pts) — MDM signals (managed, patched, encrypted, …)
  * **Suricata IDS** (25 pts) — signature-based alerts from network traffic
  * **ML anomaly detection** (15 pts) — RandomForest classifier over flow features

The policy engine consumes an opaque `device.trust_score` and re-evaluates
every request in real time. When the detection pipeline flags a device, its
trust drops, and the *same policies* start denying — no policy edits needed.

---

## File map

```
final year project/
├── engine.py                 Rego-style policy evaluator (safe AST)
├── trust_scorer.py           Fuses posture + Suricata + ML into 0..100
├── policies.yaml             LIVE-EDITABLE zero-trust policies
├── scenarios.yaml            Sample access requests
├── demo.py                   Rich CLI: single-shot / --watch / --scenario / --request
├── run_pipeline.py           Orchestrator: eve.json + flows.json → telemetry snapshot
├── requirements.txt
│
├── detection/
│   ├── suricata_signal.py    Parses Suricata eve.json → per-device alerts
│   └── ml_signal.py          Runs trained model on flows → per-device anomaly
│
├── ml/
│   ├── generate_dataset.py   Synthetic CIC-IDS-style labeled flows
│   ├── train.py              Trains RandomForest, saves joblib model
│   ├── dataset.csv           (generated)
│   ├── model.joblib          (generated)
│   └── model_report.txt      (generated — accuracy, F1, confusion matrix)
│
└── data/
    ├── eve_benign.json       Suricata output — no alerts
    ├── eve_attack.json       Suricata output — portscan + Cobalt Strike C2
    ├── flows_benign.json     Flow features — all normal
    └── flows_attack.json     Flow features — Bob's device compromised
```

---

## Setup (once)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m ml.generate_dataset   # synthesize 5000 labeled flows
python -m ml.train              # train RandomForest → ml/model.joblib
```

Training report is written to `ml/model_report.txt`
(~97% accuracy, macro F1 ~0.96 on the noisy synthetic set).

Real Suricata is optional — install with `sudo apt install suricata` and
point `run_pipeline.py --eve /var/log/suricata/eve.json` at real output.
The bundled `data/eve_*.json` samples match Suricata's schema exactly.

---

## Run the demo

```bash
# 1. Baseline — no telemetry, scenario defaults only
python demo.py

# 2. Benign telemetry — Suricata sees nothing, ML classifies all flows benign
python run_pipeline.py --benign
python demo.py                          # verdicts identical to baseline

# 3. Attack telemetry — Bob's device has Cobalt Strike + portscan alerts
python run_pipeline.py --attack
python demo.py                          # Bob (scenario #2) flips to DENY

# Extras
python demo.py --scenario 2             # focus one scenario
python demo.py --watch                  # auto-rerun on policy / telemetry save
python run_pipeline.py --eve /var/log/suricata/eve.json --flows myflows.json
```

---

## What the demo shows

**Scenario #2 (Bob, employee, confidential doc):**

| State | trust_score | Breakdown (posture / suricata / ml) | Verdict |
|---|---|---|---|
| Baseline (no telemetry) | 85 | 45 / 25 / 15 | ALLOW + MFA |
| Benign telemetry | 85 | 45 / 25 / 15 | ALLOW + MFA |
| Attack telemetry | **45** | 45 / **0** / **0** | **DENY** (implicit — no allow rule fires below trust 70) |

The 40-point drop comes entirely from the network detection layer.
Posture is unchanged (Bob's laptop is still managed, still unpatched, etc.)
— it's the *behaviour* that flipped him.

---

## How the trust score works

`trust_scorer.compute_trust_score(signals, suricata, ml)`:

* **Posture (0–60)** — sum of weighted boolean signals in `device.signals`.
* **Suricata (0–25)** —
  * 0 alerts → 25
  * medium (severity 3) only → 25 − 3·count
  * high (severity 2) → max(0, 8 − 2·count)
  * any critical (severity 1) → **0**
* **ML (0–15)** — `15 × (1 − anomaly_rate)`; −5 extra if `top_class ∈ {c2_beacon, dos}`.

The full breakdown is attached to `device.trust_breakdown` so decisions
are explainable.

---

## How the ML piece works

* **Dataset**: 5000 flows, 15 CIC-IDS-style features, 5 classes
  (`benign`, `port_scan`, `dos`, `brute_force`, `c2_beacon`).
  Generated synthetically with realistic per-class distributions,
  multiplicative gaussian noise, and 3% label noise (prevents unrealistic
  100% accuracy). Schema matches CIC-IDS2017 so real CSVs can be swapped in.
* **Model**: RandomForest (120 trees, class-balanced), StandardScaler pipeline.
* **Reported**: ~97% accuracy, macro F1 ~0.96, confusion matrix in
  `ml/model_report.txt`.

Swap to real CIC-IDS2017: rename columns to match `FEATURES` in
`ml/generate_dataset.py`, then `python -m ml.train --data yourfile.csv`.

---

## Live demo script (5 min)

Two panes: `python demo.py --watch` on the left, editor on the right.

1. **Baseline.** Run `python demo.py` — Alice ALLOW, Bob ALLOW+MFA, etc.
2. **Simulate attack.** Run `python run_pipeline.py --attack`. The snapshot
   file changes → `--watch` re-renders → Bob flips to **DENY** live.
3. **Explain the flip.** Point at Bob's row: `trust_score: 85 → 45`,
   with `suricata=0` (Cobalt Strike alert) and `ml=0` (4/4 flows malicious).
4. **Same policy, different verdict.** Emphasise nothing in `policies.yaml`
   changed — the *dynamic* trust signal is what moved the decision.
5. **Restore.** Run `python run_pipeline.py --benign` → Bob back to ALLOW+MFA.

---

## What plugs in next

* Live Suricata: `sudo apt install suricata`, point at a real interface,
  the same eve.json parser feeds the pipeline unchanged.
* Real dataset: download CIC-IDS2017 CSV, rename columns, `python -m ml.train --data ...`.
* On-the-fly flow extraction from pcap (nfstream / scapy).
* Continuous re-scoring instead of on-demand.
* HTTP PDP wrapper so a real proxy (Envoy ext-authz) can call the engine.
