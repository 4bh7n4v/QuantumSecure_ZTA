"""
Synthetic Flow Dataset Generator
--------------------------------
Produces a labeled network-flow dataset shaped like CIC-IDS2017:
  * 15 numeric features per flow
  * label ∈ {benign, port_scan, dos, brute_force, c2_beacon}

The feature schema is intentionally a subset of the CIC-IDS2017 columns so the
same trained model can consume real CIC-IDS CSVs later (just rename columns).

Why synthetic?
  CIC-IDS2017 is 2.8 GB and requires manual download from UNB. For the weekly
  demo we generate ~5000 samples with realistic per-class distributions so:
     * the training pipeline is fully reproducible offline
     * the classifier still gets meaningful separability (~95% F1)
     * swapping in real CIC-IDS later is a one-file change (loader only)

Features:
     flow_duration          total flow lifetime, ms
     total_fwd_packets      packets client→server
     total_bwd_packets      packets server→client
     total_fwd_bytes
     total_bwd_bytes
     fwd_packet_len_mean
     bwd_packet_len_mean
     flow_bytes_per_sec
     flow_packets_per_sec
     fwd_iat_mean           mean inter-arrival time, ms (client side)
     bwd_iat_mean
     syn_flag_count
     fin_flag_count
     rst_flag_count
     dst_port               (kept as feature — many attacks are port-specific)
"""

from __future__ import annotations

import csv
import random
from pathlib import Path

FEATURES = [
    "flow_duration",
    "total_fwd_packets",
    "total_bwd_packets",
    "total_fwd_bytes",
    "total_bwd_bytes",
    "fwd_packet_len_mean",
    "bwd_packet_len_mean",
    "flow_bytes_per_sec",
    "flow_packets_per_sec",
    "fwd_iat_mean",
    "bwd_iat_mean",
    "syn_flag_count",
    "fin_flag_count",
    "rst_flag_count",
    "dst_port",
]

LABELS = ["benign", "port_scan", "dos", "brute_force", "c2_beacon"]


def _clip(v: float, lo: float = 0.0) -> float:
    return max(lo, v)


def _gen_benign(rng: random.Random) -> list[float]:
    dur = _clip(rng.gauss(3500, 1500))                    # ~3.5s flows
    fp  = _clip(rng.gauss(12, 5))
    bp  = _clip(rng.gauss(14, 6))
    fb  = _clip(rng.gauss(1200, 500))
    bb  = _clip(rng.gauss(4800, 2200))
    return [
        dur, fp, bp, fb, bb,
        fb / max(fp, 1),                                   # fwd_pkt_len_mean
        bb / max(bp, 1),                                   # bwd_pkt_len_mean
        (fb + bb) / max(dur / 1000, 0.01),                 # bytes/sec
        (fp + bp) / max(dur / 1000, 0.01),                 # pkts/sec
        _clip(rng.gauss(280, 120)),                        # fwd IAT
        _clip(rng.gauss(240, 100)),                        # bwd IAT
        rng.randint(1, 2),                                 # SYN
        rng.randint(1, 2),                                 # FIN
        rng.choices([0, 1], weights=[95, 5])[0],           # RST
        rng.choices([80, 443, 22, 53, 3389], weights=[35, 45, 10, 5, 5])[0],
    ]


def _gen_port_scan(rng: random.Random) -> list[float]:
    # short flows, many SYNs, mostly no reply, random destination ports
    dur = _clip(rng.gauss(40, 25))
    fp  = _clip(rng.gauss(3, 1))
    bp  = rng.choices([0, 1], weights=[70, 30])[0]
    fb  = _clip(rng.gauss(120, 40))
    bb  = _clip(rng.gauss(40, 30))
    return [
        dur, fp, bp, fb, bb,
        fb / max(fp, 1),
        bb / max(bp, 1),
        (fb + bb) / max(dur / 1000, 0.01),
        (fp + bp) / max(dur / 1000, 0.01),
        _clip(rng.gauss(8, 4)),
        _clip(rng.gauss(15, 8)),
        rng.randint(2, 3),                                 # elevated SYN
        rng.choices([0, 1], weights=[85, 15])[0],
        rng.choices([0, 1, 2], weights=[40, 40, 20])[0],   # more RSTs
        rng.randint(1, 65535),                             # RANDOM port
    ]


def _gen_dos(rng: random.Random) -> list[float]:
    # sustained flood: many packets, high pkt-rate, one target port
    dur = _clip(rng.gauss(8000, 3000))
    fp  = _clip(rng.gauss(4000, 1500))
    bp  = _clip(rng.gauss(50, 30))
    fb  = _clip(rng.gauss(220000, 80000))
    bb  = _clip(rng.gauss(2500, 1500))
    return [
        dur, fp, bp, fb, bb,
        fb / max(fp, 1),
        bb / max(bp, 1),
        (fb + bb) / max(dur / 1000, 0.01),
        (fp + bp) / max(dur / 1000, 0.01),
        _clip(rng.gauss(2, 1)),                            # very fast fwd
        _clip(rng.gauss(180, 90)),
        rng.randint(50, 400),                              # SYN flood
        rng.randint(0, 5),
        rng.randint(20, 100),                              # many RSTs
        rng.choices([80, 443])[0],
    ]


def _gen_brute_force(rng: random.Random) -> list[float]:
    # many small login attempts to a single service port (SSH / RDP / MySQL)
    dur = _clip(rng.gauss(45000, 15000))
    fp  = _clip(rng.gauss(180, 60))
    bp  = _clip(rng.gauss(180, 60))
    fb  = _clip(rng.gauss(18000, 6000))
    bb  = _clip(rng.gauss(22000, 8000))
    return [
        dur, fp, bp, fb, bb,
        fb / max(fp, 1),
        bb / max(bp, 1),
        (fb + bb) / max(dur / 1000, 0.01),
        (fp + bp) / max(dur / 1000, 0.01),
        _clip(rng.gauss(250, 60)),
        _clip(rng.gauss(230, 60)),
        rng.randint(30, 80),                               # many login SYNs
        rng.randint(20, 60),
        rng.randint(20, 60),
        rng.choices([22, 3389, 3306], weights=[50, 30, 20])[0],
    ]


def _gen_c2_beacon(rng: random.Random) -> list[float]:
    # long-lived, very regular, small bidirectional, over TLS-ish port
    dur = _clip(rng.gauss(180000, 40000))                  # 3-minute avg
    fp  = _clip(rng.gauss(60, 15))
    bp  = _clip(rng.gauss(60, 15))
    fb  = _clip(rng.gauss(4200, 900))
    bb  = _clip(rng.gauss(5500, 1200))
    return [
        dur, fp, bp, fb, bb,
        fb / max(fp, 1),
        bb / max(bp, 1),
        (fb + bb) / max(dur / 1000, 0.01),
        (fp + bp) / max(dur / 1000, 0.01),
        _clip(rng.gauss(2800, 200)),                       # highly regular IAT
        _clip(rng.gauss(2800, 200)),
        rng.randint(1, 3),
        rng.randint(1, 3),
        rng.randint(0, 1),
        rng.choices([443, 8443, 8080], weights=[60, 25, 15])[0],
    ]


_GEN = {
    "benign":       _gen_benign,
    "port_scan":    _gen_port_scan,
    "dos":          _gen_dos,
    "brute_force":  _gen_brute_force,
    "c2_beacon":    _gen_c2_beacon,
}

# Class balance — heavy benign, like real traffic
CLASS_COUNTS = {
    "benign":       3000,
    "port_scan":     500,
    "dos":           500,
    "brute_force":   500,
    "c2_beacon":     500,
}


def _noisy(row: list[float], rng: random.Random, sigma: float = 0.18) -> list[float]:
    """Multiplicative gaussian noise on continuous features to blur class boundaries."""
    out = []
    for i, v in enumerate(row):
        # leave dst_port alone (last column) — it's categorical-ish
        if i == len(row) - 1:
            out.append(v)
        else:
            out.append(max(0.0, v * (1.0 + rng.gauss(0.0, sigma))))
    return out


def generate(out_path: str | Path, seed: int = 42, label_noise: float = 0.03) -> tuple[int, dict[str, int]]:
    """
    label_noise: fraction of rows whose label is deliberately flipped to a
    random other class. Simulates real-world label uncertainty and prevents
    unrealistic 100% test accuracy.
    """
    rng = random.Random(seed)
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(FEATURES + ["label"])
        for label, n in CLASS_COUNTS.items():
            gen = _GEN[label]
            for _ in range(n):
                row = _noisy(gen(rng), rng)
                emitted_label = label
                if rng.random() < label_noise:
                    emitted_label = rng.choice([l for l in LABELS if l != label])
                w.writerow([f"{v:.4f}" for v in row] + [emitted_label])
    return sum(CLASS_COUNTS.values()), dict(CLASS_COUNTS)


if __name__ == "__main__":
    total, counts = generate(Path(__file__).parent / "dataset.csv")
    print(f"wrote {total} rows")
    for k, v in counts.items():
        print(f"  {k:12s} {v}")
