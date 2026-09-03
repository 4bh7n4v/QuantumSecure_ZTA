"""Orchestrates all client-side posture checks into a single PostureReport.

Gathered fresh at every registration and authentication call — this
project's "posture is continuous" rule means a new report each time, not a
cached one-shot check.
"""

from __future__ import annotations

import shutil
import socket
import subprocess

from posture import cert_check, network_check, os_check, process_check
from shared.schemas.posture import PostureReport
from shared.utils.logger import get_logger, status

log = get_logger("Posture")


def collect(device_id: str, trust_anchor_type: str, trust_anchor_present: bool) -> PostureReport:
    status(log, "Collecting device posture telemetry...")

    os_facts = os_check.check()
    proc_facts = process_check.check()
    net_facts = network_check.check()
    cert_check.check()  # logging only for now — see cert_check.py docstring

    report = PostureReport(
        device_id=device_id,
        hostname=socket.gethostname(),
        os_name=os_facts["os_name"],
        os_version=os_facts["os_version"],
        os_patch_days=os_facts["os_patch_days"],
        antivirus_active=proc_facts["antivirus_active"],
        firewall_active=_firewall_active(),
        disk_encrypted=os_facts["disk_encrypted"],
        screen_lock=os_facts["screen_lock"],
        trust_anchor_type=trust_anchor_type,
        trust_anchor_present=trust_anchor_present,
        network_type=net_facts["network_type"],
        vpn_active=net_facts["vpn_active"],
    )
    status(log, "Posture collected", **report.model_dump(exclude={"collected_at"}))
    return report


def _firewall_active() -> bool:
    if shutil.which("ufw"):
        result = subprocess.run(["ufw", "status"], capture_output=True, text=True)
        return "Status: active" in result.stdout
    if shutil.which("iptables"):
        result = subprocess.run(["iptables", "-S"], capture_output=True, text=True)
        return len(result.stdout.strip().splitlines()) > 1  # more than just default policies
    return False
