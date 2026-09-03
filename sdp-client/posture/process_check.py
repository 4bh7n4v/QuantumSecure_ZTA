"""Antivirus / EDR process presence check."""

from __future__ import annotations

from shared.utils.logger import get_logger, status

log = get_logger("Posture-Proc")

_KNOWN_AV_PROCESS_NAMES = (
    "clamd", "clamav", "freshclam",  # ClamAV (common on Linux)
    "sophosav", "sav-protect",       # Sophos
    "mfehidin", "mfetp",             # McAfee
)


def check() -> dict:
    running = _running_process_names()
    av_active = any(name.lower() in proc.lower() for proc in running for name in _KNOWN_AV_PROCESS_NAMES)
    status(log, "Process check", antivirus_active=av_active)
    return {"antivirus_active": av_active}


def _running_process_names() -> list[str]:
    try:
        import psutil
        return [p.info.get("name", "") for p in psutil.process_iter(["name"])]
    except ImportError:
        status(log, "psutil not installed - cannot enumerate processes, assuming AV inactive")
        return []
