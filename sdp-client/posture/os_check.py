"""OS identity, patch recency, disk-encryption and screen-lock posture checks."""

from __future__ import annotations

import platform
import time
from pathlib import Path

from shared.utils.logger import get_logger, status

log = get_logger("Posture-OS")


def check() -> dict:
    os_name = platform.system()
    os_version = platform.release()
    patch_days = _days_since_last_update()
    disk_encrypted = _disk_encrypted()
    screen_lock = _screen_lock_enabled()

    status(log, "OS check", os_name=os_name, os_version=os_version, patch_days=patch_days,
           disk_encrypted=disk_encrypted, screen_lock=screen_lock)
    return {
        "os_name": os_name,
        "os_version": os_version,
        "os_patch_days": patch_days,
        "disk_encrypted": disk_encrypted,
        "screen_lock": screen_lock,
    }


def _days_since_last_update() -> int:
    """Best-effort: on Debian/Ubuntu-family systems, the apt/dpkg log's mtime
    is a reasonable proxy for "last time packages were updated". Returns 999
    (i.e. "unknown / stale") if it can't be determined.
    """
    for path in (Path("/var/log/apt/history.log"), Path("/var/log/dpkg.log")):
        if path.exists():
            return int((time.time() - path.stat().st_mtime) / 86400)
    return 999


def _disk_encrypted() -> bool:
    """Best-effort: a LUKS-encrypted root shows up as a dm-crypt mapping."""
    mapper = Path("/dev/mapper")
    if not mapper.exists():
        return False
    return any(p.name != "control" for p in mapper.iterdir())


def _screen_lock_enabled() -> bool:
    """No reliable headless/WSL2 signal exists for this; default to the
    conservative (disabled) assumption so the policy engine never over-trusts
    a device it can't actually check.
    """
    return False
