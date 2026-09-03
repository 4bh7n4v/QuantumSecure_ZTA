"""PostureReport — device telemetry collected by the SDP client and evaluated
by the Controller's policy engine on every registration and authentication.
"""

from __future__ import annotations

import time

from pydantic import BaseModel, Field


class PostureReport(BaseModel):
    device_id: str
    hostname: str
    os_name: str
    os_version: str
    os_patch_days: int = Field(default=999, description="Days since the last OS patch was applied")
    antivirus_active: bool = True
    firewall_active: bool = True
    disk_encrypted: bool = True
    screen_lock: bool = True

    # Which hardware root of trust produced this device's FIDO2 credential.
    # "internal_tpm" | "external_tpm" | "none" — see sdp-client/tpm/anchored_trust.py
    trust_anchor_type: str = "none"
    trust_anchor_present: bool = False

    network_type: str = "unknown"
    vpn_active: bool = False
    collected_at: float = Field(default_factory=time.time)
