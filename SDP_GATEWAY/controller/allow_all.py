"""In-process stand-in for the SDP Controller: approves every verified knock.

No Policy Engine, no Policy Administrator. Every SPA_VERIFY that reaches it
has already passed the Gateway's own checks, and it approves all of them,
allocating a session for each. It exists so the Gateway can be built and run
end to end now; the real SDP Controller replaces it behind
controller.client.ControllerClient.
"""

from __future__ import annotations

import threading
import time
import uuid

from shared.utils.logger import get_logger, status

log = get_logger("Controller")

DEFAULT_TTL_SECONDS = 30


class AllowAllController:
    def __init__(self, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> None:
        self._ttl_seconds = ttl_seconds
        self._sessions: dict[str, dict] = {}
        self._lock = threading.Lock()

    def send(self, msg: dict) -> dict:
        if msg.get("type") != "SPA_VERIFY":
            return {"type": "ERROR", "reason": f"unknown: {msg.get('type')}"}

        session_id = str(uuid.uuid4())
        with self._lock:
            now = time.time()
            self._sessions = {sid: s for sid, s in self._sessions.items() if s["expires_at"] > now}
            self._sessions[session_id] = {
                "client_ip": msg["client_ip"],
                "access_port": msg["access_port"],
                "protocol": msg["protocol"],
                "identity": msg["identity"],
                "expires_at": now + self._ttl_seconds,
            }

        status(log, "APPROVED (allow-all)", session=session_id, client_ip=msg["client_ip"],
               sid=msg["identity"].get("sid"), port=msg["access_port"], ttl=self._ttl_seconds)
        return {
            "type": "APPROVED",
            "session_id": session_id,
            "access_port": msg["access_port"],
            "protocol": msg["protocol"],
            "ttl_seconds": self._ttl_seconds,
        }
