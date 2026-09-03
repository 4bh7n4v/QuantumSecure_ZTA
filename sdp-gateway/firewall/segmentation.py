"""Grants a client temporary, single-port access after a valid SPA knock,
then automatically closes it again after a fixed TTL.
"""

from __future__ import annotations

import threading

from firewall import rules
from shared.utils.logger import get_logger, status

log = get_logger("Segmentation")

DEFAULT_TTL_SECONDS = 30


def grant_temporary_access(client_ip: str, port: int, protocol: str = "tcp", ttl_seconds: int = DEFAULT_TTL_SECONDS) -> None:
    rules.allow(client_ip, port, protocol)
    status(log, "Temporary access granted", client_ip=client_ip, port=port, ttl=ttl_seconds)

    def _revoke() -> None:
        rules.revoke(client_ip, port, protocol)
        status(log, "Temporary access expired", client_ip=client_ip, port=port)

    timer = threading.Timer(ttl_seconds, _revoke)
    timer.daemon = True
    timer.start()
