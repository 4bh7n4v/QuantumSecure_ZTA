"""Ties the FIDO2 authentication result (JWT + Gateway ML-KEM public key) to
the SPA knock — the step that turns a granted access decision into an
actually-open port on the Gateway.
"""

from __future__ import annotations

from spa import knock, packet
from shared.config.settings import settings
from shared.utils.logger import get_logger, status

log = get_logger("TokenFlow")


def request_access(auth_result: dict, access_port: int, protocol: str = "tcp") -> bool:
    if auth_result.get("status") != "granted":
        status(log, "Skipping SPA - authentication was not granted", status=auth_result.get("status"))
        return False

    spa_packet = packet.build(
        gateway_kem_pubkey=auth_result["gateway_kem_pubkey"],
        jwt_token=auth_result["access_token"],
        access_port=access_port,
        protocol=protocol,
    )
    return knock.send(spa_packet, settings.gateway_ip, settings.gateway_spa_port_client, timeout=5.0)
