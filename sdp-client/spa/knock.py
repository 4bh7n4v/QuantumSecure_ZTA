"""Sends the SPA knock to the Gateway and waits for its accept/deny reply."""

from __future__ import annotations

import socket

from shared.utils.logger import get_logger, status

log = get_logger("SPA-Client")


def send(packet: bytes, gateway_ip: str, gateway_port: int, timeout: float = 5.0) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (gateway_ip, gateway_port))
        status(log, "SPA knock sent", gateway=f"{gateway_ip}:{gateway_port}", bytes=len(packet))
        reply, _ = sock.recvfrom(4096)
    except socket.timeout:
        status(log, "No reply from Gateway - by design, an invalid knock is silently dropped, not rejected")
        return False
    finally:
        sock.close()

    accepted = reply == b"SPA_OK"
    status(log, "SPA knock result", accepted=accepted, reply=reply.decode(errors="replace"))
    return accepted
