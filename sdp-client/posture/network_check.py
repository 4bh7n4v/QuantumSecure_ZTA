"""Network interface / VPN presence check."""

from __future__ import annotations

from shared.utils.logger import get_logger, status

log = get_logger("Posture-Net")

_VPN_INTERFACE_PREFIXES = ("wg", "tun", "tap", "ppp")


def check() -> dict:
    try:
        import psutil
        interfaces = list(psutil.net_if_addrs().keys())
    except ImportError:
        status(log, "psutil not installed - cannot enumerate interfaces")
        interfaces = []

    vpn_active = any(iface.startswith(_VPN_INTERFACE_PREFIXES) for iface in interfaces)
    network_type = "vpn" if vpn_active else ("wired" if any(i.startswith("eth") for i in interfaces) else "wifi")

    status(log, "Network check", network_type=network_type, vpn_active=vpn_active, interfaces=interfaces)
    return {"network_type": network_type, "vpn_active": vpn_active}
