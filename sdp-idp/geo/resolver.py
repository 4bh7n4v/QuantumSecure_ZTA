"""IP address -> geolocation, behind a single function so the baseline
Policy Engine has one place to call.

Milestone 1: returns None (no lookup) for everything. Milestone 4 plugs in
a real source here — a bundled MaxMind GeoLite2 database is the intended
choice (offline, no per-request network call from the IDP, which must not
depend on outbound internet for a policy decision).

The return string is "lat,lon" when known; the impossible-travel check
parses it. A country code alone is not enough for a velocity calculation.
"""

from __future__ import annotations

import ipaddress

from shared.utils.logger import get_logger, status

log = get_logger("IDP-Geo")


def resolve(ip: str | None) -> str | None:
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        status(log, "Geo resolve: not an IP", value=ip)
        return None

    if addr.is_loopback or addr.is_private:
        status(log, "Geo resolve: private/loopback address, no geolocation", ip=ip)
        return None

    # M4: look `ip` up in the GeoLite2 database and return "lat,lon".
    status(log, "Geo resolve: lookup source not configured yet (Milestone 4)", ip=ip)
    return None
