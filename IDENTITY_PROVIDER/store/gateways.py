"""Registered SDP Gateways and their ML-KEM public keys.

The IDP only stores and hands out what each Gateway registered about itself
over the mTLS link. Choosing which Gateway a user should use is the SDP
Controller's job once it exists; until then clients get the whole list.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from store.db import connect
from shared.ca.cert_utils import fingerprint
from shared.utils.logger import get_logger, status

log = get_logger("IDP-Gateways")


@dataclass
class Gateway:
    gateway_id: str
    kem_public_key: bytes
    spa_port: int
    registered_at: float
    revoked: bool


class GatewayRevoked(PermissionError):
    pass


def _row(r) -> Gateway:
    return Gateway(gateway_id=r["gateway_id"], kem_public_key=r["kem_public_key"],
                   spa_port=r["spa_port"], registered_at=r["registered_at"],
                   revoked=bool(r["revoked"]))


def register(gateway_id: str, kem_public_key: bytes, spa_port: int) -> Gateway:
    """Insert or replace this Gateway's key. A revoked Gateway is refused."""
    now = time.time()
    with connect() as conn:
        existing = conn.execute("SELECT revoked FROM gateways WHERE gateway_id = ?",
                                (gateway_id,)).fetchone()
        if existing is not None and existing["revoked"]:
            raise GatewayRevoked(gateway_id)
        conn.execute(
            "INSERT INTO gateways (gateway_id, kem_public_key, spa_port, registered_at, revoked)"
            " VALUES (?, ?, ?, ?, 0)"
            " ON CONFLICT(gateway_id) DO UPDATE SET kem_public_key = excluded.kem_public_key,"
            " spa_port = excluded.spa_port, registered_at = excluded.registered_at",
            (gateway_id, kem_public_key, spa_port, now),
        )
    status(log, "Gateway key registered", gateway_id=gateway_id, spa_port=spa_port,
           fingerprint=fingerprint(kem_public_key))
    return Gateway(gateway_id, kem_public_key, spa_port, now, False)


def active() -> list[Gateway]:
    with connect() as conn:
        rows = conn.execute(
            "SELECT * FROM gateways WHERE revoked = 0 ORDER BY gateway_id").fetchall()
    return [_row(r) for r in rows]


def all_gateways() -> list[Gateway]:
    with connect() as conn:
        rows = conn.execute("SELECT * FROM gateways ORDER BY gateway_id").fetchall()
    return [_row(r) for r in rows]


def revoke(gateway_id: str) -> None:
    """Stop handing out this Gateway's key and refuse its future
    registrations. Its certificate stays valid until it expires; there is no
    certificate revocation list yet, so this row is what blocks it."""
    with connect() as conn:
        conn.execute(
            "INSERT INTO gateways (gateway_id, kem_public_key, spa_port, registered_at, revoked)"
            " VALUES (?, x'', 0, ?, 1)"
            " ON CONFLICT(gateway_id) DO UPDATE SET revoked = 1",
            (gateway_id, time.time()),
        )
    status(log, "Gateway revoked", gateway_id=gateway_id)
