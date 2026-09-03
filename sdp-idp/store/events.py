"""Append-only auth-event log.

Every login, FIDO2 ceremony and token refresh writes one row here, with the
source IP and (Phase 2) resolved geolocation. The baseline Policy Engine
reads this history to make its impossible-travel decision, and the admin
dashboard renders it.
"""

from __future__ import annotations

import time

from store.db import connect
from shared.utils.logger import get_logger, status

log = get_logger("IDP-Events")


def record(
    kind: str,
    outcome: str,
    *,
    user_id: str | None = None,
    username: str | None = None,
    device_id: str | None = None,
    source_ip: str | None = None,
    source_geo: str | None = None,
    detail: str = "",
) -> None:
    with connect() as conn:
        conn.execute(
            "INSERT INTO auth_events"
            " (ts, user_id, username, device_id, kind, outcome, source_ip, source_geo, detail)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (time.time(), user_id, username, device_id, kind, outcome, source_ip, source_geo, detail),
        )
    status(log, "Auth event recorded", kind=kind, outcome=outcome, username=username,
           device_id=device_id, source_ip=source_ip, detail=detail or None)


def recent_for_user(user_id: str, limit: int = 20) -> list[dict]:
    with connect() as conn:
        rows = conn.execute(
            "SELECT ts, kind, outcome, device_id, source_ip, source_geo, detail"
            " FROM auth_events WHERE user_id = ? ORDER BY ts DESC LIMIT ?",
            (user_id, limit),
        ).fetchall()
    return [dict(r) for r in rows]


def last_successful_location(user_id: str, before_ts: float | None = None) -> dict | None:
    """The most recent OK event for this user that carries a source_ip —
    the reference point the impossible-travel check compares against.
    """
    q = (
        "SELECT ts, source_ip, source_geo FROM auth_events"
        " WHERE user_id = ? AND outcome = 'ok' AND source_ip IS NOT NULL"
    )
    args: list = [user_id]
    if before_ts is not None:
        q += " AND ts < ?"
        args.append(before_ts)
    q += " ORDER BY ts DESC LIMIT 1"
    with connect() as conn:
        r = conn.execute(q, args).fetchone()
    return dict(r) if r else None
