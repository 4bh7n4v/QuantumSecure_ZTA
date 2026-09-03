"""Refresh-token bookkeeping.

The IDP issues a short-lived access token (15 min) plus a longer-lived
refresh token (12 h). The access token is a stateless JWT; the refresh
token is tracked here so the IDP can revoke it, detect reuse, and let the
baseline Policy Engine compare where/when it is being used against where it
was issued (impossible-travel — Phase 2).
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from store.db import connect
from shared.utils.logger import get_logger, status

log = get_logger("IDP-Tokens")


@dataclass
class RefreshRecord:
    jti: str
    user_id: str
    device_id: str
    access_jti: str
    issued_at: float
    expires_at: float
    revoked: bool
    issue_ip: str | None
    issue_geo: str | None
    last_ip: str | None
    last_geo: str | None
    last_used_at: float | None


def register(rec: RefreshRecord) -> None:
    with connect() as conn:
        conn.execute(
            "INSERT INTO refresh_tokens"
            " (jti, user_id, device_id, access_jti, issued_at, expires_at, revoked,"
            "  issue_ip, issue_geo, last_ip, last_geo, last_used_at)"
            " VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?)",
            (rec.jti, rec.user_id, rec.device_id, rec.access_jti, rec.issued_at, rec.expires_at,
             rec.issue_ip, rec.issue_geo, rec.issue_ip, rec.issue_geo, rec.issued_at),
        )
    status(log, "Refresh token registered", jti=rec.jti, user_id=rec.user_id,
           device_id=rec.device_id, ttl_s=round(rec.expires_at - rec.issued_at))


def get(jti: str) -> RefreshRecord | None:
    with connect() as conn:
        r = conn.execute("SELECT * FROM refresh_tokens WHERE jti = ?", (jti,)).fetchone()
    if r is None:
        return None
    return RefreshRecord(
        jti=r["jti"], user_id=r["user_id"], device_id=r["device_id"], access_jti=r["access_jti"],
        issued_at=r["issued_at"], expires_at=r["expires_at"], revoked=bool(r["revoked"]),
        issue_ip=r["issue_ip"], issue_geo=r["issue_geo"],
        last_ip=r["last_ip"], last_geo=r["last_geo"], last_used_at=r["last_used_at"],
    )


def rotate_access_jti(jti: str, new_access_jti: str, used_ip: str | None, used_geo: str | None) -> None:
    with connect() as conn:
        conn.execute(
            "UPDATE refresh_tokens SET access_jti = ?, last_ip = ?, last_geo = ?, last_used_at = ?"
            " WHERE jti = ?",
            (new_access_jti, used_ip, used_geo, time.time(), jti),
        )


def revoke(jti: str, reason: str = "") -> None:
    with connect() as conn:
        conn.execute("UPDATE refresh_tokens SET revoked = 1 WHERE jti = ?", (jti,))
    status(log, "Refresh token revoked", jti=jti, reason=reason)


def revoke_all_for_user(user_id: str, reason: str = "") -> int:
    with connect() as conn:
        cur = conn.execute(
            "UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ? AND revoked = 0", (user_id,)
        )
        n = cur.rowcount
    status(log, "All refresh tokens revoked for user", user_id=user_id, count=n, reason=reason)
    return n


def is_usable(rec: RefreshRecord) -> tuple[bool, str]:
    if rec.revoked:
        return False, "revoked"
    if rec.expires_at < time.time():
        return False, "expired"
    return True, ""
