"""Admin-provisioned user accounts (first factor: username + Argon2id hash).

There is NO self-registration anywhere in this system. Accounts are created
only by a system administrator, either through the admin API
(`POST /admin/users`, see api/routes.py) or the offline `admin_cli.py`.
Both land here.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass

from auth.password import hash_password, verify_password
from store.db import connect
from shared.utils.logger import get_logger, status

log = get_logger("IDP-Users")


@dataclass
class User:
    user_id: str
    username: str
    enabled: bool
    access_window: str | None


class UsernameExists(ValueError):
    pass


class UnknownUser(ValueError):
    pass


def create_user(username: str, password: str, access_window: str | None = None) -> User:
    username = username.strip()
    if not username or not password:
        raise ValueError("username and password are both required")

    user_id = str(uuid.uuid4())
    with connect() as conn:
        exists = conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
        if exists:
            raise UsernameExists(f"username already provisioned: {username}")
        conn.execute(
            "INSERT INTO users (user_id, username, password_hash, enabled, access_window, created_at)"
            " VALUES (?, ?, ?, 1, ?, ?)",
            (user_id, username, hash_password(password), access_window, time.time()),
        )
    status(log, "User account provisioned by administrator", username=username, user_id=user_id)
    return User(user_id=user_id, username=username, enabled=True, access_window=access_window)


def set_enabled(username: str, enabled: bool) -> None:
    with connect() as conn:
        cur = conn.execute(
            "UPDATE users SET enabled = ? WHERE username = ?", (1 if enabled else 0, username)
        )
        if cur.rowcount == 0:
            raise UnknownUser(username)
    status(log, "User account enabled state changed", username=username, enabled=enabled)


def list_users() -> list[User]:
    with connect() as conn:
        rows = conn.execute(
            "SELECT user_id, username, enabled, access_window FROM users ORDER BY created_at"
        ).fetchall()
    return [
        User(user_id=r["user_id"], username=r["username"],
             enabled=bool(r["enabled"]), access_window=r["access_window"])
        for r in rows
    ]


def get_by_username(username: str) -> User | None:
    with connect() as conn:
        r = conn.execute(
            "SELECT user_id, username, enabled, access_window FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    if r is None:
        return None
    return User(user_id=r["user_id"], username=r["username"],
               enabled=bool(r["enabled"]), access_window=r["access_window"])


def verify_first_factor(username: str, password: str) -> User | None:
    """Return the User on a correct username+password for an ENABLED account,
    else None. The same None for "no such user", "wrong password" and
    "disabled" so a caller cannot enumerate accounts.
    """
    with connect() as conn:
        r = conn.execute(
            "SELECT user_id, username, password_hash, enabled, access_window"
            " FROM users WHERE username = ?",
            (username,),
        ).fetchone()

    if r is None:
        status(log, "First-factor check failed", username=username, reason="unknown username")
        return None
    if not r["enabled"]:
        status(log, "First-factor check failed", username=username, reason="account disabled")
        return None
    if not verify_password(password, r["password_hash"]):
        status(log, "First-factor check failed", username=username, reason="wrong password")
        return None

    status(log, "First-factor check passed", username=username, user_id=r["user_id"])
    return User(user_id=r["user_id"], username=r["username"],
               enabled=True, access_window=r["access_window"])
