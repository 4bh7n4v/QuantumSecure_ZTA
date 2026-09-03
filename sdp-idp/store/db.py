"""SQLite persistence for the standalone IDP.

Everything the IDP must remember across restarts lives here: the
admin-provisioned user accounts, the FIDO2 credentials enrolled per user,
the refresh tokens it has issued (so they can be revoked and checked), and
an append-only auth-event log the baseline Policy Engine reads.

Plain `sqlite3` from the standard library — no ORM, no extra dependency.
Each call opens its own short-lived connection; SQLite's own file locking
makes that safe across the IDP process and the offline `admin_cli.py`.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path

from shared.config.settings import settings
from shared.utils.logger import get_logger, status

log = get_logger("IDP-DB")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    user_id       TEXT PRIMARY KEY,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    enabled       INTEGER NOT NULL DEFAULT 1,
    -- Reserved for the Phase 2 time-window Policy Administrator. Free-form
    -- for now (e.g. "mon-fri 09:00-18:00 Asia/Kolkata"); NULL = no window.
    access_window TEXT,
    created_at    REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS credentials (
    credential_id     TEXT PRIMARY KEY,   -- hex
    user_id           TEXT NOT NULL REFERENCES users(user_id),
    device_id         TEXT NOT NULL,
    credential_data   BLOB NOT NULL,      -- fido2 AttestedCredentialData bytes
    trust_anchor_type TEXT NOT NULL,      -- internal_tpm | external_tpm
    aaguid            TEXT,
    sign_count        INTEGER NOT NULL DEFAULT 0,
    attestation_fmt   TEXT NOT NULL DEFAULT 'none',
    attested_hardware INTEGER NOT NULL DEFAULT 0,  -- 1 once real TPM attestation verified (M2)
    created_at        REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_credentials_user ON credentials(user_id);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    jti         TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(user_id),
    device_id   TEXT NOT NULL,
    access_jti  TEXT NOT NULL,            -- the access token last minted from this refresh token
    issued_at   REAL NOT NULL,
    expires_at  REAL NOT NULL,
    revoked     INTEGER NOT NULL DEFAULT 0,
    issue_ip    TEXT,
    issue_geo   TEXT,                     -- "lat,lon" or country code; NULL until GeoIP wired (M4)
    last_ip     TEXT,
    last_geo    TEXT,
    last_used_at REAL
);
CREATE INDEX IF NOT EXISTS idx_refresh_user ON refresh_tokens(user_id);

CREATE TABLE IF NOT EXISTS auth_events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         REAL NOT NULL,
    user_id    TEXT,
    username   TEXT,
    device_id  TEXT,
    kind       TEXT NOT NULL,             -- login | fido2_register | fido2_authenticate | token_refresh
    outcome    TEXT NOT NULL,             -- ok | denied | error
    source_ip  TEXT,
    source_geo TEXT,
    detail     TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_user_ts ON auth_events(user_id, ts);
"""


def _db_path() -> Path:
    return Path(settings.idp_db_path)


@contextmanager
def connect():
    path = _db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    """Create tables if absent. Safe to call on every startup."""
    with connect() as conn:
        conn.executescript(_SCHEMA)
    status(log, "IDP database ready", path=str(_db_path()))
