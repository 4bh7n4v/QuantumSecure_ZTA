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
    -- Comma-separated role names; stamped into every access token as `roles`.
    roles         TEXT NOT NULL DEFAULT '',
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
    attested_hardware INTEGER NOT NULL DEFAULT 0,  -- 1 when hardware custody was cryptographically proven
    -- How far the attestation key behind this credential could be trusted:
    -- vendor-root | pinned-ak | first-ak | n/a. See fido2_idp/tpm_trust.py.
    attestation_trust_path TEXT NOT NULL DEFAULT 'n/a',
    -- DER SubjectPublicKeyInfo of the TPM attestation key that certified this
    -- credential. Pinned per device: a later enrolment on the same device must
    -- present the same AK. NULL for non-TPM attestation formats.
    attestation_ak_key BLOB,
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
    last_used_at REAL,
    -- The client's WireGuard public key, bound at FIDO2 time. Every knock
    -- ticket for this session carries this key and no other.
    wg_public_key BLOB
);
CREATE INDEX IF NOT EXISTS idx_refresh_user ON refresh_tokens(user_id);

-- Administrator-granted permission for ONE device to enrol without proving
-- hardware key custody, for devices that genuinely cannot (see
-- store/attestation_exceptions.py). Deliberately per device and time-limited:
-- the alternative was switching enforcement off for the whole deployment.
CREATE TABLE IF NOT EXISTS attestation_exceptions (
    user_id    TEXT NOT NULL REFERENCES users(user_id),
    device_id  TEXT NOT NULL,
    reason     TEXT NOT NULL,            -- why this device cannot attest
    granted_by TEXT NOT NULL,            -- the administrator account at the console
    granted_at REAL NOT NULL,
    expires_at REAL NOT NULL,            -- lapses on its own; never open-ended
    PRIMARY KEY (user_id, device_id)
);

-- SDP Gateways and their ML-KEM public keys. A row is written only by the
-- Gateway itself over the mTLS link, filed under the id in its certificate
-- (api/gateway_link.py). Revoking keeps the row so the Gateway cannot simply
-- re-register on its next start.
CREATE TABLE IF NOT EXISTS gateways (
    gateway_id     TEXT PRIMARY KEY,      -- common name of the Gateway's certificate
    kem_public_key BLOB NOT NULL,
    spa_port       INTEGER NOT NULL,
    registered_at  REAL NOT NULL,
    revoked        INTEGER NOT NULL DEFAULT 0
);

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


# Columns added to an existing table after its CREATE TABLE was first shipped.
# `CREATE TABLE IF NOT EXISTS` is a no-op on a database that already has the
# table, so a new column in _SCHEMA above would never reach a database created
# by an earlier run. Every entry must be nullable or carry a DEFAULT, which is
# all SQLite's ALTER TABLE ADD COLUMN accepts.
_ADDED_COLUMNS: dict[str, dict[str, str]] = {
    "users": {"roles": "TEXT NOT NULL DEFAULT ''"},
    "refresh_tokens": {"wg_public_key": "BLOB"},
    "credentials": {
        "attestation_trust_path": "TEXT NOT NULL DEFAULT 'n/a'",
        "attestation_ak_key": "BLOB",
    },
}


def _migrate(conn: sqlite3.Connection) -> None:
    for table, columns in _ADDED_COLUMNS.items():
        present = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
        if not present:
            continue  # table not created yet; _SCHEMA already has the column
        for name, definition in columns.items():
            if name in present:
                continue
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")
            status(log, "Database migrated", table=table, added_column=name)


def init_db() -> None:
    """Create tables if absent, then add any columns a newer schema introduced.
    Safe to call on every startup.
    """
    with connect() as conn:
        conn.executescript(_SCHEMA)
        _migrate(conn)
    status(log, "IDP database ready", path=str(_db_path()))
