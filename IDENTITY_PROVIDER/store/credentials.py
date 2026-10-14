"""FIDO2 credentials enrolled per user + device.

One row per (device, credential). On a user's first login from a new device
the IDP runs the WebAuthn registration ceremony and stores the resulting
credential here; every later login is an authentication ceremony against
these rows.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from fido2.webauthn import AttestedCredentialData

from store.db import connect
from shared.utils.logger import get_logger, status

log = get_logger("IDP-Creds")


_COLUMNS = (
    "credential_id, user_id, device_id, credential_data, trust_anchor_type,"
    " sign_count, attestation_fmt, attested_hardware, attestation_trust_path,"
    " attestation_ak_key"
)


@dataclass
class CredentialRecord:
    credential_id: bytes
    user_id: str
    device_id: str
    credential_data: AttestedCredentialData
    trust_anchor_type: str
    sign_count: int
    attestation_fmt: str
    attested_hardware: bool
    # How far the TPM attestation key behind this credential could be trusted,
    # and which key it was. See fido2_idp/tpm_trust.py; both are "n/a"/None for
    # attestation formats that carry no TPM attestation key.
    attestation_trust_path: str = "n/a"
    attestation_ak_key: bytes | None = None


def add(record: CredentialRecord) -> None:
    with connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO credentials"
            " (credential_id, user_id, device_id, credential_data, trust_anchor_type,"
            "  aaguid, sign_count, attestation_fmt, attested_hardware,"
            "  attestation_trust_path, attestation_ak_key, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                record.credential_id.hex(),
                record.user_id,
                record.device_id,
                bytes(record.credential_data),
                record.trust_anchor_type,
                record.credential_data.aaguid.hex(),
                record.sign_count,
                record.attestation_fmt,
                1 if record.attested_hardware else 0,
                record.attestation_trust_path,
                record.attestation_ak_key,
                time.time(),
            ),
        )
    status(log, "Credential stored", user_id=record.user_id, device_id=record.device_id,
           credential_id=record.credential_id.hex()[:16], attestation_fmt=record.attestation_fmt,
           attested_hardware=record.attested_hardware,
           trust_path=record.attestation_trust_path)


def pinned_attestation_key(user_id: str, device_id: str) -> bytes | None:
    """The TPM attestation key already trusted for this (user, device), if any.

    A device's first TPM-attested enrolment pins its attestation key; every
    later credential from that device must be certified by the same key, so
    the hardware root cannot be swapped out behind an established identity.
    Returns None when this device has never enrolled a TPM-attested credential.
    """
    with connect() as conn:
        row = conn.execute(
            "SELECT attestation_ak_key FROM credentials"
            " WHERE user_id = ? AND device_id = ? AND attestation_ak_key IS NOT NULL"
            " ORDER BY created_at ASC LIMIT 1",
            (user_id, device_id),
        ).fetchone()
    return bytes(row["attestation_ak_key"]) if row else None


def for_user(user_id: str) -> list[CredentialRecord]:
    with connect() as conn:
        rows = conn.execute(
            f"SELECT {_COLUMNS} FROM credentials WHERE user_id = ?", (user_id,),
        ).fetchall()
    return [_row_to_record(r) for r in rows]


def get(credential_id: bytes) -> CredentialRecord | None:
    with connect() as conn:
        r = conn.execute(
            f"SELECT {_COLUMNS} FROM credentials WHERE credential_id = ?",
            (credential_id.hex(),),
        ).fetchone()
    return _row_to_record(r) if r else None


def update_sign_count(credential_id: bytes, new_count: int) -> None:
    with connect() as conn:
        r = conn.execute(
            "SELECT sign_count FROM credentials WHERE credential_id = ?", (credential_id.hex(),)
        ).fetchone()
        if r is None:
            return
        if new_count != 0 and new_count <= r["sign_count"]:
            status(log, "Signature counter did not increase - possible cloned authenticator",
                   credential_id=credential_id.hex()[:16], stored=r["sign_count"], received=new_count)
        conn.execute(
            "UPDATE credentials SET sign_count = ? WHERE credential_id = ?",
            (new_count, credential_id.hex()),
        )


def _row_to_record(r) -> CredentialRecord:
    return CredentialRecord(
        credential_id=bytes.fromhex(r["credential_id"]),
        user_id=r["user_id"],
        device_id=r["device_id"],
        credential_data=AttestedCredentialData(bytes(r["credential_data"])),
        trust_anchor_type=r["trust_anchor_type"],
        sign_count=r["sign_count"],
        attestation_fmt=r["attestation_fmt"],
        attested_hardware=bool(r["attested_hardware"]),
        attestation_trust_path=r["attestation_trust_path"],
        attestation_ak_key=bytes(r["attestation_ak_key"]) if r["attestation_ak_key"] else None,
    )
