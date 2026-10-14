"""Named, expiring permission for one device to enrol without proving
hardware custody.

Some devices genuinely cannot produce the proof the IDP requires, and no
amount of client work will change that. The case that motivated this: a
laptop with a real Intel firmware TPM, carrying a valid manufacturer
endorsement certificate, whose Windows Hello nevertheless returns no
attestation to any caller — a deliberate Windows privacy decision, confirmed
by getting the identical empty result in a browser. The key is in the chip;
Windows simply will not vouch for it outside an enterprise-managed context.

Before this, the only way to admit such a device was
IDP_ENFORCE_TPM_ATTESTATION=false, which switches the check off for the whole
deployment — including every device that *could* prove itself. That trades a
working guarantee everywhere for one machine's convenience, which is the
wrong shape of answer.

An exception here is the opposite shape. It is granted per user and device by
an administrator at the console, it records who granted it and why, it is
written to the audit log when used, and it expires on its own so a temporary
allowance cannot quietly become the permanent posture. Enforcement stays on
everywhere else, and a credential enrolled under one is still recorded as
NOT hardware-attested — the exception permits the enrolment, it does not
manufacture a proof that was never given.

What an exception deliberately cannot do is admit an attestation key that
contradicts the one already pinned to a device. That is not an absence of
evidence but evidence of a change, and fido2_idp/attestation_tpm.py refuses
it before any exception is consulted.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from store.db import connect
from shared.utils.logger import get_logger, status

log = get_logger("IDP-Exceptions")


@dataclass
class AttestationException:
    user_id: str
    device_id: str
    reason: str
    granted_by: str
    granted_at: float
    expires_at: float

    @property
    def expired(self) -> bool:
        return self.expires_at <= time.time()

    @property
    def days_remaining(self) -> float:
        return max(0.0, (self.expires_at - time.time()) / 86400)


def grant(user_id: str, device_id: str, reason: str, granted_by: str,
          days: int) -> AttestationException:
    """Allow this one device to enrol without hardware proof, for `days`.

    Replaces any existing exception for the same device, so re-granting
    extends rather than accumulating overlapping rows.
    """
    if days <= 0:
        raise ValueError("an exception must expire in the future; give a positive --days")
    if not reason.strip():
        raise ValueError("an exception must record why it was granted")

    now = time.time()
    record = AttestationException(
        user_id=user_id, device_id=device_id, reason=reason.strip(),
        granted_by=granted_by, granted_at=now, expires_at=now + days * 86400,
    )
    with connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO attestation_exceptions"
            " (user_id, device_id, reason, granted_by, granted_at, expires_at)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (record.user_id, record.device_id, record.reason,
             record.granted_by, record.granted_at, record.expires_at),
        )
    status(log, "Attestation exception granted", user_id=user_id, device_id=device_id,
           days=days, granted_by=granted_by)
    return record


def revoke(user_id: str, device_id: str) -> bool:
    with connect() as conn:
        cursor = conn.execute(
            "DELETE FROM attestation_exceptions WHERE user_id = ? AND device_id = ?",
            (user_id, device_id),
        )
    if cursor.rowcount:
        status(log, "Attestation exception revoked", user_id=user_id, device_id=device_id)
    return bool(cursor.rowcount)


def active_for(user_id: str, device_id: str) -> AttestationException | None:
    """The live exception for this device, or None.

    An expired row is treated as absent rather than deleted, so it stays
    visible to `all_exceptions()` as a record of what was once permitted.
    """
    with connect() as conn:
        row = conn.execute(
            "SELECT user_id, device_id, reason, granted_by, granted_at, expires_at"
            " FROM attestation_exceptions WHERE user_id = ? AND device_id = ?",
            (user_id, device_id),
        ).fetchone()
    if row is None:
        return None

    record = _to_record(row)
    if record.expired:
        status(log, "Attestation exception has EXPIRED - enrolment will be refused",
               user_id=user_id, device_id=device_id)
        return None
    return record


def all_exceptions() -> list[AttestationException]:
    with connect() as conn:
        rows = conn.execute(
            "SELECT user_id, device_id, reason, granted_by, granted_at, expires_at"
            " FROM attestation_exceptions ORDER BY expires_at DESC"
        ).fetchall()
    return [_to_record(row) for row in rows]


def _to_record(row) -> AttestationException:
    return AttestationException(
        user_id=row["user_id"], device_id=row["device_id"], reason=row["reason"],
        granted_by=row["granted_by"], granted_at=row["granted_at"],
        expires_at=row["expires_at"],
    )
