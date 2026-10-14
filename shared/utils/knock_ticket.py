"""Wire format of the knock ticket: the small, IDP-signed token that rides
inside the SPA knock in place of the full access JWT.

The access JWT is ~1 KB. An ML-KEM-768 knock already spends 1116 bytes on
the KEM ciphertext, nonce and tag, which leaves ~356 bytes of a 1472-byte
UDP payload for everything else. The ticket is 133 bytes.

Layout (big-endian, 133 bytes):

    byte  0        version            1
    bytes 1-16     sid                session id (UUID), same as the JWTs
    bytes 17-32    one-time id        UUID; the Gateway accepts it once
    bytes 33-36    expiry             unix seconds, issue time + 60 s
    bytes 37-68    WireGuard key      client's 32-byte WireGuard public key
    bytes 69-132   IDP signature      ES256 (P-256, SHA-256), raw r||s,
                                      over bytes 0-68

Signing lives only in the IDP. This module defines the layout once, for the
IDP that builds it and the Gateway that checks it, so the two cannot drift.
"""

from __future__ import annotations

import struct
import time
import uuid
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from shared.utils.crypto import ecdsa_raw_to_der

VERSION = 1
WG_KEY_LEN = 32
SIGNATURE_LEN = 64
_BODY = struct.Struct(">B16s16sI32s")   # 69 bytes
TICKET_LEN = _BODY.size + SIGNATURE_LEN  # 133


class InvalidTicket(ValueError):
    pass


@dataclass(frozen=True)
class KnockTicket:
    sid: str
    ticket_id: str
    expires_at: int
    wg_public_key: bytes


def pack_body(sid: str, ticket_id: str, expires_at: int, wg_public_key: bytes) -> bytes:
    if len(wg_public_key) != WG_KEY_LEN:
        raise ValueError(f"WireGuard public key must be {WG_KEY_LEN} bytes, got {len(wg_public_key)}")
    return _BODY.pack(VERSION, uuid.UUID(sid).bytes, uuid.UUID(ticket_id).bytes,
                      expires_at, wg_public_key)


def verify(ticket: bytes, public_key: ec.EllipticCurvePublicKey,
           now: float | None = None) -> KnockTicket:
    """Check length, version, signature and expiry. Single use is NOT checked
    here: that needs memory of spent ticket ids, which only the Gateway has."""
    if len(ticket) != TICKET_LEN:
        raise InvalidTicket(f"ticket must be {TICKET_LEN} bytes, got {len(ticket)}")
    body, signature = ticket[:_BODY.size], ticket[_BODY.size:]
    version, sid, ticket_id, expires_at, wg_key = _BODY.unpack(body)
    if version != VERSION:
        raise InvalidTicket(f"unsupported ticket version {version}")
    try:
        public_key.verify(ecdsa_raw_to_der(signature), body, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise InvalidTicket("ticket signature does not verify") from exc
    if (time.time() if now is None else now) > expires_at:
        raise InvalidTicket("ticket expired")
    return KnockTicket(sid=str(uuid.UUID(bytes=sid)), ticket_id=str(uuid.UUID(bytes=ticket_id)),
                       expires_at=expires_at, wg_public_key=wg_key)
