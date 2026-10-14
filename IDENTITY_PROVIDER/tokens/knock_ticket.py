"""Knock-ticket issuance: the third token the IDP hands out.

The ticket is what goes inside the SPA knock; the access JWT travels only
through the tunnel after the handshake. Layout and verification are in
shared/utils/knock_ticket.py. This module holds the signing key and signs.

The ticket is signed with its own ES256 (P-256) key, separate from the RS256
JWT key: an RSA-3072 signature alone is 384 bytes, more than the whole room
left in the knock. The public half is published in the JWKS next to the RSA
key, so the Gateway fetches both from one place.
"""

from __future__ import annotations

import base64
import hashlib
import os
import time
import uuid
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from shared.config.settings import settings
from shared.utils import knock_ticket as ticket_format
from shared.utils.logger import get_logger, status

log = get_logger("IDP-Ticket")

_private_key: ec.EllipticCurvePrivateKey
_public_key: ec.EllipticCurvePublicKey
_kid: str


def init() -> None:
    global _private_key, _public_key, _kid
    priv_path = Path(settings.idp_ticket_private_key_path)
    pub_path = Path(settings.idp_ticket_public_key_path)
    if priv_path.exists() and pub_path.exists():
        _private_key = serialization.load_pem_private_key(priv_path.read_bytes(), password=None)
    else:
        _private_key = ec.generate_private_key(ec.SECP256R1())
        priv_path.parent.mkdir(parents=True, exist_ok=True)
        pub_path.parent.mkdir(parents=True, exist_ok=True)
        priv_path.write_bytes(_private_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        pub_path.write_bytes(_private_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        os.chmod(priv_path, 0o600)
    _public_key = _private_key.public_key()
    spki = _public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    _kid = hashlib.sha256(spki).hexdigest()[:16]
    status(log, "Knock-ticket signing key loaded", kid=_kid, alg="ES256",
           private_key_path=settings.idp_ticket_private_key_path)


def issue(sid: str, wg_public_key: bytes) -> tuple[bytes, dict]:
    ticket_id = str(uuid.uuid4())
    expires_at = int(time.time()) + settings.idp_knock_ticket_ttl_seconds
    body = ticket_format.pack_body(sid, ticket_id, expires_at, wg_public_key)
    r, s = decode_dss_signature(_private_key.sign(body, ec.ECDSA(hashes.SHA256())))
    ticket = body + r.to_bytes(32, "big") + s.to_bytes(32, "big")
    status(log, "Knock ticket signed", sid=sid, ticket_id=ticket_id,
           bytes=len(ticket), ttl_s=settings.idp_knock_ticket_ttl_seconds)
    return ticket, {"sid": sid, "ticket_id": ticket_id, "expires_at": expires_at}


def public_key() -> ec.EllipticCurvePublicKey:
    return _public_key


def jwk() -> dict:
    numbers = _public_key.public_numbers()

    def _b64u(n: int) -> str:
        return base64.urlsafe_b64encode(n.to_bytes(32, "big")).rstrip(b"=").decode("ascii")

    return {"kty": "EC", "crv": "P-256", "use": "sig", "alg": "ES256", "kid": _kid,
            "x": _b64u(numbers.x), "y": _b64u(numbers.y)}
