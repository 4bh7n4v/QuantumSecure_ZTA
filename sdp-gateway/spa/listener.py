"""UDP listener implementing the Gateway side of the ML-KEM-protected SPA
knock.

A client completes FIDO2 authentication with the IDP first, which hands it
this Gateway's ML-KEM public key plus a signed access token. The client
then ML-KEM-encapsulates against that public key and sends the resulting
encrypted knock here — this is the only packet the Gateway will accept
before a port is opened; everything else is dropped by the firewall chain
set up in firewall/rules.py.

Token verification goes through the IDP's JWKS rather than a single pinned
public key, so the signing key can be rotated at the IDP without the
Gateway being redeployed; PyJWKClient matches the token's `kid` and caches
what it fetches.
"""

from __future__ import annotations

import socket

import jwt as pyjwt

from firewall import segmentation
from pqc import kem
from shared.config.settings import settings
from shared.utils.logger import get_logger, status
from shared.utils.pqc_spa import parse_spa_packet, split_kem_ciphertext

log = get_logger("SPA")


class SPAListener:
    def __init__(self, kem_private_key: bytes, jwks_url: str) -> None:
        self._kem_private_key = kem_private_key
        self._jwks_client = pyjwt.PyJWKClient(jwks_url)
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def serve_forever(self) -> None:
        self._sock.bind((settings.gateway_host, settings.gateway_spa_port))
        status(log, "SPA listener bound", host=settings.gateway_host, port=settings.gateway_spa_port)

        while True:
            packet, addr = self._sock.recvfrom(4096)
            status(log, "SPA knock received", client_ip=addr[0], bytes=len(packet))
            self._handle_packet(packet, addr)

    def _handle_packet(self, packet: bytes, addr: tuple[str, int]) -> None:
        client_ip = addr[0]
        try:
            kem_ct = split_kem_ciphertext(packet, kem.ALG_NAME)
            shared_secret = kem.decapsulate(self._kem_private_key, kem_ct)
            payload = parse_spa_packet(packet, kem.ALG_NAME, shared_secret)
        except Exception as exc:
            status(log, "SPA knock rejected - decrypt/parse failed", client_ip=client_ip, error=str(exc))
            return

        token = payload.get("jwt")
        requested_port = payload.get("access_port")
        protocol = payload.get("protocol", "tcp")

        try:
            signing_key = self._jwks_client.get_signing_key_from_jwt(token)
            claims = pyjwt.decode(
                token, signing_key.key, algorithms=["RS256"],
                audience=settings.idp_token_audience, issuer=settings.idp_issuer,
            )
        except (pyjwt.PyJWTError, pyjwt.PyJWKClientError) as exc:
            status(log, "SPA knock rejected - invalid JWT", client_ip=client_ip, error=str(exc))
            self._reply(addr, b"SPA_DENY")
            return

        if claims.get("acl") == "DENY" or not requested_port:
            status(log, "SPA knock rejected - policy denied or bad request",
                   client_ip=client_ip, user=claims.get("sub"), acl=claims.get("acl"))
            self._reply(addr, b"SPA_DENY")
            return

        status(log, "SPA knock accepted", client_ip=client_ip, user=claims.get("sub"),
               acl=claims.get("acl"), port=requested_port)
        segmentation.grant_temporary_access(client_ip, requested_port, protocol)
        self._reply(addr, b"SPA_OK")

    def _reply(self, addr: tuple[str, int], message: bytes) -> None:
        self._sock.sendto(message, addr)
