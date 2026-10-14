"""UDP listener implementing the Gateway side of the ML-KEM-protected SPA
knock.

A client completes FIDO2 authentication with the IDP first, which hands it
this Gateway's ML-KEM public key plus a knock ticket: 133 bytes, signed by
the IDP, valid 60 s, usable once (shared/utils/knock_ticket.py). The client
then ML-KEM-encapsulates against that public key and sends the resulting
encrypted knock here — this is the only packet the Gateway will accept
before a port is opened; everything else is dropped by the firewall chain
set up in firewall/rules.py.

The knock carries the ticket, never the 15-minute access JWT. The JWT is a
bearer credential for the whole access lifetime and too big for one UDP
datagram; it belongs on the session's keepalives, not in the knock.

Checks run cheapest first, following the PULGABLE_ZTNA_V2 Gateway:

  1. rate limit per source IP          spa/guard.py
  2. replay (hash of the raw packet)   spa/guard.py
  3. ML-KEM decapsulate + AES-GCM      shared/utils/pqc_spa.py
  4. timestamp freshness               spa/guard.py
  5. request shape (port, protocol)
  6. knock ticket: signature, expiry   shared/utils/knock_ticket.py
  7. knock ticket: single use          spa/guard.py
  8. SPA_VERIFY to the Controller      controller/

Only an APPROVED answer opens a port and earns a reply. Every failure,
including a Controller denial, is silent: an unauthenticated sender must
not be able to tell a Gateway is listening at all.

The ticket key comes from the IDP's JWKS rather than a pinned file, so the
IDP can rotate it without the Gateway being redeployed. A ticket carries no
`kid`, so it is checked against the JWKS's ES256 key(s); PyJWKClient caches
the set and refetches it over the same mTLS link.
"""

from __future__ import annotations

import base64
import binascii
import socket
import ssl
import time

import jwt as pyjwt

from controller.client import ControllerClient
from firewall import segmentation
from pqc import kem
from spa import guard
from shared.config.settings import settings
from shared.utils import knock_ticket as ticket_format
from shared.utils.logger import get_logger, status
from shared.utils.pqc_spa import parse_spa_packet, split_kem_ciphertext

log = get_logger("SPA")

_PROTOCOLS = ("tcp", "udp")
_TICKET_ALG = "ES256"


class SPAListener:
    def __init__(self, kem_private_key: bytes, jwks_url: str,
                 controller: ControllerClient,
                 jwks_ssl_context: ssl.SSLContext | None = None) -> None:
        self._kem_private_key = kem_private_key
        # Refetches (key rotation at the IDP) go over the same mTLS link.
        self._jwks_client = pyjwt.PyJWKClient(jwks_url, ssl_context=jwks_ssl_context)
        self._controller = controller
        self._rate_limiter = guard.RateLimiter()
        self._replay_cache = guard.ReplayCache()
        self._spent_tickets = guard.SpentTickets()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def serve_forever(self) -> None:
        self._sock.bind((settings.gateway_host, settings.gateway_spa_port))
        status(log, "SPA listener bound", host=settings.gateway_host, port=settings.gateway_spa_port)

        while True:
            packet, addr = self._sock.recvfrom(4096)
            self._handle_packet(packet, addr)

    def _handle_packet(self, packet: bytes, addr: tuple[str, int]) -> None:
        client_ip = addr[0]
        received_at = time.time()

        if not self._rate_limiter.allow(client_ip):
            status(log, "SPA knock dropped - rate limit", client_ip=client_ip)
            return
        if self._replay_cache.is_replay(packet):
            status(log, "SPA knock dropped - replay", client_ip=client_ip)
            return
        status(log, "SPA knock received", client_ip=client_ip, bytes=len(packet))

        try:
            kem_ct = split_kem_ciphertext(packet, kem.ALG_NAME)
            shared_secret = kem.decapsulate(self._kem_private_key, kem_ct)
            payload = parse_spa_packet(packet, kem.ALG_NAME, shared_secret)
        except Exception as exc:
            status(log, "SPA knock dropped - decrypt/parse failed", client_ip=client_ip, error=str(exc))
            return

        if not guard.is_fresh(payload.get("timestamp"), received_at):
            status(log, "SPA knock dropped - stale or missing timestamp",
                   client_ip=client_ip, timestamp=payload.get("timestamp"))
            return

        access_port = payload.get("access_port")
        protocol = payload.get("protocol", "tcp")
        if (not isinstance(access_port, int) or isinstance(access_port, bool)
                or not 1 <= access_port <= 65535 or protocol not in _PROTOCOLS):
            status(log, "SPA knock dropped - bad request", client_ip=client_ip,
                   port=access_port, protocol=protocol)
            return

        try:
            ticket = self._verify_ticket(payload.get("ticket"))
        except (ticket_format.InvalidTicket, pyjwt.PyJWKClientError) as exc:
            status(log, "SPA knock dropped - invalid knock ticket", client_ip=client_ip, error=str(exc))
            return

        # After the signature, so only IDP-issued ids ever land in the cache.
        if not self._spent_tickets.spend(ticket.ticket_id, ticket.expires_at):
            status(log, "SPA knock dropped - knock ticket already used", client_ip=client_ip,
                   ticket_id=ticket.ticket_id)
            return

        # The Controller sees who the ticket was issued to, never the ticket itself.
        identity = {"sid": ticket.sid, "ticket_id": ticket.ticket_id,
                    "wg_public_key": base64.b64encode(ticket.wg_public_key).decode("ascii")}
        status(log, "SPA knock verified - forwarding to Controller", client_ip=client_ip,
               sid=ticket.sid, ticket_id=ticket.ticket_id, port=access_port)

        try:
            decision = self._controller.send({
                "type": "SPA_VERIFY",
                "client_ip": client_ip,
                "access_port": access_port,
                "protocol": protocol,
                "received_at": received_at,
                "identity": identity,
            })
        except Exception as exc:
            status(log, "SPA knock dropped - Controller unreachable", client_ip=client_ip, error=str(exc))
            return

        if decision.get("type") != "APPROVED":
            status(log, "SPA knock denied by Controller", client_ip=client_ip,
                   decision=decision.get("type"), reason=decision.get("reason"))
            return

        segmentation.grant_temporary_access(
            client_ip, decision["access_port"], decision["protocol"], decision["ttl_seconds"],
        )
        status(log, "SPA knock accepted", client_ip=client_ip, session=decision["session_id"])
        self._reply(addr, b"SPA_OK")

    def _verify_ticket(self, encoded) -> ticket_format.KnockTicket:
        if not isinstance(encoded, str):
            raise ticket_format.InvalidTicket("knock carries no ticket")
        try:
            raw = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ticket_format.InvalidTicket("ticket is not base64") from exc

        keys = [k.key for k in self._jwks_client.get_signing_keys()
                if k.algorithm_name == _TICKET_ALG]
        if not keys:
            raise ticket_format.InvalidTicket("IDP JWKS has no ES256 ticket key")
        last_error = None
        for key in keys:            # more than one only while the IDP rotates
            try:
                return ticket_format.verify(raw, key)
            except ticket_format.InvalidTicket as exc:
                last_error = exc
        raise last_error

    def _reply(self, addr: tuple[str, int], message: bytes) -> None:
        self._sock.sendto(message, addr)
