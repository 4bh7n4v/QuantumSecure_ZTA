"""SPA knock handling, end to end inside the Gateway.

Knocks are built exactly as the client builds them (real ML-KEM-768, real
AES-GCM, a real ES256-signed knock ticket in the IDP's layout); only the
network edges are replaced — the JWKS fetch, the Controller, the firewall,
and the UDP reply.
"""

from __future__ import annotations

import base64
import time
import types
import uuid

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from kyber_py.ml_kem import ML_KEM_768

from controller.allow_all import AllowAllController
from firewall import segmentation
from spa import guard
from spa.listener import SPAListener
from shared.utils import knock_ticket as ticket_format
from shared.utils.pqc_spa import build_spa_packet

CLIENT = ("10.0.0.7", 40000)
SID = str(uuid.uuid4())
WG_KEY = bytes(range(32))


@pytest.fixture(scope="module")
def kem_keys():
    encaps_key, decaps_key = ML_KEM_768.keygen()
    return encaps_key, decaps_key


@pytest.fixture(scope="module")
def ticket_key():
    return ec.generate_private_key(ec.SECP256R1())


class RecordingController:
    def __init__(self, reply: dict | None = None) -> None:
        self.messages: list[dict] = []
        self._inner = AllowAllController()
        self._reply = reply

    def send(self, msg: dict) -> dict:
        self.messages.append(msg)
        return self._reply if self._reply is not None else self._inner.send(msg)


@pytest.fixture
def gateway(kem_keys, ticket_key, monkeypatch):
    grants, replies = [], []
    monkeypatch.setattr(segmentation, "grant_temporary_access",
                        lambda *args: grants.append(args))
    # The IDP's JWKS: the RS256 JWT key, which must be ignored, and the ticket key.
    jwks = [types.SimpleNamespace(algorithm_name="RS256",
                                  key=rsa.generate_private_key(65537, 2048).public_key()),
            types.SimpleNamespace(algorithm_name="ES256", key=ticket_key.public_key())]

    def build(controller=None):
        controller = controller or RecordingController()
        listener = SPAListener(kem_keys[1], "http://idp.invalid/jwks", controller)
        listener._jwks_client = types.SimpleNamespace(get_signing_keys=lambda: jwks)
        listener._reply = lambda addr, msg: replies.append((addr, msg))
        return types.SimpleNamespace(listener=listener, controller=controller,
                                     grants=grants, replies=replies)
    return build


def make_ticket(key, *, ticket_id: str | None = None, expires_at: int | None = None) -> bytes:
    """What IDENTITY_PROVIDER/tokens/knock_ticket.issue() produces."""
    body = ticket_format.pack_body(SID, ticket_id or str(uuid.uuid4()),
                                   expires_at or int(time.time()) + 60, WG_KEY)
    r, s = decode_dss_signature(key.sign(body, ec.ECDSA(hashes.SHA256())))
    return body + r.to_bytes(32, "big") + s.to_bytes(32, "big")


def make_knock(kem_keys, raw_ticket: bytes, **overrides) -> bytes:
    shared_secret, kem_ct = ML_KEM_768.encaps(kem_keys[0])
    payload = {"ticket": base64.b64encode(raw_ticket).decode(), "access_port": 443,
               "protocol": "tcp", "timestamp": time.time()}
    payload.update(overrides)
    return build_spa_packet(kem_ct, shared_secret, payload)


def test_verified_knock_is_forwarded_and_opens_the_port(gateway, kem_keys, ticket_key):
    gw = gateway()
    ticket_id = str(uuid.uuid4())
    gw.listener._handle_packet(make_knock(kem_keys, make_ticket(ticket_key, ticket_id=ticket_id)), CLIENT)

    [msg] = gw.controller.messages
    assert msg["type"] == "SPA_VERIFY"
    assert msg["client_ip"] == CLIENT[0]
    assert msg["access_port"] == 443
    assert msg["identity"] == {"sid": SID, "ticket_id": ticket_id,
                               "wg_public_key": base64.b64encode(WG_KEY).decode()}
    assert "ticket" not in msg                    # raw ticket stays at the Gateway
    assert gw.grants == [(CLIENT[0], 443, "tcp", 30)]
    assert gw.replies == [(CLIENT, b"SPA_OK")]


def test_replayed_knock_is_dropped(gateway, kem_keys, ticket_key):
    gw = gateway()
    knock = make_knock(kem_keys, make_ticket(ticket_key))
    gw.listener._handle_packet(knock, CLIENT)
    gw.listener._handle_packet(knock, CLIENT)
    assert len(gw.controller.messages) == 1
    assert len(gw.replies) == 1


def test_ticket_rewrapped_in_a_fresh_knock_is_used_only_once(gateway, kem_keys, ticket_key):
    """The gap the raw-packet replay cache cannot close: fresh ML-KEM
    ciphertext makes a new packet around the same ticket."""
    gw = gateway()
    ticket = make_ticket(ticket_key)
    first, second = make_knock(kem_keys, ticket), make_knock(kem_keys, ticket)
    assert first != second
    gw.listener._handle_packet(first, CLIENT)
    gw.listener._handle_packet(second, ("10.0.0.99", 40000))   # even from elsewhere
    assert len(gw.controller.messages) == 1
    assert gw.replies == [(CLIENT, b"SPA_OK")]


@pytest.mark.parametrize("timestamp", [None, "now", time.time() - 3600, time.time() + 3600])
def test_stale_or_missing_timestamp_is_dropped(gateway, kem_keys, ticket_key, timestamp):
    gw = gateway()
    gw.listener._handle_packet(make_knock(kem_keys, make_ticket(ticket_key), timestamp=timestamp), CLIENT)
    assert gw.controller.messages == [] and gw.replies == []


def test_expired_ticket_is_dropped(gateway, kem_keys, ticket_key):
    gw = gateway()
    expired = make_ticket(ticket_key, expires_at=int(time.time()) - 1)
    gw.listener._handle_packet(make_knock(kem_keys, expired), CLIENT)
    assert gw.controller.messages == [] and gw.replies == []


def test_ticket_signed_by_another_key_is_dropped(gateway, kem_keys):
    gw = gateway()
    forged = make_ticket(ec.generate_private_key(ec.SECP256R1()))
    gw.listener._handle_packet(make_knock(kem_keys, forged), CLIENT)
    assert gw.controller.messages == [] and gw.replies == []


def test_tampered_ticket_is_dropped(gateway, kem_keys, ticket_key):
    gw = gateway()
    ticket = bytearray(make_ticket(ticket_key))
    ticket[40] ^= 0x01                            # flip a bit of the WireGuard key
    gw.listener._handle_packet(make_knock(kem_keys, bytes(ticket)), CLIENT)
    assert gw.controller.messages == [] and gw.replies == []


@pytest.mark.parametrize("payload_ticket", [None, 12345, "not base64!!",
                                            base64.b64encode(b"short").decode()])
def test_missing_or_malformed_ticket_is_dropped(gateway, kem_keys, ticket_key, payload_ticket):
    gw = gateway()
    gw.listener._handle_packet(
        make_knock(kem_keys, make_ticket(ticket_key), ticket=payload_ticket), CLIENT)
    assert gw.controller.messages == [] and gw.replies == []


def test_access_jwt_in_place_of_a_ticket_is_dropped(gateway, kem_keys):
    """The old knock format: a JWT and no ticket. It must not open anything."""
    gw = gateway()
    shared_secret, kem_ct = ML_KEM_768.encaps(kem_keys[0])
    knock = build_spa_packet(kem_ct, shared_secret, {
        "jwt": "header.claims.sig", "access_port": 443, "protocol": "tcp", "timestamp": time.time()})
    gw.listener._handle_packet(knock, CLIENT)
    assert gw.controller.messages == [] and gw.replies == []


@pytest.mark.parametrize("overrides", [
    {"access_port": 0}, {"access_port": 70000}, {"access_port": "443"},
    {"access_port": True}, {"protocol": "icmp"},
])
def test_malformed_request_is_dropped(gateway, kem_keys, ticket_key, overrides):
    gw = gateway()
    gw.listener._handle_packet(make_knock(kem_keys, make_ticket(ticket_key), **overrides), CLIENT)
    assert gw.controller.messages == [] and gw.replies == []


def test_garbage_packet_is_dropped_silently(gateway):
    gw = gateway()
    gw.listener._handle_packet(b"\x00" * 1200, CLIENT)
    assert gw.controller.messages == [] and gw.replies == []


def test_controller_denial_opens_nothing_and_stays_silent(gateway, kem_keys, ticket_key):
    gw = gateway(RecordingController({"type": "DENIED", "reason": "test"}))
    gw.listener._handle_packet(make_knock(kem_keys, make_ticket(ticket_key)), CLIENT)
    assert len(gw.controller.messages) == 1
    assert gw.grants == [] and gw.replies == []


def test_rate_limit_drops_before_any_crypto(gateway, kem_keys, ticket_key):
    gw = gateway()
    gw.listener._rate_limiter = guard.RateLimiter(capacity=2, fill_rate=0)
    for _ in range(4):
        gw.listener._handle_packet(make_knock(kem_keys, make_ticket(ticket_key)), CLIENT)
    assert len(gw.controller.messages) == 2


# --- SpentTickets on its own ------------------------------------------------

def test_spent_ticket_is_refused_until_it_expires():
    spent = guard.SpentTickets()
    assert spent.spend("t-1", expires_at=1060, now=1000) is True
    assert spent.spend("t-1", expires_at=1060, now=1030) is False
    assert spent.spend("t-2", expires_at=1060, now=1030) is True


def test_spent_ids_are_forgotten_once_their_ticket_has_expired():
    spent = guard.SpentTickets()
    spent.spend("t-1", expires_at=1060, now=1000)
    spent.spend("t-2", expires_at=1200, now=1100)  # t-1 long expired by now
    assert "t-1" not in spent._spent and "t-2" in spent._spent
