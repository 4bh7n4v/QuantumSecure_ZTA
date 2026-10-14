"""The SPA module's entry point: reading the Gateway key and knock ticket out
of the IDP's token bundle, and one knock over real UDP to a local stand-in
Gateway."""

from __future__ import annotations

import base64
import socket
import threading
import types

import pytest
from kyber_py.ml_kem import ML_KEM_768

from spa import packet, token_flow
from shared.utils.knock_ticket import TICKET_LEN
from shared.utils.pqc_spa import parse_spa_packet, split_kem_ciphertext

TICKET = bytes(range(TICKET_LEN))
# Largest UDP payload that fits one 1500-byte Ethernet frame (IPv4 + UDP headers).
SINGLE_DATAGRAM = 1472


def _entry(key: bytes, gateway_id: str = "gw-1") -> dict:
    return {"gateway_id": gateway_id, "spa_port": 62201,
            "public_key": base64.b64encode(key).decode()}


def test_gateway_key_is_decoded_from_the_idp_bundle():
    key = b"\x01\x02\x03" * 10
    assert token_flow.gateway_key_from_bundle({"gateways": [_entry(key)]}) == key


@pytest.mark.parametrize("bundle", [
    {}, {"gateways": []}, {"gateways": None},
    {"gateways": [{"gateway_id": "gw-1"}]},
    {"gateways": [{"gateway_id": "gw-1", "public_key": "not base64!!"}]},
    {"gateways": [_entry(b"a" * 30, "gw-1"), _entry(b"b" * 30, "gw-2")]},
])
def test_missing_or_bad_gateway_key_is_refused(bundle):
    with pytest.raises(token_flow.GatewayKeyMissing):
        token_flow.gateway_key_from_bundle(bundle)


def test_knock_ticket_is_decoded_from_the_idp_bundle():
    bundle = {"knock_ticket": base64.b64encode(TICKET).decode()}
    assert token_flow.ticket_from_bundle(bundle) == TICKET


@pytest.mark.parametrize("bundle", [{}, {"knock_ticket": None}, {"knock_ticket": "not base64!!"}])
def test_missing_or_bad_knock_ticket_is_refused(bundle):
    with pytest.raises(token_flow.KnockTicketMissing):
        token_flow.ticket_from_bundle(bundle)


def test_knock_fits_one_udp_datagram():
    encaps_key, _ = ML_KEM_768.keygen()
    assert len(packet.build(encaps_key, TICKET, 65535, "tcp")) <= SINGLE_DATAGRAM


def _stand_in_gateway(decaps_key: bytes, reply: bytes | None):
    """Bind a UDP socket, decrypt one knock, optionally answer. Returns the
    port and a dict the received payload lands in."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    received: dict = {}

    def serve():
        packet, addr = sock.recvfrom(4096)
        secret = ML_KEM_768.decaps(decaps_key, split_kem_ciphertext(packet, "ML-KEM-768"))
        received.update(parse_spa_packet(packet, "ML-KEM-768", secret))
        if reply is not None:
            sock.sendto(reply, addr)
        sock.close()

    threading.Thread(target=serve, daemon=True).start()
    return sock.getsockname()[1], received


@pytest.mark.parametrize("reply, accepted", [(b"SPA_OK", True), (None, False)])
def test_knock_carries_the_ticket_and_reports_the_answer(monkeypatch, reply, accepted):
    encaps_key, decaps_key = ML_KEM_768.keygen()
    port, received = _stand_in_gateway(decaps_key, reply)
    monkeypatch.setattr(token_flow, "settings", types.SimpleNamespace(
        gateway_ip="127.0.0.1", gateway_spa_port_client=port))

    assert token_flow.request_access(encaps_key, TICKET, 8443, "tcp") is accepted
    assert base64.b64decode(received["ticket"]) == TICKET
    assert "jwt" not in received                   # the access token never rides the knock
    assert received["access_port"] == 8443
    assert isinstance(received["timestamp"], float)


def test_nothing_listening_is_a_refusal_not_a_crash(monkeypatch):
    encaps_key, _ = ML_KEM_768.keygen()
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()                                  # port now closed: ICMP unreachable
    monkeypatch.setattr(token_flow, "settings", types.SimpleNamespace(
        gateway_ip="127.0.0.1", gateway_spa_port_client=port))
    assert token_flow.request_access(encaps_key, TICKET, 443) is False
