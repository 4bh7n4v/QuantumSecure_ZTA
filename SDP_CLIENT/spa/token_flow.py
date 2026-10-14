"""Ties the FIDO2 authentication result (knock ticket + Gateway ML-KEM public
key) to the SPA knock — the step that turns a granted access decision into
an actually-open port on the Gateway.

A ticket opens a port once. The first comes in the FIDO2 token bundle;
every later knock needs a fresh one from the IDP (fido2_client.knock_ticket).

This is the only entry point main.py uses into spa/: packet.py builds the
knock, knock.py sends it, and nothing outside this module needs to know how.
"""

from __future__ import annotations

import base64
import binascii

from spa import knock, packet
from shared.config.settings import settings
from shared.utils.logger import get_logger

log = get_logger("TokenFlow")


class GatewayKeyMissing(Exception):
    """The IDP's token bundle carried no usable Gateway ML-KEM public key."""


class KnockTicketMissing(Exception):
    """The IDP's token bundle carried no usable knock ticket."""


def gateway_key_from_bundle(token_bundle: dict) -> bytes:
    """The IDP sends every registered Gateway as `gateways`, each with its
    ML-KEM public key base64-encoded. Exactly one is supported for now:
    choosing between several is the SDP Controller's job, and it does not
    exist yet."""
    listed = token_bundle.get("gateways") or []
    if not listed:
        raise GatewayKeyMissing("IDP listed no Gateway - has the Gateway started and "
                                "registered over the mTLS link?")
    if len(listed) > 1:
        raise GatewayKeyMissing(f"IDP listed {len(listed)} Gateways; choosing between "
                                "several needs the SDP Controller")
    try:
        return base64.b64decode(listed[0]["public_key"], validate=True)
    except (KeyError, TypeError, binascii.Error, ValueError) as exc:
        raise GatewayKeyMissing(f"Gateway entry has no valid public_key: {exc}") from exc


def ticket_from_bundle(token_bundle: dict) -> bytes:
    """The knock ticket the IDP issued with the FIDO2 grant, base64 on the wire."""
    try:
        return base64.b64decode(token_bundle["knock_ticket"], validate=True)
    except (KeyError, TypeError, binascii.Error, ValueError) as exc:
        raise KnockTicketMissing(f"IDP bundle has no valid knock_ticket: {exc}") from exc


def request_access(gateway_kem_pubkey: bytes, knock_ticket: bytes,
                   access_port: int, protocol: str = "tcp") -> bool:
    """Build and send one knock. True only if the Gateway answered SPA_OK;
    the Gateway is silent on every refusal, so False covers deny and
    unreachable alike."""
    spa_packet = packet.build(
        gateway_kem_pubkey=gateway_kem_pubkey,
        knock_ticket=knock_ticket,
        access_port=access_port,
        protocol=protocol,
    )
    return knock.send(spa_packet, settings.gateway_ip, settings.gateway_spa_port_client, timeout=5.0)
