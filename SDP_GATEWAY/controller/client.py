"""The one seam between the Gateway and whatever makes access decisions.

The Gateway enforces; it does not decide. Once a knock has passed every
check the Gateway can do on its own (rate limit, replay, ML-KEM decrypt,
freshness, knock-ticket signature and single use), it hands the verified
facts to a Controller as an SPA_VERIFY message and does exactly what the
answer says.

Message shapes follow the PULGABLE_ZTNA_V2 Gateway <-> Controller IPC, so a
real SDP Controller reached over mTLS can replace AllowAllController later
without the listener changing:

  request  {"type": "SPA_VERIFY", "client_ip", "access_port", "protocol",
            "received_at", "identity": {sid, ticket_id, wg_public_key}}

The identity is what the knock ticket carries: the IDP session id, not a
username. A Controller that needs the user resolves the sid with the IDP.
  approved {"type": "APPROVED", "session_id", "access_port", "protocol",
            "ttl_seconds"}
  denied   {"type": "DENIED", "reason"}

One difference from PULGABLE on purpose: the Gateway forwards the decrypted,
verified identity, not the raw packet. Only the Gateway holds the ML-KEM
private key, so a Controller could not open the packet anyway.
"""

from __future__ import annotations

from typing import Protocol


class ControllerClient(Protocol):
    def send(self, msg: dict) -> dict:
        """Deliver one IPC message and return the Controller's reply."""
        ...
