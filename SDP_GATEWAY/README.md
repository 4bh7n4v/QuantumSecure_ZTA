# SDP Gateway (Accepting Host)

**Status: not yet implemented — planned for weeks 3–7.**

The Policy Enforcement Point. Sits in the data path in front of protected
resources and enforces decisions made by the [controller](../SDP_CONTROLLER/).

## Planned responsibilities

| Capability | Week | Notes |
|---|---|---|
| nftables default-DROP posture | 3 | Resources are dark to unauthorized hosts — a port scan returns nothing |
| Pinhole API (open/close with TTL) | 3 | Controller calls this to authorize a specific `src → dst:port` for N seconds |
| Session table | 3 | Tracks live sessions so they can be revoked |
| SPA listener | 4 | Validates encrypted, HMAC'd single packets; replay protection via nonce + time window |
| Authorization token validation | 5 | Verifies controller-signed short-lived tokens before opening anything |
| mTLS to controller | 5 | Mutual auth on the control channel |
| Gateway-side IDS (Suricata) | 6 | Resource-directed attack rules — ET WEB_SERVER, ET EXPLOIT, ET ATTACK_RESPONSE |
| Gateway-side ML | 6 | Session-behaviour anomaly detection (distinct feature set from the controller's flow classifier) |
| Trust feedback to controller | 6 | Findings push back so future authorizations are denied too |
| Live session revocation | 7 | Trust drop → pinhole closes → active connection dies mid-stream |

## Why packet-filter enforcement

Enforcing at L3/L4 rather than as an HTTP reverse proxy makes the gateway
**protocol-agnostic**. The same code protects an SSH server, an HTTPS app, and
an IoT device without parsing any of their protocols.

## Requirements

- Root privileges (nftables manipulation)
- Suricata
- Ideally two NICs (one facing clients, one facing protected resources)
