"""SDP Gateway entrypoint.

The Gateway consults the standalone IDP, never a Controller. Two things
have to line up before the SPA listener can do its job:

  1. The client needs this Gateway's ML-KEM public key in order to
     encapsulate a knock against it. The client only ever talks to the IDP
     and the Gateway, so the IDP is what hands that key over, alongside the
     access token. The Gateway publishes the key by writing it where the
     IDP can read it (GATEWAY_PUBKEY_PUBLISH_PATH here,
     IDP_GATEWAY_PUBKEY_PATH there — a shared volume in compose). It is
     deliberately a file drop rather than a call into the IDP: the IDP is
     never a client of anything downstream of it.

  2. The Gateway must verify the RS256 access tokens carried inside those
     knocks. It fetches the IDP's JWKS for that — the one consultation that
     legitimately runs Gateway -> IDP.
"""

import os
import sys

# Make the shared/ package (project root, one level up) importable.
# Component directories use hyphenated names (sdp-gateway) which are not
# valid Python package names, so each component is run with its own
# directory as the import root and reaches into `shared` through this
# explicit sys.path bootstrap.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import time
from pathlib import Path

import requests

from firewall import rules as firewall_rules
from pqc import kem
from spa.listener import SPAListener
from shared.config.settings import settings
from shared.utils.logger import get_logger, status

log = get_logger("Gateway")


def _publish_kem_public_key(kem_public_key: bytes) -> None:
    """Drop the ML-KEM public key where the IDP can pick it up.

    No-op when GATEWAY_PUBKEY_PUBLISH_PATH is unset, which is the normal
    case for a local single-host run where the IDP is pointed straight at
    the Gateway's own certs directory.
    """
    target = settings.gateway_pubkey_publish_path
    if not target:
        status(log, "No GATEWAY_PUBKEY_PUBLISH_PATH set - skipping public-key publish")
        return

    path = Path(target)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(kem_public_key)
    status(log, "ML-KEM public key published for the IDP",
           path=target, alg=kem.ALG_NAME, bytes=len(kem_public_key))


def _wait_for_idp_jwks(retries: int = 15, delay: float = 2.0) -> str:
    """Block until the IDP's JWKS is served, then return its URL.

    Startup fails closed: without the IDP's signing keys the Gateway cannot
    verify a single access token, so opening the SPA port would be
    meaningless.
    """
    jwks_url = f"{settings.idp_base_url}/.well-known/jwks.json"
    for attempt in range(1, retries + 1):
        try:
            resp = requests.get(jwks_url, timeout=5)
            resp.raise_for_status()
            keys = resp.json().get("keys", [])
            if not keys:
                raise ValueError("IDP served an empty JWKS")
            status(log, "IDP JWKS reachable", url=jwks_url, keys=len(keys),
                   kids=[k.get("kid") for k in keys])
            return jwks_url
        except (requests.RequestException, ValueError) as exc:
            status(log, f"IDP not reachable yet (attempt {attempt}/{retries})", error=str(exc))
            time.sleep(delay)
    raise RuntimeError(f"Could not reach the IDP JWKS at {jwks_url} - aborting startup")


if __name__ == "__main__":
    status(log, "=" * 60)
    status(log, "SDP GATEWAY STARTING")
    status(log, f"IDP: {settings.idp_base_url}")
    status(log, "=" * 60)

    kem_private_key, kem_public_key = kem.load_or_generate_keypair(
        settings.kem_private_key_path, settings.kem_public_key_path,
    )
    _publish_kem_public_key(kem_public_key)
    firewall_rules.ensure_chain()
    jwks_url = _wait_for_idp_jwks()

    listener = SPAListener(kem_private_key, jwks_url)
    status(log, "SPA listener starting", port=settings.gateway_spa_port)
    listener.serve_forever()
