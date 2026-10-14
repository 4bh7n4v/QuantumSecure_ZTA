"""SDP Gateway entrypoint.

The Gateway consults the standalone IDP, never a Controller. Two things
have to line up before the SPA listener can do its job, and both go over
the one IDP <-> Gateway link, which is mutual TLS with the project CA
(mtls/idp_link.py). The Gateway opens that connection; the IDP never calls
the Gateway.

  1. The client needs this Gateway's ML-KEM public key in order to
     encapsulate a knock against it. The client only ever talks to the IDP
     and the Gateway, so the IDP is what hands that key over, alongside the
     tokens. The Gateway registers the key with the IDP at startup; the IDP
     files it under the Gateway id in this Gateway's certificate.

  2. The Gateway must verify the knock ticket carried inside each knock. It
     fetches the IDP's JWKS (which holds the ES256 ticket key) for that, over
     the same link, so a forged JWKS cannot be slipped in on the way.

A knock that passes every Gateway check is forwarded to a Controller for the
access decision (controller/). For now that is an in-process allow-all
stand-in; the real SDP Controller will replace it.
"""

import os
import sys

# Make the shared/ package (project root, one level up) importable. Each
# component runs with its own directory as the import root (`from spa import
# ...`, not SDP_GATEWAY.spa), so `shared` is reached through this bootstrap.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from controller.allow_all import AllowAllController
from firewall import rules as firewall_rules
from mtls import idp_link
from pqc import kem
from spa.listener import SPAListener
from shared.ca.cert_utils import fingerprint
from shared.config.settings import settings
from shared.utils.logger import get_logger, status

log = get_logger("Gateway")


def _check_idp_jwks(ctx) -> None:
    """Startup fails closed: without the IDP's signing keys the Gateway cannot
    verify a single knock, so opening the SPA port would be meaningless."""
    keys = idp_link.fetch_jwks(ctx).get("keys", [])
    if not keys:
        raise RuntimeError("IDP served an empty JWKS - aborting startup")
    if not any(k.get("alg") == "ES256" for k in keys):
        raise RuntimeError("IDP JWKS has no ES256 knock-ticket key - aborting startup")
    status(log, "IDP JWKS fetched over mTLS", keys=len(keys),
           kids=[k.get("kid") for k in keys])


if __name__ == "__main__":
    status(log, "=" * 60)
    status(log, "SDP GATEWAY STARTING")
    status(log, f"IDP link: {settings.gateway_idp_link_url} (mTLS)")
    status(log, "=" * 60)

    kem_private_key, kem_public_key = kem.load_or_generate_keypair(
        settings.kem_private_key_path, settings.kem_public_key_path,
    )
    # Compare with `admin_cli.py list-gateways` on the IDP: a mismatch means
    # clients are encrypting knocks to a key this Gateway does not hold.
    status(log, "ML-KEM public key", alg=kem.ALG_NAME, fingerprint=fingerprint(kem_public_key))

    ctx = idp_link.ssl_context()
    idp_link.register_kem_key(kem_public_key, settings.gateway_spa_port, ctx)
    _check_idp_jwks(ctx)
    firewall_rules.ensure_chain()

    # Stand-in until the real SDP Controller exists: approves every knock the
    # Gateway has verified. Swap it here; the listener does not change.
    controller = AllowAllController()
    status(log, "Controller: allow-all stand-in (no policy engine)")

    listener = SPAListener(kem_private_key, idp_link.jwks_url(), controller, jwks_ssl_context=ctx)
    status(log, "SPA listener starting", port=settings.gateway_spa_port)
    listener.serve_forever()
