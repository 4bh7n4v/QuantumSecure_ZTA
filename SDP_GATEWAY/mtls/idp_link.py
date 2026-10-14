"""The Gateway's side of the IDP <-> Gateway link, over mutual TLS.

The Gateway opens every connection; the IDP never calls in. Over it the
Gateway does two things at startup:

  1. registers its ML-KEM public key, which the IDP then hands to clients;
  2. fetches the IDP's JWKS, to verify the knock tickets inside knocks.

Both ends prove who they are with certificates from the project CA: the
IDP's certificate must name the host in GATEWAY_IDP_LINK_URL, and this
Gateway's certificate carries its id, which is what the IDP files the key
under. The bundle (gateway.crt, gateway.key, ca.crt) comes from
`admin_cli.py issue-gateway-cert` on the IDP machine.
"""

from __future__ import annotations

import base64
import json
import ssl
import time
import urllib.error
import urllib.request
from pathlib import Path

from shared.ca import cert_utils
from shared.config.settings import settings
from shared.utils.logger import get_logger, status

log = get_logger("GwIdpLink")


class LinkNotConfigured(RuntimeError):
    pass


def ssl_context() -> ssl.SSLContext:
    paths = {"certificate": settings.gateway_tls_cert_path,
             "private key": settings.gateway_tls_key_path,
             "CA certificate": settings.gateway_ca_cert_path}
    missing = [f"{what} ({p})" for what, p in paths.items() if not Path(p).exists()]
    if missing:
        raise LinkNotConfigured(
            "Gateway certificate bundle missing: " + ", ".join(missing)
            + " - on the IDP machine run `admin_cli.py issue-gateway-cert --id <id>`"
              " and copy the folder here as certs/pki/")
    return cert_utils.client_context(settings.gateway_tls_cert_path,
                                     settings.gateway_tls_key_path,
                                     settings.gateway_ca_cert_path)


def jwks_url() -> str:
    return f"{settings.gateway_idp_link_url}/.well-known/jwks.json"


def _request(req: urllib.request.Request, ctx: ssl.SSLContext) -> dict:
    with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
        return json.loads(resp.read())


def register_kem_key(kem_public_key: bytes, spa_port: int, ctx: ssl.SSLContext,
                     retries: int = 15, delay: float = 2.0) -> dict:
    """Register this Gateway's ML-KEM public key with the IDP. Retries while
    the IDP is unreachable; a refusal (bad bundle, revoked Gateway) is final."""
    body = json.dumps({"kem_public_key": base64.b64encode(kem_public_key).decode("ascii"),
                       "spa_port": spa_port}).encode("utf-8")
    url = f"{settings.gateway_idp_link_url}/gateway/register"
    for attempt in range(1, retries + 1):
        req = urllib.request.Request(url, data=body, method="POST",
                                     headers={"Content-Type": "application/json"})
        try:
            reply = _request(req, ctx)
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:300]
            raise RuntimeError(f"IDP refused the Gateway registration ({exc.code}): {detail}") from exc
        except (urllib.error.URLError, OSError) as exc:
            # urllib wraps TLS failures in URLError. Those are final - retrying
            # cannot fix a certificate - so they must not read as "unreachable".
            reason = getattr(exc, "reason", exc)
            if isinstance(reason, ssl.SSLCertVerificationError):
                raise RuntimeError(f"IDP certificate not trusted - wrong CA, or "
                                   f"{settings.gateway_idp_link_url} is not a name it was "
                                   f"issued for: {reason}") from exc
            if isinstance(reason, ssl.SSLError):
                raise RuntimeError(f"TLS with the IDP failed - is this Gateway's certificate "
                                   f"from the IDP's CA? {reason}") from exc
            status(log, f"IDP link not reachable yet (attempt {attempt}/{retries})",
                   url=url, error=str(exc))
            time.sleep(delay)
            continue
        status(log, "ML-KEM public key registered with the IDP over mTLS",
               gateway_id=reply.get("gateway_id"), fingerprint=reply.get("fingerprint"))
        return reply
    raise RuntimeError(f"Could not reach the IDP link at {url} - aborting startup")


def fetch_jwks(ctx: ssl.SSLContext) -> dict:
    return _request(urllib.request.Request(jwks_url()), ctx)
