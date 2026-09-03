"""FIDO2 client: drives first-factor login + the WebAuthn ceremony against
the standalone IDP, using whichever hardware trust anchor is available
(internal TPM or external USB key — see tpm/anchored_trust.py), and returns
the access token, refresh token and Gateway public key the IDP hands back.

The client talks ONLY to the IDP here (`settings.idp_base_url`). It never
contacts the SDP Controller. There is no account signup path — accounts are
provisioned by an administrator at the IDP.

Terminal output: each ceremony prints a title banner, then numbered
"Step n/N: ..." lines mirroring the WebAuthn/CTAP2 protocol, then a summary
block — so a demo viewer (and a failed run) can be followed step by step.
"""

from __future__ import annotations

import base64
import json

import requests
from fido2 import cbor
from fido2.webauthn import CredentialCreationOptions, CredentialRequestOptions

from fido2_agent import external_authenticator, tpm_authenticator
from tpm.anchored_trust import AnchoredIdentity
from shared.config.settings import settings
from shared.utils.logger import banner, field, get_logger, status, step

log = get_logger("FIDO2Client")


def _wire_safe(value):
    """fido2's CBOR encoder has no float / None support — stringify floats and
    drop None dict entries at the wire boundary (mirrors the IDP)."""
    if isinstance(value, float):
        return repr(value)
    if isinstance(value, dict):
        return {k: _wire_safe(v) for k, v in value.items() if v is not None}
    if isinstance(value, list):
        return [_wire_safe(v) for v in value if v is not None]
    return value


def _idp_url(path: str) -> str:
    return f"{settings.idp_base_url}{path}"


def _post_cbor(path: str, payload: dict, login_token: str) -> dict:
    resp = requests.post(
        _idp_url(path),
        data=cbor.encode(_wire_safe(payload)),
        headers={"Content-Type": "application/cbor",
                 "Authorization": f"Bearer {login_token}"},
        timeout=15,
    )
    if not resp.ok:
        status(log, "IDP rejected request", path=path,
               status_code=resp.status_code, detail=resp.text[:500])
    resp.raise_for_status()
    return cbor.decode(resp.content)


def _jwt_claims(token: str) -> dict:
    """Best-effort decode of a JWT payload for display only (no verification —
    the Gateway verifies these tokens against the IDP's JWKS later)."""
    try:
        payload_b64 = token.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)
        return json.loads(base64.urlsafe_b64decode(payload_b64))
    except Exception:
        return {}


# --------------------------------------------------------------------------- #
# first factor                                                               #
# --------------------------------------------------------------------------- #

def login(username: str, password: str, device_id: str) -> dict:
    """Send username + password to the IDP. On success returns a dict with
    `login_token` (short-lived), `device_enrolled` (bool) and `next`.
    """
    banner(log, "FIRST-FACTOR LOGIN")
    field(log, "Username", username)
    field(log, "Device ID", device_id)
    field(log, "IDP", settings.idp_base_url)

    step(log, 1, 2, "POST username + password to IDP", endpoint="/auth/login")
    resp = requests.post(
        _idp_url("/auth/login"),
        json={"username": username, "password": password, "device_id": device_id},
        timeout=15,
    )
    if not resp.ok:
        status(log, "IDP rejected first-factor login",
               status_code=resp.status_code, detail=resp.text[:500])
    resp.raise_for_status()
    data = resp.json()
    step(log, 2, 2, "IDP accepted the first factor and issued a login_token",
         device_enrolled=data.get("device_enrolled"), next=data.get("next"),
         login_token_ttl_s=data.get("expires_in"))
    return data


# --------------------------------------------------------------------------- #
# WebAuthn registration                                                      #
# --------------------------------------------------------------------------- #

def register(login_token: str, anchor: AnchoredIdentity, rp_id: str, origin: str) -> bytes:
    """Run the WebAuthn registration ceremony (first login for this device).
    Returns the new credential_id.
    """
    banner(log, "FIDO2 REGISTRATION INITIATED")
    field(log, "Relying Party (IDP)", rp_id)
    field(log, "Origin", origin)
    field(log, "Trust anchor", anchor.kind)

    step(log, 1, 6, "Requesting credential-creation options from IDP",
         endpoint="/fido2/register/begin")
    resp = _post_cbor("/fido2/register/begin", {}, login_token)
    options = CredentialCreationOptions.from_dict(resp["options"])
    pk = options.public_key
    step(log, 2, 6, "Received registration challenge from IDP",
         challenge_bytes=len(pk.challenge), flow_id=resp["flow_id"], rp_id=pk.rp.id,
         pubkey_algs=[p.alg for p in pk.pub_key_cred_params])

    if anchor.kind == "internal_tpm":
        step(log, 3, 6, "Building clientDataJSON (type=webauthn.create) and binding the challenge")
        step(log, 4, 6, "Generating an ES256 credential key inside the TPM and building the attestation object")
        response, credential_id = tpm_authenticator.build_registration_response(
            options, anchor, origin, rp_id)
    else:
        step(log, 3, 6, "Delegating to external USB CTAP2 authenticator - touch it now")
        step(log, 4, 6, "External authenticator generated the key and attestation")
        client = external_authenticator.build_client(anchor.ctap_device, origin)
        response = external_authenticator.register(client, options)
        credential_id = response.raw_id

    step(log, 5, 6, "Submitting attestation object to IDP",
         endpoint="/fido2/register/complete", credential_id=credential_id.hex()[:16])
    result = _post_cbor("/fido2/register/complete", {
        "flow_id": resp["flow_id"], "response": response, "trust_anchor_type": anchor.kind,
    }, login_token)

    step(log, 6, 6, "IDP verified the attestation and stored the credential")
    banner(log, "FIDO2 REGISTRATION COMPLETE")
    field(log, "Credential ID", result.get("credential_id"))
    field(log, "Attestation format", result.get("attestation_fmt"))
    field(log, "Hardware-attested", result.get("hardware_attested"))
    return credential_id


# --------------------------------------------------------------------------- #
# WebAuthn authentication                                                    #
# --------------------------------------------------------------------------- #

def authenticate(login_token: str, credential_id: bytes, anchor: AnchoredIdentity,
                 rp_id: str, origin: str) -> dict:
    """Run the WebAuthn authentication ceremony. Returns the IDP token bundle
    (`access_token`, `refresh_token`, `expires_in`, `gateway_public_key`, …).
    """
    banner(log, "FIDO2 AUTHENTICATION INITIATED")
    field(log, "Relying Party (IDP)", rp_id)
    field(log, "Credential ID", credential_id.hex()[:16] + "…")
    field(log, "Trust anchor", anchor.kind)

    step(log, 1, 6, "Requesting an assertion challenge from IDP",
         endpoint="/fido2/authenticate/begin")
    resp = _post_cbor("/fido2/authenticate/begin", {}, login_token)
    options = CredentialRequestOptions.from_dict(resp["options"])
    pk = options.public_key
    step(log, 2, 6, "Received assertion challenge from IDP",
         challenge_bytes=len(pk.challenge), flow_id=resp["flow_id"],
         allow_credentials=len(pk.allow_credentials or []))

    if anchor.kind == "internal_tpm":
        step(log, 3, 6, "Building clientDataJSON (type=webauthn.get) + authenticatorData (flags UP|UV)")
        step(log, 4, 6, "Signing authenticatorData || SHA-256(clientDataJSON) with the TPM key (ES256)")
        response = tpm_authenticator.build_authentication_response(
            options, anchor, credential_id, origin, rp_id)
    else:
        step(log, 3, 6, "Delegating to external USB CTAP2 authenticator - touch it now")
        step(log, 4, 6, "External authenticator signed the assertion")
        client = external_authenticator.build_client(anchor.ctap_device, origin)
        response = external_authenticator.authenticate(client, options)

    step(log, 5, 6, "Submitting the signed assertion to IDP", endpoint="/fido2/authenticate/complete")
    result = _post_cbor("/fido2/authenticate/complete", {
        "flow_id": resp["flow_id"], "response": response,
    }, login_token)

    if result.get("status") != "granted":
        status(log, "FIDO2 authentication: NOT granted", status=result.get("status"))
        return result

    step(log, 6, 6, "IDP verified the assertion and issued the token pair")
    claims = _jwt_claims(result["access_token"])
    banner(log, "FIDO2 AUTHENTICATION SUCCESSFUL - SESSION ESTABLISHED")
    field(log, "Subject (user_id)", claims.get("sub"))
    field(log, "Access token (head)", result["access_token"][:40] + "…")
    field(log, "Access token TTL", f"{result.get('expires_in')}s")
    field(log, "Refresh token TTL", f"{result.get('refresh_expires_in')}s")
    field(log, "Token audience", claims.get("aud"))
    field(log, "AMR (auth methods)", claims.get("amr"))
    field(log, "Hardware-attested", result.get("hardware_attested"))
    field(log, "Gateway public key", "received" if result.get("gateway_public_key") else "not provided yet (Gateway phase)")
    return result


# --------------------------------------------------------------------------- #
# token refresh                                                              #
# --------------------------------------------------------------------------- #

def refresh(refresh_token: str) -> dict:
    """Swap a valid refresh token for a fresh access token. No FIDO2 replay."""
    status(log, "Token refresh: POST /token/refresh to IDP")
    resp = requests.post(
        _idp_url("/token/refresh"),
        json={"refresh_token": refresh_token},
        timeout=15,
    )
    if not resp.ok:
        status(log, "IDP refused token refresh",
               status_code=resp.status_code, detail=resp.text[:500])
    resp.raise_for_status()
    data = resp.json()
    status(log, "Token refresh: new access token received", expires_in=data.get("expires_in"))
    return data
