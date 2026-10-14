"""IDP HTTP API.

Two content types:
  - JSON for first-factor login, token refresh and the admin endpoints;
  - CBOR for the FIDO2 ceremony payloads (application/cbor) — python-fido2's
    dataclasses (options, RegistrationResponse, AuthenticationResponse)
    encode/decode through CBOR natively, so the scripted client and the IDP
    exchange them with no field munging.

Flow binding: POST /auth/login checks the password and returns a ~2-minute
`login_token` (a JWT, aud="idp-login"). The client sends that as
`Authorization: Bearer <login_token>` on every /fido2/* call; the verified
user_id / username / device_id are read from the token, never from the
request body, so the ceremony cannot be re-pointed at another account.

Every step logs. On failure the log line names the step and the reason.
"""

from __future__ import annotations

import base64
import json
import time
import uuid

import jwt as pyjwt
from fido2 import cbor
from fido2.webauthn import AuthenticationResponse, RegistrationResponse
from fastapi import APIRouter, Header, HTTPException, Request, Response

from api.middleware import client_ip
from fido2_idp import server as fido2_server
from fido2_idp.attestation_tpm import AttestationRejected
from geo import resolver as geo
from policy import baseline as policy
from store import credentials as cred_store
from store import events, tokens as token_store
from store import gateways as gateway_store
from store import users as user_store
from tokens import jwt_service
from tokens import knock_ticket as knock_ticket_service
from shared.config.settings import settings
from shared.utils import knock_ticket as ticket_format
from shared.utils.logger import banner, field, get_logger, status

log = get_logger("IDP-Routes")
router = APIRouter()


# --------------------------------------------------------------------------- #
# helpers                                                                    #
# --------------------------------------------------------------------------- #

def _wire_safe(value):
    """Normalise a payload for fido2's minimal CBOR encoder, which supports
    only int/str/bytes/bool/list/dict — no float and no None. Floats are
    stringified; dict entries whose value is None are dropped (the client
    treats a missing key and a null the same way). Mirrors the client's
    _wire_safe.
    """
    if isinstance(value, float):
        return repr(value)
    if isinstance(value, dict):
        return {k: _wire_safe(v) for k, v in value.items() if v is not None}
    if isinstance(value, list):
        return [_wire_safe(v) for v in value if v is not None]
    return value


def _cbor_response(payload: dict) -> Response:
    return Response(content=cbor.encode(_wire_safe(payload)), media_type="application/cbor")


async def _cbor_body(request: Request) -> dict:
    return cbor.decode(await request.body())


def _require_admin(x_admin_key: str | None) -> None:
    if not x_admin_key or x_admin_key != settings.idp_admin_api_key:
        status(log, "Admin request rejected", reason="missing or wrong X-Admin-Key")
        raise HTTPException(status_code=401, detail="admin authentication required")


def _login_claims(authorization: str | None) -> dict:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="missing login_token bearer")
    token = authorization.split(" ", 1)[1].strip()
    try:
        return jwt_service.verify(token, jwt_service.AUD_LOGIN)
    except pyjwt.PyJWTError as exc:
        raise HTTPException(status_code=401, detail=f"invalid login_token: {exc}") from exc


def _log_access_token_before_send(username: str, user_id: str, claims: dict,
                                  access_jwt: str) -> None:
    """Print the exact access token the IDP is about to hand to this client:
    first WHO it is for (username + user_id), then every claim in plain text,
    then the whole compact JWT. The refresh token is deliberately withheld.
    """
    banner(log, f"ACCESS TOKEN FOR {username} - ABOUT TO SEND TO CLIENT")
    field(log, "Username", username)
    field(log, "User ID (sub)", user_id)
    field(log, "Session ID (sid)", claims.get("sid"))
    field(log, "Token ID (jti)", claims.get("jti"))
    log.info("Access token claims (plaintext):\n%s",
             json.dumps(claims, indent=2, sort_keys=True, default=str))
    log.info("Access token (full compact JWT - refresh token NOT shown):\n%s", access_jwt)
    banner(log, f"END ACCESS TOKEN FOR {username}")


def _gateway_list() -> list[dict]:
    """Every active Gateway's ML-KEM public key, as each registered it over
    the mTLS link (api/gateway_link.py). A list even with one Gateway, so a
    second Gateway or the Controller changes the source, not the shape."""
    listed = gateway_store.active()
    if not listed:
        status(log, "No Gateway has registered its key yet - clients will get an empty list")
    return [{"gateway_id": g.gateway_id, "spa_port": g.spa_port,
             "public_key": base64.b64encode(g.kem_public_key).decode("ascii")}
            for g in listed]


# --------------------------------------------------------------------------- #
# health / keys                                                              #
# --------------------------------------------------------------------------- #

@router.get("/healthz")
async def healthz():
    return {"status": "ok", "component": "sdp-idp"}


@router.get("/.well-known/jwks.json")
async def jwks():
    status(log, "JWKS requested")
    return jwt_service.jwks()


# --------------------------------------------------------------------------- #
# admin — user provisioning (no self-registration anywhere)                   #
# --------------------------------------------------------------------------- #

@router.post("/admin/users", status_code=201)
async def admin_create_user(request: Request, x_admin_key: str | None = Header(default=None)):
    _require_admin(x_admin_key)
    body = await request.json()
    username = body.get("username", "")
    password = body.get("password", "")
    access_window = body.get("access_window")
    roles = body.get("roles") or []
    if not isinstance(roles, list) or not all(isinstance(r, str) for r in roles):
        raise HTTPException(status_code=400, detail="roles must be a list of strings")
    try:
        user = user_store.create_user(username, password, access_window, roles)
    except user_store.UsernameExists as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    events.record("admin", "ok", user_id=user.user_id, username=user.username,
                  source_ip=client_ip(request), detail="user provisioned")
    return {"user_id": user.user_id, "username": user.username, "enabled": user.enabled,
            "roles": user.roles}


@router.get("/admin/users")
async def admin_list_users(x_admin_key: str | None = Header(default=None)):
    _require_admin(x_admin_key)
    return [
        {"user_id": u.user_id, "username": u.username, "enabled": u.enabled,
         "access_window": u.access_window, "roles": u.roles}
        for u in user_store.list_users()
    ]


@router.post("/admin/users/{username}/disable")
async def admin_disable_user(username: str, x_admin_key: str | None = Header(default=None)):
    _require_admin(x_admin_key)
    try:
        user_store.set_enabled(username, False)
    except user_store.UnknownUser as exc:
        raise HTTPException(status_code=404, detail="no such user") from exc
    u = user_store.get_by_username(username)
    if u:
        n = token_store.revoke_all_for_user(u.user_id, reason="account disabled")
        return {"username": username, "enabled": False, "refresh_tokens_revoked": n}
    return {"username": username, "enabled": False}


@router.post("/admin/users/{username}/enable")
async def admin_enable_user(username: str, x_admin_key: str | None = Header(default=None)):
    _require_admin(x_admin_key)
    try:
        user_store.set_enabled(username, True)
    except user_store.UnknownUser as exc:
        raise HTTPException(status_code=404, detail="no such user") from exc
    return {"username": username, "enabled": True}


@router.post("/admin/users/{username}/revoke-tokens")
async def admin_revoke_tokens(username: str, x_admin_key: str | None = Header(default=None)):
    _require_admin(x_admin_key)
    u = user_store.get_by_username(username)
    if u is None:
        raise HTTPException(status_code=404, detail="no such user")
    n = token_store.revoke_all_for_user(u.user_id, reason="admin revoke")
    return {"username": username, "refresh_tokens_revoked": n}


# --------------------------------------------------------------------------- #
# first factor                                                               #
# --------------------------------------------------------------------------- #

@router.post("/auth/login")
async def login(request: Request):
    body = await request.json()
    username = body.get("username", "")
    password = body.get("password", "")
    device_id = str(body.get("device_id", "")).strip()
    src_ip = client_ip(request)
    src_geo = geo.resolve(src_ip)

    status(log, "Login: first-factor attempt", username=username, device_id=device_id, source_ip=src_ip)

    if not device_id:
        raise HTTPException(status_code=400, detail="device_id is required")

    user = user_store.verify_first_factor(username, password)
    if user is None:
        events.record("login", "denied", username=username, device_id=device_id,
                      source_ip=src_ip, source_geo=src_geo, detail="first factor failed")
        # same response for unknown user / wrong password / disabled
        raise HTTPException(status_code=401, detail="invalid username or password")

    verdict = policy.check_login(user, src_ip, src_geo)
    if not verdict.allowed:
        events.record("login", "denied", user_id=user.user_id, username=username,
                      device_id=device_id, source_ip=src_ip, source_geo=src_geo,
                      detail=f"baseline policy: {verdict.reason}")
        raise HTTPException(status_code=403, detail=f"login denied by policy: {verdict.reason}")

    enrolled = any(c.device_id == device_id for c in cred_store.for_user(user.user_id))
    login_token, claims = jwt_service.issue_login_token(user.user_id, user.username, device_id)

    events.record("login", "ok", user_id=user.user_id, username=username, device_id=device_id,
                  source_ip=src_ip, source_geo=src_geo,
                  detail=f"device_enrolled={enrolled}")
    status(log, "Login: first factor accepted, login_token issued",
           username=username, device_id=device_id, device_enrolled=enrolled,
           login_token_jti=claims["jti"], expires_in=settings.idp_login_token_ttl_seconds)

    return {
        "login_token": login_token,
        "token_type": "Bearer",
        "expires_in": settings.idp_login_token_ttl_seconds,
        "device_enrolled": enrolled,
        "next": "fido2_authenticate" if enrolled else "fido2_register",
    }


# --------------------------------------------------------------------------- #
# FIDO2 ceremony (CBOR)                                                       #
# --------------------------------------------------------------------------- #

@router.post("/fido2/register/begin")
async def fido2_register_begin(request: Request, authorization: str | None = Header(default=None)):
    c = _login_claims(authorization)
    status(log, "FIDO2 register/begin", user_id=c["sub"], username=c["username"],
           device_id=c["device_id"])
    flow_id, options = fido2_server.registration_begin(c["sub"], c["username"], c["device_id"])
    return _cbor_response({"flow_id": flow_id, "options": options})


@router.post("/fido2/register/complete")
async def fido2_register_complete(request: Request, authorization: str | None = Header(default=None)):
    c = _login_claims(authorization)
    body = await _cbor_body(request)
    trust_anchor_type = body.get("trust_anchor_type", "unknown")
    status(log, "FIDO2 register/complete", user_id=c["sub"], device_id=c["device_id"],
           trust_anchor_type=trust_anchor_type)
    try:
        response = RegistrationResponse.from_dict(body["response"])
        record = fido2_server.registration_complete(body["flow_id"], response, trust_anchor_type)
    except AttestationRejected as exc:
        events.record("fido2_register", "denied", user_id=c["sub"], username=c["username"],
                      device_id=c["device_id"], source_ip=client_ip(request), detail=str(exc))
        raise HTTPException(status_code=400, detail=f"attestation rejected: {exc}") from exc
    except ValueError as exc:
        events.record("fido2_register", "error", user_id=c["sub"], username=c["username"],
                      device_id=c["device_id"], source_ip=client_ip(request), detail=str(exc))
        raise HTTPException(status_code=400, detail=f"registration failed: {exc}") from exc

    events.record("fido2_register", "ok", user_id=c["sub"], username=c["username"],
                  device_id=c["device_id"], source_ip=client_ip(request),
                  detail=f"credential_id={record.credential_id.hex()[:16]} "
                         f"attestation_fmt={record.attestation_fmt} "
                         f"trust_path={record.attestation_trust_path} "
                         f"hardware_attested={record.attested_hardware}")
    return _cbor_response({"status": "registered",
                           "credential_id": record.credential_id.hex(),
                           "attestation_fmt": record.attestation_fmt,
                           "hardware_attested": record.attested_hardware,
                           "attestation_trust_path": record.attestation_trust_path})


@router.post("/fido2/authenticate/begin")
async def fido2_authenticate_begin(request: Request, authorization: str | None = Header(default=None)):
    c = _login_claims(authorization)
    status(log, "FIDO2 authenticate/begin", user_id=c["sub"], username=c["username"],
           device_id=c["device_id"])
    try:
        flow_id, options = fido2_server.authentication_begin(c["sub"])
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return _cbor_response({"flow_id": flow_id, "options": options})


@router.post("/fido2/authenticate/complete")
async def fido2_authenticate_complete(request: Request, authorization: str | None = Header(default=None)):
    c = _login_claims(authorization)
    body = await _cbor_body(request)
    src_ip = client_ip(request)
    src_geo = geo.resolve(src_ip)
    status(log, "FIDO2 authenticate/complete", user_id=c["sub"], device_id=c["device_id"])

    # The knock ticket carries the client's WireGuard public key, so it is
    # bound here, once, behind the second factor, and stored with the session.
    wg_public_key = body.get("wg_public_key")
    if not isinstance(wg_public_key, bytes) or len(wg_public_key) != ticket_format.WG_KEY_LEN:
        raise HTTPException(status_code=400,
                            detail=f"wg_public_key must be {ticket_format.WG_KEY_LEN} raw bytes")

    user = user_store.get_by_username(c["username"])
    if user is None or not user.enabled:
        raise HTTPException(status_code=403, detail="account is not active")

    try:
        response = AuthenticationResponse.from_dict(body["response"])
        record = fido2_server.authentication_complete(body["flow_id"], response)
    except ValueError as exc:
        events.record("fido2_authenticate", "denied", user_id=c["sub"], username=c["username"],
                      device_id=c["device_id"], source_ip=src_ip, detail=str(exc))
        raise HTTPException(status_code=401, detail=f"assertion rejected: {exc}") from exc

    # Second factor complete -> issue the token pair. One session id ties the
    # access token, its refresh token and every access token later minted from
    # that refresh together, so a session can be revoked / logged out as a unit.
    sid = str(uuid.uuid4())
    amr = ["pwd", "fido2"] + (["hwattest"] if record.attested_hardware else [])
    access_token, access_claims = jwt_service.issue_access_token(
        c["sub"], c["username"], c["device_id"], record.credential_id.hex(),
        amr=amr, sid=sid, roles=user.roles,
        # cnf_jkt: bind to the client mTLS cert once that path exists (Gateway phase).
        cnf_jkt=None,
    )
    refresh_token, refresh_claims = jwt_service.issue_refresh_token(
        c["sub"], c["username"], c["device_id"], sid=sid,
    )
    token_store.register(token_store.RefreshRecord(
        jti=refresh_claims["jti"], user_id=c["sub"], device_id=c["device_id"],
        access_jti=access_claims["jti"],
        issued_at=refresh_claims["iat"], expires_at=refresh_claims["exp"],
        revoked=False, issue_ip=src_ip, issue_geo=src_geo, last_ip=src_ip, last_geo=src_geo,
        last_used_at=refresh_claims["iat"], wg_public_key=wg_public_key,
    ))
    knock_ticket, ticket_info = knock_ticket_service.issue(sid, wg_public_key)

    events.record("fido2_authenticate", "ok", user_id=c["sub"], username=c["username"],
                  device_id=c["device_id"], source_ip=src_ip, source_geo=src_geo,
                  detail=f"access_jti={access_claims['jti']} refresh_jti={refresh_claims['jti']} "
                         f"ticket_id={ticket_info['ticket_id']}")
    status(log, "Authentication COMPLETE - access, refresh and knock ticket issued", username=c["username"],
           device_id=c["device_id"], access_ttl_s=settings.idp_access_ttl_seconds,
           refresh_ttl_s=settings.idp_refresh_ttl_seconds,
           hardware_attested=record.attested_hardware)

    _log_access_token_before_send(c["username"], c["sub"], access_claims, access_token)

    return _cbor_response({
        "status": "granted",
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "Bearer",
        "expires_in": settings.idp_access_ttl_seconds,
        "refresh_expires_in": settings.idp_refresh_ttl_seconds,
        "scope": access_claims["scope"],
        "session_id": sid,
        "knock_ticket": base64.b64encode(knock_ticket).decode("ascii"),
        "knock_ticket_expires_in": settings.idp_knock_ticket_ttl_seconds,
        "gateways": _gateway_list(),
        "hardware_attested": record.attested_hardware,
    })


# --------------------------------------------------------------------------- #
# token refresh                                                              #
# --------------------------------------------------------------------------- #

def _usable_refresh(refresh_token: str, src_ip: str, src_geo: str | None,
                    purpose: str) -> tuple[dict, token_store.RefreshRecord, user_store.User]:
    """Everything a refresh token must pass before the IDP issues anything on
    it: signature, on record, not revoked or expired, account still active,
    baseline policy. Shared by /token/refresh and /token/knock-ticket."""
    try:
        claims = jwt_service.verify(refresh_token, jwt_service.AUD_REFRESH)
    except pyjwt.PyJWTError as exc:
        raise HTTPException(status_code=401, detail=f"invalid refresh token: {exc}") from exc

    rec = token_store.get(claims["jti"])
    if rec is None:
        status(log, f"{purpose}: FAIL", reason="refresh jti not on record", jti=claims["jti"])
        raise HTTPException(status_code=401, detail="unknown refresh token")

    usable, why = token_store.is_usable(rec)
    if not usable:
        status(log, f"{purpose}: FAIL", reason=why, jti=rec.jti)
        raise HTTPException(status_code=401, detail=f"refresh token {why}")

    user = user_store.get_by_username(claims["username"])
    if user is None or not user.enabled:
        token_store.revoke(rec.jti, reason="user missing or disabled")
        raise HTTPException(status_code=403, detail="account is not active")

    seconds_since_prev = None
    if rec.last_used_at is not None:
        seconds_since_prev = max(0.0, time.time() - rec.last_used_at)

    verdict = policy.check_refresh(
        rec.user_id, claims["username"], rec.device_id, src_ip, src_geo,
        rec.last_ip, rec.last_geo, seconds_since_prev,
    )
    if not verdict.allowed:
        token_store.revoke(rec.jti, reason=f"baseline policy: {verdict.reason}")
        raise HTTPException(status_code=403, detail=f"{purpose} denied by policy: {verdict.reason}")
    return claims, rec, user


@router.post("/token/refresh")
async def token_refresh(request: Request):
    body = await request.json()
    refresh_token = body.get("refresh_token", "")
    src_ip = client_ip(request)
    src_geo = geo.resolve(src_ip)
    status(log, "Token refresh requested", source_ip=src_ip)

    claims, rec, user = _usable_refresh(refresh_token, src_ip, src_geo, "Token refresh")

    access_token, access_claims = jwt_service.issue_access_token(
        rec.user_id, claims["username"], rec.device_id,
        credential_id="", amr=["pwd", "fido2", "refresh"],
        # Same session as the original grant. Fall back to the refresh jti for
        # refresh tokens issued before `sid` existed.
        sid=claims.get("sid", rec.jti),
        # Looked up fresh on every refresh, so a role change reaches the
        # client within one access-token lifetime.
        roles=user.roles,
    )
    token_store.rotate_access_jti(rec.jti, access_claims["jti"], src_ip, src_geo)

    events.record("token_refresh", "ok", user_id=rec.user_id, username=claims["username"],
                  device_id=rec.device_id, source_ip=src_ip, source_geo=src_geo,
                  detail=f"new access_jti={access_claims['jti']}")
    status(log, "Token refresh: new access token issued", username=claims["username"],
           device_id=rec.device_id, access_ttl_s=settings.idp_access_ttl_seconds)

    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": settings.idp_access_ttl_seconds,
        "scope": access_claims["scope"],
    }


# --------------------------------------------------------------------------- #
# knock ticket                                                               #
# --------------------------------------------------------------------------- #

@router.post("/token/knock-ticket")
async def token_knock_ticket(request: Request):
    """A fresh knock ticket for this session. A ticket lasts 60 s and the
    Gateway accepts it once, so the client asks for one per knock. It always
    carries the WireGuard key bound at FIDO2 time; the request cannot name
    another."""
    body = await request.json()
    src_ip = client_ip(request)
    src_geo = geo.resolve(src_ip)
    status(log, "Knock ticket requested", source_ip=src_ip)

    claims, rec, _user = _usable_refresh(body.get("refresh_token", ""), src_ip, src_geo,
                                         "Knock ticket")
    if not rec.wg_public_key:
        # Sessions opened before tickets existed have no bound key.
        raise HTTPException(status_code=409, detail="session has no WireGuard key; sign in again")

    ticket, info = knock_ticket_service.issue(claims.get("sid", rec.jti), rec.wg_public_key)
    events.record("knock_ticket", "ok", user_id=rec.user_id, username=claims["username"],
                  device_id=rec.device_id, source_ip=src_ip, source_geo=src_geo,
                  detail=f"ticket_id={info['ticket_id']}")
    return {
        "knock_ticket": base64.b64encode(ticket).decode("ascii"),
        "expires_in": settings.idp_knock_ticket_ttl_seconds,
    }
