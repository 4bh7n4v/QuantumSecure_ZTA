"""The three tokens the IDP hands out: access token, refresh token, knock
ticket. Signing keys and the database are real and temporary; the HTTP
routes run through FastAPI's test client."""

from __future__ import annotations

import base64
import dataclasses
import sqlite3
import time
import uuid

import jwt as pyjwt
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api import routes
from shared.config.settings import settings
from shared.utils import knock_ticket as ticket_format
from store import db, tokens as token_store, users
from tokens import jwt_service, knock_ticket

WG_KEY = bytes(range(32))


@pytest.fixture
def idp(monkeypatch, tmp_path):
    test_settings = dataclasses.replace(
        settings,
        idp_db_path=str(tmp_path / "idp.db"),
        idp_jwt_private_key_path=str(tmp_path / "jwt.pem"),
        idp_jwt_public_key_path=str(tmp_path / "jwt.pub.pem"),
        idp_ticket_private_key_path=str(tmp_path / "ticket.pem"),
        idp_ticket_public_key_path=str(tmp_path / "ticket.pub.pem"),
    )
    for module in (db, jwt_service, knock_ticket, routes):
        monkeypatch.setattr(module, "settings", test_settings)
    db.init_db()
    jwt_service.init()
    knock_ticket.init()
    app = FastAPI()
    app.include_router(routes.router)
    return TestClient(app)


def open_session(user, wg_key: bytes | None = WG_KEY) -> tuple[str, str]:
    """What /fido2/authenticate/complete records, minus the ceremony."""
    sid = str(uuid.uuid4())
    refresh, claims = jwt_service.issue_refresh_token(user.user_id, user.username, "dev-1", sid)
    token_store.register(token_store.RefreshRecord(
        jti=claims["jti"], user_id=user.user_id, device_id="dev-1", access_jti="-",
        issued_at=claims["iat"], expires_at=claims["exp"], revoked=False,
        issue_ip=None, issue_geo=None, last_ip=None, last_geo=None, last_used_at=None,
        wg_public_key=wg_key))
    return refresh, sid


# --- access token ------------------------------------------------------------

def test_access_token_names_gateway_and_resource_nodes_and_carries_roles(idp):
    token, _ = jwt_service.issue_access_token(
        "u1", "alice", "dev-1", "cred", amr=["pwd", "fido2", "hwattest"],
        sid=str(uuid.uuid4()), roles=["engineer"])
    public_key = jwt_service._public_key
    for audience in (settings.idp_token_audience, settings.idp_resource_audience):
        claims = pyjwt.decode(token, public_key, algorithms=["RS256"],
                              audience=audience, issuer=settings.idp_issuer)
        assert claims["roles"] == ["engineer"]
        assert claims["acr"] == "aal3"
    with pytest.raises(pyjwt.InvalidAudienceError):
        pyjwt.decode(token, public_key, algorithms=["RS256"],
                     audience="idp-refresh", issuer=settings.idp_issuer)


def test_refresh_reads_roles_fresh(idp):
    user = users.create_user("alice", "pw", roles=["engineer"])
    refresh, sid = open_session(user)
    users.set_roles("alice", ["ops", "engineer"])

    resp = idp.post("/token/refresh", json={"refresh_token": refresh})
    assert resp.status_code == 200
    claims = pyjwt.decode(resp.json()["access_token"], options={"verify_signature": False})
    assert claims["roles"] == ["engineer", "ops"]
    assert claims["sid"] == sid


# --- refresh token -----------------------------------------------------------

def test_refresh_token_has_no_roles_or_acr_and_only_the_idp_accepts_it(idp):
    token, claims = jwt_service.issue_refresh_token("u1", "alice", "dev-1", str(uuid.uuid4()))
    assert "roles" not in claims and "acr" not in claims
    with pytest.raises(pyjwt.InvalidAudienceError):
        pyjwt.decode(token, jwt_service._public_key, algorithms=["RS256"],
                     audience=settings.idp_token_audience, issuer=settings.idp_issuer)


# --- knock ticket ------------------------------------------------------------

def test_ticket_is_133_bytes_and_verifies(idp):
    sid = str(uuid.uuid4())
    ticket, info = knock_ticket.issue(sid, WG_KEY)
    assert len(ticket) == ticket_format.TICKET_LEN == 133
    parsed = ticket_format.verify(ticket, knock_ticket.public_key())
    assert parsed.sid == sid
    assert parsed.ticket_id == info["ticket_id"]
    assert parsed.wg_public_key == WG_KEY
    assert 0 < parsed.expires_at - time.time() <= 60


def test_every_ticket_has_its_own_one_time_id(idp):
    sid = str(uuid.uuid4())
    ids = {knock_ticket.issue(sid, WG_KEY)[1]["ticket_id"] for _ in range(5)}
    assert len(ids) == 5


@pytest.mark.parametrize("offset", [0, 20, 40, 70, 100])
def test_any_changed_byte_breaks_the_signature(idp, offset):
    ticket = bytearray(knock_ticket.issue(str(uuid.uuid4()), WG_KEY)[0])
    ticket[offset] ^= 0x01
    with pytest.raises(ticket_format.InvalidTicket):
        ticket_format.verify(bytes(ticket), knock_ticket.public_key())


def test_expired_ticket_is_refused(idp):
    ticket, info = knock_ticket.issue(str(uuid.uuid4()), WG_KEY)
    with pytest.raises(ticket_format.InvalidTicket, match="expired"):
        ticket_format.verify(ticket, knock_ticket.public_key(), now=info["expires_at"] + 1)


def test_ticket_needs_a_32_byte_wireguard_key(idp):
    with pytest.raises(ValueError):
        knock_ticket.issue(str(uuid.uuid4()), b"short")


def test_jwks_publishes_the_ticket_key_so_the_gateway_can_verify(idp):
    keys = idp.get("/.well-known/jwks.json").json()["keys"]
    assert {k["alg"] for k in keys} == {"RS256", "ES256"}
    ec_jwk = next(k for k in keys if k["alg"] == "ES256")
    gateway_view = pyjwt.PyJWK(ec_jwk).key

    ticket, _ = knock_ticket.issue(str(uuid.uuid4()), WG_KEY)
    assert ticket_format.verify(ticket, gateway_view).wg_public_key == WG_KEY


def test_knock_ticket_endpoint_uses_the_key_bound_at_fido2_time(idp):
    user = users.create_user("alice", "pw")
    refresh, sid = open_session(user)

    resp = idp.post("/token/knock-ticket", json={"refresh_token": refresh, "wg_public_key": "x"})
    assert resp.status_code == 200
    ticket = base64.b64decode(resp.json()["knock_ticket"])
    parsed = ticket_format.verify(ticket, knock_ticket.public_key())
    assert parsed.sid == sid and parsed.wg_public_key == WG_KEY


def test_knock_ticket_refused_on_revoked_session_or_disabled_account(idp):
    user = users.create_user("alice", "pw")
    refresh, _ = open_session(user)
    users.set_enabled("alice", False)
    assert idp.post("/token/knock-ticket", json={"refresh_token": refresh}).status_code == 403
    # the disabled account's refresh token is now revoked too
    users.set_enabled("alice", True)
    assert idp.post("/token/knock-ticket", json={"refresh_token": refresh}).status_code == 401


def test_knock_ticket_refused_for_a_session_without_a_wireguard_key(idp):
    user = users.create_user("alice", "pw")
    refresh, _ = open_session(user, wg_key=None)
    assert idp.post("/token/knock-ticket", json={"refresh_token": refresh}).status_code == 409


def test_access_token_cannot_buy_a_ticket(idp):
    access, _ = jwt_service.issue_access_token(
        "u1", "alice", "dev-1", "c", amr=["pwd"], sid=str(uuid.uuid4()), roles=[])
    assert idp.post("/token/knock-ticket", json={"refresh_token": access}).status_code == 401


@pytest.mark.parametrize("wg_public_key", [None, b"short", "not-bytes" * 4])
def test_fido2_completion_requires_a_wireguard_key(idp, wg_public_key):
    from fido2 import cbor
    user = users.create_user("alice", "pw")
    login_token, _ = jwt_service.issue_login_token(user.user_id, "alice", "dev-1")
    body = {"flow_id": "x", "response": {}}
    if wg_public_key is not None:
        body["wg_public_key"] = wg_public_key
    resp = idp.post("/fido2/authenticate/complete", content=cbor.encode(body),
                    headers={"Authorization": f"Bearer {login_token}",
                             "Content-Type": "application/cbor"})
    assert resp.status_code == 400
    assert "wg_public_key" in resp.json()["detail"]


# --- database upgrade --------------------------------------------------------

def test_existing_database_gains_roles_and_wireguard_columns(monkeypatch, tmp_path):
    path = tmp_path / "old.db"
    conn = sqlite3.connect(path)
    conn.executescript("""
        CREATE TABLE users (user_id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
            access_window TEXT, created_at REAL NOT NULL);
        INSERT INTO users VALUES ('u1', 'old-alice', 'x', 1, NULL, 0);
        CREATE TABLE refresh_tokens (jti TEXT PRIMARY KEY, user_id TEXT NOT NULL,
            device_id TEXT NOT NULL, access_jti TEXT NOT NULL, issued_at REAL NOT NULL,
            expires_at REAL NOT NULL, revoked INTEGER NOT NULL DEFAULT 0, issue_ip TEXT,
            issue_geo TEXT, last_ip TEXT, last_geo TEXT, last_used_at REAL);
    """)
    conn.close()
    monkeypatch.setattr(db, "settings", dataclasses.replace(settings, idp_db_path=str(path)))
    db.init_db()
    assert users.get_by_username("old-alice").roles == []
    with db.connect() as conn:
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(refresh_tokens)")}
    assert "wg_public_key" in cols
