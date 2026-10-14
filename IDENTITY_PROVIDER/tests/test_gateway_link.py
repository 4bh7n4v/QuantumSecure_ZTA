"""The IDP's Gateway-only mTLS listener, run for real on a local port with a
throw-away CA. Connects as a genuine Gateway, as a stranger, and as things
that look like a Gateway but are not."""

from __future__ import annotations

import base64
import dataclasses
import json
import ssl
import urllib.error
import urllib.request

import pytest

from api import gateway_link, routes
from shared.ca import cert_utils, root_ca
from shared.config.settings import settings
from store import db, gateways as gateway_store
from tokens import jwt_service, knock_ticket

KEM_KEY = bytes(range(256)) * 4 + bytes(160)          # 1184 bytes


@pytest.fixture
def pki(tmp_path):
    ca_dir = tmp_path / "ca"
    root_ca.create(ca_dir)
    ca = root_ca.load(ca_dir)
    out = tmp_path / "pki"
    idp_crt, idp_key = cert_utils.issue(*ca, "sdp-idp", "server", out, hosts=["127.0.0.1"],
                                        file_stem="idp")
    gw_crt, gw_key = cert_utils.issue(*ca, "gw-1", "client", out, file_stem="gw-1")

    other_dir = tmp_path / "other-ca"
    root_ca.create(other_dir, common_name="Someone else's CA")
    stranger = cert_utils.issue(*root_ca.load(other_dir), "gw-1", "client", out,
                                file_stem="stranger")
    return {"ca": str(ca_dir / root_ca.CA_CERT_NAME), "idp": (str(idp_crt), str(idp_key)),
            "gw": (str(gw_crt), str(gw_key)), "stranger": tuple(map(str, stranger))}


@pytest.fixture
def link(monkeypatch, tmp_path, pki):
    test_settings = dataclasses.replace(
        settings, idp_db_path=str(tmp_path / "idp.db"),
        idp_jwt_private_key_path=str(tmp_path / "jwt.pem"),
        idp_jwt_public_key_path=str(tmp_path / "jwt.pub.pem"),
        idp_ticket_private_key_path=str(tmp_path / "t.pem"),
        idp_ticket_public_key_path=str(tmp_path / "t.pub.pem"))
    for module in (db, jwt_service, knock_ticket, routes):
        monkeypatch.setattr(module, "settings", test_settings)
    db.init_db()
    jwt_service.init()
    knock_ticket.init()
    server = gateway_link.serve("127.0.0.1", 0,
                                cert_utils.server_context(*pki["idp"], pki["ca"]))
    yield f"https://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


def call(url: str, path: str, ctx: ssl.SSLContext, body: dict | None = None) -> tuple[int, dict]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url + path, data=data, method="POST" if data else "GET",
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=5) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def gateway_ctx(pki, who: str = "gw") -> ssl.SSLContext:
    return cert_utils.client_context(*pki[who], pki["ca"])


def registration(key: bytes = KEM_KEY, spa_port=62201, **extra) -> dict:
    return {"kem_public_key": base64.b64encode(key).decode(), "spa_port": spa_port, **extra}


def test_gateway_registers_and_clients_get_its_key(link, pki):
    code, reply = call(link, "/gateway/register", gateway_ctx(pki), registration())
    assert code == 200
    assert reply == {"gateway_id": "gw-1", "fingerprint": cert_utils.fingerprint(KEM_KEY)}
    [listed] = routes._gateway_list()
    assert listed["gateway_id"] == "gw-1"
    assert base64.b64decode(listed["public_key"]) == KEM_KEY


def test_the_id_comes_from_the_certificate_not_the_request(link, pki):
    call(link, "/gateway/register", gateway_ctx(pki), registration(gateway_id="gw-9"))
    assert [g.gateway_id for g in gateway_store.active()] == ["gw-1"]


def test_re_registering_replaces_the_key(link, pki):
    call(link, "/gateway/register", gateway_ctx(pki), registration())
    new_key = bytes(reversed(KEM_KEY))
    call(link, "/gateway/register", gateway_ctx(pki), registration(new_key))
    [gw] = gateway_store.active()
    assert gw.kem_public_key == new_key


def test_gateway_fetches_the_jwks_over_the_link(link, pki):
    code, jwks = call(link, "/.well-known/jwks.json", gateway_ctx(pki))
    assert code == 200
    assert {k["alg"] for k in jwks["keys"]} == {"RS256", "ES256"}


def _refused(link, ctx) -> None:
    with pytest.raises((ssl.SSLError, urllib.error.URLError, ConnectionError, OSError)):
        call(link, "/gateway/register", ctx, registration())
    assert gateway_store.active() == []


def test_no_certificate_is_refused(link, pki):
    ctx = ssl.create_default_context(cafile=pki["ca"])
    _refused(link, ctx)


def test_certificate_from_another_ca_is_refused(link, pki):
    _refused(link, gateway_ctx(pki, "stranger"))


def test_the_idps_own_server_certificate_cannot_pose_as_a_gateway(link, pki):
    _refused(link, gateway_ctx(pki, "idp"))


@pytest.mark.parametrize("body", [
    registration(KEM_KEY[:100]),
    registration(spa_port=0),
    registration(spa_port="62201"),
    {"spa_port": 62201},
    {"kem_public_key": "not base64!!", "spa_port": 62201},
])
def test_malformed_registration_is_rejected(link, pki, body):
    code, _ = call(link, "/gateway/register", gateway_ctx(pki), body)
    assert code == 400
    assert gateway_store.active() == []


def test_revoked_gateway_is_not_listed_and_cannot_come_back(link, pki):
    call(link, "/gateway/register", gateway_ctx(pki), registration())
    gateway_store.revoke("gw-1")
    assert routes._gateway_list() == []
    code, _ = call(link, "/gateway/register", gateway_ctx(pki), registration())
    assert code == 403
    assert routes._gateway_list() == []


def test_unknown_paths_are_404(link, pki):
    code, _ = call(link, "/admin/users", gateway_ctx(pki))
    assert code == 404


def test_a_second_ca_is_never_created_over_the_first(tmp_path):
    root_ca.create(tmp_path)
    with pytest.raises(root_ca.CAExists):
        root_ca.create(tmp_path)
