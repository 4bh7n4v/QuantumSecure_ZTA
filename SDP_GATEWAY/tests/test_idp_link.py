"""The Gateway's side of the IDP link, against a small stand-in IDP that
speaks mutual TLS with a throw-away CA."""

from __future__ import annotations

import base64
import dataclasses
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from mtls import idp_link
from shared.ca import cert_utils, root_ca
from shared.config.settings import settings

KEM_KEY = b"\x07" * 1184


class _StandInIdp(BaseHTTPRequestHandler):
    received: list = []

    def log_message(self, *args) -> None:
        pass

    def _json(self, code: int, body: dict) -> None:
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:
        peer = cert_utils.gateway_id_from_peer(self.connection.getpeercert(binary_form=True))
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.received.append((peer, body))
        self._json(200, {"gateway_id": peer, "fingerprint": "fp"})

    def do_GET(self) -> None:
        self._json(200, {"keys": [{"kid": "k1"}]})


@pytest.fixture
def pki(tmp_path):
    root_ca.create(tmp_path / "ca")
    ca = root_ca.load(tmp_path / "ca")
    out = tmp_path / "pki"
    idp = cert_utils.issue(*ca, "sdp-idp", "server", out, hosts=["127.0.0.1"], file_stem="idp")
    gw = cert_utils.issue(*ca, "gw-1", "client", out, file_stem="gateway")
    return {"ca": str(tmp_path / "ca" / root_ca.CA_CERT_NAME), "idp": idp, "gw": gw,
            "tmp": tmp_path}


@pytest.fixture
def idp(pki):
    ctx = cert_utils.server_context(str(pki["idp"][0]), str(pki["idp"][1]), pki["ca"])
    server = ThreadingHTTPServer(("127.0.0.1", 0), _StandInIdp)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    _StandInIdp.received = []
    yield server.server_address[1]
    server.shutdown()


def use(monkeypatch, pki, port: int, host: str = "127.0.0.1", ca: str | None = None) -> None:
    monkeypatch.setattr(idp_link, "settings", dataclasses.replace(
        settings, gateway_idp_link_url=f"https://{host}:{port}",
        gateway_tls_cert_path=str(pki["gw"][0]), gateway_tls_key_path=str(pki["gw"][1]),
        gateway_ca_cert_path=ca or pki["ca"]))


def test_registers_the_key_under_the_certificate_id(monkeypatch, pki, idp):
    use(monkeypatch, pki, idp)
    reply = idp_link.register_kem_key(KEM_KEY, 62201, idp_link.ssl_context(), retries=1)
    assert reply["gateway_id"] == "gw-1"
    [(peer, body)] = _StandInIdp.received
    assert peer == "gw-1"
    assert base64.b64decode(body["kem_public_key"]) == KEM_KEY
    assert body["spa_port"] == 62201


def test_fetches_the_jwks_over_the_same_link(monkeypatch, pki, idp):
    use(monkeypatch, pki, idp)
    assert idp_link.fetch_jwks(idp_link.ssl_context())["keys"] == [{"kid": "k1"}]


def test_an_idp_signed_by_another_ca_is_not_trusted(monkeypatch, pki, idp):
    root_ca.create(pki["tmp"] / "other")
    use(monkeypatch, pki, idp, ca=str(pki["tmp"] / "other" / root_ca.CA_CERT_NAME))
    with pytest.raises(RuntimeError, match="not trusted"):
        idp_link.register_kem_key(KEM_KEY, 62201, idp_link.ssl_context(), retries=1)
    assert _StandInIdp.received == []


def test_dialling_a_name_the_idp_certificate_does_not_carry_is_refused(monkeypatch, pki, idp):
    use(monkeypatch, pki, idp, host="localhost")      # certificate names 127.0.0.1 only
    with pytest.raises(RuntimeError, match="not trusted"):
        idp_link.register_kem_key(KEM_KEY, 62201, idp_link.ssl_context(), retries=1)


def test_missing_bundle_says_how_to_get_one(monkeypatch, pki, tmp_path):
    monkeypatch.setattr(idp_link, "settings", dataclasses.replace(
        settings, gateway_tls_cert_path=str(tmp_path / "nope.crt")))
    with pytest.raises(idp_link.LinkNotConfigured, match="issue-gateway-cert"):
        idp_link.ssl_context()


def test_unreachable_idp_gives_up_after_the_retries(monkeypatch, pki):
    use(monkeypatch, pki, 1)                           # nothing listens on port 1
    with pytest.raises(RuntimeError, match="Could not reach"):
        idp_link.register_kem_key(KEM_KEY, 62201, idp_link.ssl_context(), retries=2, delay=0)
