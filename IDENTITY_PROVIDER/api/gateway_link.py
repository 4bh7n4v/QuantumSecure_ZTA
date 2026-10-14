"""The IDP's Gateway-only listener, over mutual TLS.

Separate from the client-facing API on purpose: it listens on its own port,
accepts only peers holding a Gateway certificate from the project CA, and
does two things:

    POST /gateway/register        a Gateway files its ML-KEM public key
    GET  /.well-known/jwks.json   a Gateway fetches the keys that sign tokens

Traffic runs Gateway -> IDP only. The IDP never opens a connection to a
Gateway; it answers the ones Gateways open.

Why not a FastAPI route: the Gateway's id is the common name in its
certificate, and uvicorn does not hand the peer certificate to the
application. Python's own HTTP server does, so this small listener runs on
that instead, in a background thread of the IDP process.
"""

from __future__ import annotations

import base64
import binascii
import json
import socket
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from store import events, gateways as gateway_store
from tokens import jwt_service
from shared.ca import cert_utils, root_ca
from shared.config.settings import settings
from shared.utils.logger import get_logger, status

log = get_logger("IDP-GwLink")

KEM_PUBLIC_KEY_LEN = 1184       # ML-KEM-768 encapsulation key (FIPS 203)
_MAX_BODY = 16 * 1024
_HANDSHAKE_TIMEOUT = 10.0


class _Handler(BaseHTTPRequestHandler):
    server_version = "sdp-idp-gateway-link"
    gateway_id: str

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(_HANDSHAKE_TIMEOUT)

    def handle(self) -> None:
        # The handshake runs here, in this connection's own thread, so a slow
        # or hostile peer cannot stall the accept loop.
        try:
            self.connection.do_handshake()
            self.gateway_id = cert_utils.gateway_id_from_peer(
                self.connection.getpeercert(binary_form=True))
        except (ssl.SSLError, OSError, ValueError) as exc:
            status(log, "Gateway link: connection refused", peer=self.client_address[0],
                   reason=str(exc))
            return
        super().handle()

    def log_message(self, format: str, *args) -> None:  # noqa: A002 - stdlib name
        pass  # every request is logged by status() below instead

    def _reply(self, code: int, body: dict) -> None:
        data = json.dumps(body).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        if self.path != "/.well-known/jwks.json":
            self._reply(404, {"detail": "not found"})
            return
        status(log, "Gateway link: JWKS fetched", gateway_id=self.gateway_id)
        self._reply(200, jwt_service.jwks())

    def do_POST(self) -> None:
        if self.path != "/gateway/register":
            self._reply(404, {"detail": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= _MAX_BODY:
                raise ValueError("body missing or too large")
            body = json.loads(self.rfile.read(length))
            kem_key = base64.b64decode(body["kem_public_key"], validate=True)
            spa_port = body["spa_port"]
            if len(kem_key) != KEM_PUBLIC_KEY_LEN:
                raise ValueError(f"kem_public_key must be {KEM_PUBLIC_KEY_LEN} bytes")
            if not isinstance(spa_port, int) or isinstance(spa_port, bool) \
                    or not 1 <= spa_port <= 65535:
                raise ValueError("spa_port must be 1-65535")
        except (ValueError, KeyError, TypeError, binascii.Error) as exc:
            status(log, "Gateway link: registration rejected", gateway_id=self.gateway_id,
                   reason=str(exc))
            self._reply(400, {"detail": f"bad registration: {exc}"})
            return

        try:
            gateway_store.register(self.gateway_id, kem_key, spa_port)
        except gateway_store.GatewayRevoked:
            events.record("gateway_register", "denied", source_ip=self.client_address[0],
                          detail=f"gateway_id={self.gateway_id} revoked")
            self._reply(403, {"detail": "gateway revoked"})
            return
        events.record("gateway_register", "ok", source_ip=self.client_address[0],
                      detail=f"gateway_id={self.gateway_id} "
                             f"fingerprint={cert_utils.fingerprint(kem_key)}")
        self._reply(200, {"gateway_id": self.gateway_id,
                          "fingerprint": cert_utils.fingerprint(kem_key)})


class _Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], ctx: ssl.SSLContext) -> None:
        self._ctx = ctx
        super().__init__(address, _Handler)

    def get_request(self) -> tuple[socket.socket, tuple]:
        sock, addr = self.socket.accept()
        return self._ctx.wrap_socket(sock, server_side=True, do_handshake_on_connect=False), addr


def serve(host: str, port: int, ctx: ssl.SSLContext) -> ThreadingHTTPServer:
    """Bind and serve in a daemon thread. Returns the server (port 0 picks a
    free one; see server.server_address)."""
    server = _Server((host, port), ctx)
    threading.Thread(target=server.serve_forever, name="gateway-link", daemon=True).start()
    return server


def start() -> ThreadingHTTPServer | None:
    """Start the listener from the IDP's settings. If the admin has not yet
    created the CA and the IDP certificate, the client-facing IDP still runs
    but no Gateway can register - said loudly, not silently."""
    ca_cert = Path(settings.idp_ca_dir) / root_ca.CA_CERT_NAME
    needed = [ca_cert, Path(settings.idp_tls_cert_path), Path(settings.idp_tls_key_path)]
    missing = [str(p) for p in needed if not p.exists()]
    if missing:
        status(log, "WARNING: Gateway link NOT started - no Gateway can register its key. "
                    "Run: admin_cli.py init-ca, then admin_cli.py issue-idp-cert",
               missing=missing)
        return None
    ctx = cert_utils.server_context(settings.idp_tls_cert_path, settings.idp_tls_key_path,
                                    str(ca_cert))
    server = serve(settings.idp_gateway_link_host, settings.idp_gateway_link_port, ctx)
    status(log, "Gateway link listening (mTLS, Gateway certificates only)",
           host=settings.idp_gateway_link_host, port=settings.idp_gateway_link_port)
    return server
