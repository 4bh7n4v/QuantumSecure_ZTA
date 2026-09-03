"""Standalone SDP Identity Provider entrypoint.

The IDP is a SEPARATE component from the SDP Controller. In this
architecture the client on an open network can reach only the IDP and the
SDP Gateway — never the Controller. The IDP owns: admin-provisioned user
accounts, the FIDO2/WebAuthn ceremony (challenge generation + attestation
and assertion verification), device hardware-trust checks, a baseline
Policy Engine (impossible-travel / time-window), and issuance of the JWT
access token, refresh token and Gateway public key.

The IDP never calls the Controller or the Gateway. Consultation only ever
runs the other way: the Gateway later calls the IDP's /.well-known/jwks.json
to verify access tokens carried in SPA packets.
"""

import os
import sys

# Make the shared/ package (project root, one level up) importable, and this
# component's own directory the import root. Component directories use
# hyphenated names (sdp-idp) which are not valid Python package names, hence
# this explicit sys.path bootstrap rather than a normal package import.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import uvicorn
from contextlib import asynccontextmanager
from fastapi import FastAPI

from api.middleware import StatusLoggingMiddleware
from api.routes import router
from store.db import init_db
from tokens import jwt_service
from shared.config.settings import settings
from shared.utils.logger import get_logger, status

log = get_logger("IDP")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    status(log, "=" * 60)
    status(log, "SDP IDENTITY PROVIDER STARTING")
    status(log, f"RP ID:   {settings.rp_id}")
    status(log, f"Issuer:  {settings.idp_issuer}")
    status(log, f"Listen:  {settings.idp_host}:{settings.idp_port}")
    status(log, f"Access token TTL:  {settings.idp_access_ttl_seconds}s")
    status(log, f"Refresh token TTL: {settings.idp_refresh_ttl_seconds}s")
    status(log, "=" * 60)
    init_db()
    jwt_service.init()
    if settings.idp_admin_api_key in ("change-me-admin-key", "dev-admin-key-change-me"):
        status(log, "WARNING: IDP_ADMIN_API_KEY is a default value - set it in .env before real use")
    yield


app = FastAPI(title="ZTNA-SDP Identity Provider", version="0.1.0", lifespan=lifespan)
app.add_middleware(StatusLoggingMiddleware)
app.include_router(router)


if __name__ == "__main__":
    uvicorn.run(app, host=settings.idp_host, port=settings.idp_port, log_level="warning")
