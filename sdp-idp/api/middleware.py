"""Logs every inbound request/response of the IDP as a live status line."""

from __future__ import annotations

import time

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from shared.utils.logger import get_logger, status

log = get_logger("IDP-API")


def client_ip(request: Request) -> str | None:
    """Best source-IP guess: first hop of X-Forwarded-For if the IDP is
    behind a reverse proxy, else the direct peer.
    """
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else None


# Paths whose requests are not logged — pure liveness noise (the container
# HEALTHCHECK hits /healthz every 30s), never part of a ceremony.
_QUIET_PATHS = {"/healthz"}


class StatusLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        quiet = request.url.path in _QUIET_PATHS
        start = time.time()
        if not quiet:
            status(log, f"--> {request.method} {request.url.path}", src=client_ip(request))
        response = await call_next(request)
        if not quiet:
            elapsed_ms = round((time.time() - start) * 1000, 1)
            status(log, f"<-- {request.method} {request.url.path}",
                   status_code=response.status_code, ms=elapsed_ms)
        return response
