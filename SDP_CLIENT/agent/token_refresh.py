"""Access-token refresh loop.

The IDP issues a 15-minute access token plus a longer-lived refresh token.
This loop wakes shortly before each access token expires and swaps the
refresh token for a new access token via the IDP's /token/refresh — no
FIDO2 replay. It stops (and reports) the moment the IDP refuses a refresh:
that means the refresh token was revoked, expired, or the baseline Policy
Engine flagged the request (e.g. impossible travel), and the session is
over until the user logs in again.
"""

from __future__ import annotations

import threading
import time

import requests

from fido2_agent import client as fido2_client
from shared.utils.logger import get_logger, status

log = get_logger("TokenRefresh")

# Refresh this many seconds before the access token actually expires, so a
# slow round-trip never leaves the client tokenless.
_SKEW_SECONDS = 60


class TokenRefresher:
    def __init__(self, refresh_token: str, access_expires_in: int) -> None:
        self._refresh_token = refresh_token
        self._access_ttl = max(access_expires_in, 120)
        self._access_token: str | None = None
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def access_token(self) -> str | None:
        with self._lock:
            return self._access_token

    def set_initial_access_token(self, token: str) -> None:
        with self._lock:
            self._access_token = token

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="token-refresh", daemon=True)
        self._thread.start()
        status(log, "Refresh loop started", interval_s=self._access_ttl - _SKEW_SECONDS)

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        while not self._stop.is_set():
            wait_s = max(self._access_ttl - _SKEW_SECONDS, 30)
            if self._stop.wait(wait_s):
                return
            try:
                data = fido2_client.refresh(self._refresh_token)
            except requests.HTTPError as exc:
                detail = exc.response.text[:300] if exc.response is not None else str(exc)
                status(log, "[FATAL] Refresh rejected by IDP - session ends", detail=detail)
                self._stop.set()
                return
            except requests.RequestException as exc:
                status(log, "Refresh network error - will retry next cycle", error=str(exc))
                continue

            with self._lock:
                self._access_token = data["access_token"]
            self._access_ttl = max(int(data.get("expires_in", self._access_ttl)), 120)
            status(log, "Access token refreshed", next_refresh_in_s=self._access_ttl - _SKEW_SECONDS,
                   at=time.strftime("%H:%M:%S"))
