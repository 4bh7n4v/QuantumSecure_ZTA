"""SDP Client Agent entrypoint.

Flow (Model A — the agent drives everything; the IDP's web UI is
admin-only):

    1. First factor: username + password to the IDP. Accounts are
       provisioned by an administrator at the IDP — there is NO signup here.
       The IDP returns a short-lived login_token and says whether this
       device is already enrolled.
    2. Select a hardware trust anchor: internal TPM -> external USB key ->
       abort. No software-only identity fallback.
    3. FIDO2/WebAuthn ceremony against the IDP, carrying the login_token:
       register on first login for this device, otherwise authenticate.
    4. On success the IDP issues an access token (15 min), a refresh token,
       and (later) the Gateway public key. A background loop refreshes the
       access token before it expires.

ML-KEM / SPA / Gateway integration is a later phase; this milestone ends
once the agent holds a live, auto-refreshing IDP session.
"""

import getpass
import hashlib
import os
import sys

# Make the shared/ package (project root, one level up) importable.
# Component directories use hyphenated names (sdp-client) which are not
# valid Python package names, so each component is run with its own
# directory as the import root and reaches into `shared` through this
# explicit sys.path bootstrap.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import time
import uuid
from pathlib import Path

import requests

from agent.token_refresh import TokenRefresher
from fido2_agent import client as fido2_client
from posture import checker
from tpm.anchored_trust import TrustAnchorUnavailable, select_trust_anchor
from shared.config.settings import settings
from shared.utils.logger import get_logger, status

log = get_logger("Client")

CREDENTIAL_DIR = Path("./certs/credentials")


def _credential_from_noninteractive() -> tuple[str | None, str | None]:
    """Credentials supplied without a prompt, so the agent can run where no
    real console stdin is available (Windows paste-in, VS Code terminal,
    CI). Order: CLI flags override environment variables.

        python main.py --username alice --password s3cret
        CLIENT_USERNAME=alice CLIENT_PASSWORD=s3cret python main.py
    """
    username = os.environ.get("CLIENT_USERNAME") or None
    password = os.environ.get("CLIENT_PASSWORD") or None
    argv = sys.argv[1:]
    for flag, setter in (("--username", "u"), ("--password", "p")):
        if flag in argv:
            value = argv[argv.index(flag) + 1] if argv.index(flag) + 1 < len(argv) else None
            if setter == "u":
                username = value or username
            else:
                password = value or password
    return username, password


def _first_factor_login() -> tuple[str, str]:
    """Get username + password. Non-interactive sources (CLI flags /
    environment) win; otherwise prompt on the terminal. No account creation
    — if the account does not exist at the IDP, login simply fails and an
    administrator must provision it.
    """
    username, password = _credential_from_noninteractive()
    if username and password:
        status(log, "Using non-interactive credentials", username=username, source="cli/env")
        return username, password

    print("\n=== ZTNA-SDP Client: Sign in ===")
    try:
        if not username:
            username = input("Username: ").strip()
        if not password:
            password = getpass.getpass("Password: ")
    except EOFError:
        status(log, "[FATAL] No console available for the sign-in prompt. "
                    "Pass --username/--password or set CLIENT_USERNAME/CLIENT_PASSWORD.")
        raise SystemExit(2)
    return username, password


def _device_id(username: str) -> str:
    if settings.client_device_id:
        return settings.client_device_id
    # Stable per (machine, user) without persisting anything extra.
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{username}@{uuid.getnode():x}"))


def main() -> int:
    status(log, "=" * 60)
    status(log, "SDP CLIENT AGENT STARTING")
    status(log, f"IDP: {settings.idp_base_url}")
    status(log, "=" * 60)

    status(log, "[1/4] First-factor login against IDP...")
    username, password = _first_factor_login()
    device_id = _device_id(username)

    try:
        login_data = fido2_client.login(username, password, device_id)
    except requests.HTTPError as exc:
        detail = exc.response.text[:300] if exc.response is not None else str(exc)
        status(log, "[FATAL] IDP rejected first-factor login", detail=detail)
        return 1
    except requests.RequestException as exc:
        status(log, "[FATAL] Could not reach IDP", error=str(exc))
        return 1

    login_token = login_data["login_token"]
    device_enrolled = bool(login_data.get("device_enrolled"))
    status(log, f"[1/4] First factor accepted", username=username, device_id=device_id,
           device_enrolled=device_enrolled)

    status(log, "[2/4] Selecting hardware trust anchor...")
    try:
        anchor = select_trust_anchor(username)
    except TrustAnchorUnavailable as exc:
        status(log, "[FATAL] No hardware trust anchor available - refusing to connect", error=str(exc))
        return 1
    status(log, f"[2/4] Trust anchor selected: {anchor.kind}",
           backend=anchor.backend, simulated=anchor.simulated)

    # Posture telemetry is collected locally for visibility only; it is NOT
    # sent to the IDP in this phase (telemetry design is deferred).
    try:
        posture = checker.collect(device_id, anchor.kind, trust_anchor_present=True)
        status(log, "[2/4] Local posture snapshot (not transmitted)",
               os=posture.os_name, anchor=posture.trust_anchor_type)
    except Exception as exc:  # posture must never block auth in this phase
        status(log, "[2/4] Local posture snapshot failed (ignored)", error=str(exc))

    origin = f"https://{settings.rp_id}"
    credential_file = CREDENTIAL_DIR / f"{hashlib.sha256(username.encode()).hexdigest()[:16]}.bin"
    should_register = not credential_file.exists() or not device_enrolled

    status(log, "[3/4] Running FIDO2 ceremony against IDP...",
           mode="register" if should_register else "authenticate")
    try:
        if should_register:
            credential_id = fido2_client.register(login_token, anchor, settings.rp_id, origin)
            credential_file.parent.mkdir(parents=True, exist_ok=True)
            credential_file.write_bytes(credential_id)
            status(log, "Device credential enrolled and cached", path=str(credential_file))
        else:
            credential_id = credential_file.read_bytes()
            status(log, "Using cached device credential", credential_id=credential_id.hex()[:16])

        token_bundle = fido2_client.authenticate(
            login_token, credential_id, anchor, settings.rp_id, origin)
    except requests.HTTPError as exc:
        detail = exc.response.text[:300] if exc.response is not None else str(exc)
        status(log, "[FATAL] FIDO2 ceremony rejected by IDP", detail=detail)
        return 1
    except requests.RequestException as exc:
        status(log, "[FATAL] IDP unreachable during FIDO2 ceremony", error=str(exc))
        return 1

    if token_bundle.get("status") != "granted":
        status(log, "[FATAL] IDP did not grant a token", status=token_bundle.get("status"))
        return 1

    access_token = token_bundle["access_token"]
    refresh_token = token_bundle["refresh_token"]
    gateway_pubkey = token_bundle.get("gateway_public_key")

    status(log, "[4/4] IDP session established", hardware_attested=token_bundle.get("hardware_attested"),
           access_ttl_s=token_bundle.get("expires_in"),
           gateway_public_key=("received" if gateway_pubkey else "not provided yet (Gateway phase)"))

    refresher = TokenRefresher(refresh_token, int(token_bundle.get("expires_in", 900)))
    refresher.set_initial_access_token(access_token)
    refresher.start()

    status(log, "SESSION LIVE - access token will auto-refresh. Ctrl-C to exit.")
    try:
        while True:
            time.sleep(60)
            tok = refresher.access_token
            status(log, "heartbeat: holding IDP session",
                   access_token_tail=(tok[-8:] if tok else None))
            if refresher._stop.is_set():
                status(log, "[FATAL] Refresh loop stopped - session lost")
                return 1
    except KeyboardInterrupt:
        refresher.stop()
        status(log, "Client agent stopped by user")
        return 0


if __name__ == "__main__":
    sys.exit(main())
