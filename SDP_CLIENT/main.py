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
       and the Gateway's ML-KEM public key. A background loop refreshes the
       access token before it expires.
    5. SPA knock (spa/): ML-KEM-encapsulate against the Gateway's public
       key, send the encrypted access token, and wait for SPA_OK. A failed
       first knock ends the run. Each refreshed access token is knocked
       again so the Gateway always sees the current one.

Every stage is its own module; this file only sequences them in one process.
"""

import getpass
import os
import sys

# Make the shared/ package (project root, one level up) importable. Each
# component runs with its own directory as the import root (`from spa import
# ...`, not SDP_CLIENT.spa), so `shared` is reached through this bootstrap.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import time
import uuid

import requests

from agent.token_refresh import TokenRefresher
from fido2_agent import client as fido2_client
from fido2_agent import credential_cache
from posture import checker
from spa import token_flow
from tpm.anchored_trust import TrustAnchorUnavailable, select_trust_anchor
from wireguard import keys as wg_keys
from shared.config.settings import settings
from shared.utils.logger import get_logger, status

log = get_logger("Client")


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


def _knock(gateway_pubkey: bytes, knock_ticket: bytes) -> bool:
    return token_flow.request_access(
        gateway_pubkey, knock_ticket,
        settings.client_access_port, settings.client_access_protocol,
    )


def main() -> int:
    status(log, "=" * 60)
    status(log, "SDP CLIENT AGENT STARTING")
    status(log, f"IDP: {settings.idp_base_url}")
    status(log, "=" * 60)

    status(log, "[1/5] First-factor login against IDP...")
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
    status(log, f"[1/5] First factor accepted", username=username, device_id=device_id,
           device_enrolled=device_enrolled)

    status(log, "[2/5] Selecting hardware trust anchor...")
    try:
        anchor = select_trust_anchor(username)
    except TrustAnchorUnavailable as exc:
        status(log, "[FATAL] No hardware trust anchor available - refusing to connect", error=str(exc))
        return 1
    status(log, f"[2/5] Trust anchor selected: {anchor.kind}",
           backend=anchor.backend, simulated=anchor.simulated)

    # Posture telemetry is collected locally for visibility only; it is NOT
    # sent to the IDP in this phase (telemetry design is deferred).
    try:
        posture = checker.collect(device_id, anchor.kind, trust_anchor_present=True)
        status(log, "[2/5] Local posture snapshot (not transmitted)",
               os=posture.os_name, anchor=posture.trust_anchor_type)
    except Exception as exc:  # posture must never block auth in this phase
        status(log, "[2/5] Local posture snapshot failed (ignored)", error=str(exc))

    origin = f"https://{settings.rp_id}"
    # The cached credential is only usable by the trust anchor that enrolled
    # it — the private key never leaves that authenticator — so the lookup is
    # scoped to the backend in use. A credential from a different one reads as
    # absent, which re-registers instead of failing inside the authenticator.
    cached_credential = credential_cache.load(username, anchor.backend)
    should_register = cached_credential is None or not device_enrolled

    status(log, "[3/5] Running FIDO2 ceremony against IDP...",
           mode="register" if should_register else "authenticate")
    try:
        if should_register:
            credential_id = fido2_client.register(login_token, anchor, settings.rp_id, origin)
            credential_cache.save(username, anchor.backend, credential_id)
        else:
            credential_id = cached_credential

        _wg_private, wg_public = wg_keys.load_or_generate()
        token_bundle = fido2_client.authenticate(
            login_token, credential_id, anchor, settings.rp_id, origin, wg_public)
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

    status(log, "[4/5] IDP session established", hardware_attested=token_bundle.get("hardware_attested"),
           access_ttl_s=token_bundle.get("expires_in"))

    status(log, "[5/5] SPA knock to Gateway...", gateway=f"{settings.gateway_ip}:{settings.gateway_spa_port_client}",
           port=settings.client_access_port, protocol=settings.client_access_protocol)
    try:
        gateway_pubkey = token_flow.gateway_key_from_bundle(token_bundle)
        first_ticket = token_flow.ticket_from_bundle(token_bundle)
    except (token_flow.GatewayKeyMissing, token_flow.KnockTicketMissing) as exc:
        status(log, "[FATAL] Cannot knock", error=str(exc))
        return 1
    # The knock carries only the single-use ticket. The access token stays
    # here, refreshed below, for the session's keepalives.
    if not _knock(gateway_pubkey, first_ticket):
        status(log, "[FATAL] Gateway did not accept the SPA knock - refusing to continue")
        return 1
    status(log, "[5/5] Gateway accepted the SPA knock")
    knocked_token = access_token

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
            if tok and tok != knocked_token:
                # Each re-knock needs a fresh ticket: the Gateway accepts one
                # only once. Not fatal: the IDP session is still good, and the
                # next heartbeat tries again.
                try:
                    ticket = fido2_client.knock_ticket(refresh_token)
                except requests.RequestException as exc:
                    status(log, "Knock ticket unavailable - retrying next heartbeat", error=str(exc))
                    ticket = None
                if ticket and _knock(gateway_pubkey, ticket):
                    knocked_token = tok
                    status(log, "Re-knocked Gateway with a fresh knock ticket")
                elif ticket:
                    status(log, "Re-knock not accepted - retrying next heartbeat")
            if refresher._stop.is_set():
                status(log, "[FATAL] Refresh loop stopped - session lost")
                return 1
    except KeyboardInterrupt:
        refresher.stop()
        status(log, "Client agent stopped by user")
        return 0


if __name__ == "__main__":
    sys.exit(main())
