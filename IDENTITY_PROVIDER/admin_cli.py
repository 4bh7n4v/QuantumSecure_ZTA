"""Offline administrator CLI for the IDP.

Runs on the IDP host as the system administrator. Talks straight to the
IDP's SQLite database (store/*), so it works whether or not the IDP process
is running. This is the only way user accounts come into existence — there
is no self-registration anywhere in the system.

    python admin_cli.py create-user --username alice --roles engineer
    python admin_cli.py set-roles   --username alice --roles engineer,ops
    python admin_cli.py create-user --username bob --access-window "mon-fri 09:00-18:00 Asia/Kolkata"
    python admin_cli.py list-users
    python admin_cli.py disable-user --username alice
    python admin_cli.py enable-user  --username alice

Devices that cannot prove hardware key custody are admitted one at a time,
never by switching enforcement off for the whole deployment:

    python admin_cli.py grant-attestation-exception --username alice \
        --device-id 45c68349-8936-5716-ae20-d864d2470a2f --days 30 \
        --reason "Dell G15: Windows Hello returns no attestation to any caller"
    python admin_cli.py list-attestation-exceptions
    python admin_cli.py revoke-attestation-exception --username alice --device-id ...

The IDP <-> Gateway link runs over mutual TLS with the project's own CA.
Once per deployment, then once per Gateway:

    python admin_cli.py init-ca
    python admin_cli.py issue-idp-cert --host localhost --host sdp-idp --host 192.168.1.10
    python admin_cli.py issue-gateway-cert --id gw-1
        -> copy the printed folder to the Gateway machine as SDP_GATEWAY/certs/pki/
    python admin_cli.py list-gateways
    python admin_cli.py revoke-gateway --id gw-1
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import shutil
from pathlib import Path

from store.db import init_db
from store import attestation_exceptions as exception_store
from store import gateways as gateway_store
from store import users as user_store
from shared.ca import cert_utils, root_ca
from shared.config.settings import settings

# Where issue-gateway-cert writes each Gateway's bundle, for the admin to copy.
GATEWAY_BUNDLE_DIR = Path("./certs/pki/gateways")


def _init_ca(_args: argparse.Namespace) -> int:
    try:
        root_ca.create(settings.idp_ca_dir)
    except root_ca.CAExists as exc:
        print(f"error: {exc} - refusing to replace it (every issued certificate "
              "would stop working)", file=sys.stderr)
        return 1
    print(f"created the project CA in {settings.idp_ca_dir}")
    print(f"  {root_ca.CA_KEY_NAME} signs every certificate: keep it on this machine only.")
    return 0


def _load_ca():
    try:
        return root_ca.load(settings.idp_ca_dir)
    except FileNotFoundError:
        print(f"error: no CA in {settings.idp_ca_dir} - run init-ca first", file=sys.stderr)
        return None


def _issue_idp_cert(args: argparse.Namespace) -> int:
    ca = _load_ca()
    if ca is None:
        return 1
    cert_path = Path(settings.idp_tls_cert_path)
    cert_utils.issue(*ca, common_name="sdp-idp", kind="server", out_dir=cert_path.parent,
                     hosts=args.host, file_stem=cert_path.stem)
    print(f"issued the IDP's certificate for {', '.join(args.host)} -> {cert_path}")
    print("A Gateway must dial the IDP by one of those names (GATEWAY_IDP_LINK_URL).")
    return 0


def _issue_gateway_cert(args: argparse.Namespace) -> int:
    ca = _load_ca()
    if ca is None:
        return 1
    bundle = GATEWAY_BUNDLE_DIR / args.id
    cert_utils.issue(*ca, common_name=args.id, kind="client", out_dir=bundle,
                     file_stem="gateway")
    shutil.copyfile(Path(settings.idp_ca_dir) / root_ca.CA_CERT_NAME,
                    bundle / root_ca.CA_CERT_NAME)
    print(f"issued Gateway certificate {args.id!r} -> {bundle}/")
    print("  gateway.crt, gateway.key, ca.crt")
    print("Copy that folder to the Gateway machine as SDP_GATEWAY/certs/pki/ .")
    print("gateway.key is that Gateway's identity: move it, do not leave copies around.")
    return 0


def _list_gateways(_args: argparse.Namespace) -> int:
    rows = gateway_store.all_gateways()
    if not rows:
        print("(no Gateway has registered)")
        return 0
    for g in rows:
        state = "REVOKED" if g.revoked else "active"
        fp = cert_utils.fingerprint(g.kem_public_key) if g.kem_public_key else "-"
        print(f"{g.gateway_id:<16} {state:<8} spa_port={g.spa_port:<6} "
              f"registered={time.ctime(g.registered_at)}  key={fp}")
    return 0


def _revoke_gateway(args: argparse.Namespace) -> int:
    gateway_store.revoke(args.id)
    print(f"revoked Gateway {args.id!r}: its key is no longer handed to clients and it "
          "cannot re-register. Its certificate stays valid until expiry.")
    return 0


def _create_user(args: argparse.Namespace) -> int:
    password = args.password or getpass.getpass(f"Password for {args.username!r}: ")
    if not args.password:
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("passwords did not match", file=sys.stderr)
            return 1
    try:
        user = user_store.create_user(args.username, password, args.access_window,
                                      _split_roles(args.roles))
    except user_store.UsernameExists as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"created user {user.username!r} (user_id={user.user_id})")
    return 0


def _split_roles(raw: str) -> list[str]:
    return [r.strip() for r in raw.split(",") if r.strip()]


def _set_roles(args: argparse.Namespace) -> int:
    try:
        roles = user_store.set_roles(args.username, _split_roles(args.roles))
    except user_store.UnknownUser:
        print(f"error: no such user {args.username!r}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"{args.username!r} roles: {', '.join(roles) or '(none)'}")
    print("Takes effect in the next access token issued, at the latest the next refresh.")
    return 0


def _list_users(_args: argparse.Namespace) -> int:
    rows = user_store.list_users()
    if not rows:
        print("(no users provisioned)")
        return 0
    for u in rows:
        state = "enabled" if u.enabled else "DISABLED"
        window = f"  window={u.access_window!r}" if u.access_window else ""
        roles = f"  roles={','.join(u.roles)}" if u.roles else ""
        print(f"{u.username:<24} {state:<9} {u.user_id}{roles}{window}")
    return 0


def _set_enabled(args: argparse.Namespace, enabled: bool) -> int:
    try:
        user_store.set_enabled(args.username, enabled)
    except user_store.UnknownUser:
        print(f"error: no such user {args.username!r}", file=sys.stderr)
        return 1
    print(f"{args.username!r} {'enabled' if enabled else 'disabled'}")
    return 0


def _resolve_user(username: str):
    user = user_store.get_by_username(username)
    if user is None:
        print(f"error: no such user {username!r}", file=sys.stderr)
        return None
    return user


def _grant_exception(args: argparse.Namespace) -> int:
    user = _resolve_user(args.username)
    if user is None:
        return 1
    try:
        record = exception_store.grant(
            user_id=user.user_id, device_id=args.device_id, reason=args.reason,
            granted_by=getpass.getuser(), days=args.days)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"granted {args.username!r} device {args.device_id} an attestation exception")
    print(f"  expires in {args.days} day(s): {time.ctime(record.expires_at)}")
    print(f"  reason: {record.reason}")
    print("\nThis device may now enrol WITHOUT proving hardware key custody.")
    print("Its credential is still recorded as not hardware-attested.")
    return 0


def _revoke_exception(args: argparse.Namespace) -> int:
    user = _resolve_user(args.username)
    if user is None:
        return 1
    if not exception_store.revoke(user.user_id, args.device_id):
        print(f"no exception existed for device {args.device_id}", file=sys.stderr)
        return 1
    print(f"revoked the attestation exception for device {args.device_id}")
    return 0


def _list_exceptions(_args: argparse.Namespace) -> int:
    rows = exception_store.all_exceptions()
    if not rows:
        print("(no attestation exceptions granted)")
        return 0
    names = {u.user_id: u.username for u in user_store.list_users()}
    for record in rows:
        state = "EXPIRED" if record.expired else f"{record.days_remaining:.1f}d left"
        print(f"{names.get(record.user_id, record.user_id):<24} {record.device_id:<40} "
              f"{state:<12} by={record.granted_by}  {record.reason!r}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="SDP IDP administrator CLI")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("create-user")
    p.add_argument("--username", required=True)
    p.add_argument("--password", help="prompted for if omitted")
    p.add_argument("--access-window", default=None,
                   help='e.g. "mon-fri 09:00-18:00 Asia/Kolkata" (enforced from Milestone 4)')
    p.add_argument("--roles", default="", help="comma-separated, e.g. engineer,ops")
    p.set_defaults(func=_create_user)

    p = sub.add_parser("set-roles", help="replace a user's roles (comma-separated; empty clears)")
    p.add_argument("--username", required=True)
    p.add_argument("--roles", required=True)
    p.set_defaults(func=_set_roles)

    p = sub.add_parser("list-users")
    p.set_defaults(func=_list_users)

    p = sub.add_parser("disable-user")
    p.add_argument("--username", required=True)
    p.set_defaults(func=lambda a: _set_enabled(a, False))

    p = sub.add_parser("enable-user")
    p.add_argument("--username", required=True)
    p.set_defaults(func=lambda a: _set_enabled(a, True))

    p = sub.add_parser(
        "grant-attestation-exception",
        help="let ONE device enrol without proving hardware key custody, for a limited time")
    p.add_argument("--username", required=True)
    p.add_argument("--device-id", required=True,
                   help="the CLIENT_DEVICE_ID the client reports; see its startup log")
    p.add_argument("--reason", required=True,
                   help="why this device cannot attest - recorded and shown in the audit log")
    p.add_argument("--days", type=int, default=30,
                   help="how long the exception lasts before lapsing (default: 30)")
    p.set_defaults(func=_grant_exception)

    p = sub.add_parser("revoke-attestation-exception")
    p.add_argument("--username", required=True)
    p.add_argument("--device-id", required=True)
    p.set_defaults(func=_revoke_exception)

    p = sub.add_parser("list-attestation-exceptions")
    p.set_defaults(func=_list_exceptions)

    p = sub.add_parser("init-ca", help="create the project CA for the IDP <-> Gateway mTLS link")
    p.set_defaults(func=_init_ca)

    p = sub.add_parser("issue-idp-cert", help="the IDP's server certificate for the Gateway link")
    p.add_argument("--host", action="append", required=True,
                   help="a name or IP Gateways dial the IDP by; repeat for several")
    p.set_defaults(func=_issue_idp_cert)

    p = sub.add_parser("issue-gateway-cert", help="a Gateway's certificate bundle")
    p.add_argument("--id", required=True, help="the Gateway's id, e.g. gw-1")
    p.set_defaults(func=_issue_gateway_cert)

    p = sub.add_parser("list-gateways")
    p.set_defaults(func=_list_gateways)

    p = sub.add_parser("revoke-gateway")
    p.add_argument("--id", required=True)
    p.set_defaults(func=_revoke_gateway)

    args = parser.parse_args()
    init_db()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
