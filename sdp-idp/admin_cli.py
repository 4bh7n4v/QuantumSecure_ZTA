"""Offline administrator CLI for the IDP.

Runs on the IDP host as the system administrator. Talks straight to the
IDP's SQLite database (store/*), so it works whether or not the IDP process
is running. This is the only way user accounts come into existence — there
is no self-registration anywhere in the system.

    python admin_cli.py create-user --username alice
    python admin_cli.py create-user --username bob --access-window "mon-fri 09:00-18:00 Asia/Kolkata"
    python admin_cli.py list-users
    python admin_cli.py disable-user --username alice
    python admin_cli.py enable-user  --username alice
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from store.db import init_db
from store import users as user_store


def _create_user(args: argparse.Namespace) -> int:
    password = args.password or getpass.getpass(f"Password for {args.username!r}: ")
    if not args.password:
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("passwords did not match", file=sys.stderr)
            return 1
    try:
        user = user_store.create_user(args.username, password, args.access_window)
    except user_store.UsernameExists as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"created user {user.username!r} (user_id={user.user_id})")
    return 0


def _list_users(_args: argparse.Namespace) -> int:
    rows = user_store.list_users()
    if not rows:
        print("(no users provisioned)")
        return 0
    for u in rows:
        state = "enabled" if u.enabled else "DISABLED"
        window = f"  window={u.access_window!r}" if u.access_window else ""
        print(f"{u.username:<24} {state:<9} {u.user_id}{window}")
    return 0


def _set_enabled(args: argparse.Namespace, enabled: bool) -> int:
    try:
        user_store.set_enabled(args.username, enabled)
    except user_store.UnknownUser:
        print(f"error: no such user {args.username!r}", file=sys.stderr)
        return 1
    print(f"{args.username!r} {'enabled' if enabled else 'disabled'}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="SDP IDP administrator CLI")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("create-user")
    p.add_argument("--username", required=True)
    p.add_argument("--password", help="prompted for if omitted")
    p.add_argument("--access-window", default=None,
                   help='e.g. "mon-fri 09:00-18:00 Asia/Kolkata" (enforced from Milestone 4)')
    p.set_defaults(func=_create_user)

    p = sub.add_parser("list-users")
    p.set_defaults(func=_list_users)

    p = sub.add_parser("disable-user")
    p.add_argument("--username", required=True)
    p.set_defaults(func=lambda a: _set_enabled(a, False))

    p = sub.add_parser("enable-user")
    p.add_argument("--username", required=True)
    p.set_defaults(func=lambda a: _set_enabled(a, True))

    args = parser.parse_args()
    init_db()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
