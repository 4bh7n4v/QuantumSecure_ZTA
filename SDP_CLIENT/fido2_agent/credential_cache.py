"""Remembers which credential this device enrolled, and which trust anchor
produced it.

A credential id is meaningless on its own: the private key behind it lives
inside whichever authenticator created it, and no other authenticator can
sign for it. So the backend that enrolled a credential is part of that
credential's identity, and caching the id alone is a bug waiting to happen.

It happened. On Windows the client originally enrolled through CNG, which
keeps the key in the TPM under a name of our choosing. When the Windows
backend moved to Windows Hello, the cached id was still on disk and the IDP
still had the device marked as enrolled, so the client went straight to
authenticating — and asked Windows Hello to sign for a credential that had
never existed in Hello's store. Windows answered, accurately but unhelpfully,
"There was a problem signing in with your passkey."

Recording the backend turns that dead end into a re-enrolment: a cached
credential is only offered back to the same backend that created it, and any
other backend is told there is nothing cached, which sends the client down
the registration path it should have taken.

The file is not security-sensitive — a credential id is a public handle, and
every private key stays in hardware — so it is plain JSON, chosen over the
previous raw bytes because it can carry the backend and can grow a field
later without another silent migration.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from shared.utils.logger import get_logger, status

log = get_logger("CredCache")

CREDENTIAL_DIR = Path("./certs/credentials")


def _path(username: str) -> Path:
    """One file per user: a shared machine enrols each account separately, the
    same way the TPM backends namespace their keys per username.
    """
    return CREDENTIAL_DIR / f"{hashlib.sha256(username.encode()).hexdigest()[:16]}.json"


def load(username: str, backend: str) -> bytes | None:
    """The credential this user enrolled through `backend`, or None.

    None means "register", and returning it is the point: a credential from a
    different backend cannot be used, so reporting it as missing is both true
    and the behaviour that recovers.
    """
    path = _path(username)
    if not path.exists():
        _warn_if_legacy(username)
        return None

    try:
        cached = json.loads(path.read_text())
        credential_id = bytes.fromhex(cached["credential_id"])
        cached_backend = cached["backend"]
    except (ValueError, KeyError, OSError) as exc:
        status(log, "Cached credential is unreadable - re-enrolling this device",
               path=str(path), error=str(exc))
        return None

    if cached_backend != backend:
        status(log, "Cached credential belongs to a different trust anchor - re-enrolling",
               cached_backend=cached_backend, current_backend=backend,
               credential_id=credential_id.hex()[:16])
        return None

    status(log, "Using cached device credential",
           credential_id=credential_id.hex()[:16], backend=backend)
    return credential_id


def save(username: str, backend: str, credential_id: bytes) -> Path:
    path = _path(username)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "credential_id": credential_id.hex(),
        "backend": backend,
    }, indent=2))
    status(log, "Device credential enrolled and cached", path=str(path), backend=backend)
    return path


def _warn_if_legacy(username: str) -> None:
    """Point at a pre-existing `.bin` cache rather than ignoring it silently.

    Those files hold a bare credential id with no record of what made it, so
    they cannot be migrated — there is no way to tell which backend to
    attribute them to. Re-enrolling is the only safe answer; saying so beats
    leaving an orphaned file for someone to puzzle over later.
    """
    legacy = CREDENTIAL_DIR / f"{hashlib.sha256(username.encode()).hexdigest()[:16]}.bin"
    if legacy.exists():
        status(log, "Found a credential cached by an older client version; it does not record "
                    "which authenticator created it, so this device will re-enrol",
               path=str(legacy))
