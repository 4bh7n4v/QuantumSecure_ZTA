"""First-factor username/password verification (Argon2id).

This gates the FIDO2/CTAP2 ceremony behind a check of *who the human is*,
not just *what hardware key they hold*. A TPM only proves possession of a
hardware-bound key — it cannot tell two people apart on a shared device.
The first factor establishes the identity; the FIDO2 ceremony that follows
is then correctly scoped to that verified user.

The pepper MUST be overridden via the PASSWORD_PEPPER env var in any real
deployment.
"""

from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from shared.config.settings import settings

_hasher = PasswordHasher()


def _peppered(password: str) -> str:
    return password + settings.password_pepper


def hash_password(password: str) -> str:
    return _hasher.hash(_peppered(password))


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        return _hasher.verify(stored_hash, _peppered(password))
    except VerifyMismatchError:
        return False
