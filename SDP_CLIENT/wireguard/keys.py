"""The device's WireGuard key pair.

WireGuard keys are plain Curve25519 (X25519) keys, 32 bytes each. The public
half goes to the IDP at the end of FIDO2, which binds it to the session and
puts it in every knock ticket; the Gateway will later accept a tunnel only
from this key.

This is a transport key, not the device's identity: identity stays with the
hardware trust anchor, which is what the IDP verified before accepting this
key. WireGuard itself cannot use a TPM-held key, so the private half lives
on disk, readable by the owner only.
"""

from __future__ import annotations

import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from shared.utils.logger import get_logger, status

log = get_logger("WireGuard")

KEY_PATH = Path("./certs/wireguard/wg_private.key")


def load_or_generate(path: Path = KEY_PATH) -> tuple[X25519PrivateKey, bytes]:
    """Returns (private key, 32-byte raw public key)."""
    if path.exists():
        private_key = X25519PrivateKey.from_private_bytes(path.read_bytes())
        source = "loaded"
    else:
        private_key = X25519PrivateKey.generate()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(private_key.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
            serialization.NoEncryption()))
        os.chmod(path, 0o600)
        source = "generated"
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    status(log, f"WireGuard key pair {source}", public_key_head=public_key.hex()[:16])
    return private_key, public_key
