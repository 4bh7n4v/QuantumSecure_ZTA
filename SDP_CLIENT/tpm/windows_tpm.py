"""Internal (onboard) TPM 2.0 interface for Windows, via CNG.

Windows never exposes the TPM the way Linux does: there is no /dev/tpmrm0,
no Linux TSS stack, and `tpm2-tools` has no Windows build at all — which is
why tpm/tpm_handler.py cannot drive the chip on this platform. Windows
brokers the TPM through TBS (TPM Base Services) and surfaces it to
applications as a CNG key-storage provider, the "Microsoft Platform Crypto
Provider". A key created in that provider is generated inside the TPM,
marked non-exportable, and every signature is produced by the chip — the
same custody guarantee tpm_handler.py gets from tpm2-tools on Linux.

This module speaks to `ncrypt.dll` directly with ctypes rather than taking
a dependency on pywin32: the four calls needed here (open provider, create
or open a persisted key, export the public blob, sign a hash) are a small,
long-stable subset of the CNG API.

Key custody: the private key never leaves the TPM, so there is nothing to
persist to disk. The key is addressed by a stable name derived from the
username (see `key_name_for`), which is what lets a later run reload the
same credential key instead of minting a different one — the Windows
equivalent of the key.pub/key.priv blobs tpm_handler.py writes.

Mirrors tpm_handler.py's surface (`probe` / `load_signing_key` /
`create_signing_key` / `sign` / `load_public_key`) so tpm/anchored_trust.py
can treat the two backends interchangeably.
"""

from __future__ import annotations

import ctypes
import hashlib
import re
import struct
import sys
from dataclasses import dataclass

from shared.utils.crypto import ecdsa_raw_to_der
from shared.utils.logger import get_logger, status

log = get_logger("TPM-Windows")

# --------------------------------------------------------------------------- #
# CNG constants                                                              #
# --------------------------------------------------------------------------- #

# The TPM-backed key-storage provider. Opening it fails when the machine has
# no usable TPM, which is exactly what probe() relies on.
MS_PLATFORM_CRYPTO_PROVIDER = "Microsoft Platform Crypto Provider"
NCRYPT_ECDSA_P256_ALGORITHM = "ECDSA_P256"
BCRYPT_ECCPUBLIC_BLOB = "ECCPUBLICBLOB"

ERROR_SUCCESS = 0x00000000
NTE_BAD_KEYSET = 0x80090016  # named key does not exist yet
NTE_EXISTS = 0x8009000F      # named key already exists

# BCRYPT_ECCKEY_BLOB header is { ULONG dwMagic; ULONG cbKey; } then X || Y.
_ECCKEY_BLOB_HEADER = struct.Struct("<II")
BCRYPT_ECDSA_PUBLIC_P256_MAGIC = 0x31534345  # 'ECS1'

_NCRYPT_HANDLE = ctypes.c_size_t  # ULONG_PTR
# ctypes.wintypes cannot even be imported on a non-Windows host, and this
# module must stay importable there so anchored_trust.py can load on Linux.
# DWORD is a 32-bit unsigned long, so c_ulong is an exact stand-in.
_DWORD = ctypes.c_ulong


@dataclass
class WindowsTPMKey:
    """Handle to a TPM-resident key, addressed by its CNG key name."""
    key_name: str


class WindowsTPMError(RuntimeError):
    pass


def _ncrypt():
    if sys.platform != "win32":
        raise WindowsTPMError("the Windows TPM backend is only available on Windows")
    return ctypes.WinDLL("ncrypt.dll")


def _check(status_code: int, call: str) -> None:
    if status_code != ERROR_SUCCESS:
        raise WindowsTPMError(f"{call} failed with NTSTATUS 0x{status_code & 0xFFFFFFFF:08X}")


def key_name_for(username: str) -> str:
    """Stable, TPM-resident key name for a username.

    Namespaced per user for the same reason tpm_handler.py namespaces its
    workdir: one physical machine may be shared, and each verified username
    must get its own credential key. A short hash is appended because CNG
    key names are a flat namespace and usernames may contain characters
    that are awkward there.
    """
    safe = re.sub(r"[^A-Za-z0-9_-]", "_", username)[:32]
    digest = hashlib.sha256(username.encode("utf-8")).hexdigest()[:16]
    return f"ZTNA-SDP-{safe}-{digest}"


# --------------------------------------------------------------------------- #
# Provider / key lifecycle                                                   #
# --------------------------------------------------------------------------- #

def _open_provider(ncrypt) -> _NCRYPT_HANDLE:
    handle = _NCRYPT_HANDLE()
    rc = ncrypt.NCryptOpenStorageProvider(
        ctypes.byref(handle), ctypes.c_wchar_p(MS_PLATFORM_CRYPTO_PROVIDER), _DWORD(0))
    _check(rc, "NCryptOpenStorageProvider")
    return handle


def _open_key(ncrypt, provider: _NCRYPT_HANDLE, key_name: str) -> _NCRYPT_HANDLE | None:
    """Open an existing persisted key, or None if it has not been created."""
    handle = _NCRYPT_HANDLE()
    rc = ncrypt.NCryptOpenKey(
        provider, ctypes.byref(handle), ctypes.c_wchar_p(key_name),
        _DWORD(0), _DWORD(0))
    if rc & 0xFFFFFFFF == NTE_BAD_KEYSET:
        return None
    _check(rc, "NCryptOpenKey")
    return handle


def _free(ncrypt, handle: _NCRYPT_HANDLE | None) -> None:
    # ctypes instances are always truthy, so a null handle has to be caught
    # on `.value` — freeing one would be an invalid-handle call.
    if handle is not None and handle.value:
        ncrypt.NCryptFreeObject(handle)


def probe() -> bool:
    """Return True only if this machine has a TPM that CNG can actually use.

    Opening the Platform Crypto Provider is the check: it is the TPM-backed
    provider, so it fails on a machine with no TPM, with the TPM disabled in
    firmware, or with the provider otherwise unavailable.
    """
    if sys.platform != "win32":
        return False
    try:
        ncrypt = _ncrypt()
    except (WindowsTPMError, OSError) as exc:
        status(log, "ncrypt.dll unavailable - Windows TPM path unavailable", error=str(exc))
        return False

    provider = None
    try:
        provider = _open_provider(ncrypt)
        status(log, "Internal TPM responded via CNG", provider=MS_PLATFORM_CRYPTO_PROVIDER)
        return True
    except WindowsTPMError as exc:
        status(log, "No internal TPM available through CNG", error=str(exc))
        return False
    finally:
        _free(ncrypt, provider)


def load_signing_key(key_name: str) -> WindowsTPMKey | None:
    """Reload the TPM key enrolled under `key_name`, or None if there is
    none yet. Nothing is read from disk — the key lives in the TPM.
    """
    ncrypt = _ncrypt()
    provider = None
    handle = None
    try:
        provider = _open_provider(ncrypt)
        handle = _open_key(ncrypt, provider, key_name)
        if handle is None:
            return None
        status(log, "TPM signing key reloaded from existing enrollment", key_name=key_name)
        return WindowsTPMKey(key_name=key_name)
    finally:
        _free(ncrypt, handle)
        _free(ncrypt, provider)


def create_signing_key(key_name: str) -> WindowsTPMKey:
    """Create a NEW non-exportable ECC P-256 signing key inside the TPM.

    Call this only once per account, at registration time — anchored_trust.py
    enforces that by always trying load_signing_key() first.
    """
    ncrypt = _ncrypt()
    provider = None
    handle = _NCRYPT_HANDLE()
    try:
        provider = _open_provider(ncrypt)
        rc = ncrypt.NCryptCreatePersistedKey(
            provider, ctypes.byref(handle),
            ctypes.c_wchar_p(NCRYPT_ECDSA_P256_ALGORITHM), ctypes.c_wchar_p(key_name),
            _DWORD(0), _DWORD(0))
        if rc & 0xFFFFFFFF == NTE_EXISTS:
            raise WindowsTPMError(
                f"a TPM key named {key_name!r} already exists; "
                "load it instead of creating a new one")
        _check(rc, "NCryptCreatePersistedKey")

        _check(ncrypt.NCryptFinalizeKey(handle, _DWORD(0)), "NCryptFinalizeKey")
        status(log, "TPM signing key created", key_name=key_name, algorithm="ECDSA_P256")
        return WindowsTPMKey(key_name=key_name)
    finally:
        _free(ncrypt, handle)
        _free(ncrypt, provider)


# --------------------------------------------------------------------------- #
# Signing / public key                                                       #
# --------------------------------------------------------------------------- #

def sign(key: WindowsTPMKey, data: bytes) -> bytes:
    """Sign `data` with the TPM-resident key.

    CNG signs a digest, not a message, so the SHA-256 is computed here — the
    Linux backend hands the message to `tpm2_sign -g sha256` and the chip
    hashes it there. Both end up signing SHA-256(data), which is what the
    WebAuthn assertion requires. Returns DER, since NCryptSignHash emits
    raw r||s.
    """
    ncrypt = _ncrypt()
    provider = None
    handle = None
    try:
        provider = _open_provider(ncrypt)
        handle = _open_key(ncrypt, provider, key.key_name)
        if handle is None:
            raise WindowsTPMError(f"TPM key {key.key_name!r} not found")

        digest = hashlib.sha256(data).digest()
        digest_buf = (ctypes.c_ubyte * len(digest)).from_buffer_copy(digest)
        needed = _DWORD(0)

        rc = ncrypt.NCryptSignHash(
            handle, None, digest_buf, _DWORD(len(digest)),
            None, _DWORD(0), ctypes.byref(needed), _DWORD(0))
        _check(rc, "NCryptSignHash (size query)")

        sig_buf = (ctypes.c_ubyte * needed.value)()
        rc = ncrypt.NCryptSignHash(
            handle, None, digest_buf, _DWORD(len(digest)),
            sig_buf, needed, ctypes.byref(needed), _DWORD(0))
        _check(rc, "NCryptSignHash")

        return ecdsa_raw_to_der(bytes(sig_buf[:needed.value]))
    finally:
        _free(ncrypt, handle)
        _free(ncrypt, provider)


def load_public_key(key: WindowsTPMKey):
    """Export the key's PUBLIC half and rebuild it as a `cryptography`
    public key. Only the public blob is exportable — the private half is
    sealed in the TPM.
    """
    ncrypt = _ncrypt()
    provider = None
    handle = None
    try:
        provider = _open_provider(ncrypt)
        handle = _open_key(ncrypt, provider, key.key_name)
        if handle is None:
            raise WindowsTPMError(f"TPM key {key.key_name!r} not found")

        needed = _DWORD(0)
        rc = ncrypt.NCryptExportKey(
            handle, _NCRYPT_HANDLE(0), ctypes.c_wchar_p(BCRYPT_ECCPUBLIC_BLOB), None,
            None, _DWORD(0), ctypes.byref(needed), _DWORD(0))
        _check(rc, "NCryptExportKey (size query)")

        blob_buf = (ctypes.c_ubyte * needed.value)()
        rc = ncrypt.NCryptExportKey(
            handle, _NCRYPT_HANDLE(0), ctypes.c_wchar_p(BCRYPT_ECCPUBLIC_BLOB), None,
            blob_buf, needed, ctypes.byref(needed), _DWORD(0))
        _check(rc, "NCryptExportKey")

        return _public_key_from_ecc_blob(bytes(blob_buf[:needed.value]))
    finally:
        _free(ncrypt, handle)
        _free(ncrypt, provider)


def _public_key_from_ecc_blob(blob: bytes):
    """Parse a BCRYPT_ECCKEY_BLOB (header + X || Y) into a P-256 public key."""
    from cryptography.hazmat.primitives.asymmetric import ec

    if len(blob) < _ECCKEY_BLOB_HEADER.size:
        raise WindowsTPMError("ECC public blob is truncated")

    magic, cb_key = _ECCKEY_BLOB_HEADER.unpack_from(blob, 0)
    if magic != BCRYPT_ECDSA_PUBLIC_P256_MAGIC:
        raise WindowsTPMError(f"unexpected ECC blob magic 0x{magic:08X} (expected P-256 public)")

    offset = _ECCKEY_BLOB_HEADER.size
    if len(blob) < offset + 2 * cb_key:
        raise WindowsTPMError("ECC public blob shorter than its declared key size")

    x = int.from_bytes(blob[offset:offset + cb_key], "big")
    y = int.from_bytes(blob[offset + cb_key:offset + 2 * cb_key], "big")
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
