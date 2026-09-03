"""Software TEE-emulation for the crypto operations no TPM can do (ML-KEM
encapsulation, session-key handling).

This is NOT a hardware TEE — no Intel SGX / ARM TrustZone enclave is used or
available on this host. It's the best a plain Linux process can offer:
best-effort memory locking so secrets are less likely to be swapped to
disk, plus guaranteed zeroization of any bytearray registered with it when
the scope exits, success or failure.

Honest limitation: Python's `bytes` objects are immutable, and most crypto
libraries (kyber-py included) return plain `bytes`, not `bytearray` — those
values cannot be zeroized in place at all; only a `bytearray` COPY that the
caller explicitly makes and registers via `track()` can be wiped here. The
original immutable object is simply released to the garbage collector.
Treat "secure_scope" as "as much hygiene as a regular CPython process can
offer", not as a real hardware isolation boundary.
"""

from __future__ import annotations

import ctypes
import ctypes.util
from contextlib import contextmanager

from shared.utils.logger import get_logger, status

log = get_logger("TEE")

_libc_name = ctypes.util.find_library("c")
_libc = ctypes.CDLL(_libc_name) if _libc_name else None


def _mlock(buf: bytearray) -> bool:
    if _libc is None:
        return False
    addr = (ctypes.c_char * len(buf)).from_buffer(buf)
    return _libc.mlock(ctypes.byref(addr), len(buf)) == 0


def _munlock(buf: bytearray) -> None:
    if _libc is None:
        return
    addr = (ctypes.c_char * len(buf)).from_buffer(buf)
    _libc.munlock(ctypes.byref(addr), len(buf))


def _zeroize(buf: bytearray) -> None:
    for i in range(len(buf)):
        buf[i] = 0


@contextmanager
def secure_scope(name: str):
    """Yields a `track(bytearray)` function. Every bytearray passed to it is
    best-effort mlock()'d and is guaranteed to be zeroized when the `with`
    block exits, whether normally or via exception.
    """
    tracked: list[bytearray] = []
    locked: list[bytearray] = []

    def track(buf: bytearray) -> bytearray:
        tracked.append(buf)
        if _mlock(buf):
            locked.append(buf)
        return buf

    status(log, f"[TEE] Secure scope entered: {name}", mlock_available=_libc is not None)
    try:
        yield track
    finally:
        for buf in tracked:
            _zeroize(buf)
        for buf in locked:
            _munlock(buf)
        status(log, f"[TEE] Secure scope exited, {len(tracked)} secret(s) zeroized: {name}")
