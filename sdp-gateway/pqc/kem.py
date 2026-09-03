"""ML-KEM-768 keypair management for the Gateway's PQC-protected SPA channel.

Library choice: `kyber-py`, a pure-Python ML-KEM (FIPS 203) implementation
with zero native build dependencies. This project's earlier prototype
(PULGABLE_ZTNA_V2) used `oqs` (liboqs-python), which requires building the
liboqs C library via cmake/ninja in every image; this dev machine has
neither installed. kyber-py trades raw speed and side-channel hardening for
a `pip install` that works everywhere Python does — an acceptable trade for
a research/demo ZTNA system, not a hardened production KEM.
"""

from __future__ import annotations

import os
from pathlib import Path

from kyber_py.ml_kem import ML_KEM_768

from shared.utils.logger import get_logger, status

log = get_logger("GatewayKEM")

ALG_NAME = "ML-KEM-768"


def load_or_generate_keypair(private_path: str, public_path: str) -> tuple[bytes, bytes]:
    """Returns (decapsulation_key, encapsulation_key) i.e. (private, public)."""
    priv_path, pub_path = Path(private_path), Path(public_path)

    if priv_path.exists() and pub_path.exists():
        status(log, "ML-KEM keypair loaded from disk", alg=ALG_NAME)
        return priv_path.read_bytes(), pub_path.read_bytes()

    encaps_key, decaps_key = ML_KEM_768.keygen()

    priv_path.parent.mkdir(parents=True, exist_ok=True)
    pub_path.parent.mkdir(parents=True, exist_ok=True)
    priv_path.write_bytes(decaps_key)
    pub_path.write_bytes(encaps_key)
    os.chmod(priv_path, 0o600)

    status(log, "ML-KEM keypair generated", alg=ALG_NAME, public_key_len=len(encaps_key))
    return decaps_key, encaps_key


def decapsulate(private_key: bytes, ciphertext: bytes) -> bytes:
    return ML_KEM_768.decaps(private_key, ciphertext)
