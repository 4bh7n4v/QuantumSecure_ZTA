"""Crypto helpers shared across components.

  - RSA keypair persistence, used by the IDP to sign/verify access tokens
    (RS256).
  - ECDSA signature normalisation, used by every TPM backend on the client:
    hardware signers emit raw r||s, while `cryptography` and `fido2` both
    expect DER.
"""

from __future__ import annotations

import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)


def ecdsa_raw_to_der(signature: bytes) -> bytes:
    """Normalise an ECDSA signature to DER.

    Accepts either form, because the TPM backends disagree: Windows CNG
    (`NCryptSignHash`) always returns raw r||s, and `tpm2_sign -f plain` is
    documented to do the same but some tpm2-tools builds (observed on Kali +
    swtpm) emit DER there instead. If the bytes already decode as DER they
    are re-encoded canonically; otherwise they are split as raw r||s.
    """
    if signature[:1] == b"\x30":
        try:
            r, s = decode_dss_signature(signature)
            return encode_dss_signature(r, s)
        except ValueError:
            pass

    half = len(signature) // 2
    r = int.from_bytes(signature[:half], "big")
    s = int.from_bytes(signature[half:], "big")
    return encode_dss_signature(r, s)


def load_or_generate_rsa_keypair(
    private_path: str, public_path: str, key_size: int = 3072
) -> tuple[RSAPrivateKey, RSAPublicKey]:
    priv_path, pub_path = Path(private_path), Path(public_path)

    if priv_path.exists() and pub_path.exists():
        private_key = serialization.load_pem_private_key(priv_path.read_bytes(), password=None)
        public_key = serialization.load_pem_public_key(pub_path.read_bytes())
        return private_key, public_key  # type: ignore[return-value]

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()

    priv_path.parent.mkdir(parents=True, exist_ok=True)
    pub_path.parent.mkdir(parents=True, exist_ok=True)

    priv_path.write_bytes(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    pub_path.write_bytes(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    os.chmod(priv_path, 0o600)
    return private_key, public_key
