"""Shared wire format for the ML-KEM-protected SPA (Single Packet
Authorization) knock.

Both the client (encapsulates + encrypts) and the Gateway (decapsulates +
decrypts) import this module directly so the wire format is defined exactly
once and can never drift between the two ends.

Wire format (fixed-length header, variable-length ciphertext body):
    [ML-KEM ciphertext, length = KEM_CT_LEN[kem_alg]]
    [12-byte AES-GCM nonce]
    [AES-256-GCM(payload_json) + 16-byte tag]

The AES-256-GCM key is HKDF-SHA256(ikm=ml_kem_shared_secret, info=b"ztna-spa-v1").
The client derives it right after ML-KEM encapsulation; the Gateway derives
the identical key right after ML-KEM decapsulation. Neither side ever sends
the AES key itself — only the ML-KEM ciphertext travels on the wire.
"""

from __future__ import annotations

import json
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# ML-KEM ciphertext sizes are fixed by the algorithm (NIST FIPS 203).
KEM_CT_LEN = {"ML-KEM-768": 1088}
GCM_NONCE_LEN = 12


def derive_spa_key(shared_secret: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"ztna-spa-v1").derive(shared_secret)


def build_spa_packet(kem_ciphertext: bytes, shared_secret: bytes, payload: dict) -> bytes:
    key = derive_spa_key(shared_secret)
    plaintext = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    nonce = os.urandom(GCM_NONCE_LEN)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    return kem_ciphertext + nonce + ciphertext


def split_kem_ciphertext(packet: bytes, kem_alg: str) -> bytes:
    ct_len = KEM_CT_LEN[kem_alg]
    if len(packet) < ct_len + GCM_NONCE_LEN + 16:
        raise ValueError(f"SPA packet too short: {len(packet)} bytes")
    return packet[:ct_len]


def parse_spa_packet(packet: bytes, kem_alg: str, shared_secret: bytes) -> dict:
    ct_len = KEM_CT_LEN[kem_alg]
    nonce = packet[ct_len:ct_len + GCM_NONCE_LEN]
    ciphertext = packet[ct_len + GCM_NONCE_LEN:]
    key = derive_spa_key(shared_secret)
    plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
    return json.loads(plaintext)
