"""Builds the ML-KEM-protected SPA packet the client sends to the Gateway."""

from __future__ import annotations

from kyber_py.ml_kem import ML_KEM_768

from tee.secure_executor import secure_scope
from shared.utils.logger import get_logger, status
from shared.utils.pqc_spa import build_spa_packet

log = get_logger("SPA-Client")


def build(gateway_kem_pubkey: bytes, jwt_token: str, access_port: int, protocol: str = "tcp") -> bytes:
    shared_secret, kem_ciphertext = ML_KEM_768.encaps(gateway_kem_pubkey)
    status(log, "ML-KEM encapsulated against Gateway public key", ct_len=len(kem_ciphertext))

    with secure_scope("ml-kem-shared-secret") as track:
        # kyber-py (like most crypto libs) returns an immutable `bytes` for
        # the shared secret, which Python cannot zero in place; track()
        # zeroizes this bytearray copy on scope exit as best-effort hygiene
        # around the window it's actually used in. The original immutable
        # object is simply released to the garbage collector afterward.
        secret_copy = track(bytearray(shared_secret))
        payload = {"jwt": jwt_token, "access_port": access_port, "protocol": protocol}
        packet = build_spa_packet(kem_ciphertext, bytes(secret_copy), payload)

    status(log, "SPA packet built", total_bytes=len(packet))
    return packet
