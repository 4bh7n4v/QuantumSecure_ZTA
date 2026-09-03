"""Builds real WebAuthn registration/authentication responses when the
hardware root of trust is an internal TPM (not a CTAP2 device — TPM chips
don't speak CTAP2, so `fido2.client.Fido2Client` can't be used here; this
module manually assembles the same data structures the fido2 library uses
internally for physical keys, per the WebAuthn spec, using the anchor's
`sign` and `public_key_pem` to do the actual credential-key cryptography).

Note this package is named `fido2_agent`, not `fido2` — a plain `fido2/`
directory here would shadow the real installed `fido2` library for every
import in this component, since the client is run with its own directory
first on sys.path (see main.py's bootstrap comment).

Every object built below (CollectedClientData, AuthenticatorData,
AttestationObject, RegistrationResponse, AuthenticationResponse) is a real
`fido2` library class — only the "authenticator" producing the key material
and signatures is swapped from a CTAP2 device to a subprocess-driven TPM.
This exact construction was round-trip verified against the IDP's
Fido2Server (sdp-idp/fido2_idp/server.py) using a software-simulated key;
re-verify once a real/simulated TPM is available (see tpm/tpm_handler.py
and tpm/windows_tpm.py).
"""

from __future__ import annotations

import hashlib
import os
import time

from fido2.cose import ES256
from fido2.webauthn import (
    AttestationObject,
    AttestedCredentialData,
    AuthenticationResponse,
    AuthenticatorAssertionResponse,
    AuthenticatorAttestationResponse,
    AuthenticatorData,
    CollectedClientData,
    CredentialCreationOptions,
    CredentialRequestOptions,
    RegistrationResponse,
)

from tpm.anchored_trust import AnchoredIdentity
from shared.utils.logger import get_logger, status

log = get_logger("FIDO2-TPM")

AAGUID = b"\x00" * 16  # no vendor AAGUID - this is a self-attested, TPM-backed credential


def build_registration_response(
    options: CredentialCreationOptions, anchor: AnchoredIdentity, origin: str, rp_id: str,
) -> tuple[RegistrationResponse, bytes]:
    """Returns (response, credential_id)."""
    from cryptography.hazmat.primitives import serialization

    challenge = options.public_key.challenge
    client_data = CollectedClientData.create(type="webauthn.create", challenge=challenge, origin=origin)

    public_key = serialization.load_pem_public_key(anchor.public_key_pem)
    cose_key = ES256.from_cryptography_key(public_key)

    credential_id = os.urandom(32)
    cred_data = AttestedCredentialData.create(AAGUID, credential_id, cose_key)

    rp_id_hash = hashlib.sha256(rp_id.encode()).digest()
    flags = AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.UV | AuthenticatorData.FLAG.AT
    auth_data = AuthenticatorData.create(rp_id_hash, flags, 1, credential_data=cred_data)

    # fmt="none": the fido2 library ships no TPM attestation-statement
    # verifier, so this credential self-attests. The TPM still generated and
    # holds the private key and produces every signature — only the formal
    # attestation *statement* is skipped, not hardware key custody.
    att_obj = AttestationObject.create(fmt="none", auth_data=auth_data, att_stmt={})

    response = RegistrationResponse(
        raw_id=credential_id,
        response=AuthenticatorAttestationResponse(client_data=client_data, attestation_object=att_obj),
    )
    status(log, "TPM-backed registration response built", credential_id=credential_id.hex()[:16])
    return response, credential_id


def build_authentication_response(
    options: CredentialRequestOptions, anchor: AnchoredIdentity, credential_id: bytes, origin: str, rp_id: str,
) -> AuthenticationResponse:
    challenge = options.public_key.challenge
    client_data = CollectedClientData.create(type="webauthn.get", challenge=challenge, origin=origin)

    rp_id_hash = hashlib.sha256(rp_id.encode()).digest()
    flags = AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.UV
    auth_data = AuthenticatorData.create(rp_id_hash, flags, int(time.time()) % (2**32))

    signed_message = bytes(auth_data) + hashlib.sha256(bytes(client_data)).digest()
    signature = anchor.sign(signed_message)

    status(log, "TPM-backed assertion signed", credential_id=credential_id.hex()[:16])
    return AuthenticationResponse(
        raw_id=credential_id,
        response=AuthenticatorAssertionResponse(
            client_data=client_data, authenticator_data=auth_data, signature=signature,
        ),
    )
