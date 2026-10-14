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
Fido2Server (IDENTITY_PROVIDER/fido2_idp/server.py) using a software-simulated key;
re-verify once a real/simulated TPM is available (see tpm/tpm_handler.py
and tpm/windows_tpm.py).

As of Milestone 2 the registration response carries a real `fmt="tpm"`
attestation statement whenever the trust anchor can produce one, so the IDP
can verify hardware key custody instead of taking the client's word for it —
see tpm/attestation.py and _attestation_object() below.
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

    att_obj = _attestation_object(auth_data, client_data, anchor)

    response = RegistrationResponse(
        raw_id=credential_id,
        response=AuthenticatorAttestationResponse(client_data=client_data, attestation_object=att_obj),
    )
    status(log, "TPM-backed registration response built",
           credential_id=credential_id.hex()[:16], fmt=att_obj.fmt)
    return response, credential_id


def _attestation_object(auth_data: AuthenticatorData, client_data: CollectedClientData,
                        anchor: AnchoredIdentity) -> AttestationObject:
    """Attest the new credential key with the TPM, or self-attest if we can't.

    The qualifying data handed to the TPM is SHA-256(authenticatorData ||
    clientDataHash) — attToBeSigned in WebAuthn's terms. It lands in the
    certify structure's extraData, which is what ties the TPM's statement to
    this ceremony's challenge and stops a captured statement being replayed
    against another one. Both halves of it only exist here, which is why this
    function owns the construction rather than tpm/attestation.py.
    """
    if anchor.attest is None:
        # No way to prove hardware custody on this backend (see
        # AnchoredIdentity.attest). The TPM still generated and holds the
        # private key and produces every signature — but nothing in the
        # protocol proves that, so the credential self-attests and the IDP
        # decides whether that is acceptable.
        status(log, "No attestation available from this trust anchor - self-attesting",
               backend=anchor.backend)
        return AttestationObject.create(fmt="none", auth_data=auth_data, att_stmt={})

    attToBeSigned = bytes(auth_data) + client_data.hash
    qualifying_data = hashlib.sha256(attToBeSigned).digest()
    try:
        att_stmt = anchor.attest(qualifying_data)
    except Exception as exc:  # noqa: BLE001 - the IDP, not the client, is the gate
        # Fall through to a self-attested credential rather than aborting, so
        # the failure surfaces as one clear rejection from the IDP instead of
        # a stack trace here. With enforcement on, this registration WILL be
        # refused — which is the correct outcome, and the reason this is
        # logged as loudly as it is.
        status(log, "TPM ATTESTATION FAILED - falling back to a self-attested credential, "
                    "which the IDP will refuse if it enforces attestation",
               backend=anchor.backend, error=str(exc))
        return AttestationObject.create(fmt="none", auth_data=auth_data, att_stmt={})

    status(log, "TPM certified the credential key", fmt="tpm",
           qualifying_data=qualifying_data.hex()[:16])
    return AttestationObject.create(fmt="tpm", auth_data=auth_data, att_stmt=att_stmt)


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
