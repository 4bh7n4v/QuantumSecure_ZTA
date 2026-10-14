"""Drives the Windows platform authenticator (Windows Hello) through the
OS's own FIDO2 implementation — see tpm/windows_webauthn.py for why.

This is the Windows counterpart of external_authenticator.py: both hand the
ceremony to something that already speaks WebAuthn properly and simply wrap
what comes back, rather than assembling protocol objects by hand the way
tpm_authenticator.py must on Linux.

Everything platform-specific stops here. What leaves this module are ordinary
`fido2` RegistrationResponse / AuthenticationResponse objects, identical to
those from the other two backends, so fido2_agent/client.py, the wire format
and the whole IDP never learn which operating system produced them.

One asymmetry worth stating: Windows Hello mints and stores the credential
key itself, so unlike the Linux path there is no separate signing callable on
the trust anchor. The key is still generated inside the TPM and marked
non-duplicable, which is exactly what the IDP verifies from the attestation —
it just never passes through this process.
"""

from __future__ import annotations

from fido2.webauthn import (
    AttestationObject,
    AuthenticationResponse,
    AuthenticatorAssertionResponse,
    AuthenticatorAttestationResponse,
    AuthenticatorData,
    CollectedClientData,
    CredentialCreationOptions,
    CredentialRequestOptions,
    RegistrationResponse,
)

from tpm import windows_webauthn
from shared.utils.logger import get_logger, status

log = get_logger("FIDO2-WinHello")


def register(options: CredentialCreationOptions, origin: str,
             rp_id: str) -> tuple[RegistrationResponse, bytes]:
    """Run the registration ceremony. Returns (response, credential_id).

    The client data is built here rather than by Windows so the challenge the
    IDP issued is bound exactly as the IDP will re-derive it; Windows is given
    those bytes and hashes them itself.
    """
    public_key = options.public_key
    client_data = CollectedClientData.create(
        type="webauthn.create", challenge=public_key.challenge, origin=origin)

    attestation_object, credential_id, attestation_format = windows_webauthn.make_credential(
        rp_id=rp_id,
        rp_name=public_key.rp.name or rp_id,
        user_id=bytes(public_key.user.id),
        user_name=public_key.user.name,
        client_data_json=bytes(client_data),
    )

    if attestation_format == "none":
        # Windows returns an unattested credential when the machine has no
        # TPM, or when policy strips attestation. Enrolment will be refused by
        # the IDP; say so here so the cause is visible before the rejection.
        status(log, "Windows Hello returned NO attestation - this machine cannot prove "
                    "hardware key custody, and the IDP will refuse to enrol it")

    response = RegistrationResponse(
        raw_id=credential_id,
        response=AuthenticatorAttestationResponse(
            client_data=client_data,
            attestation_object=AttestationObject(attestation_object),
        ),
    )
    status(log, "Windows Hello registration response built",
           fmt=attestation_format, credential_id=credential_id.hex()[:16])
    return response, credential_id


def authenticate(options: CredentialRequestOptions, credential_id: bytes,
                 origin: str, rp_id: str) -> AuthenticationResponse:
    """Run the authentication ceremony against an already-enrolled credential."""
    public_key = options.public_key
    client_data = CollectedClientData.create(
        type="webauthn.get", challenge=public_key.challenge, origin=origin)

    authenticator_data, signature, returned_id = windows_webauthn.get_assertion(
        rp_id=rp_id,
        client_data_json=bytes(client_data),
        allow_credential_ids=[credential_id],
    )

    status(log, "Windows Hello assertion received", credential_id=returned_id.hex()[:16])
    return AuthenticationResponse(
        raw_id=returned_id,
        response=AuthenticatorAssertionResponse(
            client_data=client_data,
            authenticator_data=AuthenticatorData(authenticator_data),
            signature=signature,
        ),
    )
