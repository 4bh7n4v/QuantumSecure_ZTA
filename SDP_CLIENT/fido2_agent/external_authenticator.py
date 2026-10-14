"""Drives a real external USB CTAP2 security key through the `fido2`
library's own client implementation — this path gets full, spec-compliant
attestation for free (no manual object construction needed, unlike the
internal-TPM path in tpm_authenticator.py).
"""

from __future__ import annotations

import getpass

from fido2.client import DefaultClientDataCollector, Fido2Client, UserInteraction
from fido2.webauthn import (
    AuthenticationResponse,
    CredentialCreationOptions,
    CredentialRequestOptions,
    RegistrationResponse,
)

from shared.utils.logger import get_logger, status

log = get_logger("FIDO2-USB")


class ConsoleUserInteraction(UserInteraction):
    """Prints exactly what the user needs to do right now, and prompts for a
    PIN on the terminal when the key requires one.
    """

    def prompt_up(self) -> None:
        print("\n>>> Touch your security key now to continue... <<<\n")

    def request_pin(self, permissions, rp_id) -> str:
        return getpass.getpass("Enter your security key PIN: ")

    def request_uv(self, permissions, rp_id) -> bool:
        print(">>> Verify your presence on the security key (touch/biometric) <<<")
        return True


def build_client(device, origin: str) -> Fido2Client:
    status(log, "Connecting to external USB CTAP2 device", device=str(device))
    return Fido2Client(
        device,
        client_data_collector=DefaultClientDataCollector(origin=origin),
        user_interaction=ConsoleUserInteraction(),
    )


def register(client: Fido2Client, options: CredentialCreationOptions) -> RegistrationResponse:
    response = client.make_credential(options.public_key)
    status(log, "External key produced registration response", credential_id=response.raw_id.hex()[:16])
    return response


def authenticate(client: Fido2Client, options: CredentialRequestOptions) -> AuthenticationResponse:
    selection = client.get_assertion(options.public_key)
    response = selection.get_response(0)
    status(log, "External key produced assertion", credential_id=response.raw_id.hex()[:16])
    return response
