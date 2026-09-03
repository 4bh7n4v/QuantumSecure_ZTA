"""The IDP-side FIDO2/WebAuthn ceremony driver.

Wraps Yubico's `fido2.server.Fido2Server` (which implements the WebAuthn +
CTAP2 crypto: challenge generation, clientData binding, attestation and
assertion signature verification) and adds:

  - a title banner + numbered "Step n/N: ..." log lines for every stage of
    both ceremonies (existing credentials loaded, challenge minted, options
    issued, response received, signature verified, attestation inspected,
    credential persisted), plus a summary block, so the terminal reads as a
    walk-through and a failure names the exact step;
  - persistence of credentials via store/credentials.py (SQLite);
  - the TPM-attestation seam (fido2_idp/attestation_tpm.py).

Wire format for the ceremony payloads is CBOR (see api/routes.py) — the
fido2 dataclasses round-trip through it natively.
"""

from __future__ import annotations

import time
import uuid

from fido2.server import Fido2Server
from fido2.webauthn import (
    AuthenticationResponse,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    RegistrationResponse,
    UserVerificationRequirement,
)

from fido2_idp import attestation_tpm
from store import credentials as cred_store
from shared.config.settings import settings
from shared.utils.logger import banner, field, get_logger, step

log = get_logger("IDP-FIDO2")

_origin = f"https://{settings.rp_id}"
_rp = PublicKeyCredentialRpEntity(id=settings.rp_id, name=settings.rp_name)

# attestation="direct" so the client MAY send a real attestation statement;
# the internal-TPM path still sends fmt="none" until the client-side TPM
# attestation builder lands (M2). attestation_tpm.py decides what to do with
# whatever arrives.
_server = Fido2Server(_rp, attestation="direct", verify_origin=lambda o: o == _origin)


class ChallengeStore:
    """In-memory, short-lived store of in-flight ceremony state. Ephemeral by
    design — a dropped challenge just means the client restarts the ceremony.
    """

    def __init__(self, ttl_seconds: int = 300) -> None:
        self._states: dict[str, tuple[dict, float]] = {}
        self._ttl = ttl_seconds

    def put(self, key: str, value: dict) -> None:
        self._states[key] = (value, time.time() + self._ttl)

    def pop(self, key: str) -> dict | None:
        entry = self._states.pop(key, None)
        if entry is None:
            return None
        value, expires_at = entry
        return None if expires_at < time.time() else value


challenge_store = ChallengeStore()


def _challenge_str(state: dict) -> str:
    # fido2 stores the challenge in the ceremony state as a websafe-base64
    # string (not raw bytes) — logged as-is.
    value = state.get("challenge", "")
    return value if isinstance(value, str) else str(value)


# --------------------------------------------------------------------------- #
# Registration                                                               #
# --------------------------------------------------------------------------- #

def registration_begin(user_id: str, username: str, device_id: str):
    banner(log, "FIDO2 REGISTRATION - IDP SIDE")
    field(log, "User", f"{username} ({user_id})")
    field(log, "Device", device_id)
    field(log, "Relying Party ID", _rp.id)

    step(log, 1, 7, "Loading this user's already-enrolled credentials", to="exclude re-enrolment")
    existing = [c.credential_data for c in cred_store.for_user(user_id)]
    step(log, 1, 7, "Existing credentials loaded", count=len(existing))

    user_entity = PublicKeyCredentialUserEntity(
        id=user_id.encode("utf-8"), name=username, display_name=username,
    )
    options, state = _server.register_begin(
        user_entity, credentials=existing,
        user_verification=UserVerificationRequirement.PREFERRED,
    )

    pk = options.public_key
    step(log, 2, 7, "Generated a random cryptographic challenge (CSPRNG)",
         bytes=len(pk.challenge), challenge_b64=_challenge_str(state))
    step(log, 3, 7, "Assembled credential-creation options",
         pubkey_algs=[p.alg for p in pk.pub_key_cred_params],
         exclude_credentials=len(getattr(pk, "exclude_credentials", []) or []),
         user_verification=str(getattr(pk, "authenticator_selection", None)
                               and pk.authenticator_selection.user_verification),
         attestation=str(getattr(pk, "attestation", None)))

    flow_id = str(uuid.uuid4())
    challenge_store.put(flow_id, {"state": state, "user_id": user_id,
                                  "username": username, "device_id": device_id})
    step(log, 4, 7, "Stored the challenge; sending options to the client and awaiting attestation",
         flow_id=flow_id)
    return flow_id, options


def registration_complete(flow_id: str, response: RegistrationResponse,
                          trust_anchor_type: str) -> cred_store.CredentialRecord:
    entry = challenge_store.pop(flow_id)
    if entry is None:
        step(log, 5, 7, "FAILED - challenge unknown or expired", flow_id=flow_id)
        raise ValueError("unknown or expired registration flow_id")

    step(log, 5, 7, "Received the attestation response from the client",
         flow_id=flow_id, client_data_type=response.response.client_data.type)

    step(log, 6, 7, "Verifying clientDataJSON challenge binding and the attestation signature")
    auth_data = _server.register_complete(entry["state"], response)
    step(log, 6, 7, "WebAuthn verification passed (fido2)",
         credential_id=auth_data.credential_data.credential_id.hex()[:16],
         aaguid=auth_data.credential_data.aaguid.hex(), sign_count=auth_data.counter)

    att_result = attestation_tpm.inspect_registration(auth_data, response.response.attestation_object)

    record = cred_store.CredentialRecord(
        credential_id=auth_data.credential_data.credential_id,
        user_id=entry["user_id"],
        device_id=entry["device_id"],
        credential_data=auth_data.credential_data,
        trust_anchor_type=trust_anchor_type,
        sign_count=auth_data.counter,
        attestation_fmt=att_result.fmt,
        attested_hardware=att_result.hardware_attested,
    )
    cred_store.add(record)
    step(log, 7, 7, "Credential persisted to the IDP database")
    banner(log, "FIDO2 REGISTRATION COMPLETE - IDP SIDE")
    field(log, "User", entry["user_id"])
    field(log, "Device", entry["device_id"])
    field(log, "Credential ID", record.credential_id.hex())
    field(log, "Trust anchor (client-reported)", trust_anchor_type)
    field(log, "Attestation format", att_result.fmt)
    field(log, "Hardware-attested", att_result.hardware_attested)
    return record


# --------------------------------------------------------------------------- #
# Authentication                                                             #
# --------------------------------------------------------------------------- #

def authentication_begin(user_id: str):
    banner(log, "FIDO2 AUTHENTICATION - IDP SIDE")
    field(log, "User", user_id)

    step(log, 1, 6, "Loading this user's registered credentials")
    creds = [c.credential_data for c in cred_store.for_user(user_id)]
    if not creds:
        step(log, 1, 6, "FAILED - no registered credentials for this user", user_id=user_id)
        raise ValueError("no registered credentials for this user on any device")
    step(log, 1, 6, "Credentials loaded", count=len(creds))

    options, state = _server.authenticate_begin(
        creds, user_verification=UserVerificationRequirement.PREFERRED,
    )
    pk = options.public_key
    step(log, 2, 6, "Generated a random cryptographic challenge (CSPRNG)",
         bytes=len(pk.challenge), challenge_b64=_challenge_str(state))
    step(log, 3, 6, "Assembled assertion-request options",
         allow_credentials=len(getattr(pk, "allow_credentials", []) or []),
         user_verification=str(getattr(pk, "user_verification", None)))

    flow_id = str(uuid.uuid4())
    challenge_store.put(flow_id, {"state": state, "user_id": user_id})
    step(log, 4, 6, "Stored the challenge; sending options to the client and awaiting the assertion",
         flow_id=flow_id)
    return flow_id, options


def authentication_complete(flow_id: str, response: AuthenticationResponse) -> cred_store.CredentialRecord:
    entry = challenge_store.pop(flow_id)
    if entry is None:
        step(log, 5, 6, "FAILED - challenge unknown or expired", flow_id=flow_id)
        raise ValueError("unknown or expired authentication flow_id")

    user_id = entry["user_id"]
    step(log, 5, 6, "Received the signed assertion from the client", flow_id=flow_id,
         client_data_type=response.response.client_data.type,
         counter=response.response.authenticator_data.counter)

    step(log, 6, 6, "Verifying the assertion signature against the stored credential public key")
    creds = [c.credential_data for c in cred_store.for_user(user_id)]
    result = _server.authenticate_complete(entry["state"], creds, response)

    record = cred_store.get(result.credential_id)
    if record is None:
        step(log, 6, 6, "FAILED - matched credential not found in the IDP store")
        raise ValueError("matched credential not found in store")

    new_count = response.response.authenticator_data.counter
    cred_store.update_sign_count(record.credential_id, new_count)
    banner(log, "FIDO2 AUTHENTICATION VERIFIED - IDP SIDE")
    field(log, "User", user_id)
    field(log, "Device", record.device_id)
    field(log, "Credential ID", record.credential_id.hex())
    field(log, "Signature counter", new_count)
    field(log, "Attestation format", record.attestation_fmt)
    field(log, "Hardware-attested", record.attested_hardware)
    return record
