"""The Windows platform-authenticator path, as far as it can be checked off
Windows.

`webauthn.dll` does not exist here, so the ctypes calls themselves cannot run.
What these tests cover is everything around them, which is where a mistake
would otherwise only surface on a user's machine:

  - the structure layouts, whose field widths and offsets are part of the
    Windows ABI. They are declared with fixed-width types precisely so their
    sizes can be asserted from any platform;
  - the conversion of Windows' output into the standard objects the rest of
    the client and the whole IDP expect, driven with recorded output in place
    of the real call;
  - anchor selection, which decides that Windows Hello is preferred over the
    CNG backend that cannot prove hardware custody.

What is NOT covered is whether webauthn.dll accepts these structures. That
needs a Windows machine.
"""

from __future__ import annotations

import ctypes
import hashlib
import sys

import pytest
from fido2.webauthn import (
    AttestationObject,
    AttestedCredentialData,
    AuthenticatorData,
    CredentialCreationOptions,
    CredentialRequestOptions,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRequestOptions,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    PublicKeyCredentialParameters,
    PublicKeyCredentialType,
)
from fido2.cose import ES256
from cryptography.hazmat.primitives.asymmetric import ec

from fido2_agent import windows_authenticator
from tpm import anchored_trust, windows_webauthn

RP_ID = "ztna.local"
ORIGIN = f"https://{RP_ID}"
CHALLENGE = b"\x07" * 32
CREDENTIAL_ID = b"\x09" * 32


# --------------------------------------------------------------------------- #
# structure layout                                                            #
# --------------------------------------------------------------------------- #

def test_dword_and_bool_are_windows_width():
    """Windows is LLP64: DWORD, LONG and BOOL are all 32-bit. Using a C long
    here would be 64-bit on Linux and would silently shift every field after
    it, so the widths are pinned explicitly.
    """
    assert ctypes.sizeof(windows_webauthn._DWORD) == 4
    assert ctypes.sizeof(windows_webauthn._LONG) == 4
    assert ctypes.sizeof(windows_webauthn._BOOL) == 4


def test_options_structures_declare_their_version_field_first():
    """Windows reads dwVersion before anything else to decide how much of the
    structure it may touch. If it is not at offset 0 the call is unsafe.
    """
    for structure in (windows_webauthn._MakeCredentialOptions,
                      windows_webauthn._GetAssertionOptions,
                      windows_webauthn._CredentialAttestation,
                      windows_webauthn._Assertion):
        assert structure.dwVersion.offset == 0, structure.__name__


def test_make_credential_options_match_the_windows_x64_layout():
    """Pinned offsets for WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS.

    Declaring a version tells Windows how far into this structure it may read,
    so a field at the wrong offset is read as a different field entirely. That
    is not hypothetical here: the version this client declares turned out to
    decide whether Windows returns attestation at all, which makes the
    later-version fields load-bearing rather than decorative padding.
    """
    options = windows_webauthn._MakeCredentialOptions
    expected = {
        "dwVersion": 0, "dwTimeoutMilliseconds": 4,
        "CredentialList": 8, "Extensions": 24,
        "dwAuthenticatorAttachment": 40, "bRequireResidentKey": 44,
        "dwUserVerificationRequirement": 48,
        "dwAttestationConveyancePreference": 52, "dwFlags": 56,
        "pCancellationId": 64,            # version 2
        "pExcludeCredentialList": 72,     # version 3
        "dwEnterpriseAttestation": 80, "dwLargeBlobSupport": 84,
        "bPreferResidentKey": 88,         # version 4
    }
    for name, offset in expected.items():
        assert getattr(options, name).offset == offset, name


@pytest.mark.parametrize("rp_id", ["ztna.local", "sdp.internal", "gateway.test",
                                   "ZTNA.LOCAL", "ztna.local."])
def test_reserved_domains_are_known_not_to_attest(rp_id):
    """Windows will not release a TPM attestation to a relying party whose
    name is not a registrable domain. Measured for `.local`; the other
    reserved suffixes are refused on the same grounds.

    Case and a trailing dot are both legal ways to write the same name, and
    neither may be allowed to slip past the check.
    """
    assert windows_webauthn.rp_id_supports_attestation(rp_id) is False


@pytest.mark.parametrize("rp_id", ["localhost", "ztna.example.com", "ztna-sdp.com",
                                   "sdp.ztna.example.co.uk"])
def test_registrable_domains_and_localhost_are_expected_to_attest(rp_id):
    """localhost is the documented development exception, and was the value
    that actually produced a 4002-byte TPM attestation on the test machine.
    """
    assert windows_webauthn.rp_id_supports_attestation(rp_id) is True


def test_attestation_object_bytes_precede_credential_id_in_the_result():
    """Guards the field order this module reads out of Windows' own
    allocation. Reading these in the wrong order yields plausible-looking
    garbage rather than an error.
    """
    attestation = windows_webauthn._CredentialAttestation
    assert attestation.cbAttestationObject.offset < attestation.pbAttestationObject.offset
    assert attestation.pbAttestationObject.offset < attestation.cbCredentialId.offset


# --------------------------------------------------------------------------- #
# converting Windows' output into standard objects                            #
# --------------------------------------------------------------------------- #

def _recorded_attestation_object() -> bytes:
    """A CBOR attestation object of the shape Windows Hello returns."""
    credential_key = ec.generate_private_key(ec.SECP256R1())
    credential_data = AttestedCredentialData.create(
        b"\x00" * 16, CREDENTIAL_ID, ES256.from_cryptography_key(credential_key.public_key()))
    auth_data = AuthenticatorData.create(
        hashlib.sha256(RP_ID.encode()).digest(),
        AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.UV | AuthenticatorData.FLAG.AT,
        1, credential_data=credential_data)
    return bytes(AttestationObject.create(
        fmt="tpm", auth_data=auth_data,
        att_stmt={"ver": "2.0", "alg": -7, "x5c": [b"cert"], "sig": b"sig",
                  "certInfo": b"certinfo", "pubArea": b"pubarea"}))


def _creation_options() -> CredentialCreationOptions:
    return CredentialCreationOptions(public_key=PublicKeyCredentialCreationOptions(
        rp=PublicKeyCredentialRpEntity(id=RP_ID, name="ZTNA-SDP IDP"),
        user=PublicKeyCredentialUserEntity(id=b"user-1", name="alice", display_name="alice"),
        challenge=CHALLENGE,
        pub_key_cred_params=[PublicKeyCredentialParameters(
            type=PublicKeyCredentialType.PUBLIC_KEY, alg=-7)],
    ))


def test_registration_passes_the_idp_challenge_through_to_windows(monkeypatch):
    """Windows hashes the client data we hand it, so the challenge the IDP
    issued has to reach it verbatim — that binding is what the IDP re-derives.
    """
    captured = {}

    def fake_make_credential(**kwargs):
        captured.update(kwargs)
        return _recorded_attestation_object(), CREDENTIAL_ID, "tpm"

    monkeypatch.setattr(windows_webauthn, "make_credential", fake_make_credential)

    response, credential_id = windows_authenticator.register(_creation_options(), ORIGIN, RP_ID)

    assert credential_id == CREDENTIAL_ID
    assert captured["rp_id"] == RP_ID
    assert captured["user_id"] == b"user-1"
    # The challenge the IDP sent must be inside the client data Windows signs over.
    assert response.response.client_data.challenge == CHALLENGE
    assert captured["client_data_json"] == bytes(response.response.client_data)


def test_registration_returns_the_attestation_object_unmodified(monkeypatch):
    """Windows already produces the standard structure. Re-encoding it would
    risk changing the bytes the IDP verifies, so it must pass through whole.
    """
    recorded = _recorded_attestation_object()
    monkeypatch.setattr(windows_webauthn, "make_credential",
                        lambda **_: (recorded, CREDENTIAL_ID, "tpm"))

    response, _ = windows_authenticator.register(_creation_options(), ORIGIN, RP_ID)

    assert bytes(response.response.attestation_object) == recorded
    assert response.response.attestation_object.fmt == "tpm"


def test_unattested_windows_credential_still_builds_but_is_flagged(monkeypatch, caplog):
    """A Windows machine with no TPM gets a software-backed Hello credential.
    It is not silently dropped — it is built, flagged, and left for the IDP to
    refuse, so the client never makes the trust decision itself.
    """
    credential_key = ec.generate_private_key(ec.SECP256R1())
    credential_data = AttestedCredentialData.create(
        b"\x00" * 16, CREDENTIAL_ID, ES256.from_cryptography_key(credential_key.public_key()))
    auth_data = AuthenticatorData.create(
        hashlib.sha256(RP_ID.encode()).digest(),
        AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.AT, 1,
        credential_data=credential_data)
    unattested = bytes(AttestationObject.create(fmt="none", auth_data=auth_data, att_stmt={}))
    monkeypatch.setattr(windows_webauthn, "make_credential",
                        lambda **_: (unattested, CREDENTIAL_ID, "none"))

    with caplog.at_level("INFO"):
        response, _ = windows_authenticator.register(_creation_options(), ORIGIN, RP_ID)

    assert response.response.attestation_object.fmt == "none"
    assert "cannot prove" in caplog.text


def test_authentication_binds_the_challenge_and_allows_only_our_credential(monkeypatch):
    captured = {}

    def fake_get_assertion(**kwargs):
        captured.update(kwargs)
        auth_data = AuthenticatorData.create(
            hashlib.sha256(RP_ID.encode()).digest(),
            AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.UV, 7)
        return bytes(auth_data), b"signature-bytes", CREDENTIAL_ID

    monkeypatch.setattr(windows_webauthn, "get_assertion", fake_get_assertion)
    options = CredentialRequestOptions(public_key=PublicKeyCredentialRequestOptions(
        challenge=CHALLENGE, rp_id=RP_ID))

    response = windows_authenticator.authenticate(options, CREDENTIAL_ID, ORIGIN, RP_ID)

    assert captured["allow_credential_ids"] == [CREDENTIAL_ID]
    assert response.response.client_data.challenge == CHALLENGE
    assert response.response.signature == b"signature-bytes"


# --------------------------------------------------------------------------- #
# anchor selection                                                            #
# --------------------------------------------------------------------------- #

def test_windows_prefers_hello_over_the_cng_backend(monkeypatch):
    """CNG can hold a key in the TPM but cannot prove it to the IDP. Windows
    Hello can, so it must be tried first.
    """
    monkeypatch.setattr(sys, "platform", "win32")

    order = [backend for backend, _ in anchored_trust._internal_backends()]

    assert order == [anchored_trust.BACKEND_WINDOWS_WEBAUTHN,
                     anchored_trust.BACKEND_WINDOWS_CNG]


def test_windows_falls_back_to_cng_when_hello_is_unavailable(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(windows_webauthn, "probe", lambda: False)
    monkeypatch.setattr(anchored_trust.windows_tpm, "probe", lambda: True)
    monkeypatch.setattr(anchored_trust, "_anchor_from_windows_tpm",
                        lambda username: anchored_trust.AnchoredIdentity(
                            kind="internal_tpm", sign=None, public_key_pem=b"",
                            backend=anchored_trust.BACKEND_WINDOWS_CNG))

    anchor = anchored_trust.select_trust_anchor("alice")

    assert anchor.backend == anchored_trust.BACKEND_WINDOWS_CNG


def test_windows_hello_anchor_delegates_the_whole_ceremony(monkeypatch):
    """It holds no signing callable of its own: Windows owns the key. The
    anchor is still an internal-TPM anchor, which is what the IDP is told.
    """
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(windows_webauthn, "probe", lambda: True)

    anchor = anchored_trust.select_trust_anchor("alice")

    assert anchor.backend == anchored_trust.BACKEND_WINDOWS_WEBAUTHN
    assert anchor.kind == "internal_tpm"
    assert anchor.sign is None
    assert anchor.attest is None
    assert anchor.backend in anchored_trust.DELEGATED_BACKENDS
