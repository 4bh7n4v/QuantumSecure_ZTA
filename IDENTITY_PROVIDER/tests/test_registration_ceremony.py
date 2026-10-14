"""Milestone 2 end to end: a registration ceremony driven through the real
IDP code path, against a real (temporary) database.

test_attestation_tpm.py calls the enforcement functions directly, which says
nothing about whether they are actually reachable from a registration. That
distinction mattered here: before M2, `Fido2Server` was constructed with
`attestation="direct"` but no `verify_attestation` callable, so it silently
ignored every attestation statement it was handed. A unit test of the
verifier would have passed the whole time.

So these tests go through `fido2_idp.server.registration_complete` — the same
function api/routes.py calls — and assert on what ends up in the credentials
table. That covers the wiring, the schema migration that added the
attestation columns, and the per-device attestation-key pinning, which only
exists once a credential has been written and read back.
"""

from __future__ import annotations

import dataclasses
import hashlib

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fido2.cose import ES256
from fido2.webauthn import (
    AttestationObject,
    AttestedCredentialData,
    AuthenticatorAttestationResponse,
    AuthenticatorData,
    CollectedClientData,
    RegistrationResponse,
)

from fido2_idp import attestation_tpm, server as fido2_server, tpm_trust
from fido2_idp.attestation_tpm import AttestationRejected
from fido2_idp.tpm_trust import TrustPath
from shared.config.settings import settings
from store import credentials as cred_store, db, users
from tests import tpm_fake

USER_NAME = "alice"
DEVICE_ID = "device-under-test"


@pytest.fixture
def idp(monkeypatch, tmp_path):
    """A fresh IDP database, enforcement on, no vendor roots configured."""
    monkeypatch.setattr(
        db, "settings", dataclasses.replace(settings, idp_db_path=str(tmp_path / "idp.db")))
    monkeypatch.setattr(
        attestation_tpm, "settings",
        dataclasses.replace(settings, idp_enforce_tpm_attestation=True))
    monkeypatch.setattr(
        tpm_trust, "settings",
        dataclasses.replace(settings, idp_tpm_root_ca_dir=str(tmp_path / "no-roots")))
    db.init_db()
    return users.create_user(USER_NAME, "correct horse battery staple")


def register(user, ak_key: ec.EllipticCurvePrivateKey,
             ak_certificate: bytes, device_id: str = DEVICE_ID,
             forge_signature: bool = False):
    """Run one full registration ceremony against the real IDP driver."""
    flow_id, options = fido2_server.registration_begin(user.user_id, user.username, device_id)

    credential_key = ec.generate_private_key(ec.SECP256R1())
    credential_id = b"\x02" * 32
    client_data = CollectedClientData.create(
        type="webauthn.create", challenge=options.public_key.challenge,
        origin=f"https://{settings.rp_id}")

    cred_data = AttestedCredentialData.create(
        b"\x00" * 16, credential_id, ES256.from_cryptography_key(credential_key.public_key()))
    flags = (AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.UV
             | AuthenticatorData.FLAG.AT)
    auth_data = AuthenticatorData.create(
        hashlib.sha256(settings.rp_id.encode()).digest(), flags, 1, credential_data=cred_data)

    pub_area = tpm_fake.public_area(credential_key.public_key())
    extra_data = hashlib.sha256(bytes(auth_data) + client_data.hash).digest()
    cert_info = tpm_fake.certify_info(tpm_fake.name(pub_area), extra_data)

    signer = ec.generate_private_key(ec.SECP256R1()) if forge_signature else ak_key
    attestation_object = AttestationObject.create(fmt="tpm", auth_data=auth_data, att_stmt={
        "ver": "2.0",
        "alg": -7,
        "x5c": [ak_certificate],
        "sig": signer.sign(cert_info, ec.ECDSA(hashes.SHA256())),
        "certInfo": cert_info,
        "pubArea": pub_area,
    })
    response = RegistrationResponse(
        raw_id=credential_id,
        response=AuthenticatorAttestationResponse(
            client_data=client_data, attestation_object=attestation_object),
    )
    return fido2_server.registration_complete(flow_id, response, "internal_tpm")


def _tpm():
    """A stand-in TPM: its attestation key, and the certificate carrying it."""
    ak_key = ec.generate_private_key(ec.SECP256R1())
    return ak_key, tpm_fake.ak_certificate(ak_key.public_key())


def test_attested_credential_is_enrolled_and_recorded_as_hardware_backed(idp):
    ak_key, certificate = _tpm()

    record = register(idp, ak_key, certificate)

    assert record.attested_hardware is True
    assert record.attestation_fmt == "tpm"
    assert record.attestation_trust_path == TrustPath.FIRST_AK.value
    # Persisted, not just returned — the pin has to survive a restart.
    assert cred_store.get(record.credential_id).attestation_ak_key == record.attestation_ak_key


def test_a_forged_attestation_signature_is_caught_during_the_ceremony(idp):
    """The regression guard for the wiring this milestone fixed. The statement
    is well formed and the certified key is hardware-bound, so nothing but the
    library's signature check inside register_complete can catch it — if the
    verify_attestation hook is ever dropped again, only this test fails.
    """
    ak_key, certificate = _tpm()

    with pytest.raises(AttestationRejected, match="signature of certInfo does not match"):
        register(idp, ak_key, certificate, forge_signature=True)

    assert cred_store.for_user(idp.user_id) == []


def test_the_same_tpm_enrolling_again_matches_the_pin(idp):
    ak_key, certificate = _tpm()
    register(idp, ak_key, certificate)

    second = register(idp, ak_key, certificate)

    assert second.attestation_trust_path == TrustPath.PINNED_AK.value


def test_a_swapped_tpm_on_an_enrolled_device_is_refused(idp):
    """The device is already trusted with one TPM. A registration certified by
    a different attestation key is what a stolen credential replayed from
    other hardware would look like.
    """
    register(idp, *_tpm())

    with pytest.raises(AttestationRejected, match="untrusted TPM attestation key"):
        register(idp, *_tpm())


def test_a_second_device_pins_its_own_tpm_independently(idp):
    """Pinning is per device, not per user — the same person enrolling a
    second machine must not be blocked by the first machine's TPM.
    """
    register(idp, *_tpm())

    record = register(idp, *_tpm(), device_id="a-second-laptop")

    assert record.attestation_trust_path == TrustPath.FIRST_AK.value


def test_self_attested_credential_is_refused_by_the_registration_path(idp):
    """What the client sends when it cannot prove hardware custody. Refused
    before anything reaches the database.
    """
    flow_id, options = fido2_server.registration_begin(
        idp.user_id, idp.username, DEVICE_ID)
    credential_key = ec.generate_private_key(ec.SECP256R1())
    client_data = CollectedClientData.create(
        type="webauthn.create", challenge=options.public_key.challenge,
        origin=f"https://{settings.rp_id}")
    cred_data = AttestedCredentialData.create(
        b"\x00" * 16, b"\x03" * 32, ES256.from_cryptography_key(credential_key.public_key()))
    auth_data = AuthenticatorData.create(
        hashlib.sha256(settings.rp_id.encode()).digest(),
        AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.UV | AuthenticatorData.FLAG.AT,
        1, credential_data=cred_data)
    response = RegistrationResponse(
        raw_id=b"\x03" * 32,
        response=AuthenticatorAttestationResponse(
            client_data=client_data,
            attestation_object=AttestationObject.create(
                fmt="none", auth_data=auth_data, att_stmt={})),
    )

    with pytest.raises(AttestationRejected, match="hardware attestation required"):
        fido2_server.registration_complete(flow_id, response, "internal_tpm")

    assert cred_store.for_user(idp.user_id) == []
