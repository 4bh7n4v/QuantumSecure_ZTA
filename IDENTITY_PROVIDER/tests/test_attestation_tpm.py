"""Milestone 2: the IDP must only enrol credentials whose hardware custody
was proven, and must reject every way of faking it.

Each test builds a complete WebAuthn registration — authenticatorData, client
data hash, attestation statement — using tests/tpm_fake.py to marshal the TPM
structures, then runs it through the two halves of the real enforcement path:

  attestation_tpm.verify_attestation_statement()  the cryptography
  attestation_tpm.decide()                        the trust and policy call

The negative cases are the point. Every one of them differs from the valid
case in exactly one respect, so a passing test says the IDP refused for that
specific reason rather than tripping over something incidental.
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
    AuthenticatorData,
)

from fido2_idp import attestation_tpm, tpm_trust
from fido2_idp.attestation_tpm import AttestationRejected
from fido2_idp.tpm_trust import TrustPath
from shared.config.settings import settings
from tests import tpm_fake

RP_ID = "ztna.local"
CLIENT_DATA_HASH = hashlib.sha256(b"client data for one specific ceremony").digest()


# --------------------------------------------------------------------------- #
# fixtures                                                                    #
# --------------------------------------------------------------------------- #

@dataclasses.dataclass
class Registration:
    """One assembled registration, ready to hand to the IDP."""

    auth_data: AuthenticatorData
    attestation_object: AttestationObject
    ak_public_key_der: bytes
    client_data_hash: bytes = CLIENT_DATA_HASH


def _auth_data(credential_public_key: ec.EllipticCurvePublicKey) -> AuthenticatorData:
    cred_data = AttestedCredentialData.create(
        b"\x00" * 16, b"\x01" * 32, ES256.from_cryptography_key(credential_public_key))
    flags = (AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.UV
             | AuthenticatorData.FLAG.AT)
    return AuthenticatorData.create(
        hashlib.sha256(RP_ID.encode()).digest(), flags, 0, credential_data=cred_data)


def build_registration(*, attributes: int = tpm_fake.HARDWARE_BOUND,
                       ak_key: ec.EllipticCurvePrivateKey | None = None,
                       ak_certificate: bytes | None = None,
                       signing_key: ec.EllipticCurvePrivateKey | None = None,
                       pub_area_key: ec.EllipticCurvePublicKey | None = None,
                       extra_data: bytes | None = None) -> Registration:
    """Assemble a valid registration, with hooks for the negative cases.

    Each keyword replaces exactly one input, which is how a test isolates the
    single defect it is checking for.
    """
    credential_key = ec.generate_private_key(ec.SECP256R1())
    ak_key = ak_key or ec.generate_private_key(ec.SECP256R1())

    auth_data = _auth_data(credential_key.public_key())
    pub_area = tpm_fake.public_area(pub_area_key or credential_key.public_key(), attributes)

    if extra_data is None:
        # WebAuthn: extraData is the hash of attToBeSigned, which is
        # authenticatorData concatenated with the client data hash.
        extra_data = hashlib.sha256(bytes(auth_data) + CLIENT_DATA_HASH).digest()
    cert_info = tpm_fake.certify_info(tpm_fake.name(pub_area), extra_data)

    certificate = ak_certificate or tpm_fake.ak_certificate(ak_key.public_key())
    att_stmt = {
        "ver": "2.0",
        "alg": -7,
        "x5c": [certificate],
        "sig": (signing_key or ak_key).sign(cert_info, ec.ECDSA(hashes.SHA256())),
        "certInfo": cert_info,
        "pubArea": pub_area,
    }

    return Registration(
        auth_data=auth_data,
        attestation_object=AttestationObject.create(
            fmt="tpm", auth_data=auth_data, att_stmt=att_stmt),
        ak_public_key_der=tpm_trust.evaluate_attestation_key([certificate], None).ak_public_key,
    )


def _verify_and_decide(registration: Registration, pinned_ak: bytes | None = None):
    attestation_tpm.verify_attestation_statement(
        registration.attestation_object, registration.client_data_hash)
    return attestation_tpm.decide(
        registration.auth_data, registration.attestation_object, pinned_ak)


@pytest.fixture
def enforcing(monkeypatch):
    monkeypatch.setattr(attestation_tpm, "settings",
                        dataclasses.replace(settings, idp_enforce_tpm_attestation=True))


@pytest.fixture
def no_root_store(monkeypatch, tmp_path):
    """No TPM vendor roots configured — the pinned-AK posture."""
    monkeypatch.setattr(tpm_trust, "settings",
                        dataclasses.replace(settings, idp_tpm_root_ca_dir=str(tmp_path)))


# --------------------------------------------------------------------------- #
# the credential is accepted when the TPM really did vouch for it             #
# --------------------------------------------------------------------------- #

def test_valid_tpm_attestation_is_accepted(enforcing, no_root_store):
    decision = _verify_and_decide(build_registration())

    assert decision.fmt == "tpm"
    assert decision.hardware_attested is True
    # No vendor roots configured, and this device has enrolled nothing before,
    # so the attestation key is pinned rather than traced to a manufacturer.
    assert decision.trust_path == TrustPath.FIRST_AK.value
    assert decision.ak_public_key is not None


def test_second_enrolment_from_the_same_tpm_matches_the_pin(enforcing, no_root_store):
    ak_key = ec.generate_private_key(ec.SECP256R1())
    certificate = tpm_fake.ak_certificate(ak_key.public_key())

    first = _verify_and_decide(build_registration(ak_key=ak_key, ak_certificate=certificate))
    second = _verify_and_decide(
        build_registration(ak_key=ak_key, ak_certificate=certificate),
        pinned_ak=first.ak_public_key)

    assert second.trust_path == TrustPath.PINNED_AK.value
    assert second.hardware_attested is True


# --------------------------------------------------------------------------- #
# ... and refused for every single way of faking it                           #
# --------------------------------------------------------------------------- #

def test_statement_from_another_ceremony_is_refused(enforcing, no_root_store):
    """A statement captured from one registration must not be replayable
    against a different challenge: extraData binds it to one ceremony.
    """
    registration = build_registration(extra_data=hashlib.sha256(b"another ceremony").digest())

    with pytest.raises(AttestationRejected, match="does not sign for authData and ClientData"):
        _verify_and_decide(registration)


def test_pub_area_describing_a_different_key_is_refused(enforcing, no_root_store):
    """The certified key must be the credential key. Attesting some other
    TPM-resident key while enrolling a software one is the attack here.
    """
    registration = build_registration(
        pub_area_key=ec.generate_private_key(ec.SECP256R1()).public_key())

    with pytest.raises(AttestationRejected,
                       match="pubArea does not match attestedCredentialData"):
        _verify_and_decide(registration)


def test_signature_from_a_key_other_than_the_certified_ak_is_refused(enforcing, no_root_store):
    registration = build_registration(signing_key=ec.generate_private_key(ec.SECP256R1()))

    with pytest.raises(AttestationRejected, match="signature of certInfo does not match"):
        _verify_and_decide(registration)


def test_exportable_key_is_refused_even_though_the_tpm_signed_for_it(enforcing, no_root_store):
    """A structurally perfect statement that attests a key WITHOUT the
    fixedTPM / fixedParent / sensitiveDataOrigin bits. The TPM holds the key,
    but it could have been imported or duplicated out, so it is not a hardware
    root of trust in the sense this project requires.
    """
    registration = build_registration(
        attributes=tpm_fake.USER_WITH_AUTH | tpm_fake.SIGN_ENCRYPT)

    with pytest.raises(AttestationRejected, match="hardware attestation required"):
        _verify_and_decide(registration)


def test_a_different_tpm_on_a_known_device_is_refused(enforcing, no_root_store):
    """The device enrolled once with one TPM; a second enrolment presents a
    different attestation key. Refused regardless of enforcement settings.
    """
    first = _verify_and_decide(build_registration())
    replacement = build_registration()

    with pytest.raises(AttestationRejected, match="untrusted TPM attestation key"):
        _verify_and_decide(replacement, pinned_ak=first.ak_public_key)


def test_a_different_tpm_is_refused_even_with_enforcement_disabled(monkeypatch, no_root_store):
    monkeypatch.setattr(attestation_tpm, "settings",
                        dataclasses.replace(settings, idp_enforce_tpm_attestation=False))
    first = _verify_and_decide(build_registration())

    with pytest.raises(AttestationRejected, match="untrusted TPM attestation key"):
        _verify_and_decide(build_registration(), pinned_ak=first.ak_public_key)


# --------------------------------------------------------------------------- #
# self-attested credentials: the M1 default, now gated                        #
# --------------------------------------------------------------------------- #

def _self_attested(credential_key: ec.EllipticCurvePrivateKey) -> Registration:
    auth_data = _auth_data(credential_key.public_key())
    return Registration(
        auth_data=auth_data,
        attestation_object=AttestationObject.create(
            fmt="none", auth_data=auth_data, att_stmt={}),
        ak_public_key_der=b"",
    )


def test_self_attested_credential_is_refused_when_enforcing(enforcing):
    registration = _self_attested(ec.generate_private_key(ec.SECP256R1()))

    with pytest.raises(AttestationRejected, match="hardware attestation required"):
        _verify_and_decide(registration)


def test_self_attested_credential_is_allowed_when_enforcement_is_disabled(monkeypatch):
    monkeypatch.setattr(attestation_tpm, "settings",
                        dataclasses.replace(settings, idp_enforce_tpm_attestation=False))
    registration = _self_attested(ec.generate_private_key(ec.SECP256R1()))

    decision = _verify_and_decide(registration)

    assert decision.fmt == "none"
    assert decision.hardware_attested is False
    assert decision.trust_path == TrustPath.NOT_APPLICABLE.value


# --------------------------------------------------------------------------- #
# vendor roots: the strong posture, when an operator configures one           #
# --------------------------------------------------------------------------- #

@pytest.fixture
def vendor_root(monkeypatch, tmp_path):
    """A configured root store, and the CA key that chains to it."""
    ca_key = ec.generate_private_key(ec.SECP256R1())
    root = tpm_fake.root_certificate(ca_key, "Test TPM Vendor Root CA")
    (tmp_path / "vendor-root.pem").write_bytes(tpm_fake.pem(root))
    monkeypatch.setattr(tpm_trust, "settings",
                        dataclasses.replace(settings, idp_tpm_root_ca_dir=str(tmp_path)))
    return ca_key, root


def test_ak_chaining_to_a_configured_vendor_root_is_the_strongest_path(enforcing, vendor_root):
    ca_key, root = vendor_root
    ak_key = ec.generate_private_key(ec.SECP256R1())
    certificate = tpm_fake.ak_certificate(
        ak_key.public_key(), issuer_key=ca_key,
        issuer_name=root.subject.rfc4514_string().removeprefix("CN="))

    decision = _verify_and_decide(
        build_registration(ak_key=ak_key, ak_certificate=certificate))

    assert decision.trust_path == TrustPath.VENDOR_ROOT.value
    assert decision.hardware_attested is True


def test_self_issued_ak_is_refused_once_vendor_roots_are_configured(enforcing, vendor_root):
    """This is what the client's own tpm/ak_cert.py produces. It is accepted
    in the pinned-AK posture and must stop being accepted the moment an
    operator declares which TPMs the deployment trusts.
    """
    with pytest.raises(AttestationRejected, match="untrusted TPM attestation key"):
        _verify_and_decide(build_registration())
