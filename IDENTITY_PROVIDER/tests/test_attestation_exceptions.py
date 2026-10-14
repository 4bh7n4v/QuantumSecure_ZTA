"""An exception admits one device that cannot prove hardware custody, and
nothing more than that.

The pressure these tests apply is on the boundaries, because an escape hatch
is only worth having if it stays small: it must not leak to other devices, it
must not outlive its expiry, it must not launder an unattested credential into
an attested one, and it must not override the one signal that means a device's
hardware root actually changed.
"""

from __future__ import annotations

import dataclasses
import hashlib
import time

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
from store import attestation_exceptions as exception_store
from store import credentials as cred_store, db, users
from tests import tpm_fake

DEVICE_ID = "45c68349-8936-5716-ae20-d864d2470a2f"
OTHER_DEVICE = "some-other-laptop"


@pytest.fixture
def idp(monkeypatch, tmp_path):
    monkeypatch.setattr(
        db, "settings", dataclasses.replace(settings, idp_db_path=str(tmp_path / "idp.db")))
    monkeypatch.setattr(
        attestation_tpm, "settings",
        dataclasses.replace(settings, idp_enforce_tpm_attestation=True))
    monkeypatch.setattr(
        tpm_trust, "settings",
        dataclasses.replace(settings, idp_tpm_root_ca_dir=str(tmp_path / "no-roots")))
    db.init_db()
    return users.create_user("alice", "correct horse battery staple")


def register_unattested(user, device_id: str = DEVICE_ID):
    """A registration with no proof - what a Windows Hello device produces."""
    flow_id, options = fido2_server.registration_begin(user.user_id, user.username, device_id)
    credential_key = ec.generate_private_key(ec.SECP256R1())
    credential_id = hashlib.sha256(device_id.encode()).digest()
    client_data = CollectedClientData.create(
        type="webauthn.create", challenge=options.public_key.challenge,
        origin=f"https://{settings.rp_id}")
    credential_data = AttestedCredentialData.create(
        b"\x00" * 16, credential_id, ES256.from_cryptography_key(credential_key.public_key()))
    auth_data = AuthenticatorData.create(
        hashlib.sha256(settings.rp_id.encode()).digest(),
        AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.UV | AuthenticatorData.FLAG.AT,
        1, credential_data=credential_data)
    response = RegistrationResponse(
        raw_id=credential_id,
        response=AuthenticatorAttestationResponse(
            client_data=client_data,
            attestation_object=AttestationObject.create(
                fmt="none", auth_data=auth_data, att_stmt={})),
    )
    return fido2_server.registration_complete(flow_id, response, "internal_tpm")


def grant(user, device_id: str = DEVICE_ID, days: int = 30):
    return exception_store.grant(
        user_id=user.user_id, device_id=device_id, days=days,
        reason="Windows Hello returns no attestation to any caller",
        granted_by="admin")


# --------------------------------------------------------------------------- #
# what an exception permits                                                    #
# --------------------------------------------------------------------------- #

def test_without_an_exception_an_unprovable_device_cannot_enrol(idp):
    with pytest.raises(AttestationRejected, match="hardware attestation required"):
        register_unattested(idp)


def test_an_exception_lets_that_device_enrol(idp):
    grant(idp)

    record = register_unattested(idp)

    assert record.attestation_trust_path == TrustPath.EXCEPTION.value


def test_the_credential_is_still_recorded_as_not_hardware_attested(idp):
    """The exception permits the enrolment; it does not manufacture a proof.
    Anything downstream reading this credential must see the truth.
    """
    grant(idp)

    record = register_unattested(idp)

    assert record.attested_hardware is False
    assert cred_store.get(record.credential_id).attested_hardware is False


def test_the_reason_and_grantor_are_recorded_on_the_decision(idp, caplog):
    grant(idp)

    with caplog.at_level("INFO"):
        register_unattested(idp)

    assert "ADMITTED WITHOUT PROOF" in caplog.text
    assert "Windows Hello returns no attestation" in caplog.text


# --------------------------------------------------------------------------- #
# what it must NOT permit                                                      #
# --------------------------------------------------------------------------- #

def test_an_exception_does_not_leak_to_another_device(idp):
    """Per device is the whole point: the alternative it replaces was a
    deployment-wide switch.
    """
    grant(idp, device_id=DEVICE_ID)

    with pytest.raises(AttestationRejected, match="hardware attestation required"):
        register_unattested(idp, device_id=OTHER_DEVICE)


def _backdate(user_id: str, device_id: str) -> None:
    """Move a granted exception's expiry into the past.

    Rewriting the stored row rather than faking the clock, so the expiry logic
    is exercised exactly as it runs in production.
    """
    with db.connect() as conn:
        conn.execute(
            "UPDATE attestation_exceptions SET expires_at = ?"
            " WHERE user_id = ? AND device_id = ?",
            (time.time() - 60, user_id, device_id))


def test_an_expired_exception_stops_working(idp):
    """A temporary allowance must not quietly become the permanent posture."""
    grant(idp, days=1)
    _backdate(idp.user_id, DEVICE_ID)

    with pytest.raises(AttestationRejected, match="hardware attestation required"):
        register_unattested(idp)


def test_an_expired_exception_stays_visible_as_a_record(idp):
    """Expired rows are not deleted: what was once permitted, and why, is part
    of the audit trail.
    """
    grant(idp, days=1)
    _backdate(idp.user_id, DEVICE_ID)

    assert exception_store.active_for(idp.user_id, DEVICE_ID) is None
    listed = exception_store.all_exceptions()
    assert len(listed) == 1 and listed[0].expired is True


def test_a_revoked_exception_stops_working(idp):
    grant(idp)
    assert exception_store.revoke(idp.user_id, DEVICE_ID) is True

    with pytest.raises(AttestationRejected, match="hardware attestation required"):
        register_unattested(idp)


def test_an_exception_cannot_admit_a_changed_hardware_root(idp):
    """A conflicting attestation key is not missing evidence - it is evidence
    that the device's TPM changed. No exception may wave that through.
    """
    grant(idp)
    first = tpm_fake.ak_certificate(ec.generate_private_key(ec.SECP256R1()).public_key())
    pinned = tpm_trust.evaluate_attestation_key([first], None).ak_public_key

    replacement_key = ec.generate_private_key(ec.SECP256R1())
    decision_input = _tpm_registration(replacement_key)

    with pytest.raises(AttestationRejected, match="untrusted TPM attestation key"):
        attestation_tpm.decide(*decision_input, pinned_ak=pinned,
                               exception=grant(idp))


def _tpm_registration(ak_key: ec.EllipticCurvePrivateKey):
    """A structurally valid TPM attestation, for the conflict test above."""
    credential_key = ec.generate_private_key(ec.SECP256R1())
    credential_data = AttestedCredentialData.create(
        b"\x00" * 16, b"\x01" * 32, ES256.from_cryptography_key(credential_key.public_key()))
    auth_data = AuthenticatorData.create(
        hashlib.sha256(settings.rp_id.encode()).digest(),
        AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.AT, 1,
        credential_data=credential_data)
    pub_area = tpm_fake.public_area(credential_key.public_key())
    cert_info = tpm_fake.certify_info(tpm_fake.name(pub_area), b"\x00" * 32)
    attestation_object = AttestationObject.create(fmt="tpm", auth_data=auth_data, att_stmt={
        "ver": "2.0", "alg": -7,
        "x5c": [tpm_fake.ak_certificate(ak_key.public_key())],
        "sig": ak_key.sign(cert_info, ec.ECDSA(hashes.SHA256())),
        "certInfo": cert_info, "pubArea": pub_area,
    })
    return auth_data, attestation_object


# --------------------------------------------------------------------------- #
# the grant itself                                                             #
# --------------------------------------------------------------------------- #

def test_an_exception_must_have_an_expiry(idp):
    with pytest.raises(ValueError, match="positive --days"):
        exception_store.grant(idp.user_id, DEVICE_ID, "why", "admin", days=0)


def test_an_exception_must_record_why(idp):
    with pytest.raises(ValueError, match="record why"):
        exception_store.grant(idp.user_id, DEVICE_ID, "   ", "admin", days=30)


def test_regranting_extends_rather_than_duplicating(idp):
    grant(idp, days=1)
    grant(idp, days=60)

    rows = exception_store.all_exceptions()
    assert len(rows) == 1
    assert rows[0].days_remaining > 59
