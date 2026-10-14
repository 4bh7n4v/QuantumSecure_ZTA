"""Milestone 2, client side: the parts of building a TPM attestation
statement that do not need a TPM.

The chip itself is out of reach here — tpm/tpm_handler.py shells out to
`tpm2-tools`, and neither a real TPM nor an `swtpm` simulator is available on
this machine — so what is tested is everything around the chip, which is
where the silent failures live:

  - the AK certificate this client issues must satisfy a WebAuthn verifier's
    requirements for a TPM attestation certificate, checked against
    python-fido2's own validator rather than a reimplementation of it;
  - the byte-level unmarshalling of what tpm2-tools writes. These bytes are
    hashed by the verifier, so an off-by-two on a TPM2B size prefix produces
    no error here and an inscrutable signature failure at the IDP;
  - the qualifying data handed to the TPM, which is what binds a statement to
    one ceremony and is the difference between attestation and a replayable
    token.
"""

from __future__ import annotations

import hashlib
import struct

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography import x509
from fido2.attestation.tpm import _validate_tpm_cert
from fido2.webauthn import CollectedClientData

from fido2_agent import tpm_authenticator
from tpm import ak_cert, tpm_handler
from tpm.anchored_trust import AnchoredIdentity

RP_ID = "ztna.local"
ORIGIN = f"https://{RP_ID}"


# --------------------------------------------------------------------------- #
# the AK certificate                                                          #
# --------------------------------------------------------------------------- #

def test_ak_certificate_meets_webauthn_tpm_requirements():
    """python-fido2 rejects an AK certificate that has a subject, lacks a
    subjectAltName, lacks the tcg-kp-AIKCertificate extended key usage, or is
    marked as a CA. Checked with the verifier's own validator so this test
    cannot drift from what the IDP will actually apply.
    """
    ak_key = ec.generate_private_key(ec.SECP256R1())

    certificate = x509.load_der_x509_certificate(ak_cert.build_self_issued(ak_key.public_key()))

    _validate_tpm_cert(certificate)
    assert certificate.public_key().public_numbers() == ak_key.public_key().public_numbers()


def test_ak_certificate_does_not_claim_to_be_vendor_issued():
    """Its issuer must say plainly that nothing vouched for this key, so an
    operator reading the certificate cannot mistake it for a real one.
    """
    certificate = x509.load_der_x509_certificate(
        ak_cert.build_self_issued(ec.generate_private_key(ec.SECP256R1()).public_key()))

    assert ak_cert.ISSUER_NAME in certificate.issuer.rfc4514_string()


# --------------------------------------------------------------------------- #
# unmarshalling what tpm2-tools writes                                        #
# --------------------------------------------------------------------------- #

def test_size_prefixed_public_area_is_unwrapped():
    """tpm2_readpublic writes a TPM2B_PUBLIC: a UINT16 length then the
    TPMT_PUBLIC the verifier actually hashes.
    """
    public_area = bytes(range(80))

    assert tpm_handler._strip_tpm2b(struct.pack("!H", 80) + public_area) == public_area


def test_bare_public_area_is_left_alone():
    """Some builds write the TPMT_PUBLIC with no prefix. Its first field is
    the object type (0x0023 for ECC), which cannot be mistaken for a length
    that matches the remaining bytes.
    """
    public_area = struct.pack("!HH", 0x0023, 0x000B) + bytes(76)

    assert tpm_handler._strip_tpm2b(public_area) == public_area


def test_cert_info_is_recognised_by_its_magic_either_way():
    body = tpm_handler.TPM_GENERATED_VALUE + b"\x80\x17" + bytes(40)

    assert tpm_handler._strip_tpm2b(body, magic=tpm_handler.TPM_GENERATED_VALUE) == body
    prefixed = struct.pack("!H", len(body)) + body
    assert tpm_handler._strip_tpm2b(prefixed, magic=tpm_handler.TPM_GENERATED_VALUE) == body


def test_structure_without_the_expected_magic_is_an_error():
    """Better to fail here than to hand the IDP bytes it will reject as a
    signature mismatch, which says nothing about the real cause.
    """
    with pytest.raises(RuntimeError, match="does not start with"):
        tpm_handler._strip_tpm2b(bytes(40), magic=tpm_handler.TPM_GENERATED_VALUE)


def test_tpmt_signature_is_converted_to_der():
    """tpm2_certify's default output is a marshalled TPMT_SIGNATURE, while
    every verifier wants DER.
    """
    r, s = 0x11 * 32, 0x22 * 32
    r_bytes, s_bytes = r.to_bytes(32, "big"), s.to_bytes(32, "big")
    tpmt = (struct.pack("!HH", tpm_handler.TPM_ALG_ECDSA, 0x000B)
            + struct.pack("!H", 32) + r_bytes
            + struct.pack("!H", 32) + s_bytes)

    assert decode_dss_signature(tpm_handler._signature_to_der(tpmt)) == (r, s)


def test_already_der_signature_is_passed_through():
    key = ec.generate_private_key(ec.SECP256R1())
    der = key.sign(b"data", ec.ECDSA(hashes.SHA256()))

    assert decode_dss_signature(tpm_handler._signature_to_der(der)) == decode_dss_signature(der)


# --------------------------------------------------------------------------- #
# the hand-built TPM2_Certify command                                         #
# --------------------------------------------------------------------------- #

def test_certify_command_carries_the_qualifying_data():
    """The reason this command is marshalled by hand at all: tpm2-tools will
    not pass qualifying data to TPM2_Certify, and without it the attestation
    is not bound to a ceremony and every verifier rejects it.
    """
    qualifying = bytes(range(32))

    command = tpm_handler._certify_command(0x81002001, 0x81002002, qualifying)

    assert struct.pack("!H", len(qualifying)) + qualifying in command


def test_certify_command_header_is_well_formed():
    command = tpm_handler._certify_command(0x81002001, 0x81002002, bytes(32))

    tag, size, command_code = struct.unpack("!HII", command[:10])
    assert tag == tpm_handler.TPM_ST_SESSIONS
    assert command_code == tpm_handler.TPM_CC_CERTIFY
    # The declared size must cover the whole packet, header included, or the
    # TPM reads past the command or truncates it.
    assert size == len(command)


def test_certify_command_authorises_both_objects():
    """TPM2_Certify takes two handles, each needing its own authorisation. One
    session area would leave the TPM parsing the second as command data.
    """
    command = tpm_handler._certify_command(0x81002001, 0x81002002, bytes(32))

    object_handle, sign_handle = struct.unpack("!II", command[10:18])
    assert (object_handle, sign_handle) == (0x81002001, 0x81002002)
    authorisation_size = struct.unpack("!I", command[18:22])[0]
    assert authorisation_size == 18  # two password sessions, 9 bytes each


def test_certify_response_is_split_into_attest_and_signature():
    attest, signature = b"\xffTCG" + bytes(40), b"\x00\x18" + bytes(70)
    parameters = struct.pack("!H", len(attest)) + attest + signature
    response = (struct.pack("!HII", tpm_handler.TPM_ST_SESSIONS, 0, 0)
                + struct.pack("!I", len(parameters)) + parameters)

    parsed_attest, parsed_signature = tpm_handler._parse_certify_response(response)

    assert parsed_attest == struct.pack("!H", len(attest)) + attest
    assert parsed_signature == signature


def test_a_tpm_error_response_is_raised_not_parsed():
    """A non-zero response code means the parameters are absent; reading them
    anyway would yield convincing nonsense.
    """
    response = struct.pack("!HII", tpm_handler.TPM_ST_SESSIONS, 10, 0x000002D6)

    with pytest.raises(RuntimeError, match="0x000002D6"):
        tpm_handler._parse_certify_response(response)


# --------------------------------------------------------------------------- #
# binding the statement to one ceremony                                       #
# --------------------------------------------------------------------------- #

def _anchor(attest=None) -> AnchoredIdentity:
    return AnchoredIdentity(kind="internal_tpm", sign=lambda data: b"", public_key_pem=b"",
                            backend="test", attest=attest)


def _client_data() -> CollectedClientData:
    return CollectedClientData.create(
        type="webauthn.create", challenge=b"\x05" * 32, origin=ORIGIN)


def test_qualifying_data_is_the_hash_of_auth_data_and_client_data_hash():
    """WebAuthn's attToBeSigned. The TPM copies it into the certify
    structure's extraData, and the IDP recomputes it from the same two inputs
    — so a statement captured from one ceremony cannot be replayed into
    another.
    """
    captured = {}
    client_data = _client_data()
    auth_data = tpm_authenticator.AuthenticatorData.create(
        hashlib.sha256(RP_ID.encode()).digest(),
        tpm_authenticator.AuthenticatorData.FLAG.UP, 1)

    def attest(qualifying_data):
        captured["value"] = qualifying_data
        return {"ver": "2.0", "alg": -7, "x5c": [b""], "sig": b"", "certInfo": b"", "pubArea": b""}

    tpm_authenticator._attestation_object(auth_data, client_data, _anchor(attest))

    assert captured["value"] == hashlib.sha256(bytes(auth_data) + client_data.hash).digest()


def test_anchor_that_cannot_attest_produces_a_self_attested_credential():
    """The Windows CNG and USB paths have no TPM statement to offer. The
    credential is still built; it is the IDP that decides whether unproven
    hardware custody is acceptable.
    """
    auth_data = tpm_authenticator.AuthenticatorData.create(
        hashlib.sha256(RP_ID.encode()).digest(),
        tpm_authenticator.AuthenticatorData.FLAG.UP, 1)

    attestation_object = tpm_authenticator._attestation_object(
        auth_data, _client_data(), _anchor(attest=None))

    assert attestation_object.fmt == "none"


def test_a_failing_tpm_falls_back_rather_than_crashing_the_client():
    """A statement the TPM could not produce must surface as one clear
    rejection from the IDP, not a stack trace mid-ceremony.
    """
    auth_data = tpm_authenticator.AuthenticatorData.create(
        hashlib.sha256(RP_ID.encode()).digest(),
        tpm_authenticator.AuthenticatorData.FLAG.UP, 1)

    def attest(_qualifying_data):
        raise RuntimeError("tpm2_certify failed: TPM_RC_OBJECT_MEMORY")

    attestation_object = tpm_authenticator._attestation_object(
        auth_data, _client_data(), _anchor(attest))

    assert attestation_object.fmt == "none"
