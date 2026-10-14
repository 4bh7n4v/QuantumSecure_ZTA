"""A software stand-in for a TPM, for testing the IDP's attestation checks.

The IDP's job in Milestone 2 is to accept a genuine TPM attestation statement
and reject every near-miss. Testing that needs statements to verify against,
and the client cannot supply them here — its path runs through `tpm2-tools`
against a chip this machine does not have.

So this module marshals the same TPM structures a real chip emits, from the
TPM 2.0 Structures specification (Part 2): a TPMT_PUBLIC public area, the
Name derived from it, and a TPMS_ATTEST certify structure, signed by a
software key standing in for the attestation key. Everything the IDP parses
is byte-identical to hardware output; only the source of the signature
differs, and the IDP cannot tell the difference — which is precisely the
point of the pinning and vendor-root distinctions in fido2_idp/tpm_trust.py,
and why this file is a test helper and never importable by the IDP itself.

Being able to forge a statement here is also what makes the negative tests
meaningful: each one takes a statement that is valid in every respect but
one, so a passing test says the IDP rejected it for that specific reason.
"""

from __future__ import annotations

import datetime
import hashlib
import struct

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ObjectIdentifier

# TPM 2.0 constants (Part 2, "Structures").
TPM_ALG_NULL = 0x0010
TPM_ALG_SHA256 = 0x000B
TPM_ALG_ECC = 0x0023
TPM_ECC_NIST_P256 = 0x0003
TPM_GENERATED_VALUE = b"\xffTCG"
TPM_ST_ATTEST_CERTIFY = b"\x80\x17"

# TPMA_OBJECT bits, matching fido2.attestation.tpm.ATTRIBUTES.
FIXED_TPM = 1 << 1
FIXED_PARENT = 1 << 4
SENSITIVE_DATA_ORIGIN = 1 << 5
USER_WITH_AUTH = 1 << 6
SIGN_ENCRYPT = 1 << 18

# What tpm/tpm_handler.py creates a credential key with: born in the chip,
# never duplicable out of it.
HARDWARE_BOUND = FIXED_TPM | FIXED_PARENT | SENSITIVE_DATA_ORIGIN | USER_WITH_AUTH | SIGN_ENCRYPT

OID_AIK_CERTIFICATE = ObjectIdentifier("2.23.133.8.3")
OID_TPM_MANUFACTURER = ObjectIdentifier("2.23.133.2.1")


def _tpm2b(data: bytes) -> bytes:
    return struct.pack("!H", len(data)) + data


def public_area(public_key: ec.EllipticCurvePublicKey,
                attributes: int = HARDWARE_BOUND) -> bytes:
    """TPMT_PUBLIC for an ECC P-256 key (Part 2, §12.2.4).

    The signing scheme is TPM_ALG_NULL because a WebAuthn verifier requires
    it: the credential key carries no fixed scheme, and each signature names
    its own hash algorithm instead.
    """
    numbers = public_key.public_numbers()
    parameters = struct.pack("!HHHH", TPM_ALG_NULL, TPM_ALG_NULL,
                             TPM_ECC_NIST_P256, TPM_ALG_NULL)
    unique = _tpm2b(numbers.x.to_bytes(32, "big")) + _tpm2b(numbers.y.to_bytes(32, "big"))
    return (
        struct.pack("!HHL", TPM_ALG_ECC, TPM_ALG_SHA256, attributes)
        + _tpm2b(b"")          # authPolicy: none
        + parameters
        + unique
    )


def name(pub_area: bytes) -> bytes:
    """The Name of an object: nameAlg || H_nameAlg(TPMT_PUBLIC) (Part 1, §16)."""
    return struct.pack("!H", TPM_ALG_SHA256) + hashlib.sha256(pub_area).digest()


def certify_info(attested_name: bytes, extra_data: bytes) -> bytes:
    """TPMS_ATTEST of type TPM_ST_ATTEST_CERTIFY (Part 2, §10.12.8)."""
    return (
        TPM_GENERATED_VALUE
        + TPM_ST_ATTEST_CERTIFY
        + _tpm2b(b"\x00" * 34)             # qualifiedSigner: the AK's own Name
        + _tpm2b(extra_data)               # what binds this to one ceremony
        + struct.pack("!QLLB", 0, 0, 0, 1)  # clockInfo
        + struct.pack("!Q", 0)             # firmwareVersion
        + _tpm2b(attested_name)            # TPMS_CERTIFY_INFO.name
        + _tpm2b(b"\x00" * 34)             # TPMS_CERTIFY_INFO.qualifiedName
    )


def ak_certificate(ak_public_key: ec.EllipticCurvePublicKey,
                   issuer_key: ec.EllipticCurvePrivateKey | None = None,
                   issuer_name: str = "test attestation CA",
                   ca: bool = False) -> bytes:
    """An AK certificate meeting WebAuthn's requirements, in DER.

    Signed by `issuer_key` when given, so a test can build a real chain up to
    a root; otherwise self-signed and therefore chaining to nothing, which is
    what the client's own tpm/ak_cert.py produces.
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    signing_key = issuer_key or ec.generate_private_key(ec.SECP256R1())
    return (
        x509.CertificateBuilder()
        .subject_name(x509.Name([]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name)]))
        .public_key(ak_public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([
            x509.DirectoryName(x509.Name([
                x509.NameAttribute(OID_TPM_MANUFACTURER, "id:FFFFF1D0"),
            ])),
        ]), critical=True)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([OID_AIK_CERTIFICATE]), critical=False)
        .sign(signing_key, hashes.SHA256())
        .public_bytes(serialization.Encoding.DER)
    )


def root_certificate(key: ec.EllipticCurvePrivateKey, common_name: str) -> x509.Certificate:
    """A self-signed CA certificate, standing in for a TPM vendor root."""
    now = datetime.datetime.now(datetime.timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )


def pem(certificate: x509.Certificate) -> bytes:
    return certificate.public_bytes(serialization.Encoding.PEM)
