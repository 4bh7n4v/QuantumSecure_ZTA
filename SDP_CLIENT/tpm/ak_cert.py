"""The X.509 certificate that carries the TPM attestation key (AK).

A WebAuthn `fmt="tpm"` attestation statement must include an `x5c` chain, and
the verifier takes the AK's public key from `x5c[0]` to check the signature
over certInfo. So even though the interesting cryptography is the TPM's
certify operation, the AK still has to arrive wrapped in a certificate.

Where that certificate comes from decides how much it is worth. In a
production deployment it is issued by an attestation CA that first proved,
through TPM credential activation against the chip's manufacturer-issued
endorsement key, that the AK really lives in genuine silicon; the resulting
chain is what an IDP walks back to a vendor root. This project has no such
CA, so the client issues the certificate to itself.

Why the signature on it is deliberately worthless
-------------------------------------------------
There is no way to make a self-signed AK certificate, and that is by design
in the TPM architecture rather than a gap here: an attestation key is created
`restricted`, and a restricted signing key will only ever sign data the TPM
itself produced. That restriction is exactly what makes the AK's signature
over a certify structure mean "the TPM asserts this" instead of merely
"someone asked the TPM to sign these bytes" — an unrestricted AK could be
asked to sign a hand-crafted TPMS_ATTEST naming a software key as
TPM-resident. Keeping the AK restricted is worth far more than a
self-signature would be, so the AK cannot sign its own certificate.

The certificate is therefore signed by an ephemeral key generated here and
discarded on return. It is a structurally valid X.509 container for the AK
public key and nothing more: no chain, no trust, nothing persisted, nothing
for an attacker to steal. Its issuer name says so in as many words, so an
operator reading the certificate cannot mistake it for a vendor-issued one.

Trust in the AK comes from elsewhere, and the IDP is written to match:
IDENTITY_PROVIDER/fido2_idp/tpm_trust.py records such a credential as `first-ak` /
`pinned-ak` rather than `vendor-root`, and once a deployment configures
IDP_TPM_ROOT_CA_DIR this certificate stops being accepted at all — correctly,
because it chains to nothing. What it still carries, together with the
certify structure it accompanies, is the property this project needs: the
credential key was generated inside the same TPM as the AK and is marked
non-duplicable, and that same TPM keeps signing for the identity over time.
"""

from __future__ import annotations

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ObjectIdentifier

from shared.utils.logger import get_logger, status

log = get_logger("TPM-AKCert")

# TCG OIDs. The first three name the chip inside the subjectAltName; the last
# is the extended key usage a WebAuthn verifier requires on an AK certificate
# (tcg-kp-AIKCertificate) — see the TPM attestation statement format in the
# WebAuthn spec, §8.3.
OID_TPM_MANUFACTURER = ObjectIdentifier("2.23.133.2.1")
OID_TPM_MODEL = ObjectIdentifier("2.23.133.2.2")
OID_TPM_VERSION = ObjectIdentifier("2.23.133.2.3")
OID_AIK_CERTIFICATE = ObjectIdentifier("2.23.133.8.3")

ISSUER_NAME = "ZTNA-SDP self-issued AK certificate (no attestation CA)"

_VALIDITY_DAYS = 3650


def build_self_issued(ak_public_key: ec.EllipticCurvePublicKey,
                      manufacturer: str = "id:00000000",
                      model: str = "ZTNA-SDP client TPM",
                      version: str = "id:00020000") -> bytes:
    """Return a DER AK certificate carrying `ak_public_key`.

    The certificate meets the WebAuthn requirements for a TPM attestation
    certificate: version 3, an empty subject, a critical subjectAltName naming
    the TPM, an extended key usage containing tcg-kp-AIKCertificate, and
    basicConstraints with CA false. Its signature is made by an ephemeral key
    that is discarded before this function returns — see the module docstring
    for why no meaningful signature is possible.
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    # An empty subject is mandatory for a TPM AK certificate, which is exactly
    # why subjectAltName must be critical: it becomes the certificate's only
    # identity.
    san = x509.SubjectAlternativeName([
        x509.DirectoryName(x509.Name([
            x509.NameAttribute(OID_TPM_MANUFACTURER, manufacturer),
            x509.NameAttribute(OID_TPM_MODEL, model),
            x509.NameAttribute(OID_TPM_VERSION, version),
        ])),
    ])

    certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, ISSUER_NAME)]))
        .public_key(ak_public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=_VALIDITY_DAYS))
        .add_extension(san, critical=True)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([OID_AIK_CERTIFICATE]), critical=False)
        .sign(ec.generate_private_key(ec.SECP256R1()), hashes.SHA256())
    )

    der = certificate.public_bytes(serialization.Encoding.DER)
    status(log, "Self-issued AK certificate built", bytes=len(der))
    return der
