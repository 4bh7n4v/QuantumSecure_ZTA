"""The project's own certificate authority (CA).

Used for exactly one link today: mutual TLS between the IDP and each SDP
Gateway. The admin creates the CA once, offline, with the IDP's admin_cli.py,
then issues one certificate for the IDP and one per Gateway (see
cert_utils.py). Whoever holds a certificate signed by this CA is trusted on
that link; nothing else is.

The CA private key signs every certificate, so it never leaves the admin's
machine and never goes into a Gateway bundle.
"""

from __future__ import annotations

import datetime
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

CA_CERT_NAME = "ca.crt"
CA_KEY_NAME = "ca.key"
CA_VALID_DAYS = 3650


class CAExists(FileExistsError):
    pass


def create(ca_dir: str | Path, common_name: str = "ZTNA-SDP Project CA") -> x509.Certificate:
    """Make a new CA key and self-signed CA certificate in `ca_dir`. Refuses
    to overwrite: a new CA silently invalidates every certificate issued so far."""
    ca_dir = Path(ca_dir)
    key_path, cert_path = ca_dir / CA_KEY_NAME, ca_dir / CA_CERT_NAME
    if key_path.exists() or cert_path.exists():
        raise CAExists(f"a CA already exists in {ca_dir}")

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=CA_VALID_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=False, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
            encipher_only=False, decipher_only=False), critical=True)
        .sign(key, hashes.SHA256())
    )

    ca_dir.mkdir(parents=True, exist_ok=True)
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    os.chmod(key_path, 0o600)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert


def load(ca_dir: str | Path) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    ca_dir = Path(ca_dir)
    key = serialization.load_pem_private_key((ca_dir / CA_KEY_NAME).read_bytes(), password=None)
    cert = x509.load_pem_x509_certificate((ca_dir / CA_CERT_NAME).read_bytes())
    return key, cert  # type: ignore[return-value]
