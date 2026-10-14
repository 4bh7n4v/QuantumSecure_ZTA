"""Certificates issued by the project CA, and the TLS settings both ends of
the IDP <-> Gateway link use.

Two kinds of certificate:

  - server  the IDP's. Names the host names / IPs the Gateway dials, so the
            Gateway can check it reached the real IDP.
  - client  one per Gateway. Its common name IS the Gateway's id (e.g.
            "gw-1"). The IDP files a Gateway's public key under that name,
            never under anything the Gateway writes in the request.

The extended-key-usage field says which kind a certificate is, so a server
certificate cannot be presented as a Gateway's and the other way round.
"""

from __future__ import annotations

import datetime
import hashlib
import ipaddress
import os
import ssl
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

CERT_VALID_DAYS = 365


def _san(hosts: list[str]) -> x509.SubjectAlternativeName:
    names: list[x509.GeneralName] = []
    for host in hosts:
        try:
            names.append(x509.IPAddress(ipaddress.ip_address(host)))
        except ValueError:
            names.append(x509.DNSName(host))
    return x509.SubjectAlternativeName(names)


def issue(ca_key: ec.EllipticCurvePrivateKey, ca_cert: x509.Certificate,
          common_name: str, kind: str, out_dir: str | Path,
          hosts: list[str] | None = None, file_stem: str | None = None) -> tuple[Path, Path]:
    """Issue a server or client certificate. Writes <file_stem>.crt and
    <file_stem>.key (file_stem defaults to the common name) into out_dir and
    returns their paths."""
    if kind not in ("server", "client"):
        raise ValueError("kind must be 'server' or 'client'")
    if kind == "server" and not hosts:
        raise ValueError("a server certificate needs at least one host name or IP")

    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    usage = ExtendedKeyUsageOID.SERVER_AUTH if kind == "server" else ExtendedKeyUsageOID.CLIENT_AUTH
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=CERT_VALID_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
    )
    if hosts:
        builder = builder.add_extension(_san(hosts), critical=False)
    cert = builder.sign(ca_key, hashes.SHA256())

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = file_stem or common_name
    cert_path, key_path = out_dir / f"{stem}.crt", out_dir / f"{stem}.key"
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    os.chmod(key_path, 0o600)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert_path, key_path


def server_context(cert_path: str, key_path: str, ca_path: str) -> ssl.SSLContext:
    """The IDP's side: present the server certificate, and refuse any peer
    that does not present a certificate signed by the project CA."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(cert_path, key_path)
    ctx.load_verify_locations(ca_path)
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def client_context(cert_path: str, key_path: str, ca_path: str) -> ssl.SSLContext:
    """The Gateway's side: present the Gateway certificate, and trust only an
    IDP whose certificate the project CA signed for the host being dialled."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(cert_path, key_path)
    ctx.load_verify_locations(ca_path)
    return ctx  # PROTOCOL_TLS_CLIENT already requires and checks the host name


def gateway_id_from_peer(der_cert: bytes | None) -> str:
    """The Gateway id a verified peer certificate carries. Raises ValueError
    unless it is a client (Gateway) certificate with a common name."""
    if not der_cert:
        raise ValueError("no peer certificate")
    cert = x509.load_der_x509_certificate(der_cert)
    try:
        usages = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound as exc:
        raise ValueError("certificate has no extended key usage") from exc
    if ExtendedKeyUsageOID.CLIENT_AUTH not in usages:
        raise ValueError("certificate is not a Gateway (client) certificate")
    names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not names or not names[0].value:
        raise ValueError("certificate has no common name")
    return str(names[0].value)


def fingerprint(data: bytes) -> str:
    """Short SHA-256 fingerprint, for an admin to compare by eye on two machines."""
    digest = hashlib.sha256(data).hexdigest()
    return ":".join(digest[i:i + 4] for i in range(0, 32, 4))
