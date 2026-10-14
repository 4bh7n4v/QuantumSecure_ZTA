"""Trust-path evaluation for a WebAuthn `fmt="tpm"` attestation statement.

`python-fido2` (fido2/attestation/tpm.py) already does the *cryptographic*
half of TPM attestation for us: it parses the pubArea and certInfo, checks
that the pubArea describes the same public key as the credential in
authenticatorData, checks that certInfo's extraData is the hash of
(authenticatorData || clientDataHash), checks that certInfo's attested Name
is the Name of the pubArea, and verifies the attestation key's signature
over certInfo using the public key of x5c[0]. What it deliberately does NOT
do is decide whether that attestation key should be *trusted*, or say
anything about the properties of the certified key.

Those two questions are this module's job, and they are what make TPM
attestation worth enforcing:

  1. `credential_key_properties()` — read the TPMA_OBJECT attribute bits out
     of the pubArea. `fixedTPM | fixedParent | sensitiveDataOrigin` together
     are the TPM's own statement that the credential private key was
     generated inside this chip and can never be duplicated out of it. That
     is precisely the project rule "device identity is hardware-rooted, do
     not fall back to software-only identity", asserted by the hardware
     rather than claimed by the client.

  2. `evaluate_attestation_key()` — decide how much the attestation key (AK)
     itself is worth. In a production deployment the AK certificate chains
     to a TPM manufacturer's (or platform vendor's) attestation CA root, and
     that chain is what proves the chip is genuine silicon rather than a
     simulator. Drop those roots as PEM files into IDP_TPM_ROOT_CA_DIR and
     they are enforced.

     With no roots configured there is nothing to chain to — the lab case,
     and the only case available under WSL, where the anchor is an `swtpm`
     simulator that has no manufacturer certificate at all. Rather than
     silently accept any AK, the IDP pins the AK on a device's first
     enrolment: every later credential from that same (user, device) must be
     certified by the same attestation key. That does not prove the first
     enrolment came from real hardware, and this module never claims it
     does — `TrustPath.VENDOR_ROOT` and `TrustPath.PINNED_AK` are recorded
     distinctly, stored on the credential, and logged — but it does mean a
     device cannot later swap in a different TPM (or a software forgery)
     behind an already-trusted identity.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from fido2.attestation.base import InvalidData, verify_x509_chain
from fido2.attestation.tpm import ATTRIBUTES, TpmPublicFormat

from shared.config.settings import settings
from shared.utils.logger import get_logger, status

log = get_logger("IDP-TPMTrust")


class TrustPath(str, Enum):
    """How much the attestation key behind a credential is actually worth.

    Ordered strongest to weakest. Stored on the credential row so an operator
    can tell afterwards which credentials rest on proven silicon.
    """

    VENDOR_ROOT = "vendor-root"    # x5c chains to a configured TPM vendor / AttCA root
    PINNED_AK = "pinned-ak"        # matches the AK already pinned to this device
    FIRST_AK = "first-ak"          # first enrolment on this device; AK pinned now
    CONFLICTING_AK = "conflict"    # device already has a DIFFERENT AK pinned -> reject
    EXCEPTION = "exception"        # no proof; admitted on an expiring admin exception
    NOT_APPLICABLE = "n/a"         # non-TPM format, or no attestation at all


@dataclass
class KeyProperties:
    """The TPMA_OBJECT bits that matter for hardware key custody."""

    fixed_tpm: bool
    fixed_parent: bool
    sensitive_data_origin: bool

    @property
    def non_exportable(self) -> bool:
        """True when the TPM asserts the key was born in this chip and cannot
        be duplicated to another parent or another TPM.
        """
        return self.fixed_tpm and self.fixed_parent and self.sensitive_data_origin

    def missing(self) -> list[str]:
        return [
            name for name, present in (
                ("fixedTPM", self.fixed_tpm),
                ("fixedParent", self.fixed_parent),
                ("sensitiveDataOrigin", self.sensitive_data_origin),
            ) if not present
        ]


@dataclass
class AkEvaluation:
    trust_path: TrustPath
    ak_public_key: bytes   # DER SubjectPublicKeyInfo of the attestation key
    detail: str


# --------------------------------------------------------------------------- #
# 1. properties of the certified credential key                               #
# --------------------------------------------------------------------------- #

def credential_key_properties(pub_area: bytes) -> KeyProperties:
    """Parse the attestation statement's pubArea and return its custody bits.

    Raises InvalidData if the pubArea will not parse — by the time this is
    called python-fido2 has already parsed it once, so a failure here means
    the statement changed underneath us and must be treated as invalid.
    """
    try:
        parsed = TpmPublicFormat.parse(pub_area)
    except Exception as exc:  # noqa: BLE001 - normalised into InvalidData below
        raise InvalidData(f"unable to parse pubArea: {exc}") from exc

    return KeyProperties(
        fixed_tpm=bool(parsed.attributes & ATTRIBUTES.FIXED_TPM),
        fixed_parent=bool(parsed.attributes & ATTRIBUTES.FIXED_PARENT),
        sensitive_data_origin=bool(parsed.attributes & ATTRIBUTES.SENSITIVE_DATA_ORIGIN),
    )


# --------------------------------------------------------------------------- #
# 2. trust in the attestation key                                             #
# --------------------------------------------------------------------------- #

def load_roots(root_dir: str | None = None) -> list[x509.Certificate]:
    """Load every PEM certificate in the configured root store.

    A missing or empty directory is not an error — it selects the pinned-AK
    posture described in the module docstring. A file that will not parse IS
    an error worth shouting about, because a root store that silently drops
    certificates would silently weaken enforcement.
    """
    directory = Path(root_dir if root_dir is not None else settings.idp_tpm_root_ca_dir)
    if not directory.is_dir():
        return []

    roots: list[x509.Certificate] = []
    for pem_path in sorted(directory.glob("*.pem")) + sorted(directory.glob("*.crt")):
        try:
            roots.append(x509.load_pem_x509_certificate(pem_path.read_bytes()))
        except Exception as exc:  # noqa: BLE001 - one bad file must not hide the rest
            status(log, "Ignoring unreadable TPM root certificate",
                   path=str(pem_path), error=str(exc))
    return roots


def _chains_to_root(x5c: list[bytes], roots: list[x509.Certificate]) -> x509.Certificate | None:
    """Return the root that terminates this chain, or None.

    `x5c` is leaf-first, as WebAuthn requires. A TPM AK certificate is issued
    by an intermediate that is itself issued by the vendor root, so the chain
    handed to us may be several certificates long; we only have to supply the
    root and let fido2's `verify_x509_chain` walk every link.
    """
    if not x5c:
        return None
    try:
        top = x509.load_der_x509_certificate(x5c[-1])
    except Exception as exc:  # noqa: BLE001
        status(log, "Attestation chain contains an unparseable certificate", error=str(exc))
        return None

    for root in roots:
        if root.subject != top.issuer:
            continue
        try:
            verify_x509_chain([*x5c, root.public_bytes(serialization.Encoding.DER)])
        except Exception as exc:  # noqa: BLE001 - a failed candidate is not fatal
            status(log, "Attestation chain did not verify against a candidate root",
                   root=root.subject.rfc4514_string(), error=str(exc))
            continue
        return root
    return None


def evaluate_attestation_key(x5c: list[bytes], pinned_ak: bytes | None,
                             roots: list[x509.Certificate] | None = None) -> AkEvaluation:
    """Decide how far the attestation key behind this statement can be trusted.

    `pinned_ak` is the DER SubjectPublicKeyInfo already recorded for this
    (user, device), or None if this device has never enrolled a credential.
    """
    roots = load_roots() if roots is None else roots
    leaf = x509.load_der_x509_certificate(x5c[0])
    ak_public_key = leaf.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    if roots:
        root = _chains_to_root(x5c, roots)
        if root is not None:
            return AkEvaluation(
                trust_path=TrustPath.VENDOR_ROOT, ak_public_key=ak_public_key,
                detail=f"AK certificate chains to trusted root {root.subject.rfc4514_string()}",
            )
        # Roots ARE configured, so an unchainable AK is a hard failure: the
        # operator has declared which TPMs this deployment accepts.
        return AkEvaluation(
            trust_path=TrustPath.CONFLICTING_AK, ak_public_key=ak_public_key,
            detail=(f"AK certificate does not chain to any of the {len(roots)} configured "
                    "TPM root certificates"),
        )

    if pinned_ak is None:
        return AkEvaluation(
            trust_path=TrustPath.FIRST_AK, ak_public_key=ak_public_key,
            detail="no TPM root store configured; pinning this attestation key to the device",
        )
    if pinned_ak == ak_public_key:
        return AkEvaluation(
            trust_path=TrustPath.PINNED_AK, ak_public_key=ak_public_key,
            detail="attestation key matches the key pinned to this device",
        )
    return AkEvaluation(
        trust_path=TrustPath.CONFLICTING_AK, ak_public_key=ak_public_key,
        detail="attestation key does NOT match the key pinned to this device",
    )
