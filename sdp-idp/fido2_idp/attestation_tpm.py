"""TPM attestation verification for the IDP.

Milestone 1: this is the SEAM only. `python-fido2` verifies the WebAuthn
structure and the assertion/registration signature; this module is the hook
where genuine TPM attestation (`fmt="tpm"`: pubArea/certInfo parse, AK
signature check, EK certificate-chain validation to a trusted TPM-vendor
root) will be enforced in Milestone 2.

Until then it inspects and logs the attestation format the client sent and
records whether the credential is hardware-attested, without rejecting a
self-attested (`fmt="none"`) credential. Every field it looks at is logged
so that when M2 turns on enforcement, failures are already legible.
"""

from __future__ import annotations

from dataclasses import dataclass

from shared.utils.logger import get_logger, status

log = get_logger("IDP-Attest")

# Flip to True in Milestone 2 (or via env) to require a verified TPM
# attestation statement for every new credential.
ENFORCE_TPM_ATTESTATION = False


@dataclass
class AttestationResult:
    fmt: str
    hardware_attested: bool
    detail: str


class AttestationRejected(ValueError):
    pass


def inspect_registration(auth_data, attestation_object) -> AttestationResult:
    """Called by fido2_idp.server after `Fido2Server.register_complete` has
    already checked the WebAuthn structure + signature. `attestation_object`
    is the fido2 `AttestationObject`.
    """
    fmt = getattr(attestation_object, "fmt", "unknown")
    status(log, "Inspecting attestation statement", fmt=fmt,
           aaguid=auth_data.credential_data.aaguid.hex(),
           has_att_stmt=bool(getattr(attestation_object, "att_stmt", None)))

    if fmt == "tpm":
        # M2: parse att_stmt {ver, alg, x5c, sig, certInfo, pubArea}, verify
        # the AK signature over certInfo, confirm pubArea matches the
        # credential public key, and walk x5c to a trusted EK root.
        status(log, "TPM attestation statement present - full verification lands in Milestone 2")
        return AttestationResult(fmt="tpm", hardware_attested=True,
                                 detail="tpm attestation accepted without chain check (M1)")

    if fmt in ("packed", "android-key", "apple", "fido-u2f"):
        status(log, "Hardware attestation statement present", fmt=fmt)
        return AttestationResult(fmt=fmt, hardware_attested=True,
                                 detail=f"{fmt} attestation accepted (M1)")

    # fmt == "none" — self-attested (internal-TPM path builds this today
    # because python-fido2 ships no TPM verifier).
    if ENFORCE_TPM_ATTESTATION:
        status(log, "Rejecting self-attested credential - TPM attestation is required")
        raise AttestationRejected("self-attested credential rejected: TPM attestation required")

    status(log, "Self-attested credential accepted (M1: attestation enforcement off)", fmt=fmt)
    return AttestationResult(fmt="none", hardware_attested=False,
                             detail="self-attested; hardware not cryptographically proven")
