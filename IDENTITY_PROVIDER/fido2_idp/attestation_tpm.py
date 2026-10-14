"""TPM attestation enforcement for the IDP — Milestone 2.

Milestone 1 left this file as a seam: it logged whichever attestation format
the client happened to send and accepted all of them, because nothing was
verifying attestation statements at all. That was true in a stronger sense
than the M1 comments admitted — `Fido2Server` ignores attestation unless it
is handed a `verify_attestation` callable, and it was not being handed one,
so `attestation="direct"` bought nothing.

M2 closes that. Two functions, deliberately separate:

  `verify_attestation_statement()` is wired into `Fido2Server` as its
  `verify_attestation` hook, so the attestation signature is checked inside
  the same library call that checks the rest of the WebAuthn structure and
  cannot be skipped by a later refactor of this module. It answers "is this
  statement internally valid and does it sign for THIS ceremony?".

  `decide()` runs afterwards, in fido2_idp/server.py, and answers the two
  questions the library leaves open: does the pubArea say the credential key
  is non-exportable and TPM-born, and is the attestation key that signed for
  it one we trust (see fido2_idp/tpm_trust.py). Only `decide()` may reject on
  policy grounds, so the whole policy decision reads in one place.

Enforcement is fail-closed by default (IDP_ENFORCE_TPM_ATTESTATION, see
shared/config/settings.py). With it on, a self-attested `fmt="none"`
credential — what a client sends when it has no way to prove hardware
custody — is refused at registration. That is the point of the milestone:
before M2 the "hardware-rooted identity" rule was asserted by the client and
believed by the IDP; after it, the authenticator has to prove it.
"""

from __future__ import annotations

from dataclasses import dataclass

from fido2.attestation.base import Attestation, InvalidAttestation

from fido2_idp import tpm_trust
from fido2_idp.tpm_trust import TrustPath
from store.attestation_exceptions import AttestationException
from shared.config.settings import settings
from shared.utils.logger import field, get_logger, status

log = get_logger("IDP-Attest")

# Formats whose attestation statement carries an authenticator-manufacturer
# certificate. python-fido2 verifies that certificate's signature over this
# ceremony's data before we get here, so reaching `decide()` with one of these
# already means a hardware authenticator signed for the credential. Only "tpm"
# additionally describes the *properties* of the key it attests, which is why
# it gets the extra scrutiny below.
_HARDWARE_FORMATS = ("packed", "android-key", "android-safetynet", "apple", "fido-u2f")


@dataclass
class AttestationDecision:
    fmt: str
    hardware_attested: bool
    trust_path: str
    ak_public_key: bytes | None
    detail: str


class AttestationRejected(ValueError):
    """Registration refused on attestation grounds. Surfaced to the client as
    HTTP 400 by api/routes.py, and recorded as a denied auth event.
    """


# --------------------------------------------------------------------------- #
# 1. cryptographic verification - wired into Fido2Server                      #
# --------------------------------------------------------------------------- #

def verify_attestation_statement(attestation_object, client_data_hash: bytes) -> None:
    """`Fido2Server(verify_attestation=...)` hook. Raises on failure.

    Delegates to python-fido2's per-format verifier. For "tpm" that means:
    pubArea describes the same public key as the credential in
    authenticatorData; certInfo is a well-formed TPMS_ATTEST of type
    TPM_ST_ATTEST_CERTIFY with TPM_GENERATED_VALUE magic; its extraData is
    the hash of (authenticatorData || clientDataHash), which binds the
    statement to this ceremony's challenge; its attested Name is the Name of
    the pubArea; and x5c[0]'s public key verifies the signature over certInfo.
    """
    fmt = attestation_object.fmt
    verifier = Attestation.for_type(fmt)()
    try:
        result = verifier.verify(
            attestation_object.att_stmt, attestation_object.auth_data, client_data_hash)
    except InvalidAttestation as exc:
        status(log, "Attestation statement FAILED cryptographic verification",
               fmt=fmt, error=str(exc))
        raise AttestationRejected(f"invalid {fmt} attestation statement: {exc}") from exc

    status(log, "Attestation statement cryptographically verified",
           fmt=fmt, attestation_type=result.attestation_type.name,
           chain_length=len(result.trust_path))


# --------------------------------------------------------------------------- #
# 2. policy decision - called from fido2_idp/server.py                        #
# --------------------------------------------------------------------------- #

def decide(auth_data, attestation_object, pinned_ak: bytes | None,
           exception: AttestationException | None = None) -> AttestationDecision:
    """Turn a verified attestation statement into an enrolment decision.

    `pinned_ak` is the attestation-key SPKI already recorded for this
    (user, device), or None when this device has not enrolled before.
    `exception` is an administrator's standing permission for this device to
    enrol without proof, if one is live — see store/attestation_exceptions.py.
    """
    fmt = getattr(attestation_object, "fmt", "unknown")
    att_stmt = getattr(attestation_object, "att_stmt", {}) or {}
    status(log, "Evaluating attestation", fmt=fmt,
           aaguid=auth_data.credential_data.aaguid.hex(),
           enforcing=settings.idp_enforce_tpm_attestation)

    if fmt == "tpm":
        decision = _decide_tpm(att_stmt, pinned_ak)
    elif fmt in _HARDWARE_FORMATS:
        decision = AttestationDecision(
            fmt=fmt, hardware_attested=True, trust_path=TrustPath.NOT_APPLICABLE.value,
            ak_public_key=None,
            detail=f"{fmt} attestation verified against the authenticator's own certificate",
        )
    else:
        # fmt == "none": the client had no way to prove hardware custody. The
        # key may well be in a TPM — the internal-TPM path really does hold it
        # there — but nothing here proves it, so it cannot be recorded as
        # hardware-attested.
        decision = AttestationDecision(
            fmt=fmt, hardware_attested=False, trust_path=TrustPath.NOT_APPLICABLE.value,
            ak_public_key=None,
            detail="self-attested; hardware custody is claimed by the client, not proven",
        )

    _enforce(decision, exception)
    return decision


def _decide_tpm(att_stmt: dict, pinned_ak: bytes | None) -> AttestationDecision:
    # Everything read here was already parsed once by the verification hook, so
    # a failure means the statement is malformed in a way that verification did
    # not model. Refuse rather than let it escape as a 500 from api/routes.py,
    # which only knows how to turn a ValueError into a client-facing error.
    try:
        properties = tpm_trust.credential_key_properties(att_stmt["pubArea"])
        evaluation = tpm_trust.evaluate_attestation_key(list(att_stmt["x5c"]), pinned_ak)
    except AttestationRejected:
        raise
    except Exception as exc:  # noqa: BLE001
        status(log, "REJECTED - TPM attestation statement could not be evaluated", error=str(exc))
        raise AttestationRejected(f"malformed tpm attestation statement: {exc}") from exc

    status(log, "TPM credential-key custody bits read from pubArea",
           fixed_tpm=properties.fixed_tpm, fixed_parent=properties.fixed_parent,
           sensitive_data_origin=properties.sensitive_data_origin)
    status(log, "TPM attestation-key trust evaluated",
           trust_path=evaluation.trust_path.value, detail=evaluation.detail)

    if not properties.non_exportable:
        return AttestationDecision(
            fmt="tpm", hardware_attested=False, trust_path=evaluation.trust_path.value,
            ak_public_key=evaluation.ak_public_key,
            detail=("TPM attested a key that is not hardware-bound; missing "
                    + "|".join(properties.missing())),
        )

    return AttestationDecision(
        fmt="tpm", hardware_attested=True, trust_path=evaluation.trust_path.value,
        ak_public_key=evaluation.ak_public_key, detail=evaluation.detail,
    )


def _enforce(decision: AttestationDecision,
             exception: AttestationException | None = None) -> None:
    """Apply policy. Raises AttestationRejected to refuse the enrolment.

    A conflicting attestation key is refused regardless of the enforcement
    flag AND regardless of any exception. Turning enforcement off, or granting
    a device an exception, both say "this device cannot prove hardware
    custody"; neither says "accept an attestation key that contradicts the one
    already pinned to this device", which is not missing evidence but evidence
    that the device's hardware root changed underneath an established identity.
    """
    if decision.trust_path == TrustPath.CONFLICTING_AK.value:
        status(log, "REJECTED - attestation key is not the one this device is trusted with",
               detail=decision.detail)
        raise AttestationRejected(f"untrusted TPM attestation key: {decision.detail}")

    if not decision.hardware_attested and settings.idp_enforce_tpm_attestation:
        if exception is None:
            status(log, "REJECTED - hardware attestation is required and was not proven",
                   fmt=decision.fmt, detail=decision.detail)
            raise AttestationRejected(
                f"hardware attestation required, got fmt={decision.fmt!r}: {decision.detail}")

        # Admitted on an administrator's explicit, expiring authority. The
        # credential is still recorded as unattested: the exception permits the
        # enrolment, it does not invent a proof that was never given.
        decision.trust_path = TrustPath.EXCEPTION.value
        decision.detail = (f"{decision.detail}; admitted by an administrator exception "
                           f"granted by {exception.granted_by}: {exception.reason}")
        status(log, "ADMITTED WITHOUT PROOF on an administrator exception",
               fmt=decision.fmt, granted_by=exception.granted_by,
               reason=exception.reason,
               days_remaining=round(exception.days_remaining, 1))
        return

    if not decision.hardware_attested:
        status(log, "Accepted WITHOUT proven hardware custody - enforcement is disabled",
               fmt=decision.fmt, detail=decision.detail)
    else:
        status(log, "Accepted - hardware custody proven", fmt=decision.fmt,
               trust_path=decision.trust_path)


# --------------------------------------------------------------------------- #
# startup posture                                                             #
# --------------------------------------------------------------------------- #

def startup_report() -> None:
    """Print the attestation posture at IDP boot, so an operator can see from
    the first screen of logs what this instance will and will not enrol.
    """
    roots = tpm_trust.load_roots()
    field(log, "TPM attestation enforced", settings.idp_enforce_tpm_attestation)
    field(log, "TPM root certificate store", settings.idp_tpm_root_ca_dir)
    field(log, "Trusted TPM roots loaded", len(roots))
    if roots:
        field(log, "Attestation-key trust", "vendor chain (x5c must reach a configured root)")
    else:
        field(log, "Attestation-key trust",
              "per-device pinning (no vendor roots configured - genuine silicon is NOT proven)")
    if not settings.idp_enforce_tpm_attestation:
        field(log, "WARNING",
              "self-attested credentials will be accepted; set IDP_ENFORCE_TPM_ATTESTATION=true")
