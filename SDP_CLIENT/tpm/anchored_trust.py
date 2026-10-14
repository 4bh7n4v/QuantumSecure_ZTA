"""Selects this device's hardware root of trust, fail-closed, on both
Linux and Windows.

Priority order (per project policy: "TPM anchored trust — device identity is
hardware-rooted, do not fall back to software-only identity"):
    1. Internal TPM (the onboard chip), through whichever backend can
       actually reach it on this platform — see `_internal_backends()`.
    2. External TPM — in practice, a USB CTAP2 FIDO2 security key, since
       that is the externally-attachable hardware root this project can
       actually drive end to end (standalone USB TPM dongles are rare and
       have no standard OS-level interface to probe generically).
    3. Neither present -> TrustAnchorUnavailable. The caller MUST abort the
       connection attempt; there is no software-only fallback.

The two internal-TPM backends exist because the platforms expose the chip
completely differently, not because the security model differs:

  - Linux (tpm/tpm_handler.py) drives `tpm2-tools` against /dev/tpmrm0.
  - Windows (tpm/windows_tpm.py) drives CNG's Microsoft Platform Crypto
    Provider, because Windows has no /dev node, no Linux TSS, and no
    tpm2-tools build at all.

Both generate a non-exportable ECC P-256 key inside the chip and have the
chip produce every signature, so `AnchoredIdentity` looks identical to
callers either way; `backend` records which one served the request.

WSL is the one case where a SOFTWARE TPM is accepted. A WSL2 kernel does
not pass the host's physical TPM through, so there is no chip to reach; an
`swtpm` simulator implements the identical TPM2 command set and is the
recognised development stand-in. It is attempted ONLY under WSL, and only
after the real-device probe has failed, so a native Linux or Windows host
can never silently end up on a simulated anchor.
"""

from __future__ import annotations

import platform
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

import fido2.hid as fido2_hid
from cryptography.hazmat.primitives import serialization

from tpm import attestation, tpm_handler, windows_tpm, windows_webauthn
from shared.config.settings import settings
from shared.utils.logger import get_logger, status

log = get_logger("AnchoredTrust")

TPM_BASE_DIR = Path("./certs/tpm_keys")

# The kernel's TPM device files, newest interface first. /dev/tpmrm0 is the
# in-kernel resource manager, which multiplexes access; /dev/tpm0 is the raw
# device, used only where no resource manager exists. Both are named
# explicitly rather than left to tpm2-tools' default — see _internal_backends.
DEVICE_TCTIS = ("device:/dev/tpmrm0", "device:/dev/tpm0")

# Backend identifiers recorded on the anchor, for logs and for telling a
# real chip apart from a simulator after the fact.
BACKEND_TPM2_TOOLS = "tpm2-tools"
BACKEND_WINDOWS_WEBAUTHN = "windows-webauthn"
BACKEND_WINDOWS_CNG = "windows-cng"
BACKEND_SWTPM = "swtpm"
BACKEND_CTAP2 = "usb-ctap2"

# Backends that hand the whole WebAuthn ceremony to something that already
# implements it, instead of this client assembling the protocol objects. The
# distinction matters only to fido2_agent/client.py, which has to pick a
# driver; nothing above it, and nothing on the IDP, can tell the difference.
DELEGATED_BACKENDS = (BACKEND_WINDOWS_WEBAUTHN, BACKEND_CTAP2)


class TrustAnchorUnavailable(RuntimeError):
    """Raised when neither an internal nor an external hardware root of trust
    is available. Callers must treat this as fatal and abort the connection —
    there is no software-only identity fallback in this system.
    """


@dataclass
class AnchoredIdentity:
    kind: str  # "internal_tpm" | "external_tpm"
    sign: Optional[Callable[[bytes], bytes]]      # set for internal_tpm
    public_key_pem: bytes                          # set for internal_tpm
    ctap_device: Optional[object] = None           # set for external_tpm
    backend: str = ""                              # which backend served this anchor
    simulated: bool = False                        # True only for swtpm under WSL
    # Produce a WebAuthn TPM attestation statement over the given qualifying
    # data (M2, tpm/attestation.py). None when this backend cannot prove key
    # custody to the IDP: the Windows CNG path, whose TPM key attestation is a
    # Microsoft-specific claim rather than a WebAuthn statement, and the
    # external USB key, which produces its own "packed" attestation through
    # the CTAP2 authenticator instead. The IDP's policy decides whether a
    # credential without one may be enrolled.
    attest: Optional[Callable[[bytes], dict]] = None


def is_wsl() -> bool:
    """True when running under WSL. Checked via the kernel release string,
    which carries a "microsoft"/"WSL" marker on every WSL kernel.
    """
    if sys.platform != "linux":
        return False
    release = platform.uname().release.lower()
    return "microsoft" in release or "wsl" in release


def _internal_backends() -> list[tuple[str, str | None]]:
    """Ordered (backend, tcti) pairs to probe for an internal TPM on this
    platform. `tcti` is meaningful only for the tpm2-tools backend.
    """
    if sys.platform == "win32":
        # Windows Hello first: it is the only Windows path that can prove
        # hardware key custody to the IDP, because Windows will issue the
        # TPM's certify command on its own behalf but not on CNG's. CNG stays
        # as a fallback for a machine with a TPM but no usable Hello
        # enrolment — the key still lives in the chip there, it just cannot be
        # proven to, so the IDP will refuse it while enforcement is on.
        return [(BACKEND_WINDOWS_WEBAUTHN, None), (BACKEND_WINDOWS_CNG, None)]

    candidates: list[tuple[str, str | None]] = []
    # An explicit TPM_TCTI always wins — it is how an operator points the
    # client at a non-default chip or a deliberately chosen simulator.
    if settings.tpm_tcti:
        candidates.append((BACKEND_TPM2_TOOLS, settings.tpm_tcti))
    # The real onboard chip, named explicitly. Leaving the target unset would
    # be shorter but is unsafe: with no -T, tpm2-tools walks a fallback chain
    # of /dev/tpmrm0, then /dev/tpm0, then a SIMULATOR on the default port. A
    # machine with no chip but a stray swtpm running would therefore probe
    # "successfully" and be recorded as real hardware (simulated=False),
    # quietly defeating the rule that a software TPM is acceptable under WSL
    # and nowhere else. Naming the device files keeps "internal TPM" honest.
    candidates.extend((BACKEND_TPM2_TOOLS, device) for device in DEVICE_TCTIS)
    # Software TPM, WSL only — see the module docstring.
    if is_wsl():
        candidates.append((BACKEND_SWTPM, settings.tpm_swtpm_tcti))
    return candidates


def _anchor_from_windows_hello() -> AnchoredIdentity:
    """Windows Hello holds the credential key and signs with it internally, so
    there is no signing callable and no public key to hand out here — the
    ceremony is delegated wholesale (fido2_agent/windows_authenticator.py).
    `attest` stays None for the same reason: Windows produces the complete
    attestation object itself rather than a statement this client assembles.
    """
    return AnchoredIdentity(
        kind="internal_tpm",
        sign=None,
        public_key_pem=b"",
        backend=BACKEND_WINDOWS_WEBAUTHN,
    )


def _anchor_from_windows_tpm(username: str) -> AnchoredIdentity:
    key_name = windows_tpm.key_name_for(username)
    key = windows_tpm.load_signing_key(key_name) or windows_tpm.create_signing_key(key_name)
    public_key = windows_tpm.load_public_key(key)
    return AnchoredIdentity(
        kind="internal_tpm",
        sign=lambda data: windows_tpm.sign(key, data),
        public_key_pem=_pem(public_key),
        backend=BACKEND_WINDOWS_CNG,
    )


def _anchor_from_tpm2_tools(username: str, tcti: str | None, backend: str) -> AnchoredIdentity:
    workdir = TPM_BASE_DIR / username
    key = tpm_handler.load_signing_key(workdir, tcti) or tpm_handler.create_signing_key(workdir, tcti)
    public_key = tpm_handler.load_public_key(key)

    # Only this backend can certify the credential key to the IDP today, and
    # only when tpm2_certify is installed. Missing tools degrade the anchor to
    # an unattested one rather than failing it: the chip still holds the key,
    # and it is the IDP that decides whether unproven custody is acceptable.
    can_attest = attestation.available()
    if not can_attest:
        status(log, "tpm2_certify unavailable - this device cannot prove key custody to the IDP")

    return AnchoredIdentity(
        kind="internal_tpm",
        sign=lambda data: tpm_handler.sign(key, data, tcti),
        public_key_pem=_pem(public_key),
        backend=backend,
        simulated=(backend == BACKEND_SWTPM),
        attest=(lambda qualifying_data: attestation.build_statement(
            key, workdir, qualifying_data, tcti)) if can_attest else None,
    )


def _pem(public_key) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def select_trust_anchor(username: str, tcti: str | None = None) -> AnchoredIdentity:
    """`username` namespaces the credential key. This is what lets several
    people share one physical device/TPM safely: each verified username gets
    its own key in the same chip, created once at registration and reloaded
    (never regenerated) on every later authenticate() — without this, a
    shared TPM would otherwise have no way to keep two people's credentials
    distinct, which is exactly the gap this project's first-factor
    username/password step and this per-username namespacing are both meant
    to close together.

    `tcti` overrides the probe order entirely and forces the tpm2-tools
    backend; it exists for tests and for callers that already know which
    chip to talk to.
    """
    status(log, "Probing internal TPM...", platform=sys.platform,
           wsl=is_wsl(), username=username)

    if tcti is not None:
        if not tpm_handler.probe(tcti):
            raise TrustAnchorUnavailable(f"no TPM responded on the requested TCTI {tcti!r}")
        status(log, "Using internal TPM as hardware trust anchor (explicit TCTI)", tcti=tcti)
        return _anchor_from_tpm2_tools(username, tcti, BACKEND_TPM2_TOOLS)

    for backend, backend_tcti in _internal_backends():
        if backend == BACKEND_WINDOWS_WEBAUTHN:
            if not windows_webauthn.probe():
                continue
            status(log, "Using Windows Hello as hardware trust anchor - the OS drives the "
                        "ceremony and attests the key from the TPM", backend=backend)
            return _anchor_from_windows_hello()

        if backend == BACKEND_WINDOWS_CNG:
            if not windows_tpm.probe():
                continue
            status(log, "Using internal TPM as hardware trust anchor", backend=backend)
            return _anchor_from_windows_tpm(username)

        if not tpm_handler.probe(backend_tcti):
            continue
        if backend == BACKEND_SWTPM:
            status(log, "Using SOFTWARE TPM (swtpm) as hardware trust anchor - WSL only",
                   backend=backend, tcti=backend_tcti)
        else:
            status(log, "Using internal TPM as hardware trust anchor",
                   backend=backend, tcti=backend_tcti or "(default device)")
        return _anchor_from_tpm2_tools(username, backend_tcti, backend)

    status(log, "Internal TPM not available - probing external USB security key...")
    device = next(fido2_hid.list_devices(), None)
    if device is not None:
        status(log, "External USB CTAP2 security key found", device=str(device))
        return AnchoredIdentity(kind="external_tpm", sign=None, public_key_pem=b"",
                                ctap_device=device, backend=BACKEND_CTAP2)

    status(log, "No internal or external hardware trust anchor found - refusing to continue")
    raise TrustAnchorUnavailable(
        "Neither an internal TPM nor an external USB security key is present. "
        "This project does not fall back to software-only identity - aborting connection."
    )
