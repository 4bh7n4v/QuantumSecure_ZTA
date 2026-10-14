"""Windows platform authenticator (Windows Hello), via `webauthn.dll`.

Why this exists alongside tpm/windows_tpm.py
--------------------------------------------
Both reach the same TPM; they differ in how much of the WebAuthn ceremony
Windows performs, and that difference decides whether hardware custody can be
proven at all.

`windows_tpm.py` uses CNG to create a TPM-resident key and sign with it, and
this client then hand-builds the WebAuthn objects around those signatures.
That works, but CNG will not issue the TPM's certify command, and Windows'
own key attestation (`NCryptCreateClaim`) comes back in a Microsoft-defined
container rather than the WebAuthn one. So that path can never produce the
attestation statement the IDP requires — not because the chip cannot do it,
but because the interface does not expose it.

Windows already solves this internally for Windows Hello: `webauthn.dll` is
the OS's own FIDO2 implementation, it drives the TPM directly, and it returns
a complete, standard attestation object. Handing it the ceremony gets the
proof the IDP wants and, unlike the Linux path, an attestation certificate
that chains to a real Microsoft attestation root — so a deployment that loads
those roots into IDP_TPM_ROOT_CA_DIR gets the strongest trust level the IDP
can record, with genuine hardware actually proven rather than merely pinned.

The trade is that Windows manages the credential key inside Windows Hello
instead of us naming it in CNG, and the user confirms with a Hello PIN,
face or fingerprint. Both are appropriate: the key is still non-duplicable in
the TPM, and the prompt is a real user-verification step.

Nothing above this module is platform-aware. This produces the same standard
objects the Linux backend does, so fido2_agent/ and the entire IDP stay
identical across platforms.

CAVEAT, as for the rest of the Windows code here: the structure layouts and
constants below follow Microsoft's `webauthn.h`, but nothing in this file has
been executed — this repository is developed on WSL2, which has no
`webauthn.dll`. The conversion layer built on top of it
(fido2_agent/windows_authenticator.py) IS covered by tests, because it can be
driven with recorded output. Field order in a ctypes structure is
load-bearing, so treat this file as unverified until it has run on Windows.
"""

from __future__ import annotations

import ctypes
import sys
from ctypes import POINTER, byref, c_ubyte, c_void_p, c_wchar_p

from shared.utils.logger import get_logger, status

log = get_logger("WinWebAuthn")

# --------------------------------------------------------------------------- #
# constants (webauthn.h)                                                      #
# --------------------------------------------------------------------------- #

S_OK = 0

WEBAUTHN_HASH_ALGORITHM_SHA_256 = "SHA-256"
WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY = "public-key"

WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256 = -7

# Only the onboard authenticator will do: a cross-platform (USB) key is
# reached through fido2_agent/external_authenticator.py instead, and letting
# Windows offer one here would silently bypass that path.
WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM = 1

WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED = 1

# Ask for the real attestation statement. Without this Windows strips it to
# fmt="none" and the IDP has nothing to verify.
WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT = 3

# Structure versions. The small input structures have only ever had one
# version, so 1 is current for them.
WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION = 1
WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION = 1
WEBAUTHN_CLIENT_DATA_CURRENT_VERSION = 1
WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION = 1
WEBAUTHN_CREDENTIAL_CURRENT_VERSION = 1

# Options structure version. Measured on a Dell G15 with
# tools/webauthn_variants.py: version 1 and version 4 behave identically, so
# this does NOT affect whether Windows attests — the relying party id does
# (see rp_id_supports_attestation below). Version 4 is declared anyway because
# it is what current callers use and it leaves the later fields available;
# there is simply no behaviour riding on it.
WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_1 = 1
WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_3 = 3
WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_4 = 4
MAKE_CREDENTIAL_OPTIONS_VERSION = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_4

# Top-level domains reserved for special use, which are not registrable and
# which Windows will not release a TPM attestation for. Attestation identifies
# a specific machine, so Windows only hands it to a relying party whose name it
# can treat as a real, registrable domain; for anything else it still creates
# the credential but returns fmt="none".
#
# Measured, not assumed: with RP_ID=ztna.local Windows returned fmt="none" and
# 194 bytes, and with rp_id="localhost" the identical request returned
# fmt="tpm" with a 4002-byte attestation and a full certificate chain. localhost
# is the documented exception, explicitly allowed for development.
NON_REGISTRABLE_TLDS = (".local", ".localdomain", ".internal", ".home.arpa",
                        ".test", ".invalid", ".onion")

WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_1 = 1

DEFAULT_TIMEOUT_MS = 60_000


class WindowsWebAuthnError(RuntimeError):
    """A webauthn.dll call failed, or the platform authenticator is absent."""


# --------------------------------------------------------------------------- #
# structures (webauthn.h) - field ORDER is part of the ABI, do not reorder    #
# --------------------------------------------------------------------------- #

# Fixed-width rather than c_ulong/c_long: Windows is LLP64, so its DWORD and
# LONG are 32-bit, while a C long is 64-bit on Linux. Spelling the widths out
# keeps these layouts correct on any platform, which is what lets the sizes be
# checked by a test that runs here rather than only on Windows.
_DWORD = ctypes.c_uint32
_LONG = ctypes.c_int32
_BOOL = ctypes.c_int32
_PBYTE = POINTER(c_ubyte)


class _RpEntityInformation(ctypes.Structure):
    _fields_ = [
        ("dwVersion", _DWORD),
        ("pwszId", c_wchar_p),
        ("pwszName", c_wchar_p),
        ("pwszIcon", c_wchar_p),
    ]


class _UserEntityInformation(ctypes.Structure):
    _fields_ = [
        ("dwVersion", _DWORD),
        ("cbId", _DWORD),
        ("pbId", _PBYTE),
        ("pwszName", c_wchar_p),
        ("pwszIcon", c_wchar_p),
        ("pwszDisplayName", c_wchar_p),
    ]


class _CoseCredentialParameter(ctypes.Structure):
    _fields_ = [
        ("dwVersion", _DWORD),
        ("pwszCredentialType", c_wchar_p),
        ("lAlg", _LONG),
    ]


class _CoseCredentialParameters(ctypes.Structure):
    _fields_ = [
        ("cCredentialParameters", _DWORD),
        ("pCredentialParameters", POINTER(_CoseCredentialParameter)),
    ]


class _ClientData(ctypes.Structure):
    _fields_ = [
        ("dwVersion", _DWORD),
        ("cbClientDataJSON", _DWORD),
        ("pbClientDataJSON", _PBYTE),
        ("pwszHashAlgId", c_wchar_p),
    ]


class _Credential(ctypes.Structure):
    _fields_ = [
        ("dwVersion", _DWORD),
        ("cbId", _DWORD),
        ("pbId", _PBYTE),
        ("pwszCredentialType", c_wchar_p),
    ]


class _Credentials(ctypes.Structure):
    _fields_ = [
        ("cCredentials", _DWORD),
        ("pCredentials", POINTER(_Credential)),
    ]


class _Extensions(ctypes.Structure):
    _fields_ = [
        ("cExtensions", _DWORD),
        ("pExtensions", c_void_p),
    ]


class _MakeCredentialOptions(ctypes.Structure):
    """WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS, through version 4.

    Windows reads only as far as `dwVersion` says, so declaring the later
    fields costs nothing at a lower version and makes a higher one available.
    That matters: a version-1 caller is served by a legacy path that returns
    no attestation, which is not documented anywhere and was found by
    comparing this client against a browser on the same machine (see
    MAKE_CREDENTIAL_OPTIONS_VERSION below).

    All-zero values are valid for every version-4 field — enterprise
    attestation none, large-blob support none, no resident-key preference.
    """

    _fields_ = [
        ("dwVersion", _DWORD),
        ("dwTimeoutMilliseconds", _DWORD),
        ("CredentialList", _Credentials),      # credentials to EXCLUDE
        ("Extensions", _Extensions),
        ("dwAuthenticatorAttachment", _DWORD),
        ("bRequireResidentKey", _BOOL),
        ("dwUserVerificationRequirement", _DWORD),
        ("dwAttestationConveyancePreference", _DWORD),
        ("dwFlags", _DWORD),
        # Version 2
        ("pCancellationId", c_void_p),
        # Version 3
        ("pExcludeCredentialList", c_void_p),
        # Version 4
        ("dwEnterpriseAttestation", _DWORD),
        ("dwLargeBlobSupport", _DWORD),
        ("bPreferResidentKey", _BOOL),
    ]


class _GetAssertionOptions(ctypes.Structure):
    """WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS, version 1 only."""

    _fields_ = [
        ("dwVersion", _DWORD),
        ("dwTimeoutMilliseconds", _DWORD),
        ("CredentialList", _Credentials),      # credentials to ALLOW
        ("Extensions", _Extensions),
        ("dwAuthenticatorAttachment", _DWORD),
        ("dwUserVerificationRequirement", _DWORD),
        ("dwFlags", _DWORD),
    ]


class _CredentialAttestation(ctypes.Structure):
    """WEBAUTHN_CREDENTIAL_ATTESTATION, allocated and returned by Windows.

    Declared only as far as the fields read below; Windows allocates the full
    structure for whichever version it supports, so stopping early is safe
    while reading past what it allocated would not be.
    """

    _fields_ = [
        ("dwVersion", _DWORD),
        ("pwszFormatType", c_wchar_p),
        ("cbAuthenticatorData", _DWORD),
        ("pbAuthenticatorData", _PBYTE),
        ("cbAttestation", _DWORD),
        ("pbAttestation", _PBYTE),
        ("dwAttestationDecodeType", _DWORD),
        ("pvAttestationDecode", c_void_p),
        ("cbAttestationObject", _DWORD),
        ("pbAttestationObject", _PBYTE),
        ("cbCredentialId", _DWORD),
        ("pbCredentialId", _PBYTE),
    ]


class _Assertion(ctypes.Structure):
    """WEBAUTHN_ASSERTION, allocated and returned by Windows."""

    _fields_ = [
        ("dwVersion", _DWORD),
        ("cbAuthenticatorData", _DWORD),
        ("pbAuthenticatorData", _PBYTE),
        ("cbSignature", _DWORD),
        ("pbSignature", _PBYTE),
        ("Credential", _Credential),
        ("cbUserId", _DWORD),
        ("pbUserId", _PBYTE),
    ]


# --------------------------------------------------------------------------- #
# library access                                                              #
# --------------------------------------------------------------------------- #

def _webauthn():
    if sys.platform != "win32":
        raise WindowsWebAuthnError("the Windows platform authenticator is only available on Windows")
    try:
        library = ctypes.WinDLL("webauthn.dll")
    except OSError as exc:
        raise WindowsWebAuthnError(f"webauthn.dll could not be loaded: {exc}") from exc

    library.WebAuthNGetApiVersionNumber.restype = _DWORD
    library.WebAuthNGetErrorName.restype = c_wchar_p
    library.WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable.argtypes = [POINTER(_BOOL)]
    library.WebAuthNAuthenticatorMakeCredential.argtypes = [
        c_void_p, POINTER(_RpEntityInformation), POINTER(_UserEntityInformation),
        POINTER(_CoseCredentialParameters), POINTER(_ClientData),
        POINTER(_MakeCredentialOptions), POINTER(POINTER(_CredentialAttestation)),
    ]
    library.WebAuthNAuthenticatorGetAssertion.argtypes = [
        c_void_p, c_wchar_p, POINTER(_ClientData),
        POINTER(_GetAssertionOptions), POINTER(POINTER(_Assertion)),
    ]
    return library


def _check(library, result: int, call: str) -> None:
    if result != S_OK:
        name = library.WebAuthNGetErrorName(result) or "unknown"
        raise WindowsWebAuthnError(f"{call} failed: {name} (0x{result & 0xFFFFFFFF:08X})")


def _window_handle():
    """Windows shows the Hello prompt parented to a window, so it needs one.

    A console application has its own window; when there is none (a service,
    or a redirected console) the foreground window is the documented fallback.
    """
    kernel32 = ctypes.WinDLL("kernel32.dll")
    kernel32.GetConsoleWindow.restype = c_void_p
    handle = kernel32.GetConsoleWindow()
    if handle:
        return handle
    user32 = ctypes.WinDLL("user32.dll")
    user32.GetForegroundWindow.restype = c_void_p
    return user32.GetForegroundWindow()


def _buffer(data: bytes):
    """A mutable byte buffer Windows can read through a PBYTE."""
    return (c_ubyte * len(data)).from_buffer_copy(data)


def _read(pointer, length: int) -> bytes:
    return ctypes.string_at(pointer, length) if length else b""


# --------------------------------------------------------------------------- #
# public surface                                                              #
# --------------------------------------------------------------------------- #

def probe() -> bool:
    """True only when this machine has a usable Windows Hello authenticator.

    Whether that authenticator is TPM-backed is deliberately NOT decided here.
    A machine without a TPM falls back to software key storage and produces an
    attestation the IDP will refuse — which is the right place for that
    decision. The client offers evidence; the IDP judges it.
    """
    if sys.platform != "win32":
        return False
    try:
        library = _webauthn()
    except WindowsWebAuthnError as exc:
        status(log, "Windows platform authenticator unavailable", error=str(exc))
        return False

    available = _BOOL(0)
    result = library.WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable(byref(available))
    if result != S_OK or not available.value:
        status(log, "No Windows Hello platform authenticator on this machine")
        return False

    status(log, "Windows Hello platform authenticator available",
           api_version=library.WebAuthNGetApiVersionNumber())
    return True


def rp_id_supports_attestation(rp_id: str) -> bool:
    """Will Windows release a TPM attestation to this relying party id?

    Exists to turn a silent, mystifying result into an explained one. A bad
    RP_ID does not fail the ceremony: Windows cheerfully returns a working
    credential with no attestation, the IDP then refuses the enrolment, and
    nothing in either message points at the RP_ID as the cause. This is what
    lets the client say so directly.
    """
    name = rp_id.strip().lower().rstrip(".")
    if name == "localhost":
        return True
    return not any(name == tld.lstrip(".") or name.endswith(tld)
                   for tld in NON_REGISTRABLE_TLDS)


def make_credential(rp_id: str, rp_name: str, user_id: bytes, user_name: str,
                    client_data_json: bytes,
                    timeout_ms: int = DEFAULT_TIMEOUT_MS,
                    options_version: int = MAKE_CREDENTIAL_OPTIONS_VERSION,
                    require_resident_key: bool = False) -> tuple[bytes, bytes, str]:
    """Run the registration ceremony through Windows Hello.

    Returns (attestation_object, credential_id, attestation_format). The
    attestation object is already the CBOR structure WebAuthn defines, so it
    goes to the IDP untouched — no reassembly, and nothing platform-specific
    crosses the wire.

    `options_version` and `require_resident_key` exist so tools/webauthn_variants.py
    can sweep them against a real machine without duplicating this call. The
    defaults are what production uses; see MAKE_CREDENTIAL_OPTIONS_VERSION for
    why the version is not simply 1.
    """
    library = _webauthn()

    rp = _RpEntityInformation(
        dwVersion=WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION,
        pwszId=rp_id, pwszName=rp_name, pwszIcon=None)

    user_id_buffer = _buffer(user_id)
    user = _UserEntityInformation(
        dwVersion=WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION,
        cbId=len(user_id), pbId=ctypes.cast(user_id_buffer, _PBYTE),
        pwszName=user_name, pwszIcon=None, pwszDisplayName=user_name)

    algorithm = _CoseCredentialParameter(
        dwVersion=WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION,
        pwszCredentialType=WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
        lAlg=WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256)
    parameters = _CoseCredentialParameters(
        cCredentialParameters=1, pCredentialParameters=ctypes.pointer(algorithm))

    client_data_buffer = _buffer(client_data_json)
    client_data = _ClientData(
        dwVersion=WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
        cbClientDataJSON=len(client_data_json),
        pbClientDataJSON=ctypes.cast(client_data_buffer, _PBYTE),
        pwszHashAlgId=WEBAUTHN_HASH_ALGORITHM_SHA_256)

    options = _MakeCredentialOptions(
        dwVersion=options_version,
        dwTimeoutMilliseconds=timeout_ms,
        CredentialList=_Credentials(cCredentials=0, pCredentials=None),
        Extensions=_Extensions(cExtensions=0, pExtensions=None),
        dwAuthenticatorAttachment=WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM,
        bRequireResidentKey=1 if require_resident_key else 0,
        dwUserVerificationRequirement=WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
        dwAttestationConveyancePreference=WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT,
        dwFlags=0,
        # Version 2-4 fields. Zero is the "no preference" value for each, so
        # they change nothing beyond making the higher version declarable.
        pCancellationId=None,
        pExcludeCredentialList=None,
        dwEnterpriseAttestation=0,
        dwLargeBlobSupport=0,
        bPreferResidentKey=0)

    if not rp_id_supports_attestation(rp_id):
        status(log, f"RP_ID {rp_id!r} uses a reserved, non-registrable domain suffix. "
                    "Windows will create the credential but WILL NOT attest it, so the IDP "
                    "will refuse to enrol this device. Set RP_ID to a registrable domain "
                    "(both the IDP and the client must agree on it)")

    status(log, "Requesting a credential from Windows Hello - confirm on the prompt",
           rp_id=rp_id, user=user_name, options_version=options_version)
    attestation = POINTER(_CredentialAttestation)()
    result = library.WebAuthNAuthenticatorMakeCredential(
        _window_handle(), byref(rp), byref(user), byref(parameters),
        byref(client_data), byref(options), byref(attestation))
    _check(library, result, "WebAuthNAuthenticatorMakeCredential")

    try:
        value = attestation.contents
        attestation_object = _read(value.pbAttestationObject, value.cbAttestationObject)
        credential_id = _read(value.pbCredentialId, value.cbCredentialId)
        attestation_format = value.pwszFormatType or "unknown"
    finally:
        # Windows owns this memory; every byte needed must be copied out first.
        library.WebAuthNFreeCredentialAttestation(attestation)

    status(log, "Windows Hello produced a credential", fmt=attestation_format,
           credential_id=credential_id.hex()[:16],
           attestation_object_bytes=len(attestation_object))
    return attestation_object, credential_id, attestation_format


def get_assertion(rp_id: str, client_data_json: bytes, allow_credential_ids: list[bytes],
                  timeout_ms: int = DEFAULT_TIMEOUT_MS) -> tuple[bytes, bytes, bytes]:
    """Run the authentication ceremony through Windows Hello.

    Returns (authenticator_data, signature, credential_id).
    """
    library = _webauthn()

    # The credential array and its id buffers must outlive the call, so they
    # are held in locals rather than built inline in the argument list.
    id_buffers = [_buffer(credential_id) for credential_id in allow_credential_ids]
    array = (_Credential * len(id_buffers))(*[
        _Credential(dwVersion=WEBAUTHN_CREDENTIAL_CURRENT_VERSION,
                    cbId=len(allow_credential_ids[index]),
                    pbId=ctypes.cast(buffer, _PBYTE),
                    pwszCredentialType=WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY)
        for index, buffer in enumerate(id_buffers)
    ])

    client_data_buffer = _buffer(client_data_json)
    client_data = _ClientData(
        dwVersion=WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
        cbClientDataJSON=len(client_data_json),
        pbClientDataJSON=ctypes.cast(client_data_buffer, _PBYTE),
        pwszHashAlgId=WEBAUTHN_HASH_ALGORITHM_SHA_256)

    options = _GetAssertionOptions(
        dwVersion=WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_1,
        dwTimeoutMilliseconds=timeout_ms,
        CredentialList=_Credentials(
            cCredentials=len(array),
            pCredentials=ctypes.cast(array, POINTER(_Credential)) if len(array) else None),
        Extensions=_Extensions(cExtensions=0, pExtensions=None),
        dwAuthenticatorAttachment=WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM,
        dwUserVerificationRequirement=WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
        dwFlags=0)

    status(log, "Requesting an assertion from Windows Hello - confirm on the prompt",
           rp_id=rp_id, allow_credentials=len(array))
    assertion = POINTER(_Assertion)()
    result = library.WebAuthNAuthenticatorGetAssertion(
        _window_handle(), rp_id, byref(client_data), byref(options), byref(assertion))
    _check(library, result, "WebAuthNAuthenticatorGetAssertion")

    try:
        value = assertion.contents
        authenticator_data = _read(value.pbAuthenticatorData, value.cbAuthenticatorData)
        signature = _read(value.pbSignature, value.cbSignature)
        credential_id = _read(value.Credential.pbId, value.Credential.cbId)
    finally:
        library.WebAuthNFreeAssertion(assertion)

    status(log, "Windows Hello produced an assertion",
           credential_id=credential_id.hex()[:16], signature_bytes=len(signature))
    return authenticator_data, signature, credential_id
