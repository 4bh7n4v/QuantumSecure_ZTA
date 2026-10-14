"""Internal (onboard) TPM 2.0 interface, via the `tpm2-tools` CLI.

VERIFIED against `swtpm` 0.10.1 with tpm2-tools 5.7: key creation, signing,
attestation-key creation and certify all run, and the resulting attestation is
accepted by the IDP. Two real bugs surfaced on that first run and are fixed —
a restricted signing key needs its symmetric algorithm named explicitly, and
`tpm2_certify` cannot pass qualifying data at all (see certify()). Not yet run
against a physical Linux TPM; only the TCTI differs there.

Uses tpm2-tools rather than the `tpm2-pytss` Python bindings because the
bindings require building against a native tss2-esapi library (>=2.4.0)
that also isn't installed here, whereas tpm2-tools ships as ordinary CLI
binaries (`apt install tpm2-tools`) with a command syntax stable for years.

A software TPM simulator (`swtpm`) implements the exact same TPM2 command
set as real hardware, so it is a legitimate stand-in for development, not a
fallback that weakens the security model — this module makes no
distinction between them; only the TCTI target (`device:/dev/tpmrm0` vs
`swtpm:host=...,port=...`) differs.
"""

from __future__ import annotations

import shutil
import struct
import subprocess
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from shared.utils.crypto import ecdsa_raw_to_der
from shared.utils.logger import get_logger, status

log = get_logger("TPM-Internal")

_REQUIRED_TOOLS = (
    "tpm2_getcap", "tpm2_createprimary", "tpm2_create",
    "tpm2_load", "tpm2_readpublic", "tpm2_sign", "tpm2_evictcontrol",
    "tpm2_flushcontext",
)

# Needed only to produce a WebAuthn attestation statement. Kept out of
# _REQUIRED_TOOLS deliberately: a TPM that can hold the credential key is
# still a usable trust anchor even if attestation cannot be built, and the
# IDP's policy — not the client — decides whether that is good enough.
#
# `tpm2_send` rather than `tpm2_certify`, because tpm2-tools does not expose
# the one parameter this depends on — see certify() below.
_ATTESTATION_TOOLS = ("tpm2_send", "tpm2_evictcontrol")

# Raw TPM2 constants, needed because the certify command is issued directly.
TPM_ST_SESSIONS = 0x8002
TPM_CC_CERTIFY = 0x00000148
TPM_RS_PW = 0x40000009          # the password authorisation "session"
TPM_ALG_NULL = 0x0010

# Persistent handles borrowed while a certify runs, then released. TPM2_Certify
# addresses its objects by handle, and a saved context file is not one, so both
# keys are briefly persisted here. They are evicted before use as well as
# after, so a crashed run does not leave them occupied. Two certifies running
# at the same moment on one machine would collide; that window is milliseconds
# and the client is interactive, so it is accepted rather than designed around.
_CERTIFY_SUBJECT_HANDLE = "0x81002001"
_CERTIFY_AK_HANDLE = "0x81002002"

# Object attributes for the credential key. Spelled out rather than left to
# tpm2_create's defaults because the IDP reads these exact bits back out of
# the attested pubArea (IDENTITY_PROVIDER/fido2_idp/tpm_trust.py):
#   fixedtpm            - the key can never be duplicated to another TPM
#   fixedparent         - nor re-parented within this one
#   sensitivedataorigin - the TPM generated it; it was not imported
# Together they are the hardware's own statement that this private key was
# born in the chip and cannot leave it. `restricted` is deliberately absent,
# and no signing scheme is set on the key (-G ecc256, not ecc256:ecdsa-sha256),
# because a WebAuthn verifier requires the pubArea's scheme to be TPM_ALG_NULL;
# the scheme is supplied per operation by tpm2_sign's -g instead.
_CREDENTIAL_KEY_ATTRS = "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|sign"
_CREDENTIAL_KEY_ALG = "ecc256"

# The attestation key (AK) that certifies the credential key. This one IS
# restricted — a restricted signing key will only sign data the TPM itself
# produced, which is what makes its signature over a certify structure mean
# "the TPM says this", not "someone asked the TPM to sign these bytes". A
# restricted signing key must carry a scheme, hence the ecdsa-sha256 suffix.
_AK_ATTRS = "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|sign"
# The trailing ":null" is the symmetric algorithm, and omitting it is fatal
# here. `restricted` normally marks a storage key, so tpm2-tools fills in a
# default symmetric cipher (AES) — which the TPM rejects for a restricted
# SIGNING key with "unsupported symmetric algorithm ... not appropriate for
# instance". Naming it explicitly is what distinguishes the two.
_AK_ALG = "ecc256:ecdsa-sha256:null"

TPM_GENERATED_VALUE = b"\xffTCG"  # magic prefixing every TPMS_ATTEST
TPM_ALG_ECDSA = 0x0018

# The owner-hierarchy primary is deterministic for a fixed template, so we
# create it once and evict it to this persistent handle. Child-key ops then
# reference the parent by handle instead of reloading it from a context file
# on every call — a context-file parent stays resident in the TPM's tiny
# transient-object memory (swtpm allows only ~3), and reloading it for each
# tpm2_create / tpm2_load exhausts that: "out of memory for object contexts".
_PRIMARY_HANDLE = "0x81000001"


@dataclass
class TPMKeyHandle:
    workdir: Path
    primary_ctx: Path
    key_ctx: Path
    public_pem: Path


def _tools_available() -> bool:
    return all(shutil.which(tool) for tool in _REQUIRED_TOOLS)


def _flush_transient(t: list[str]) -> None:
    """Clear all loaded transient objects.

    Some tpm2-tools / tss builds (seen on Kali + swtpm) leak the transient
    object an invocation loads instead of flushing it on exit. swtpm allows
    only HR_LOADED_AVAIL (3) transient objects, so after a few calls every
    further command fails with TPM_RC_OBJECT_MEMORY ("out of memory for
    object contexts"). Every operation in this module persists its state to
    a context file or the persistent primary handle, so nothing transient
    needs to survive between invocations — clear them before each step.
    Best-effort: a failure here is not fatal.
    """
    subprocess.run(["tpm2_flushcontext", *t, "-t"], capture_output=True, text=True)


def _ensure_primary(primary_ctx: Path, t: list[str]) -> str:
    """Return the persistent handle of the owner-hierarchy primary, creating
    and persisting it on first use. Idempotent: if a primary is already
    persisted at the handle (from an earlier run) it is reused, since the
    fixed template makes every regenerated primary identical.
    """
    _flush_transient(t)
    already = subprocess.run(
        ["tpm2_readpublic", *t, "-c", _PRIMARY_HANDLE],
        capture_output=True, text=True,
    )
    if already.returncode == 0:
        return _PRIMARY_HANDLE

    _flush_transient(t)
    _run(["tpm2_createprimary", *t, "-C", "o", "-g", "sha256", "-G", "ecc", "-c", str(primary_ctx)])
    _flush_transient(t)
    _run(["tpm2_evictcontrol", *t, "-C", "o", "-c", str(primary_ctx), _PRIMARY_HANDLE])
    _flush_transient(t)
    return _PRIMARY_HANDLE


def probe(tcti: str | None = None) -> bool:
    """Return True only if an internal TPM is present AND actually responds."""
    if not _tools_available():
        status(log, "tpm2-tools not installed - internal TPM path unavailable")
        return False

    cmd = ["tpm2_getcap"] + (["-T", tcti] if tcti else []) + ["properties-fixed"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        status(log, "Internal TPM probe failed to execute", error=str(exc))
        return False

    if result.returncode == 0:
        status(log, "Internal TPM responded", tcti=tcti or "(default)")
        return True

    status(log, "No internal TPM responding", tcti=tcti or "(default)", stderr=result.stderr.strip()[:200])
    return False


def _create_child(workdir: Path, prefix: str, alg: str, attrs: str,
                  tcti: str | None) -> TPMKeyHandle:
    workdir.mkdir(parents=True, exist_ok=True)
    t = ["-T", tcti] if tcti else []

    primary_ctx = workdir / "primary.ctx"
    pub_blob = workdir / f"{prefix}.pub"
    priv_blob = workdir / f"{prefix}.priv"
    key_ctx = workdir / f"{prefix}.ctx"
    public_pem = workdir / f"{prefix}_public.pem"

    parent = _ensure_primary(primary_ctx, t)
    _flush_transient(t)
    _run(["tpm2_create", *t, "-C", parent, "-g", "sha256", "-G", alg, "-a", attrs,
          "-u", str(pub_blob), "-r", str(priv_blob)])
    _flush_transient(t)
    _run(["tpm2_load", *t, "-C", parent, "-u", str(pub_blob), "-r", str(priv_blob), "-c", str(key_ctx)])
    _flush_transient(t)
    _run(["tpm2_readpublic", *t, "-c", str(key_ctx), "-o", str(public_pem), "-f", "pem"])

    return TPMKeyHandle(workdir=workdir, primary_ctx=primary_ctx, key_ctx=key_ctx, public_pem=public_pem)


def _load_child(workdir: Path, prefix: str, tcti: str | None) -> TPMKeyHandle | None:
    pub_blob = workdir / f"{prefix}.pub"
    priv_blob = workdir / f"{prefix}.priv"
    public_pem = workdir / f"{prefix}_public.pem"
    if not (pub_blob.exists() and priv_blob.exists()):
        return None

    t = ["-T", tcti] if tcti else []
    primary_ctx = workdir / "primary.ctx"
    key_ctx = workdir / f"{prefix}.ctx"

    parent = _ensure_primary(primary_ctx, t)
    _flush_transient(t)
    _run(["tpm2_load", *t, "-C", parent, "-u", str(pub_blob), "-r", str(priv_blob), "-c", str(key_ctx)])
    _flush_transient(t)

    return TPMKeyHandle(workdir=workdir, primary_ctx=primary_ctx, key_ctx=key_ctx, public_pem=public_pem)


def create_signing_key(workdir: Path, tcti: str | None = None) -> TPMKeyHandle:
    """Create a NEW ECC P-256 child signing key under the TPM's owner
    hierarchy and persist its wrapped pub/priv blobs to `workdir`, so a
    later `load_signing_key()` call (e.g. from a subsequent authenticate())
    reloads this exact key rather than minting a different one.

    Call this only once per account, at registration time — see
    tpm/anchored_trust.py, which is what actually enforces that (it always
    tries load_signing_key() first and only falls back to this).
    """
    key = _create_child(workdir, "key", _CREDENTIAL_KEY_ALG, _CREDENTIAL_KEY_ATTRS, tcti)
    status(log, "TPM signing key created", workdir=str(workdir), attributes=_CREDENTIAL_KEY_ATTRS)
    return key


def load_signing_key(workdir: Path, tcti: str | None = None) -> TPMKeyHandle | None:
    """Reload a previously created key's wrapped blobs into a fresh TPM
    context. Returns None if no key has been created in `workdir` yet.

    The primary is not re-created here — it lives at a persistent handle
    (see _ensure_primary). TPM primaries are deterministic given the same
    hierarchy/template on the same TPM, so the persisted parent still
    unwraps a child enrolled under a freshly created one; only the child
    key's own blobs (key.pub/key.priv) need to persist across runs.
    """
    key = _load_child(workdir, "key", tcti)
    if key is not None:
        status(log, "TPM signing key reloaded from existing enrollment", workdir=str(workdir))
    return key


# --------------------------------------------------------------------------- #
# attestation: the AK, and certifying the credential key with it              #
# --------------------------------------------------------------------------- #

def attestation_available() -> bool:
    """True when this host has the tools needed to build a TPM attestation
    statement. tpm2-tools 5.0 or newer, for `tpm2_certify -q`.
    """
    return all(shutil.which(tool) for tool in _ATTESTATION_TOOLS)


def load_or_create_attestation_key(workdir: Path, tcti: str | None = None) -> TPMKeyHandle:
    """The restricted signing key that vouches for the credential key.

    Created once per account alongside the credential key and reloaded
    thereafter, so the IDP sees the same attestation key on every enrolment
    from this device — which is what its per-device AK pinning checks.
    """
    key = _load_child(workdir, "ak", tcti)
    if key is not None:
        status(log, "TPM attestation key reloaded", workdir=str(workdir))
        return key
    key = _create_child(workdir, "ak", _AK_ALG, _AK_ATTRS, tcti)
    status(log, "TPM attestation key created", workdir=str(workdir), attributes=_AK_ATTRS)
    return key


def read_public_area(key: TPMKeyHandle, tcti: str | None = None) -> bytes:
    """The key's TPMT_PUBLIC — the `pubArea` of a WebAuthn TPM attestation
    statement, and the input to the Name the certify structure attests to.

    These bytes are hashed by the verifier and compared against the Name in
    certInfo, so the TPM2B size prefix that tpm2_readpublic writes around them
    has to come off exactly (see _strip_tpm2b).
    """
    t = ["-T", tcti] if tcti else []
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "public.tss"
        _flush_transient(t)
        _run(["tpm2_readpublic", *t, "-c", str(key.key_ctx), "-o", str(out), "-f", "tss"])
        _flush_transient(t)
        return _strip_tpm2b(out.read_bytes())


def certify(subject: TPMKeyHandle, attestation_key: TPMKeyHandle,
            qualifying_data: bytes, tcti: str | None = None) -> tuple[bytes, bytes]:
    """Have the TPM certify `subject` with `attestation_key`.

    Returns (certInfo, signature): a TPMS_ATTEST of type TPM_ST_ATTEST_CERTIFY
    naming the subject key, and the AK's DER ECDSA signature over it.
    `qualifying_data` is embedded verbatim as the structure's extraData, which
    is what binds the attestation to one specific WebAuthn ceremony rather
    than letting a captured statement be replayed against another challenge.

    Why this builds the command by hand instead of calling `tpm2_certify`:
    that tool does not expose the qualifying-data parameter (checked on
    tpm2-tools 5.7 — `tpm2_certify: invalid option -- 'q'`), and without it
    extraData is whatever the tool chooses, so the statement is not bound to
    the ceremony and every WebAuthn verifier rejects it. Of all the tpm2-tools
    commands that DO take qualifying data, none produce TPM_ST_ATTEST_CERTIFY,
    which is the only attest type the WebAuthn TPM format accepts. So the
    command goes to the chip directly through `tpm2_send`.
    """
    t = ["-T", tcti] if tcti else []
    with _persisted(subject, _CERTIFY_SUBJECT_HANDLE, t), \
            _persisted(attestation_key, _CERTIFY_AK_HANDLE, t):
        response = _send(_certify_command(
            int(_CERTIFY_SUBJECT_HANDLE, 16), int(_CERTIFY_AK_HANDLE, 16), qualifying_data), t)

    cert_info, signature = _parse_certify_response(response)
    status(log, "TPM certified the credential key", cert_info_bytes=len(cert_info))
    return _strip_tpm2b(cert_info, magic=TPM_GENERATED_VALUE), _signature_to_der(signature)


@contextmanager
def _persisted(key: TPMKeyHandle, handle: str, t: list[str]):
    """Briefly give `key` a persistent handle, and always take it back."""
    _evict(handle, t)                       # clear anything a crashed run left
    _flush_transient(t)
    _run(["tpm2_evictcontrol", *t, "-C", "o", "-c", str(key.key_ctx), handle])
    _flush_transient(t)
    try:
        yield handle
    finally:
        _evict(handle, t)


def _evict(handle: str, t: list[str]) -> None:
    """Release a persistent handle. Best-effort: it is normal for it to be
    empty, and a failure here must not mask whatever else went wrong.
    """
    subprocess.run(["tpm2_evictcontrol", *t, "-C", "o", "-c", handle],
                   capture_output=True, text=True)
    _flush_transient(t)


def _certify_command(object_handle: int, sign_handle: int, qualifying_data: bytes) -> bytes:
    """Marshal TPM2_Certify (TPM 2.0 Part 3, §18.2).

    Both objects are authorised with an empty password, which is what they
    were created with; TPM_RS_PW is the TPM's built-in stand-in for a real
    session. inScheme is TPM_ALG_NULL so the AK signs with the scheme fixed in
    its own public area — a restricted key insists on that anyway.
    """
    authorisation = b""
    for _ in range(2):                                  # objectHandle, then signHandle
        authorisation += struct.pack("!I", TPM_RS_PW)   # sessionHandle
        authorisation += struct.pack("!H", 0)           # nonce: absent
        authorisation += struct.pack("!B", 0)           # sessionAttributes
        authorisation += struct.pack("!H", 0)           # hmac: empty password

    body = (struct.pack("!II", object_handle, sign_handle)
            + struct.pack("!I", len(authorisation)) + authorisation
            + struct.pack("!H", len(qualifying_data)) + qualifying_data   # TPM2B_DATA
            + struct.pack("!H", TPM_ALG_NULL))                           # TPMT_SIG_SCHEME
    header = struct.pack("!HII", TPM_ST_SESSIONS, 10 + len(body), TPM_CC_CERTIFY)
    return header + body


def _parse_certify_response(response: bytes) -> tuple[bytes, bytes]:
    """Split a TPM2_Certify response into its TPM2B_ATTEST and TPMT_SIGNATURE."""
    if len(response) < 10:
        raise RuntimeError(f"TPM response too short: {len(response)} bytes")
    _tag, _size, return_code = struct.unpack("!HII", response[:10])
    if return_code != 0:
        raise RuntimeError(f"TPM2_Certify failed with response code 0x{return_code:08X}")

    # The response tag is TPM_ST_SESSIONS because the command carried
    # authorisation, so a parameterSize precedes the parameters themselves.
    body = response[10:]
    parameter_size = struct.unpack("!I", body[:4])[0]
    parameters = body[4:4 + parameter_size]

    attest_size = struct.unpack("!H", parameters[:2])[0]
    return parameters[:2 + attest_size], parameters[2 + attest_size:]


def _send(command: bytes, t: list[str]) -> bytes:
    result = subprocess.run(["tpm2_send", *t], input=command, capture_output=True)
    if result.returncode != 0:
        raise RuntimeError(f"tpm2_send failed: {result.stderr.decode(errors='replace').strip()}")
    return result.stdout


def _strip_tpm2b(data: bytes, magic: bytes | None = None) -> bytes:
    """Remove a TPM2B UINT16 size prefix if one is present.

    tpm2-tools is not consistent about whether a marshalled structure is
    written with its length prefix, and the difference matters here: these
    bytes are hashed by the verifier, so an extra two bytes silently breaks
    every comparison downstream. Two independent checks, either of which is
    conclusive: the declared length matching the remainder, or the structure's
    own magic appearing right after the prefix.
    """
    if magic is not None:
        if data.startswith(magic):
            return data
        if data[2:2 + len(magic)] == magic:
            return data[2:]
        raise RuntimeError(f"TPM structure does not start with {magic!r}")

    if len(data) > 2 and int.from_bytes(data[:2], "big") == len(data) - 2:
        return data[2:]
    return data


def _signature_to_der(signature: bytes) -> bytes:
    """Normalise whatever tpm2_certify wrote into a DER ECDSA signature.

    Left at tpm2-tools' default "tss" output format, which marshals a
    TPMT_SIGNATURE — asking for `-f plain` instead would be simpler but is not
    supported by every build. A TPMT_SIGNATURE for ECDSA is
    { UINT16 sigAlg, UINT16 hashAlg, TPM2B r, TPM2B s }, and is recognisable
    by its leading algorithm identifier; anything else is handed to the shared
    raw/DER normaliser that the sign() path already relies on.
    """
    if len(signature) > 4 and int.from_bytes(signature[:2], "big") == TPM_ALG_ECDSA:
        reader = signature[4:]
        r_len = int.from_bytes(reader[:2], "big")
        r = reader[2:2 + r_len]
        reader = reader[2 + r_len:]
        s_len = int.from_bytes(reader[:2], "big")
        s = reader[2:2 + s_len]
        # Encode from the integers rather than re-concatenating: a TPM2B may
        # drop leading zero bytes, so the halves are not reliably equal-length
        # and splitting a concatenation down the middle would misread them.
        if len(r) == r_len and len(s) == s_len and not reader[2 + s_len:]:
            return encode_dss_signature(int.from_bytes(r, "big"), int.from_bytes(s, "big"))
    return ecdsa_raw_to_der(signature)


def sign(key: TPMKeyHandle, data: bytes, tcti: str | None = None) -> bytes:
    """Sign `data` with the TPM-resident key. Returns a DER-encoded ECDSA
    signature (converted from the TPM's raw r||s output) so it's directly
    usable with `cryptography`'s ECDSA verifier, matching what the fido2
    library expects when it verifies an assertion signature.
    """
    t = ["-T", tcti] if tcti else []
    with tempfile.TemporaryDirectory() as tmp:
        data_path = Path(tmp) / "data.bin"
        sig_path = Path(tmp) / "sig.bin"
        data_path.write_bytes(data)

        _flush_transient(t)
        _run(["tpm2_sign", *t, "-c", str(key.key_ctx), "-g", "sha256", "-f", "plain",
              "-o", str(sig_path), str(data_path)])
        _flush_transient(t)

        raw_sig = sig_path.read_bytes()

    return _raw_to_der(raw_sig)


def load_public_key(key: TPMKeyHandle):
    from cryptography.hazmat.primitives import serialization
    return serialization.load_pem_public_key(key.public_pem.read_bytes())


def _raw_to_der(raw_sig: bytes) -> bytes:
    """Normalise a tpm2_sign ECDSA signature to DER, which is what
    cryptography/fido2 expect. Shared with the Windows CNG backend, whose
    NCryptSignHash has the same raw-r||s output convention — see
    shared/utils/crypto.py for the both-forms-accepted rationale.
    """
    return ecdsa_raw_to_der(raw_sig)


def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} failed: {result.stderr.strip()}")
    return result
