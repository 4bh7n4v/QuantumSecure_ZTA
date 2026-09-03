"""Internal (onboard) TPM 2.0 interface, via the `tpm2-tools` CLI.

CAVEAT: this module is written against tpm2-tools' documented, long-stable
command syntax, but has NOT been executed against a real TPM or an swtpm
simulator in this session — this dev machine (WSL2/Kali) has neither
/dev/tpm0 nor tpm2-tools installed, and installing them needed an
interactive sudo password this session couldn't supply. Everything in
the IDP and the ML-KEM/SPA path WAS verified end-to-end by actually
running it; treat this file with correspondingly less confidence until it's
run against real hardware or `swtpm` and any format mismatch (see
`_raw_to_der`) gets fixed against real tool output.

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
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from shared.utils.crypto import ecdsa_raw_to_der
from shared.utils.logger import get_logger, status

log = get_logger("TPM-Internal")

_REQUIRED_TOOLS = (
    "tpm2_getcap", "tpm2_createprimary", "tpm2_create",
    "tpm2_load", "tpm2_readpublic", "tpm2_sign", "tpm2_evictcontrol",
    "tpm2_flushcontext",
)

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


def create_signing_key(workdir: Path, tcti: str | None = None) -> TPMKeyHandle:
    """Create a NEW ECC P-256 child signing key under the TPM's owner
    hierarchy and persist its wrapped pub/priv blobs to `workdir`, so a
    later `load_signing_key()` call (e.g. from a subsequent authenticate())
    reloads this exact key rather than minting a different one.

    Call this only once per account, at registration time — see
    tpm/anchored_trust.py, which is what actually enforces that (it always
    tries load_signing_key() first and only falls back to this).
    """
    workdir.mkdir(parents=True, exist_ok=True)
    t = ["-T", tcti] if tcti else []

    primary_ctx = workdir / "primary.ctx"
    pub_blob = workdir / "key.pub"
    priv_blob = workdir / "key.priv"
    key_ctx = workdir / "key.ctx"
    public_pem = workdir / "key_public.pem"

    parent = _ensure_primary(primary_ctx, t)
    _flush_transient(t)
    _run(["tpm2_create", *t, "-C", parent, "-g", "sha256", "-G", "ecc",
          "-u", str(pub_blob), "-r", str(priv_blob)])
    _flush_transient(t)
    _run(["tpm2_load", *t, "-C", parent, "-u", str(pub_blob), "-r", str(priv_blob), "-c", str(key_ctx)])
    _flush_transient(t)
    _run(["tpm2_readpublic", *t, "-c", str(key_ctx), "-o", str(public_pem), "-f", "pem"])

    status(log, "TPM signing key created", workdir=str(workdir))
    return TPMKeyHandle(workdir=workdir, primary_ctx=primary_ctx, key_ctx=key_ctx, public_pem=public_pem)


def load_signing_key(workdir: Path, tcti: str | None = None) -> TPMKeyHandle | None:
    """Reload a previously created key's wrapped blobs into a fresh TPM
    context. Returns None if no key has been created in `workdir` yet.

    The primary is not re-created here — it lives at a persistent handle
    (see _ensure_primary). TPM primaries are deterministic given the same
    hierarchy/template on the same TPM, so the persisted parent still
    unwraps a child enrolled under a freshly created one; only the child
    key's own blobs (key.pub/key.priv) need to persist across runs.
    """
    pub_blob = workdir / "key.pub"
    priv_blob = workdir / "key.priv"
    public_pem = workdir / "key_public.pem"
    if not (pub_blob.exists() and priv_blob.exists()):
        return None

    t = ["-T", tcti] if tcti else []
    primary_ctx = workdir / "primary.ctx"
    key_ctx = workdir / "key.ctx"

    parent = _ensure_primary(primary_ctx, t)
    _flush_transient(t)
    _run(["tpm2_load", *t, "-C", parent, "-u", str(pub_blob), "-r", str(priv_blob), "-c", str(key_ctx)])
    _flush_transient(t)

    status(log, "TPM signing key reloaded from existing enrollment", workdir=str(workdir))
    return TPMKeyHandle(workdir=workdir, primary_ctx=primary_ctx, key_ctx=key_ctx, public_pem=public_pem)


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
