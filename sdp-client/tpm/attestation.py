"""Optional TPM2 quote (PCR attestation) — supplementary evidence only.

Not verified by the IDP: the `fido2` library ships no TPM
attestation-statement verifier, so the IDP accepts a "none"-format
self-attested credential from the internal-TPM path (see
sdp-idp/fido2_idp/attestation_tpm.py, where enforcement lands in M2).
This module exists so the client can
still capture and log a genuine hardware quote locally; wiring it into the
server-side trust decision is future work, not part of this pass.
"""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

from tpm.tpm_handler import TPMKeyHandle
from shared.utils.logger import get_logger, status

log = get_logger("TPM-Attest")


def quote(key: TPMKeyHandle, pcr_list: str = "sha256:0,1,2,3,4,5,6,7", tcti: str | None = None) -> bytes | None:
    """Best-effort PCR quote signed by the TPM key. Returns None on any
    failure rather than raising — this is supplementary evidence, not on the
    critical path to a granted access decision.
    """
    t = ["-T", tcti] if tcti else []
    with tempfile.TemporaryDirectory() as tmp:
        msg_path = Path(tmp) / "quote.msg"
        sig_path = Path(tmp) / "quote.sig"
        pcrs_path = Path(tmp) / "quote.pcrs"
        try:
            subprocess.run(
                ["tpm2_quote", *t, "-c", str(key.key_ctx), "-l", pcr_list,
                 "-m", str(msg_path), "-s", str(sig_path), "-o", str(pcrs_path)],
                capture_output=True, text=True, check=True,
            )
            status(log, "TPM quote captured", pcr_list=pcr_list)
            return msg_path.read_bytes() + sig_path.read_bytes()
        except (subprocess.CalledProcessError, FileNotFoundError) as exc:
            status(log, "TPM quote failed (non-fatal, supplementary only)", error=str(exc))
            return None
