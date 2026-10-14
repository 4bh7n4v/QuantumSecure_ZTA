"""Builds the WebAuthn `fmt="tpm"` attestation statement — Milestone 2.

Before M2 the internal-TPM path registered self-attested (`fmt="none"`)
credentials: the TPM really did hold the key and produce every signature, but
nothing in the protocol proved that to the IDP, which had to take the
client's word for it. A client that had lost its TPM — or never had one —
could send exactly the same bytes. That is the gap this module closes.

What the statement proves
-------------------------
The TPM's certify operation is the whole mechanism. `tpm2_certify` asks the
chip to produce a signed TPMS_ATTEST describing another object it holds, and
because the attestation key doing the signing is `restricted`, the chip will
only sign structures it generated itself. The resulting statement lets the
IDP establish three things it previously assumed:

  - the credential key really is inside a TPM — a key the chip does not hold
    cannot be certified at all;
  - it is non-duplicable — the attested pubArea carries the key's
    fixedTPM / fixedParent / sensitiveDataOrigin bits, which the IDP reads
    back in IDENTITY_PROVIDER/fido2_idp/tpm_trust.py;
  - this statement belongs to this ceremony — the qualifying data becomes the
    structure's extraData, and the IDP requires it to equal
    SHA-256(authenticatorData || clientDataHash), so a captured statement
    cannot be replayed against a different challenge.

What it does not prove is that the chip is genuine silicon rather than a
simulator; that needs an AK certificate chaining to a manufacturer root, and
tpm/ak_cert.py explains why this project self-issues instead.

Also here: `quote()`, an optional PCR quote. That is platform-integrity
evidence (what firmware and boot chain the machine came up with), a different
question from key custody, and it remains supplementary and unverified — see
its own docstring.

Verified against an `swtpm` simulator with tpm2-tools 5.7: the statement this
builds is accepted by the IDP's own verifier, with the credential key's
fixedTPM / fixedParent / sensitiveDataOrigin bits all set. Not yet run against
a physical Linux TPM, though the command sequence is identical — only the TCTI
differs.

Note that the certify step does NOT use `tpm2_certify`: that tool cannot pass
qualifying data, without which the statement is not bound to a ceremony. See
tpm_handler.certify().
"""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from tpm import ak_cert, tpm_handler
from tpm.tpm_handler import TPMKeyHandle
from shared.utils.logger import get_logger, status

log = get_logger("TPM-Attest")

# COSE algorithm identifier for ECDSA w/ SHA-256. Names the algorithm the AK
# signs certInfo with, and the hash the IDP uses to rebuild extraData.
COSE_ES256 = -7


def available() -> bool:
    """True when this host can build a TPM attestation statement at all."""
    return tpm_handler.attestation_available()


def build_statement(credential_key: TPMKeyHandle, workdir: Path,
                    qualifying_data: bytes, tcti: str | None = None) -> dict:
    """Return the `att_stmt` of a WebAuthn TPM attestation object.

    `qualifying_data` must be SHA-256(authenticatorData || clientDataHash);
    the caller owns that construction because only it has both halves. See
    fido2_agent/tpm_authenticator.py.
    """
    attestation_key = tpm_handler.load_or_create_attestation_key(workdir, tcti)

    pub_area = tpm_handler.read_public_area(credential_key, tcti)
    cert_info, signature = tpm_handler.certify(
        credential_key, attestation_key, qualifying_data, tcti)

    ak_public_key = serialization.load_pem_public_key(attestation_key.public_pem.read_bytes())
    certificate = ak_cert.build_self_issued(ak_public_key)

    status(log, "TPM attestation statement built",
           pub_area_bytes=len(pub_area), cert_info_bytes=len(cert_info),
           signature_bytes=len(signature))
    return {
        "ver": "2.0",
        "alg": COSE_ES256,
        "x5c": [certificate],
        "sig": signature,
        "certInfo": cert_info,
        "pubArea": pub_area,
    }


def quote(key: TPMKeyHandle, pcr_list: str = "sha256:0,1,2,3,4,5,6,7",
          tcti: str | None = None) -> bytes | None:
    """Best-effort PCR quote signed by the TPM key. Returns None on any
    failure rather than raising.

    Distinct from the attestation statement above and still not verified by
    the IDP: a quote attests to the machine's boot-time measurements, which is
    device *posture* rather than key custody, and belongs with the continuous
    posture reporting in posture/ once that is wired to the server side. It is
    captured and logged locally in the meantime.
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
