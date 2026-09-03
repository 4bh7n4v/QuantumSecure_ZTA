"""Device (mTLS) certificate presence/validity check — logging only in this
pass. Issuing/validating mTLS client certs is a separate feature
(shared/ca/, sdp-client/certs/) not built out yet, so this has
nothing to feed into PostureReport today; it just surfaces what's on disk.
"""

from __future__ import annotations

import datetime
from pathlib import Path

from shared.utils.logger import get_logger, status

log = get_logger("Posture-Cert")

DEFAULT_CERT_PATH = Path("./certs/client.crt")


def check(cert_path: Path = DEFAULT_CERT_PATH) -> None:
    if not cert_path.exists():
        status(log, "No mTLS device certificate present yet")
        return

    from cryptography import x509
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    valid = cert.not_valid_after_utc > datetime.datetime.now(datetime.timezone.utc)
    status(log, "Device certificate checked", valid=valid, expires=cert.not_valid_after_utc.isoformat())
