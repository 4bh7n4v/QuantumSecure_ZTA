"""Which relying party ids will Windows release a TPM attestation for?

A first sweep with this tool established that neither the options structure
version nor the resident-key flag makes any difference: version 1 and version
4 behaved identically, and the only input that changed the answer was the
relying party id. `ztna.local` produced a credential with no attestation,
while `localhost` produced a full one from the same machine seconds later.

Windows treats attestation as machine-identifying and only releases it to a
relying party whose name it can treat as a real, registrable domain. `.local`
is reserved for multicast DNS and is not registrable, so it is refused;
localhost is the documented development exception.

This sweep now compares candidate replacements, so RP_ID can be changed to
something that works on Windows and stays sensible for the project. Run it on
Windows and confirm the Hello prompt for each candidate. Every candidate
creates one throwaway passkey; the ids are printed at the end so they can be
removed under Settings -> Accounts -> Passkeys.

    .venv-win\\Scripts\\python.exe tools\\webauthn_variants.py
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import json
import secrets

from fido2.webauthn import CollectedClientData

from tpm import windows_webauthn
from shared.config.settings import settings


def _client_data(origin: str) -> bytes:
    return bytes(CollectedClientData.create(
        type="webauthn.create", challenge=secrets.token_bytes(32), origin=origin))


def run(label: str, rp_id: str, options_version: int, resident_key: bool) -> dict:
    print(f"\n--- {label} ---")
    print(f"    rp_id={rp_id}  options_version={options_version}  resident_key={resident_key}")
    print("    Confirm on the Windows Hello prompt...")
    try:
        attestation_object, credential_id, fmt = windows_webauthn.make_credential(
            rp_id=rp_id,
            rp_name="ZTNA-SDP attestation variant probe",
            user_id=secrets.token_bytes(16),
            user_name="variant-probe",
            client_data_json=_client_data(f"https://{rp_id}"),
            options_version=options_version,
            require_resident_key=resident_key,
        )
    except Exception as exc:  # noqa: BLE001 - a failing variant is a result, not a crash
        print(f"    FAILED: {exc}")
        return {"label": label, "fmt": "(call failed)", "bytes": 0, "error": str(exc)}

    print(f"    -> fmt={fmt}  attestation_object={len(attestation_object)} bytes")
    return {"label": label, "fmt": fmt, "bytes": len(attestation_object),
            "credential_id": credential_id.hex()}


def main() -> int:
    if sys.platform != "win32":
        print("This probe only means anything on Windows.", file=sys.stderr)
        return 1
    if not windows_webauthn.probe():
        print("No Windows Hello platform authenticator available.", file=sys.stderr)
        return 1

    rp_id = settings.rp_id
    print(f"Sweeping Windows Hello attestation. Configured RP_ID is {rp_id!r}"
          f" ({'should attest' if windows_webauthn.rp_id_supports_attestation(rp_id) else 'will NOT attest'}).")
    print("Four prompts follow; each creates one throwaway passkey.")

    # An earlier sweep of the options structure version and the resident-key
    # flag showed neither changes anything: only the relying party id does.
    # ztna.local returned no attestation and localhost returned a full one, so
    # what is left to establish is which registrable domain to settle on.
    results = [
        run(f"configured RP_ID ({rp_id})", rp_id, 4, False),
        run("localhost (known good)", "localhost", 4, False),
        run("ztna.example.com", "ztna.example.com", 4, False),
        run("ztna-sdp.com", "ztna-sdp.com", 4, False),
    ]

    print("\n" + "=" * 68)
    print(f"{'variant':<34}{'fmt':<10}{'bytes':>8}")
    print("-" * 68)
    for row in results:
        print(f"{row['label']:<34}{row['fmt']:<10}{row['bytes']:>8}")
    print("=" * 68)

    attested = [row["label"] for row in results if row["fmt"] not in ("none", "(call failed)")]
    if attested:
        print("\nAttestation WAS returned for: " + ", ".join(attested))
        print("Set the winning combination as the default in tpm/windows_webauthn.py.")
    else:
        print("\nNo variant produced attestation. The difference from the browser lies")
        print("somewhere else in the request; capture this output before digging further.")

    print("\nThrowaway passkeys created (remove under Settings -> Accounts -> Passkeys):")
    print(json.dumps([r.get("credential_id") for r in results if r.get("credential_id")], indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
