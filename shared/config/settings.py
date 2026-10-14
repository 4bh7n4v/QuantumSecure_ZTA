"""Central environment-variable-backed settings, shared by all four components.

Per project rule: secrets and per-deployment values live in the environment
(.env, gitignored) — never hardcoded here. This module only defines names,
types and safe defaults.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()


@dataclass(frozen=True)
class Settings:
    # --- WebAuthn Relying Party (shared by the IDP and the client) ---
    # Must be a REGISTRABLE domain. It was "ztna.local" until a Windows machine
    # showed why that cannot stand: Windows treats an attestation as
    # machine-identifying and only releases one to a relying party whose name
    # it can treat as a real domain. With a .local name it still returns a
    # working credential, just with no attestation, so the IDP refuses the
    # enrolment and nothing in the failure mentions the cause. The same request
    # with a registrable name returned a full TPM attestation.
    #
    # No DNS lookup happens: the IDP is reached at IDP_BASE_URL, and this value
    # is only the label both sides bind credentials to. It must be identical on
    # the IDP and the client, and changing it invalidates existing credentials,
    # which then re-enrol. See SDP_CLIENT/tpm/windows_webauthn.py.
    rp_id: str = os.environ.get("RP_ID", "ztna.example.com")
    rp_name: str = os.environ.get("RP_NAME", "ZTNA-SDP Identity Provider")
    # First-factor username/password pepper (Argon2id). MUST be overridden via
    # env var in any real deployment — see IDENTITY_PROVIDER/auth/password.py.
    password_pepper: str = os.environ.get("PASSWORD_PEPPER", "change-me-in-production")
    trust_threshold_full: float = float(os.environ.get("TRUST_THRESHOLD_FULL", "0.70"))
    trust_threshold_limited: float = float(os.environ.get("TRUST_THRESHOLD_LIMITED", "0.40"))

    # --- Standalone IDP (IDENTITY_PROVIDER/) — client-facing authentication ---
    # The client talks only to the IDP (auth) and the Gateway (data plane).
    # The Gateway consults the IDP's JWKS to verify access tokens; the IDP
    # never calls anything downstream of it.
    idp_host: str = os.environ.get("IDP_HOST", "0.0.0.0")
    idp_port: int = int(os.environ.get("IDP_PORT", "9000"))
    idp_db_path: str = os.environ.get("IDP_DB_PATH", "./data/idp.db")
    idp_jwt_private_key_path: str = os.environ.get(
        "IDP_JWT_PRIVATE_KEY_PATH", "./certs/idp_jwt_private.pem")
    idp_jwt_public_key_path: str = os.environ.get(
        "IDP_JWT_PUBLIC_KEY_PATH", "./certs/idp_jwt_public.pem")
    idp_access_ttl_seconds: int = int(os.environ.get("IDP_ACCESS_TTL_SECONDS", "900"))     # 15 min
    idp_refresh_ttl_seconds: int = int(os.environ.get("IDP_REFRESH_TTL_SECONDS", "43200"))  # 12 h
    idp_login_token_ttl_seconds: int = int(os.environ.get("IDP_LOGIN_TOKEN_TTL_SECONDS", "120"))
    idp_admin_api_key: str = os.environ.get("IDP_ADMIN_API_KEY", "change-me-admin-key")
    idp_token_audience: str = os.environ.get("IDP_TOKEN_AUDIENCE", "sdp-gateway")
    # Second audience on the access token: the resource nodes also accept it,
    # after the Gateway, so it names both.
    idp_resource_audience: str = os.environ.get("IDP_RESOURCE_AUDIENCE", "resource-node")
    # Knock ticket: the small ES256-signed token carried inside the SPA knock
    # (see shared/utils/knock_ticket.py). Separate key from the RS256 JWT key.
    idp_knock_ticket_ttl_seconds: int = int(os.environ.get("IDP_KNOCK_TICKET_TTL_SECONDS", "60"))
    idp_ticket_private_key_path: str = os.environ.get(
        "IDP_TICKET_PRIVATE_KEY_PATH", "./certs/idp_ticket_private.pem")
    idp_ticket_public_key_path: str = os.environ.get(
        "IDP_TICKET_PUBLIC_KEY_PATH", "./certs/idp_ticket_public.pem")
    idp_issuer: str = os.environ.get("IDP_ISSUER", "https://idp.ztna.example.com")
    # Space-delimited OAuth scopes stamped into every access token. Coarse for
    # now (the Gateway currently allows/denies); widen per-resource later.
    idp_default_scopes: str = os.environ.get("IDP_DEFAULT_SCOPES", "resource.access")
    # --- IDP <-> Gateway link (mutual TLS, project CA in shared/ca/) ---
    # A second, Gateway-only listener. Each Gateway connects here with its own
    # CA-issued certificate to register its ML-KEM public key and to fetch the
    # JWKS. Clients never use this port.
    idp_gateway_link_host: str = os.environ.get("IDP_GATEWAY_LINK_HOST", "0.0.0.0")
    idp_gateway_link_port: int = int(os.environ.get("IDP_GATEWAY_LINK_PORT", "9443"))
    # Where admin_cli.py keeps the CA (its key never leaves this machine) and
    # the IDP's own server certificate.
    idp_ca_dir: str = os.environ.get("IDP_CA_DIR", "./certs/ca")
    idp_tls_cert_path: str = os.environ.get("IDP_TLS_CERT_PATH", "./certs/pki/idp.crt")
    idp_tls_key_path: str = os.environ.get("IDP_TLS_KEY_PATH", "./certs/pki/idp.key")

    # --- IDP: TPM attestation enforcement (M2) ---
    # Fail closed by default: a credential may only be enrolled if the
    # authenticator proved, cryptographically, that the credential private key
    # was generated inside and cannot leave a hardware authenticator. A
    # self-attested (fmt="none") credential is refused. Set false only for a
    # backend that cannot yet produce an attestation statement — today that is
    # the Windows CNG path (see SDP_CLIENT/tpm/windows_tpm.py).
    idp_enforce_tpm_attestation: bool = os.environ.get(
        "IDP_ENFORCE_TPM_ATTESTATION", "true").strip().lower() in ("1", "true", "yes", "on")
    # Directory of PEM-encoded TPM vendor / platform AttCA root certificates.
    # When it holds at least one certificate, a "tpm" attestation's x5c chain
    # MUST terminate in one of them — that is what proves the attestation key
    # lives in a genuine manufacturer-issued TPM. When the directory is empty
    # the chain cannot be traced to a manufacturer, so the attestation key is
    # pinned per device on first enrolment instead; see fido2_idp/tpm_trust.py.
    idp_tpm_root_ca_dir: str = os.environ.get("IDP_TPM_ROOT_CA_DIR", "./certs/tpm_roots")

    # --- Gateway ---
    gateway_host: str = os.environ.get("GATEWAY_HOST", "0.0.0.0")
    gateway_spa_port: int = int(os.environ.get("GATEWAY_SPA_PORT", "62201"))
    # The IDP's Gateway-only mTLS listener, and this Gateway's bundle from
    # `admin_cli.py issue-gateway-cert` (its certificate, its key, the CA).
    # The host in the URL must be one the IDP certificate was issued for.
    gateway_idp_link_url: str = os.environ.get("GATEWAY_IDP_LINK_URL", "https://localhost:9443")
    gateway_tls_cert_path: str = os.environ.get("GATEWAY_TLS_CERT_PATH", "./certs/pki/gateway.crt")
    gateway_tls_key_path: str = os.environ.get("GATEWAY_TLS_KEY_PATH", "./certs/pki/gateway.key")
    gateway_ca_cert_path: str = os.environ.get("GATEWAY_CA_CERT_PATH", "./certs/pki/ca.crt")
    kem_alg: str = os.environ.get("KEM_ALG", "ML-KEM-768")
    kem_private_key_path: str = os.environ.get("KEM_PRIVATE_KEY_PATH", "./certs/gateway_kem_private.bin")
    kem_public_key_path: str = os.environ.get("KEM_PUBLIC_KEY_PATH", "./certs/gateway_kem_public.bin")

    # --- Client ---
    client_device_id: str = os.environ.get("CLIENT_DEVICE_ID", "")
    # Optional explicit tpm2-tools TCTI. Set this to point the client at a
    # non-default chip or a deliberately chosen simulator; it overrides the
    # platform probe order in SDP_CLIENT/tpm/anchored_trust.py.
    tpm_tcti: str = os.environ.get("TPM_TCTI", "")
    # Software-TPM endpoint, attempted ONLY under WSL (where the host's
    # physical TPM is not passed through to the guest kernel).
    tpm_swtpm_tcti: str = os.environ.get("TPM_SWTPM_TCTI", "swtpm:host=127.0.0.1,port=2321")
    # The client authenticates against the standalone IDP only. (The Gateway
    # reaches the IDP over the mTLS link instead: gateway_idp_link_url.)
    idp_base_url: str = os.environ.get("IDP_BASE_URL", "http://localhost:9000")
    gateway_ip: str = os.environ.get("GATEWAY_IP", "127.0.0.1")
    gateway_spa_port_client: int = int(os.environ.get("GATEWAY_SPA_PORT", "62201"))
    # The resource port the client's SPA knock asks the Gateway to open.
    client_access_port: int = int(os.environ.get("CLIENT_ACCESS_PORT", "443"))
    client_access_protocol: str = os.environ.get("CLIENT_ACCESS_PROTOCOL", "tcp")


settings = Settings()
