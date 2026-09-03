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
    rp_id: str = os.environ.get("RP_ID", "ztna.local")
    rp_name: str = os.environ.get("RP_NAME", "ZTNA-SDP Identity Provider")
    # First-factor username/password pepper (Argon2id). MUST be overridden via
    # env var in any real deployment — see sdp-idp/auth/password.py.
    password_pepper: str = os.environ.get("PASSWORD_PEPPER", "change-me-in-production")
    trust_threshold_full: float = float(os.environ.get("TRUST_THRESHOLD_FULL", "0.70"))
    trust_threshold_limited: float = float(os.environ.get("TRUST_THRESHOLD_LIMITED", "0.40"))

    # --- Standalone IDP (sdp-idp/) — client-facing authentication ---
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
    idp_issuer: str = os.environ.get("IDP_ISSUER", "https://idp.ztna.local")
    # Space-delimited OAuth scopes stamped into every access token. Coarse for
    # now (the Gateway currently allows/denies); widen per-resource later.
    idp_default_scopes: str = os.environ.get("IDP_DEFAULT_SCOPES", "resource.access")
    # Path the IDP READS the Gateway's ML-KEM public key from, to hand to the
    # client with its tokens. Pairs with GATEWAY_PUBKEY_PUBLISH_PATH below,
    # which is where the Gateway WRITES it. Empty -> returned as null.
    idp_gateway_pubkey_path: str = os.environ.get("IDP_GATEWAY_PUBKEY_PATH", "")

    # --- Gateway ---
    gateway_host: str = os.environ.get("GATEWAY_HOST", "0.0.0.0")
    gateway_spa_port: int = int(os.environ.get("GATEWAY_SPA_PORT", "62201"))
    # Where the Gateway drops a copy of its ML-KEM public key for the IDP to
    # serve. Empty -> no publish (point IDP_GATEWAY_PUBKEY_PATH straight at
    # the Gateway's own certs directory instead, on a single host).
    gateway_pubkey_publish_path: str = os.environ.get("GATEWAY_PUBKEY_PUBLISH_PATH", "")
    kem_alg: str = os.environ.get("KEM_ALG", "ML-KEM-768")
    kem_private_key_path: str = os.environ.get("KEM_PRIVATE_KEY_PATH", "./certs/gateway_kem_private.bin")
    kem_public_key_path: str = os.environ.get("KEM_PUBLIC_KEY_PATH", "./certs/gateway_kem_public.bin")

    # --- Client ---
    client_device_id: str = os.environ.get("CLIENT_DEVICE_ID", "")
    # Optional explicit tpm2-tools TCTI. Set this to point the client at a
    # non-default chip or a deliberately chosen simulator; it overrides the
    # platform probe order in sdp-client/tpm/anchored_trust.py.
    tpm_tcti: str = os.environ.get("TPM_TCTI", "")
    # Software-TPM endpoint, attempted ONLY under WSL (where the host's
    # physical TPM is not passed through to the guest kernel).
    tpm_swtpm_tcti: str = os.environ.get("TPM_SWTPM_TCTI", "swtpm:host=127.0.0.1,port=2321")
    # The client authenticates against the standalone IDP only. The Gateway
    # also reads this, to fetch the IDP's JWKS for token verification.
    idp_base_url: str = os.environ.get("IDP_BASE_URL", "http://localhost:9000")
    gateway_ip: str = os.environ.get("GATEWAY_IP", "127.0.0.1")
    gateway_spa_port_client: int = int(os.environ.get("GATEWAY_SPA_PORT", "62201"))


settings = Settings()
