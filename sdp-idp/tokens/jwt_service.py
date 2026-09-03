"""RS256 token service for the IDP.

The IDP is the only holder of the signing private key. It mints three kinds
of JWT, all signed with the same RSA key but distinguished by `aud`:

  - login  (`aud = "idp-login"`)  : ~2 min. Proof that the first factor
                                    passed; the client presents it on the
                                    /fido2/* calls so the ceremony is bound
                                    to the verified user without replaying
                                    the password.
  - access (`aud = <token audience>`, default "sdp-gateway"): 15 min. What
                                    the client will later put in the SPA
                                    packet; the Gateway verifies it with the
                                    IDP's JWKS. Carries `sid` (session id,
                                    shared with the refresh token and every
                                    access token later minted from it),
                                    `acr` (assurance level derived from the
                                    methods actually performed), `scope`, and
                                    — once the client<->Gateway mTLS path
                                    exists — `cnf` binding it to the client
                                    certificate (RFC 7800).
  - refresh(`aud = "idp-refresh"`) : 12 h. Swapped at /token/refresh for a
                                    fresh access token, no FIDO2 replay.
                                    Tracked in store/tokens.py so it can be
                                    revoked.

Every step logs: key load, claim assembly, signing, and (on verify) which
check failed.
"""

from __future__ import annotations

import time
import uuid

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from shared.config.settings import settings
from shared.utils.crypto import load_or_generate_rsa_keypair
from shared.utils.logger import get_logger, status

log = get_logger("IDP-JWT")

AUD_LOGIN = "idp-login"
AUD_REFRESH = "idp-refresh"

_private_key: RSAPrivateKey
_public_key: RSAPublicKey
_kid: str


def init() -> None:
    global _private_key, _public_key, _kid
    _private_key, _public_key = load_or_generate_rsa_keypair(
        settings.idp_jwt_private_key_path, settings.idp_jwt_public_key_path,
    )
    # Stable key id derived from the public key bytes, so the JWKS `kid` does
    # not change across restarts as long as the key file is the same.
    pub_der = _public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    import hashlib
    _kid = hashlib.sha256(pub_der).hexdigest()[:16]
    status(log, "IDP signing key loaded", kid=_kid,
           private_key_path=settings.idp_jwt_private_key_path)


def _encode(claims: dict, kind: str) -> str:
    status(log, "Assembling JWT claims", kind=kind, sub=claims.get("sub"),
           aud=claims.get("aud"), jti=claims.get("jti"), sid=claims.get("sid"),
           acr=claims.get("acr"), scope=claims.get("scope"),
           cnf=("bound" if claims.get("cnf") else None),
           ttl_s=claims["exp"] - claims["iat"])
    token = jwt.encode(claims, _private_key, algorithm="RS256", headers={"kid": _kid})
    status(log, "JWT signed", kind=kind, jti=claims.get("jti"), alg="RS256", kid=_kid)
    return token


def _acr_for(amr: list[str]) -> str:
    """Map the methods actually performed to an assurance level. Hardware-
    attested FIDO2 (phishing-resistant, hardware-bound key) clears AAL3;
    password + software FIDO2 is AAL2. Resources use this to demand step-up.
    """
    return "aal3" if "hwattest" in amr else "aal2"


def issue_login_token(user_id: str, username: str, device_id: str) -> tuple[str, dict]:
    now = int(time.time())
    claims = {
        "iss": settings.idp_issuer, "sub": user_id, "aud": AUD_LOGIN,
        "iat": now, "exp": now + settings.idp_login_token_ttl_seconds,
        "jti": str(uuid.uuid4()), "username": username, "device_id": device_id,
        "amr": ["pwd"],
    }
    return _encode(claims, "login"), claims


def issue_access_token(user_id: str, username: str, device_id: str, credential_id: str,
                       amr: list[str], sid: str, scope: str | None = None,
                       cnf_jkt: str | None = None) -> tuple[str, dict]:
    now = int(time.time())
    claims = {
        "iss": settings.idp_issuer, "sub": user_id, "aud": settings.idp_token_audience,
        "iat": now, "exp": now + settings.idp_access_ttl_seconds,
        "jti": str(uuid.uuid4()), "sid": sid,
        "username": username, "device_id": device_id,
        "credential_id": credential_id,
        "amr": amr, "acr": _acr_for(amr),
        "scope": scope if scope is not None else settings.idp_default_scopes,
    }
    if cnf_jkt:
        # Sender-constrained token (RFC 7800): the Gateway must reject this
        # token unless the TLS client certificate on the connection hashes to
        # this value. Passed None until the client<->Gateway mTLS path lands
        # (Gateway phase) — same "wired but dormant" pattern as
        # gateway_public_key.
        claims["cnf"] = {"x5t#S256": cnf_jkt}
    return _encode(claims, "access"), claims


def issue_refresh_token(user_id: str, username: str, device_id: str,
                        sid: str) -> tuple[str, dict]:
    now = int(time.time())
    claims = {
        "iss": settings.idp_issuer, "sub": user_id, "aud": AUD_REFRESH,
        "iat": now, "exp": now + settings.idp_refresh_ttl_seconds,
        "jti": str(uuid.uuid4()), "sid": sid,
        "username": username, "device_id": device_id,
    }
    return _encode(claims, "refresh"), claims


def verify(token: str, expected_aud: str) -> dict:
    """Decode + validate. Raises jwt.PyJWTError with a specific message on
    any failed check (expiry, audience, signature)."""
    try:
        claims = jwt.decode(
            token, _public_key, algorithms=["RS256"],
            audience=expected_aud, issuer=settings.idp_issuer,
        )
    except jwt.ExpiredSignatureError:
        status(log, "JWT rejected", reason="expired", expected_aud=expected_aud)
        raise
    except jwt.InvalidAudienceError:
        status(log, "JWT rejected", reason="wrong audience", expected_aud=expected_aud)
        raise
    except jwt.InvalidIssuerError:
        status(log, "JWT rejected", reason="wrong issuer", expected_aud=expected_aud)
        raise
    except jwt.PyJWTError as exc:
        status(log, "JWT rejected", reason=str(exc), expected_aud=expected_aud)
        raise
    status(log, "JWT verified", aud=expected_aud, sub=claims.get("sub"), jti=claims.get("jti"))
    return claims


def public_key_pem() -> bytes:
    return _public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def jwks() -> dict:
    """RFC 7517 JWK Set for the Gateway (and anyone else) to verify IDP
    access tokens. RSA public key only.
    """
    numbers = _public_key.public_numbers()

    def _b64u(n: int) -> str:
        import base64
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    return {
        "keys": [{
            "kty": "RSA", "use": "sig", "alg": "RS256", "kid": _kid,
            "n": _b64u(numbers.n), "e": _b64u(numbers.e),
        }]
    }
