"""AccessTokenClaims — the JWT claim shape issued by the Controller's IdP
after a successful FIDO2 authentication + policy decision.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class AccessTokenClaims(BaseModel):
    iss: str
    sub: str  # user_id
    aud: str
    iat: int
    exp: int
    jti: str
    credential_id: str
    trust_score: float
    acl: str  # "FULL" | "LIMITED" | "DENY"
    trust_anchor: str
    device_id: str
    amr: list[str] = Field(default_factory=lambda: ["fido2"])
