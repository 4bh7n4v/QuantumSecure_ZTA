"""PolicyDecision — output of the Controller's policy engine for a given
posture + identity evaluation.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class PolicyDecision(BaseModel):
    allowed: bool
    acl: str  # "FULL" | "LIMITED" | "DENY"
    trust_score: float
    reasons: list[str] = Field(default_factory=list)
