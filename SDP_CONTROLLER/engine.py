"""
Zero Trust Policy Engine
------------------------
Rego-style semantics in pure Python:
  * All matching rules are collected (no first-match short-circuit).
  * Any matching `deny` rule wins immediately.
  * `require_mfa` / `require_stepup` rules add obligations.
  * At least one matching `allow` rule is required to permit the request
    (zero-trust implicit deny).

Conditions are Python-ish expressions evaluated by a whitelisted AST walker,
so live-editing `policies.yaml` is safe (no `eval` on user input).
"""

from __future__ import annotations

import ast
import operator as op
from dataclasses import dataclass, field
from typing import Any

import yaml


# ---------------------------------------------------------------------------
# Safe expression evaluator
# ---------------------------------------------------------------------------

_BIN_OPS = {
    ast.Add: op.add, ast.Sub: op.sub, ast.Mult: op.mul, ast.Div: op.truediv,
    ast.Mod: op.mod, ast.FloorDiv: op.floordiv, ast.Pow: op.pow,
}
_CMP_OPS = {
    ast.Eq: op.eq, ast.NotEq: op.ne,
    ast.Lt: op.lt, ast.LtE: op.le, ast.Gt: op.gt, ast.GtE: op.ge,
    ast.In: lambda a, b: a in (b or []),
    ast.NotIn: lambda a, b: a not in (b or []),
}
_UNARY_OPS = {ast.USub: op.neg, ast.UAdd: op.pos, ast.Not: op.not_}
_SAFE_CALLS = {
    "len": len, "abs": abs, "min": min, "max": max,
    "int": int, "float": float, "str": str, "bool": bool,
    "any": any, "all": all,
}


class PolicyExprError(Exception):
    pass


def _get_attr(obj: Any, name: str) -> Any:
    if obj is None:
        return None
    if isinstance(obj, dict):
        return obj.get(name)
    return getattr(obj, name, None)


def _eval(node: ast.AST, ctx: dict) -> Any:
    if isinstance(node, ast.Expression):
        return _eval(node.body, ctx)
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        if node.id in ctx:
            return ctx[node.id]
        if node.id in {"true", "True"}: return True
        if node.id in {"false", "False"}: return False
        if node.id in {"null", "None"}: return None
        raise PolicyExprError(f"unknown name: {node.id}")
    if isinstance(node, ast.Attribute):
        return _get_attr(_eval(node.value, ctx), node.attr)
    if isinstance(node, ast.Subscript):
        obj = _eval(node.value, ctx)
        key = _eval(node.slice, ctx)
        try:
            return obj[key]
        except (KeyError, IndexError, TypeError):
            return None
    if isinstance(node, ast.Compare):
        left = _eval(node.left, ctx)
        for op_node, comp in zip(node.ops, node.comparators):
            right = _eval(comp, ctx)
            fn = _CMP_OPS.get(type(op_node))
            if fn is None:
                raise PolicyExprError(f"unsupported compare op: {type(op_node).__name__}")
            if not fn(left, right):
                return False
            left = right
        return True
    if isinstance(node, ast.BoolOp):
        vals = [_eval(v, ctx) for v in node.values]
        return all(vals) if isinstance(node.op, ast.And) else any(vals)
    if isinstance(node, ast.UnaryOp):
        return _UNARY_OPS[type(node.op)](_eval(node.operand, ctx))
    if isinstance(node, ast.BinOp):
        fn = _BIN_OPS.get(type(node.op))
        if fn is None:
            raise PolicyExprError(f"unsupported binop: {type(node.op).__name__}")
        return fn(_eval(node.left, ctx), _eval(node.right, ctx))
    if isinstance(node, ast.List):
        return [_eval(e, ctx) for e in node.elts]
    if isinstance(node, ast.Tuple):
        return tuple(_eval(e, ctx) for e in node.elts)
    if isinstance(node, ast.Call):
        if not isinstance(node.func, ast.Name) or node.func.id not in _SAFE_CALLS:
            raise PolicyExprError(f"call not allowed: {ast.dump(node.func)}")
        args = [_eval(a, ctx) for a in node.args]
        return _SAFE_CALLS[node.func.id](*args)
    raise PolicyExprError(f"unsupported syntax: {type(node).__name__}")


def evaluate_expression(expr: str, context: dict) -> bool:
    try:
        tree = ast.parse(expr, mode="eval")
    except SyntaxError as e:
        raise PolicyExprError(f"syntax error in `{expr}`: {e}") from e
    return bool(_eval(tree, context))


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

EFFECT_ALLOW = "allow"
EFFECT_DENY = "deny"
EFFECT_MFA = "require_mfa"
EFFECT_STEPUP = "require_stepup"
EFFECT_LOG = "log"

VALID_EFFECTS = {EFFECT_ALLOW, EFFECT_DENY, EFFECT_MFA, EFFECT_STEPUP, EFFECT_LOG}


@dataclass
class Policy:
    id: str
    description: str
    effect: str
    when: str
    priority: int = 0
    tags: list[str] = field(default_factory=list)


@dataclass
class MatchResult:
    policy: Policy
    matched: bool
    error: str | None = None


@dataclass
class Decision:
    verdict: str                 # "ALLOW" | "DENY"
    obligations: list[str]       # e.g. ["require_mfa"]
    matched: list[MatchResult]   # every rule that matched
    reasons: list[str]           # human-readable why
    request: dict


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

def load_policies(path: str) -> list[Policy]:
    with open(path, "r", encoding="utf-8") as f:
        doc = yaml.safe_load(f) or {}
    raw = doc.get("policies", [])
    out: list[Policy] = []
    for i, r in enumerate(raw):
        effect = r.get("effect")
        if effect not in VALID_EFFECTS:
            raise ValueError(f"policy[{i}] {r.get('id')!r}: invalid effect {effect!r}")
        out.append(Policy(
            id=r["id"],
            description=r.get("description", ""),
            effect=effect,
            when=r.get("when", "false"),
            priority=int(r.get("priority", 0)),
            tags=list(r.get("tags", [])),
        ))
    return out


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------

def evaluate(policies: list[Policy], request: dict) -> Decision:
    """
    Evaluate an access request against every policy.
    Zero-trust semantics: at least one `allow` must match, and any `deny`
    kills the request.
    """
    matches: list[MatchResult] = []
    for p in sorted(policies, key=lambda x: -x.priority):
        try:
            hit = evaluate_expression(p.when, request)
            matches.append(MatchResult(policy=p, matched=bool(hit)))
        except PolicyExprError as e:
            matches.append(MatchResult(policy=p, matched=False, error=str(e)))

    matched = [m for m in matches if m.matched]

    denies = [m for m in matched if m.policy.effect == EFFECT_DENY]
    allows = [m for m in matched if m.policy.effect == EFFECT_ALLOW]
    mfas   = [m for m in matched if m.policy.effect == EFFECT_MFA]
    steps  = [m for m in matched if m.policy.effect == EFFECT_STEPUP]

    reasons: list[str] = []
    obligations: list[str] = []

    if denies:
        for m in denies:
            reasons.append(f"DENY by {m.policy.id}: {m.policy.description}")
        return Decision("DENY", [], matches, reasons, request)

    if not allows:
        reasons.append("No allow rule matched — zero-trust implicit deny.")
        return Decision("DENY", [], matches, reasons, request)

    for m in allows:
        reasons.append(f"allow by {m.policy.id}: {m.policy.description}")

    if mfas:
        obligations.append("require_mfa")
        for m in mfas:
            reasons.append(f"obligation: MFA required by {m.policy.id}")
    if steps:
        obligations.append("require_stepup")
        for m in steps:
            reasons.append(f"obligation: step-up auth required by {m.policy.id}")

    return Decision("ALLOW", obligations, matches, reasons, request)
