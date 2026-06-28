"""Containment with SAFE_MODE + the protected-identity allowlist.

SAFE_MODE=true  -> return the action plan only, execute nothing (default/demo).
SAFE_MODE=false -> execute scoped identity actions via boto3 (Phase 3).

Round 2 #1: the responder must NEVER act on a protected identity (root,
break-glass, its own role). Those escalate to a human instead.
"""
import os

from .models import ContainRequest, ContainResult


def _protected() -> set[str]:
    raw = os.environ.get("PROTECTED_IDENTITIES", "root")
    return {p.strip().lower() for p in raw.split(",") if p.strip()}


def _safe_mode() -> bool:
    return os.environ.get("SAFE_MODE", "true").strip().lower() != "false"


def _plan_for(req: ContainRequest) -> list[str]:
    if req.action == "deactivate_key":
        return [
            f"aws iam update-access-key --user-name {req.identity} "
            f"--access-key-id {req.access_key_id or '<ACCESS_KEY_ID>'} --status Inactive"
        ]
    if req.action == "disable_user":
        return [
            f"aws iam delete-login-profile --user-name {req.identity}  # force console logout",
        ]
    if req.action == "attach_deny":
        return [
            f"aws iam attach-user-policy --user-name {req.identity} "
            f"--policy-arn arn:aws:iam::<ACCOUNT_ID>:policy/AegisTrail-Quarantine",
        ]
    return [f"# no plan template for action={req.action}"]


def contain(req: ContainRequest) -> ContainResult:
    safe = _safe_mode()

    # Hard guard: protected identities and root are never auto-contained.
    if req.identity_type == "root" or req.identity.lower() in _protected():
        return ContainResult(
            safe_mode=safe,
            allowed=False,
            executed=False,
            plan=[],
            notes="BLOCKED: protected identity — escalate to a human; do not auto-contain.",
        )

    plan = _plan_for(req)

    if safe:
        return ContainResult(
            safe_mode=True,
            allowed=True,
            executed=False,
            plan=plan,
            notes="SAFE_MODE: plan only, nothing executed.",
        )

    # SAFE_MODE=false: real execution via boto3 lands here in Phase 3.
    return ContainResult(
        safe_mode=False,
        allowed=True,
        executed=False,
        plan=plan,
        notes="Execution path not yet implemented (Phase 3).",
    )
