"""Detection rules — the deterministic half of triage (Phase 2a).

Each rule emits a signal dict {type, detail}. The signal *types* feed scoring.py
for a 0..100 risk score. Rules treat finding data as untrusted input.
"""
from typing import Any, Optional

# Scenario #2: classic IAM privilege-escalation actions (Rhino-style paths).
PRIVESC_ACTIONS = {
    "AttachUserPolicy",
    "AttachRolePolicy",
    "PutUserPolicy",
    "CreateAccessKey",
    "AddUserToGroup",
    "CreatePolicyVersion",
    "UpdateAssumeRolePolicy",
    "CreateLoginProfile",
}


def run_rules(event: dict, geo: Optional[dict], baseline: Optional[dict]) -> list[dict[str, Any]]:
    signals: list[dict[str, Any]] = []

    # Scenario #1 — NEW_REGION: source-IP country outside the identity's baseline.
    # Only fires when we have a seeded baseline of known countries (avoids cold-start
    # false positives, Round 2 #2/#3).
    if geo and baseline:
        known = set(baseline.get("known_countries") or [])
        country = geo.get("country")
        if known and country and country not in known:
            signals.append({
                "type": "NEW_REGION",
                "detail": f"source country '{country}' not in baseline {sorted(known)}",
            })

    # Scenario #2 — PRIV_ESC_CHAIN: a sensitive IAM mutation.
    if event.get("action") in PRIVESC_ACTIONS:
        signals.append({
            "type": "PRIV_ESC_CHAIN",
            "detail": f"sensitive action {event.get('action')}",
        })

    return signals


def incident_type(signals: list[dict]) -> str:
    types = {s["type"] for s in signals}
    if {"NEW_REGION", "PRIV_ESC_CHAIN"} <= types:
        return "CREDENTIAL_COMPROMISE"
    if "PRIV_ESC_CHAIN" in types:
        return "PRIVILEGE_ESCALATION"
    if "NEW_REGION" in types:
        return "SUSPICIOUS_LOCATION"
    return "ANOMALY"


def confidence(signals: list[dict]) -> float:
    return round(min(1.0, 0.4 + 0.3 * len(signals)), 2)
