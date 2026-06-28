"""Detection rules — the deterministic half of triage (Phase 2).

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

# usageType substrings that indicate an IP is hosting/datacenter infrastructure —
# suspicious for an interactive human identity.
HOSTING_HINTS = ("data center", "datacenter", "hosting", "transit")


def run_rules(
    event: dict,
    geo: Optional[dict],
    threat_intel: Optional[dict],
    baseline: Optional[dict],
) -> list[dict[str, Any]]:
    signals: list[dict[str, Any]] = []

    # Scenario #1 — NEW_REGION: source-IP country outside the identity's baseline.
    # Only fires with a seeded baseline (avoids cold-start false positives).
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

    # Threat-intel signals (AbuseIPDB).
    if threat_intel:
        score = threat_intel.get("abuseConfidenceScore") or 0
        if score >= 50:
            signals.append({
                "type": "TI_ABUSE",
                "detail": f"AbuseIPDB score {score}/100 ({threat_intel.get('totalReports')} reports)",
            })
        usage = (threat_intel.get("usageType") or "").lower()
        if any(hint in usage for hint in HOSTING_HINTS):
            signals.append({
                "type": "TI_HOSTING",
                "detail": f"source IP usage type '{threat_intel.get('usageType')}' (datacenter/hosting)",
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
    if "TI_ABUSE" in types:
        return "MALICIOUS_IP"
    return "ANOMALY"


def confidence(signals: list[dict]) -> float:
    return round(min(1.0, 0.4 + 0.3 * len(signals)), 2)
