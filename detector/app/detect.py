"""Detection rules — the deterministic half of triage.

Each rule emits a signal dict {type, detail}. The signal *types* feed scoring.py
for a 0..100 risk score. Rules treat finding data as untrusted input.
"""
from typing import Any, Optional

# Scenario #2: classic IAM privilege-escalation actions (Rhino-style paths).
PRIVESC_ACTIONS = {
    "AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy", "CreateAccessKey",
    "AddUserToGroup", "CreatePolicyVersion", "UpdateAssumeRolePolicy", "CreateLoginProfile",
}

# Scenario #3: high-signal IAM enumeration / recon actions.
RECON_ACTIONS = {
    "GetAccountAuthorizationDetails", "ListUsers", "ListRoles", "ListAccessKeys",
    "ListAttachedUserPolicies", "ListGroupsForUser", "GetAccountSummary",
    "ListPolicies", "ListUserPolicies",
}

# Scenario #4: MFA tampering.
MFA_DISABLE_ACTIONS = {"DeactivateMFADevice", "DeleteVirtualMFADevice"}

# usageType substrings that indicate hosting/datacenter infrastructure.
HOSTING_HINTS = ("data center", "datacenter", "hosting", "transit")

RECON_BURST_THRESHOLD = 5  # read/list calls by one identity in the lookback window


def run_rules(
    event: dict,
    geo: Optional[dict],
    threat_intel: Optional[dict],
    baseline: Optional[dict],
    recon_count: int = 0,
) -> list[dict[str, Any]]:
    signals: list[dict[str, Any]] = []
    action = event.get("action")

    # Scenario #1 — NEW_REGION: source-IP country outside the identity's baseline.
    if geo and baseline:
        known = set(baseline.get("known_countries") or [])
        country = geo.get("country")
        if known and country and country not in known:
            signals.append({"type": "NEW_REGION",
                            "detail": f"source country '{country}' not in baseline {sorted(known)}"})

    # Scenario #2 — PRIV_ESC_CHAIN: a sensitive IAM mutation.
    if action in PRIVESC_ACTIONS:
        signals.append({"type": "PRIV_ESC_CHAIN", "detail": f"sensitive action {action}"})

    # Threat-intel signals (AbuseIPDB).
    if threat_intel:
        score = threat_intel.get("abuseConfidenceScore") or 0
        if score >= 50:
            signals.append({"type": "TI_ABUSE",
                            "detail": f"AbuseIPDB score {score}/100 ({threat_intel.get('totalReports')} reports)"})
        usage = (threat_intel.get("usageType") or "").lower()
        if any(hint in usage for hint in HOSTING_HINTS):
            signals.append({"type": "TI_HOSTING",
                            "detail": f"source IP usage type '{threat_intel.get('usageType')}' (datacenter/hosting)"})

    # Scenario #3 — RECON: a known enumeration action, or a burst of read/list calls.
    if action in RECON_ACTIONS:
        signals.append({"type": "RECON", "detail": f"enumeration action {action}"})
    elif recon_count >= RECON_BURST_THRESHOLD:
        signals.append({"type": "RECON", "detail": f"{recon_count} read/list calls in the lookback window"})

    # Scenario #4 — ROOT_ACTIVITY: any use of the root account.
    ui_type = (event.get("raw_event") or {}).get("userIdentity", {}).get("type")
    if event.get("identity") == "root" or ui_type == "Root":
        signals.append({"type": "ROOT_ACTIVITY", "detail": "root account activity"})

    # Scenario #4 — MFA_DISABLED: MFA being turned off.
    if action in MFA_DISABLE_ACTIONS:
        signals.append({"type": "MFA_DISABLED", "detail": f"MFA tampering: {action}"})

    return signals


def incident_type(signals: list[dict]) -> str:
    types = {s["type"] for s in signals}
    if {"NEW_REGION", "PRIV_ESC_CHAIN"} <= types:
        return "CREDENTIAL_COMPROMISE"
    if "ROOT_ACTIVITY" in types:
        return "ROOT_USAGE"
    if "MFA_DISABLED" in types:
        return "MFA_TAMPERING"
    if "PRIV_ESC_CHAIN" in types:
        return "PRIVILEGE_ESCALATION"
    if "RECON" in types:
        return "RECONNAISSANCE"
    if "NEW_REGION" in types:
        return "SUSPICIOUS_LOCATION"
    if "TI_ABUSE" in types:
        return "MALICIOUS_IP"
    return "ANOMALY"


def confidence(signals: list[dict]) -> float:
    return round(min(1.0, 0.4 + 0.3 * len(signals)), 2)
