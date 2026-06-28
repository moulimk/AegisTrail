"""Deterministic risk scoring — the rules-engine half of triage (Phase 2).

Reused from the prior design. The LLM never replaces this; it annotates the
result with a plain-English summary. See the Notion plan: "AI vs. Rules".
"""

# Base severity per detection signal.
SIGNAL_BASE = {
    "NEW_REGION": 20,
    "API_RATE_ANOMALY": 30,
    "TI_HOSTING": 15,      # source IP is datacenter/hosting (contextual)
    "TI_ABUSE": 40,        # source IP flagged by threat intel
    "PRIV_ESC_CHAIN": 60,
    "DATA_EXFIL": 70,
}


def score(
    signals: list[str],
    *,
    anomaly_multiplier: float = 1.0,
    repeat_offense_bonus: int = 0,
    privilege_weight: int = 0,
) -> int:
    """Combine signals into a 0..100 risk score (capped)."""
    base = sum(SIGNAL_BASE.get(s, 0) for s in signals)
    total = base * anomaly_multiplier + repeat_offense_bonus + privilege_weight
    return max(0, min(int(total), 100))
