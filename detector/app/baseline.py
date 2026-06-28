"""Per-identity behavioral baseline (Phase 2).

Rolling 7-day window with a 24h fallback when data is thin. Stores aggregates
only (known regions/services, bounded IP set, API-rate mean/std). Seed this
before a demo to avoid the cold-start problem (Round 2 #2): a fresh account has
no history, so every event would otherwise look "new".

TODO(Phase 2): implement update_baseline(event) and is_new_region(identity, region).
"""
from .models import NormalizedEvent

MAX_TRACKED_IPS = 50  # bound the last_seen_ips set


def update_baseline(event: NormalizedEvent) -> None:
    """Incrementally fold an event into its identity's baseline. (Phase 2)"""
    raise NotImplementedError("Phase 2")


def is_new_region(identity: str, region: str | None) -> bool:
    """True if `region` is outside the identity's known regions. (Phase 2)"""
    raise NotImplementedError("Phase 2")
