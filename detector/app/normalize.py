"""Normalize a raw AWS CloudTrail record into AegisTrail's unified event schema."""
from datetime import datetime, timezone
from typing import Any, Optional

from .models import NormalizedEvent


def _identity(user_identity: dict[str, Any]) -> str:
    """Collapse a CloudTrail userIdentity block into a stable principal string."""
    if user_identity.get("type") == "Root":
        return "root"
    return (
        user_identity.get("userName")
        or user_identity.get("arn")
        or user_identity.get("principalId")
        or "unknown"
    )


def _first_resource(record: dict[str, Any]) -> Optional[str]:
    resources = record.get("resources") or []
    if resources and isinstance(resources, list):
        return resources[0].get("ARN") or resources[0].get("type")
    return None


def _parse_time(value: Optional[str]) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def normalize_cloudtrail(record: dict[str, Any]) -> NormalizedEvent:
    user_identity = record.get("userIdentity", {})
    event_time = _parse_time(record.get("eventTime"))
    return NormalizedEvent(
        event_id=record.get("eventID") or f"synthetic-{event_time.timestamp()}",
        identity=_identity(user_identity),
        action=record.get("eventName", "Unknown"),
        service=(record.get("eventSource", "") or "").split(".")[0] or None,
        resource=_first_resource(record),
        source_ip=record.get("sourceIPAddress"),
        region=record.get("awsRegion"),
        event_time=event_time,
        raw_event=record,
    )
