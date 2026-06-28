"""Pydantic models for the detector API."""
from datetime import datetime
from typing import Any, Literal, Optional

from pydantic import BaseModel


class NormalizedEvent(BaseModel):
    event_id: str
    identity: str
    action: str
    service: Optional[str] = None
    resource: Optional[str] = None
    source_ip: Optional[str] = None
    region: Optional[str] = None
    event_time: datetime
    raw_event: dict[str, Any]


class ScoreRequest(BaseModel):
    event_id: str


class SeedRequest(BaseModel):
    identity: str
    known_regions: list[str] = []
    known_countries: list[str] = []
    known_services: list[str] = []
    last_seen_ips: list[str] = []
    event_count: int = 0


class ContainRequest(BaseModel):
    identity: str
    identity_type: Literal["iam_user", "role_session", "root"] = "iam_user"
    action: Literal["deactivate_key", "attach_deny", "disable_user"]
    access_key_id: Optional[str] = None
    reason: Optional[str] = None


class ContainResult(BaseModel):
    safe_mode: bool
    allowed: bool          # False if blocked by the protected-identity allowlist
    executed: bool
    plan: list[str]        # human-readable / CLI action plan
    notes: Optional[str] = None
