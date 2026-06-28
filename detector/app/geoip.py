"""GeoIP enrichment via ip-api.com (free, no key at low volume, HTTP only).

Returns None for private/reserved IPs or non-IP source values (e.g. an AWS
service principal like "cloudtrail.amazonaws.com"), so callers can skip geo
rules cleanly.
"""
import ipaddress
from typing import Any, Optional

import httpx

FIELDS = "status,message,country,countryCode,city,isp,query"


def _is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_link_local)
    except ValueError:
        return False


def lookup(ip: Optional[str]) -> Optional[dict[str, Any]]:
    if not ip or not _is_public_ip(ip):
        return None
    try:
        resp = httpx.get(
            f"http://ip-api.com/json/{ip}", params={"fields": FIELDS}, timeout=4.0
        )
        data = resp.json()
    except Exception:
        return None
    return data if data.get("status") == "success" else None
