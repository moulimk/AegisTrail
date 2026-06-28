"""Threat-intel enrichment via AbuseIPDB (key in ABUSEIPDB_API_KEY).

Returns None when there's no key, no IP, or a private/non-IP value, so callers
can degrade gracefully. The score is one input, not an oracle: a low abuse score
on a datacenter IP can still be highly suspicious for an interactive identity.
"""
import ipaddress
import os
from typing import Any, Optional

import httpx

API_URL = "https://api.abuseipdb.com/api/v2/check"


def _is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_link_local)
    except ValueError:
        return False


def lookup(ip: Optional[str]) -> Optional[dict[str, Any]]:
    key = os.environ.get("ABUSEIPDB_API_KEY")
    if not key or not ip or not _is_public_ip(ip):
        return None
    try:
        resp = httpx.get(
            API_URL,
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": key, "Accept": "application/json"},
            timeout=4.0,
        )
        data = resp.json().get("data")
    except Exception:
        return None
    if not data:
        return None
    return {
        "abuseConfidenceScore": data.get("abuseConfidenceScore"),
        "usageType": data.get("usageType"),
        "countryCode": data.get("countryCode"),
        "isp": data.get("isp"),
        "totalReports": data.get("totalReports"),
        "isTor": data.get("isTor"),
    }
