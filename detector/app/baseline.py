"""Per-identity behavioral baseline (Phase 2a).

Rolling aggregates per principal: known AWS regions, known source-IP countries,
a bounded set of recent IPs. Used by the detection rules to decide what is
"normal" for an identity. Seed a baseline before a demo (see /baseline/seed) to
avoid the cold-start problem: a fresh account has no history, so the first event
would otherwise look "new" (Round 2 #2).
"""
from typing import Any, Optional

from psycopg.types.json import Json

MAX_TRACKED_IPS = 50  # bound the last_seen_ips set


def get_baseline(conn, identity: str) -> Optional[dict[str, Any]]:
    return conn.execute(
        """
        SELECT identity, known_regions, known_countries, known_services,
               last_seen_ips, event_count
        FROM identity_baseline WHERE identity = %s
        """,
        (identity,),
    ).fetchone()


def update_baseline(conn, identity: str, *, region=None, country=None, service=None, ip=None) -> None:
    """Incrementally fold one event into its identity's baseline (learning)."""
    bl = get_baseline(conn, identity)

    if bl is None:
        conn.execute(
            """
            INSERT INTO identity_baseline
                (identity, known_regions, known_countries, known_services,
                 last_seen_ips, event_count, first_seen, last_updated)
            VALUES (%s, %s, %s, %s, %s, 1, now(), now())
            """,
            (
                identity,
                Json([region] if region else []),
                Json([country] if country else []),
                Json([service] if service else []),
                Json([ip] if ip else []),
            ),
        )
        return

    regions = set(bl["known_regions"] or [])
    countries = set(bl["known_countries"] or [])
    services = set(bl["known_services"] or [])
    ips = list(bl["last_seen_ips"] or [])

    if region:
        regions.add(region)
    if country:
        countries.add(country)
    if service:
        services.add(service)
    if ip and ip not in ips:
        ips.append(ip)
        ips = ips[-MAX_TRACKED_IPS:]

    conn.execute(
        """
        UPDATE identity_baseline
        SET known_regions = %s, known_countries = %s, known_services = %s,
            last_seen_ips = %s, event_count = event_count + 1, last_updated = now()
        WHERE identity = %s
        """,
        (Json(sorted(regions)), Json(sorted(countries)), Json(sorted(services)), Json(ips), identity),
    )
