"""AegisTrail detector service — FastAPI.

  GET  /health         — liveness + DB check
  POST /ingest         — normalize a CloudTrail record and store it (idempotent)
  POST /baseline/seed  — seed/overwrite an identity baseline (avoid cold-start)
  POST /score          — enrich + run rules + risk-score a stored event; raise incident
  POST /contain        — SAFE_MODE action plan (protected-identity guarded)

Phase 2b will add an LLM triage summary on top of the deterministic score.
"""
from fastapi import FastAPI, HTTPException
from psycopg.types.json import Json

from . import baseline as baseline_mod
from . import detect, geoip, scoring
from .contain import contain
from .db import get_conn
from .models import ContainRequest, ContainResult, ScoreRequest, SeedRequest
from .normalize import normalize_cloudtrail

app = FastAPI(title="AegisTrail Detector", version="0.2.0")


@app.get("/health")
def health():
    try:
        with get_conn() as conn:
            conn.execute("SELECT 1")
        return {"status": "ok", "db": "up"}
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"db down: {exc}")


@app.post("/ingest")
def ingest(record: dict):
    """Normalize + persist a raw CloudTrail record. Idempotent on event_id."""
    event = normalize_cloudtrail(record)
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO events
                (event_id, identity, action, service, resource, source_ip, region, event_time, raw_event)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (event_id) DO NOTHING
            """,
            (
                event.event_id, event.identity, event.action, event.service,
                event.resource, event.source_ip, event.region, event.event_time,
                Json(event.raw_event),
            ),
        )
        conn.commit()
    return {"stored": True, "normalized": event.model_dump(mode="json")}


@app.post("/baseline/seed")
def seed_baseline(req: SeedRequest):
    """Seed/overwrite an identity's baseline so detections have a 'normal' to compare to."""
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO identity_baseline
                (identity, known_regions, known_countries, known_services,
                 last_seen_ips, event_count, first_seen, last_updated)
            VALUES (%s, %s, %s, %s, %s, %s, now(), now())
            ON CONFLICT (identity) DO UPDATE SET
                known_regions = EXCLUDED.known_regions,
                known_countries = EXCLUDED.known_countries,
                known_services = EXCLUDED.known_services,
                last_seen_ips = EXCLUDED.last_seen_ips,
                event_count = EXCLUDED.event_count,
                last_updated = now()
            """,
            (
                req.identity, Json(req.known_regions), Json(req.known_countries),
                Json(req.known_services), Json(req.last_seen_ips), req.event_count,
            ),
        )
        conn.commit()
    return {"seeded": req.identity}


@app.post("/score")
def score_event(req: ScoreRequest):
    """Enrich a stored event, run detection rules, score it, raise an incident."""
    with get_conn() as conn:
        ev = conn.execute(
            "SELECT event_id, identity, action, service, source_ip, region FROM events WHERE event_id = %s",
            (req.event_id,),
        ).fetchone()
        if ev is None:
            raise HTTPException(status_code=404, detail="event not found")

        geo = geoip.lookup(ev["source_ip"])
        base = baseline_mod.get_baseline(conn, ev["identity"])
        signals = detect.run_rules(ev, geo, base)
        risk = scoring.score([s["type"] for s in signals])

        incident_id = None
        if signals:  # any positive signal raises an incident
            row = conn.execute(
                """
                INSERT INTO incidents (identity, incident_type, risk_score, confidence, status, signals)
                VALUES (%s, %s, %s, %s, 'OPEN', %s)
                RETURNING incident_id
                """,
                (ev["identity"], detect.incident_type(signals), risk,
                 detect.confidence(signals), Json(signals)),
            ).fetchone()
            incident_id = str(row["incident_id"])
            conn.execute(
                "INSERT INTO incident_events (incident_id, event_id, sequence_order) VALUES (%s, %s, 0)",
                (incident_id, ev["event_id"]),
            )

        # Learn: fold this event into the baseline after scoring it.
        baseline_mod.update_baseline(
            conn, ev["identity"],
            region=ev["region"],
            country=(geo or {}).get("country"),
            service=ev["service"],
            ip=ev["source_ip"],
        )
        conn.commit()

    return {
        "event_id": ev["event_id"],
        "identity": ev["identity"],
        "risk_score": risk,
        "incident_type": detect.incident_type(signals) if signals else None,
        "confidence": detect.confidence(signals) if signals else 0.0,
        "signals": signals,
        "geo": {"country": (geo or {}).get("country"), "city": (geo or {}).get("city"),
                "isp": (geo or {}).get("isp")} if geo else None,
        "incident_id": incident_id,
    }


@app.post("/contain", response_model=ContainResult)
def contain_endpoint(req: ContainRequest):
    return contain(req)
