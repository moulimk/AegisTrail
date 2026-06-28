"""AegisTrail detector service — FastAPI.

Phase 0/1 surface:
  GET  /health   — liveness + DB check
  POST /ingest   — normalize a CloudTrail record and store it (idempotent)
  POST /contain  — SAFE_MODE action plan (protected-identity guarded)

Phase 2 will add baseline updates, scoring, correlation and incident creation.
"""
from fastapi import FastAPI, HTTPException
from psycopg.types.json import Json

from .contain import contain
from .db import get_conn
from .models import ContainRequest, ContainResult
from .normalize import normalize_cloudtrail

app = FastAPI(title="AegisTrail Detector", version="0.1.0")


@app.get("/health")
def health():
    try:
        with get_conn() as conn:
            conn.execute("SELECT 1")
        return {"status": "ok", "db": "up"}
    except Exception as exc:  # surface DB problems clearly
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
                event.event_id,
                event.identity,
                event.action,
                event.service,
                event.resource,
                event.source_ip,
                event.region,
                event.event_time,
                Json(event.raw_event),
            ),
        )
        conn.commit()
    return {"stored": True, "normalized": event.model_dump(mode="json")}


@app.post("/contain", response_model=ContainResult)
def contain_endpoint(req: ContainRequest):
    return contain(req)
