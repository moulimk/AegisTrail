"""AegisTrail detector service — FastAPI.

  GET  /health         — liveness + DB check
  POST /ingest         — normalize a CloudTrail record and store it (idempotent)
  POST /baseline/seed  — seed/overwrite an identity baseline (avoid cold-start)
  POST /score          — enrich (GeoIP + AbuseIPDB) + rules + risk score + LLM triage
  POST /contain        — SAFE_MODE action plan (protected-identity guarded)
"""
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from psycopg.types.json import Json

from . import abuseipdb
from . import baseline as baseline_mod
from . import detect, geoip, scoring, triage
from .contain import contain
from .db import get_conn
from .models import ContainRequest, ContainResult, ResolveRequest, ScoreRequest, SeedRequest
from .normalize import normalize_cloudtrail
from .dashboard import DASHBOARD_HTML

app = FastAPI(title="AegisTrail Detector", version="0.3.0")


@app.get("/health")
def health():
    try:
        with get_conn() as conn:
            conn.execute("SELECT 1")
        return {"status": "ok", "db": "up", "triage": triage.available()}
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
    """Enrich a stored event, run rules, score it, AI-triage it, raise an incident."""
    with get_conn() as conn:
        ev = conn.execute(
            "SELECT event_id, identity, action, service, source_ip, region, raw_event FROM events WHERE event_id = %s",
            (req.event_id,),
        ).fetchone()
        if ev is None:
            raise HTTPException(status_code=404, detail="event not found")

        # Enrichment
        geo = geoip.lookup(ev["source_ip"])
        ti = abuseipdb.lookup(ev["source_ip"])

        # Behavioral context: count this identity's recent read/list calls (recon burst).
        recon_count = conn.execute(
            """
            SELECT count(*) AS c FROM events
            WHERE identity = %s AND event_time > now() - interval '10 minutes'
              AND (action LIKE 'List%%' OR action LIKE 'Describe%%' OR action LIKE 'Get%%')
            """,
            (ev["identity"],),
        ).fetchone()["c"]

        # Deterministic detection + scoring
        base = baseline_mod.get_baseline(conn, ev["identity"])
        signals = detect.run_rules(ev, geo, ti, base, recon_count=recon_count)
        risk = scoring.score([s["type"] for s in signals])
        itype = detect.incident_type(signals) if signals else None
        conf = detect.confidence(signals) if signals else 0.0

        # AI triage annotates the rules result (rules-only fallback if disabled/failed)
        triage_result = None
        if signals:
            triage_result = triage.triage({
                "identity": ev["identity"], "action": ev["action"], "service": ev["service"],
                "source_ip": ev["source_ip"], "aws_region": ev["region"],
                "geo": geo, "threat_intel": ti, "signals": signals,
                "risk_score": risk, "incident_type": itype,
            })
        summary = triage_result.get("summary") if triage_result else None
        recommended_action = triage_result.get("recommended_action") if triage_result else None

        incident_id = None
        if signals:
            row = conn.execute(
                """
                INSERT INTO incidents (identity, incident_type, risk_score, confidence, status, summary, signals)
                VALUES (%s, %s, %s, %s, 'OPEN', %s, %s)
                RETURNING incident_id
                """,
                (ev["identity"], itype, risk, conf, summary, Json(signals)),
            ).fetchone()
            incident_id = str(row["incident_id"])
            conn.execute(
                "INSERT INTO incident_events (incident_id, event_id, sequence_order) VALUES (%s, %s, 0)",
                (incident_id, ev["event_id"]),
            )

        # Learn: fold this event into the baseline after scoring it.
        baseline_mod.update_baseline(
            conn, ev["identity"],
            region=ev["region"], country=(geo or {}).get("country"),
            service=ev["service"], ip=ev["source_ip"],
        )
        conn.commit()

    # Containment hint: what the responder would act on (used by the approval gate).
    user_identity = (ev["raw_event"] or {}).get("userIdentity", {})
    type_map = {"Root": "root", "IAMUser": "iam_user", "AssumedRole": "role_session"}
    identity_type = type_map.get(user_identity.get("type"), "iam_user")
    access_key_id = user_identity.get("accessKeyId")
    suggested_action = "deactivate_key" if access_key_id else "disable_user"

    return {
        "event_id": ev["event_id"],
        "identity": ev["identity"],
        "risk_score": risk,
        "incident_type": itype,
        "confidence": conf,
        "signals": signals,
        "geo": {"country": (geo or {}).get("country"), "city": (geo or {}).get("city"),
                "isp": (geo or {}).get("isp")} if geo else None,
        "threat_intel": ti,
        "summary": summary,
        "recommended_action": recommended_action,
        "incident_id": incident_id,
        "containment": {
            "identity": ev["identity"],
            "identity_type": identity_type,
            "access_key_id": access_key_id,
            "suggested_action": suggested_action,
        },
    }


@app.post("/incident/resolve")
def resolve_incident(req: ResolveRequest):
    """Close the loop on an incident (CONTAINED / CLOSED / FALSE_POSITIVE) for the audit trail."""
    with get_conn() as conn:
        row = conn.execute(
            "UPDATE incidents SET status = %s, updated_at = now() WHERE incident_id = %s RETURNING incident_id",
            (req.status, req.incident_id),
        ).fetchone()
        conn.commit()
    if row is None:
        raise HTTPException(status_code=404, detail="incident not found")
    return {"incident_id": req.incident_id, "status": req.status}


@app.get("/incidents")
def list_incidents(limit: int = 50):
    """Recent incidents for the dashboard (newest first)."""
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT incident_id, identity, incident_type, risk_score, confidence,
                   status, summary, signals, created_at
            FROM incidents ORDER BY created_at DESC LIMIT %s
            """,
            (limit,),
        ).fetchall()
    return {"incidents": [
        {
            "incident_id": str(r["incident_id"]),
            "identity": r["identity"],
            "incident_type": r["incident_type"],
            "risk_score": r["risk_score"],
            "confidence": r["confidence"],
            "status": r["status"],
            "summary": r["summary"],
            "signals": r["signals"],
            "created_at": r["created_at"].isoformat() if r["created_at"] else None,
        }
        for r in rows
    ]}


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    return DASHBOARD_HTML


@app.post("/contain", response_model=ContainResult)
def contain_endpoint(req: ContainRequest):
    return contain(req)
