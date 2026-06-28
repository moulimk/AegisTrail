# 🛡️ AegisTrail

**AWS Identity Threat Detection & Response — a human-in-the-loop SOAR pipeline.**

AegisTrail detects AWS identity threats (CloudTrail / GuardDuty / IAM), enriches and
AI-triages each alert, and contains them through a **human-approved** gate — with a
full audit trail, honestly-measured response times, and a one-click rollback.

> Design principle: **human-in-the-loop SOAR with AI triage**, not "autonomous
> containment." Every destructive action is gated behind a human approval and a
> deterministic action allowlist. Some scenarios (recon, root) deliberately do **not**
> auto-contain — knowing when *not* to automate is the point.

📋 **Full plan & design decisions:** [AegisTrail in Notion](https://app.notion.com/p/38caf8d66b718135b967d029ec52c399)

---

## Architecture

```
CloudTrail / GuardDuty ──► n8n webhook ──► normalize ──► enrich (IAM · GeoIP · AbuseIPDB)
                                                              │
                                  detector service (FastAPI + Postgres):
                                  baseline · risk scoring · correlation
                                                              │
                                  rules + LLM triage ──► { severity, summary, MITRE, action }
                                                              │
                            below threshold ─► auto-close + audit log
                            above threshold ─► Slack alert  [ Contain ] [ Dismiss ]
                                                              │ human approves
                                  containment (SAFE_MODE, per-identity, allowlisted)
                                                              │
                                  audit trail · latency metrics · rollback
```

- **n8n** owns orchestration, enrichment, triage, the human gate, and response.
- **detector** (this repo's `detector/`) owns the stateful detection: per-identity
  baselines, risk scoring, and signal correlation.

## In-scope scenarios

| # | Scenario | Containment |
|---|----------|-------------|
| 1 | Leaked key, new geo/IP | Deactivate access key (approval) |
| 2 | IAM privilege escalation | Detach policy / delete key / quarantine |
| 3 | Recon / enumeration | Alert-only by default |
| 4 | Root usage / MFA disabled | Escalate to human (no auto-disable) |

**Minimum-shippable:** #1 + #2 fully complete (hero demos); #3 + #4 detect-and-alert only.

---

## Quickstart (Phase 0 + Phase 1)

Prereqs: **Docker Desktop**.

```bash
cp .env.example .env        # then edit secrets (Windows: copy .env.example .env)
docker compose up -d --build
```

This starts:

| Service   | URL                       | Purpose                       |
|-----------|---------------------------|-------------------------------|
| n8n       | http://localhost:5678     | SOAR orchestration (editor)   |
| detector  | http://localhost:8000     | FastAPI — `/health`, `/ingest`, `/contain` |
| postgres  | localhost:5432            | detector state store          |

Verify the detector:

```bash
curl http://localhost:8000/health          # {"status":"ok","db":"up"}
```

### Fire a test finding (no AWS required)

The Phase-1 shortcut: POST a sample finding straight at the n8n webhook instead of
wiring up EventBridge.

1. In n8n (http://localhost:5678), create a workflow with a **Webhook** node, path
   `aegistrail`, and click **Listen for test event**.
2. Send the sample:

   ```powershell
   ./scripts/post_sample.ps1
   ```
   ```bash
   ./scripts/post_sample.sh
   ```

The leaked-key event ([`samples/leaked_key_finding.json`](samples/leaked_key_finding.json))
flows into n8n, where you build the normalize → enrich → Slack chain.

---

## SAFE_MODE

The detector's `/contain` endpoint defaults to **SAFE_MODE=true**: it returns the
boto3/CLI **action plan only** and executes nothing. Real execution (SAFE_MODE=false)
is Phase 3 and is guarded by the **protected-identity allowlist** — root and any
break-glass admin can never be auto-contained.

```bash
curl -X POST http://localhost:8000/contain -H 'Content-Type: application/json' \
  -d '{"identity":"dev-bot","action":"deactivate_key","access_key_id":"AKIAEXAMPLE7LEAKED"}'
```

---

## Project layout

```
detector/        FastAPI detector service (normalize, baseline, scoring, contain)
db/init.sql      Postgres schema (events, identity_baseline, incidents, incident_events)
n8n/workflows/   exported n8n workflows (scrub credentials before committing)
samples/         sample findings for offline/Phase-1 testing
scripts/         helpers (post a sample finding to the webhook)
docker-compose.yml
```

## Roadmap (future work — not yet built)

Redis Streams · full microservice split · Isolation Forest / scikit-learn UEBA ·
NetworkX identity-graph analytics · ASN enrichment · Azure/Entra portability mapping.

## Security note

This is a security tool, so it is threat-modeled as one: least-privilege automation
identity, prompt-injection-resistant triage, signed webhooks, a protected-identity
allowlist, and an isolated sandbox account. See the Notion plan's red-team sections.
