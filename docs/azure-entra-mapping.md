# Cloud portability — AWS → Azure / GCP

AegisTrail is built on AWS, but the valuable parts — the n8n orchestration, the
detection rules, the risk scoring, the AI triage, and the human-in-the-loop
containment — are **vendor-neutral**. Only the connectors at each end change.
This document maps the AWS pieces to their Azure (Entra ID) and GCP equivalents
so the same pipeline can be re-pointed at a different cloud.

## Service mapping

| Concept | AWS (this project) | Azure / Entra ID | GCP |
|---|---|---|---|
| Audit / activity log | CloudTrail | Entra ID sign-in & audit logs, Activity Log | Cloud Audit Logs |
| Managed threat detection | GuardDuty | Microsoft Defender for Cloud, Entra ID Protection | Security Command Center |
| Identity & permissions | IAM | Entra ID + Azure RBAC | Cloud IAM |
| "Leaked key / new geo" signal | access key used from new country | risky sign-in / impossible travel (Entra ID Protection) | anomalous access (SCC) |
| Privilege escalation | `AttachUserPolicy`, `CreateAccessKey`, ... | role assignment changes, `Add member to role` | `setIamPolicy`, role grants |
| Containment: disable credential | `iam:UpdateAccessKey` → Inactive | disable user / revoke sessions in Entra | disable service account key |

## What changes vs. what stays

**Stays the same (the project's real value):**
- The n8n SOAR orchestration and routing logic
- The detector service: baseline, scoring, correlation, incident lifecycle
- The AI triage prompt and recommended-action enum
- The human-approval gate and SAFE_MODE containment pattern
- The security model (least privilege, protected-identity allowlist, prompt-injection defense)

**Changes (the connectors only):**
- The ingestion trigger (CloudTrail/EventBridge → Entra ID Protection / Sentinel alert)
- The enrichment IAM lookups (boto3 → Microsoft Graph / Azure SDK)
- The containment calls (`iam:UpdateAccessKey` → Entra disable-user / revoke-sessions)


**The point of this doc is to show the system was designed cloud-portable: deep on
one cloud, fluent across the others. The detection logic and response automation
port directly; re-pointing AegisTrail at Azure is a connector swap, not a rewrite.**
