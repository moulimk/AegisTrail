#!/usr/bin/env bash
# POST a sample finding to the AegisTrail n8n webhook (Phase 1 shortcut — no AWS needed).
#
# Usage:
#   ./scripts/post_sample.sh
#   ./scripts/post_sample.sh http://localhost:5678/webhook/aegistrail
set -euo pipefail

WEBHOOK_URL="${1:-http://localhost:5678/webhook-test/aegistrail}"
SAMPLE="${2:-$(dirname "$0")/../samples/leaked_key_finding.json}"

echo "POST $WEBHOOK_URL  <-  $SAMPLE"
curl -sS -X POST "$WEBHOOK_URL" \
    -H 'Content-Type: application/json' \
    --data @"$SAMPLE"
echo
