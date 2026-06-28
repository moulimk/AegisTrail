# POST a sample finding to the AegisTrail n8n webhook (Phase 1 shortcut — no AWS needed).
#
# In the n8n editor, an unactivated Webhook node listens at /webhook-test/<path>
# (only while you click "Listen for test event"). An ACTIVE workflow listens at
# /webhook/<path>. Pass -WebhookUrl to match whichever you're using.
#
#   ./scripts/post_sample.ps1
#   ./scripts/post_sample.ps1 -WebhookUrl http://localhost:5678/webhook/aegistrail

param(
    [string]$WebhookUrl = "http://localhost:5678/webhook-test/aegistrail",
    [string]$SampleFile = "$PSScriptRoot/../samples/leaked_key_finding.json"
)

$body = Get-Content -Raw -Path $SampleFile
Write-Host "POST $WebhookUrl  <-  $SampleFile" -ForegroundColor Cyan
Invoke-RestMethod -Method Post -Uri $WebhookUrl -ContentType "application/json" -Body $body
