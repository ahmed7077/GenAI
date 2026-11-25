param(
    [string]$WebUrl = "http://localhost:5173",
    [string]$ApiUrl = "http://localhost:8000/api/v1"
)

$ErrorActionPreference = "Stop"

$web = Invoke-WebRequest -Uri $WebUrl -TimeoutSec 15
if ($web.StatusCode -ne 200 -or $web.Content -notmatch '<div id="root"') {
    throw "The ThreatLens web shell is unavailable."
}

function Read-DemoEndpoint([string]$Path) {
    Invoke-RestMethod -Uri "$ApiUrl/$Path" -TimeoutSec 30
}

if ((Read-DemoEndpoint "health").status -ne "ok") {
    throw "API health check failed."
}

$summary = Read-DemoEndpoint "events/summary"
$page = Read-DemoEndpoint "events/page"
if ($page.total -ne $summary.events -or $page.items.Count -ne [Math]::Min($summary.events, 50)) {
    throw "The evidence page and stored inventory disagree."
}

$detection = Read-DemoEndpoint "detection/evaluate"
foreach ($candidate in $detection.incident_candidates) {
    if (!$candidate.success_event_id -or $candidate.failure_event_ids.Count -lt 3) {
        throw "A detection candidate is missing its evidence trail."
    }
}

$models = Read-DemoEndpoint "models/status"
$null = Read-DemoEndpoint "incidents"
[pscustomobject]@{
    stored_events = $summary.events
    first_page_records = $page.items.Count
    detection_candidates = $detection.incident_candidates.Count
    model_artifacts_available = $models.available
    case_list_accessible = $true
}
