# Local-test helper for the new dashboards.
#
# Brings up the OpenSearch backend, applies the (possibly updated) gateway
# templates and ISM policy, regenerates all 12 dashboard NDJSONs, and imports
# them into OpenSearch Dashboards. Idempotent -- safe to re-run after editing
# any generate_*.py or template file.
#
# Prereqs (one-time):
#   - Docker Desktop running
#   - observability/.env.opensearch present (copy from .env.opensearch.example
#     and set OPENSEARCH_INITIAL_ADMIN_PASSWORD +
#     MCP_GATEWAY_TELEMETRY_PLUGIN_PASSWORD)
#
# Usage:
#   pwsh observability/opensearch_dashboards/local-test.ps1
#   pwsh observability/opensearch_dashboards/local-test.ps1 -SkipUp        # skip stack up
#   pwsh observability/opensearch_dashboards/local-test.ps1 -TeardownFirst # nuke first
#
# After the script completes:
#   - OSD: http://localhost:5601 (admin / your password)
#   - Dashboards menu -> "Secure MCP Gateway - ..." (12 dashboards)
#   - Index patterns: gateway-metrics, gateway-logs, gateway-traces
#   - Optionally emit synthetic data: python observability/emit_dummy_telemetry.py

[CmdletBinding()]
param(
    [switch]$SkipUp,
    [switch]$TeardownFirst,
    [string]$OsdUrl = "http://localhost:5601",
    [string]$OsUrl = "https://localhost:9200",
    [int]$WaitSeconds = 120
)

$ErrorActionPreference = "Stop"

# --- Paths ---------------------------------------------------------------
# This script lives in `observability/opensearch_dashboards/generators/`.
# The deployable NDJSON artifacts (saved-objects + per-dashboard files) ship
# one level up in `observability/opensearch_dashboards/`.
$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "../../..") | Select-Object -ExpandProperty Path
$Observability = Join-Path $RepoRoot "observability"
$GeneratorsDir = $PSScriptRoot
$DashDir = Resolve-Path (Join-Path $PSScriptRoot "..") | Select-Object -ExpandProperty Path
$ComposeFile = Join-Path $Observability "docker-compose.opensearch.yml"
$EnvFile = Join-Path $Observability ".env.opensearch"
$SavedObjects = Join-Path $DashDir "saved-objects.ndjson"

if (-not (Test-Path $EnvFile)) {
    Write-Host "ERROR: $EnvFile not found. Copy .env.opensearch.example, set passwords, and retry." -ForegroundColor Red
    exit 1
}

# Read admin password from env file
$AdminPassword = (Select-String -Path $EnvFile -Pattern "^OPENSEARCH_INITIAL_ADMIN_PASSWORD=").Line -replace "^OPENSEARCH_INITIAL_ADMIN_PASSWORD=", ""
if (-not $AdminPassword) {
    Write-Host "ERROR: OPENSEARCH_INITIAL_ADMIN_PASSWORD not set in $EnvFile" -ForegroundColor Red
    exit 1
}
$Auth = "admin:$AdminPassword"

function Write-Step($msg) {
    Write-Host "`n=== $msg ===" -ForegroundColor Cyan
}

# --- 1. Teardown if requested -------------------------------------------
if ($TeardownFirst) {
    Write-Step "Teardown (TeardownFirst flag set)"
    docker compose -f $ComposeFile --env-file $EnvFile down -v
}

# --- 2. Bring stack up --------------------------------------------------
if (-not $SkipUp) {
    Write-Step "Bringing OpenSearch stack up (docker compose up -d)"
    docker compose -f $ComposeFile --env-file $EnvFile up -d
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: docker compose up failed" -ForegroundColor Red
        exit 1
    }
}

# --- 3. Wait for OpenSearch to be ready ---------------------------------
Write-Step "Waiting for OpenSearch at $OsUrl (timeout ${WaitSeconds}s)"
$Deadline = (Get-Date).AddSeconds($WaitSeconds)
$ready = $false
while ((Get-Date) -lt $Deadline) {
    try {
        $resp = Invoke-RestMethod -Uri "$OsUrl/_cluster/health?wait_for_status=yellow&timeout=10s" `
            -SkipCertificateCheck `
            -Headers @{ Authorization = "Basic $([Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($Auth))) " } `
            -ErrorAction Stop
        if ($resp.status -in @("green", "yellow")) {
            $ready = $true
            Write-Host "OpenSearch is ${($resp.status)}" -ForegroundColor Green
            break
        }
    } catch {
        Start-Sleep -Seconds 3
        Write-Host "." -NoNewline
    }
}
if (-not $ready) {
    Write-Host "`nERROR: OpenSearch did not become ready in ${WaitSeconds}s" -ForegroundColor Red
    Write-Host "Tip: check docker logs:" -ForegroundColor Yellow
    Write-Host "    docker compose -f observability/docker-compose.opensearch.yml logs opensearch | Select-Object -Last 50"
    exit 1
}

# --- 4. Apply gateway templates + ISM policy ----------------------------
Write-Step "Re-applying gateway index templates + ISM policy"
$TemplatesDir = Join-Path $Observability "opensearch/templates"
$PoliciesDir = Join-Path $Observability "opensearch/policies"

$AuthHeaders = @{
    Authorization = "Basic $([Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($Auth)))"
    "Content-Type" = "application/json"
}

# ISM policy first (templates reference its id). 409 = already-installed by
# bootstrap container -- harmless, skip. Anything else we bubble up.
if (Test-Path $PoliciesDir) {
    Get-ChildItem $PoliciesDir -Filter "*.json" | ForEach-Object {
        $name = $_.BaseName
        Write-Host "  ISM policy: $name -> " -NoNewline
        try {
            Invoke-RestMethod -Uri "$OsUrl/_plugins/_ism/policies/$name" `
                -Method Put -Body (Get-Content $_.FullName -Raw) `
                -Headers $AuthHeaders -SkipCertificateCheck -ErrorAction Stop | Out-Null
            Write-Host "CREATED" -ForegroundColor Green
        } catch {
            if ($_.Exception.Response -and $_.Exception.Response.StatusCode.value__ -eq 409) {
                Write-Host "already installed (409, skipped)" -ForegroundColor DarkGray
            } else {
                Write-Host "FAILED" -ForegroundColor Red
                Write-Host "    $_" -ForegroundColor Red
            }
        }
    }
}

# Templates (PUT is idempotent for index templates)
Get-ChildItem $TemplatesDir -Filter "gateway-*-elastic-template.json" | ForEach-Object {
    $name = $_.BaseName -replace "-elastic-template$", ""
    Write-Host "  Template: $name -> " -NoNewline
    try {
        Invoke-RestMethod -Uri "$OsUrl/_index_template/$name" `
            -Method Put -Body (Get-Content $_.FullName -Raw) `
            -Headers $AuthHeaders -SkipCertificateCheck -ErrorAction Stop | Out-Null
        Write-Host "OK" -ForegroundColor Green
    } catch {
        Write-Host "FAILED" -ForegroundColor Red
        Write-Host "    $_" -ForegroundColor Red
    }
}

# --- 5. Rollover existing data streams so they pick up new templates ----
Write-Step "Rolling over data streams to pick up new mappings"
foreach ($stream in @("ss4o_metrics-gateway", "ss4o_logs-gateway", "ss4o_traces-gateway")) {
    try {
        Invoke-RestMethod -Uri "$OsUrl/$stream/_rollover" `
            -Method Post `
            -Headers $AuthHeaders -SkipCertificateCheck `
            -ErrorAction Stop | Out-Null
        Write-Host "  rolled: $stream" -ForegroundColor Green
    } catch {
        Write-Host "  $stream not present yet (will be created on first ingest) -- skipping" -ForegroundColor DarkGray
    }
}

# --- 6. Audit dashboard field references vs templates ------------------
Write-Step "Auditing dashboard field references vs templates"
$Python = if (Test-Path "$RepoRoot/.venv/Scripts/python.exe") { "$RepoRoot/.venv/Scripts/python.exe" } else { "python" }
& $Python (Join-Path $GeneratorsDir "_audit_fields.py")
if ($LASTEXITCODE -ne 0) {
    Write-Host "WARN: dashboards reference fields not in templates -- some widgets will show 'Could not locate'" -ForegroundColor Yellow
}

# --- 7. Regenerate all dashboard NDJSONs --------------------------------
Write-Step "Regenerating all 12 dashboard NDJSONs"
& $Python (Join-Path $GeneratorsDir "generate_all.py")
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: generate_all.py failed" -ForegroundColor Red
    exit 1
}

# --- 7. Wait for OSD to be ready ----------------------------------------
Write-Step "Waiting for OpenSearch Dashboards at $OsdUrl"
$Deadline = (Get-Date).AddSeconds($WaitSeconds)
$osdReady = $false
while ((Get-Date) -lt $Deadline) {
    try {
        $resp = Invoke-WebRequest -Uri "$OsdUrl/api/status" -SkipCertificateCheck `
            -Headers @{ "osd-xsrf" = "true"; Authorization = "Basic $([Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($Auth)))" } `
            -ErrorAction Stop
        if ($resp.StatusCode -eq 200) {
            $osdReady = $true
            Write-Host "OSD ready" -ForegroundColor Green
            break
        }
    } catch {
        Start-Sleep -Seconds 3
        Write-Host "." -NoNewline
    }
}
if (-not $osdReady) {
    Write-Host "`nWARN: OSD didn't respond on /api/status -- continuing anyway (it may still work)" -ForegroundColor Yellow
}

# --- 8. Import index patterns + every dashboard ------------------------
Write-Step "Importing index patterns + 12 dashboards into OSD"
$OsdHeaders = @{
    Authorization = "Basic $([Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($Auth)))"
    "osd-xsrf" = "true"
}

function Import-Ndjson($path) {
    $name = Split-Path $path -Leaf
    Write-Host "  $name -> " -NoNewline
    try {
        # PS7+ -Form builds proper multipart with file-stream payload (matches what `curl --form` does).
        $resp = Invoke-RestMethod -Uri "$OsdUrl/api/saved_objects/_import?overwrite=true" `
            -Method Post `
            -Form @{ file = Get-Item $path } `
            -Headers $OsdHeaders -SkipCertificateCheck
        $errCount = 0
        if ($resp.errors) { $errCount = $resp.errors.Count }
        $totalCount = ($resp.successCount + $errCount)
        $label = if ($resp.success) { "OK" } else { "PARTIAL" }
        $color = if ($resp.success) { "Green" } else { "Yellow" }
        Write-Host "$label ($($resp.successCount)/$totalCount)" -ForegroundColor $color
        if ($errCount -gt 0) {
            foreach ($e in $resp.errors) {
                Write-Host "      err: type=$($e.type) id=$($e.id) -- $($e.error.type): $($e.error.message)" -ForegroundColor DarkYellow
            }
        }
    } catch {
        Write-Host "FAILED" -ForegroundColor Red
        Write-Host "    $_" -ForegroundColor Red
    }
}

# Index patterns first. Delete-then-reimport so OSD picks up the freshly
# template-baked field lists (re-import with `overwrite=true` alone keeps the
# old cached `attributes.fields`, which is the cause of every "Could not
# locate that index-pattern-field" error after a template change).
Write-Host "  Deleting cached index patterns first..." -ForegroundColor DarkGray
foreach ($patternId in @("gateway-metrics", "gateway-logs", "gateway-traces", "ss4o_traces-gateway-pattern", "otel-v1-apm-service-map")) {
    try {
        Invoke-RestMethod -Uri "$OsdUrl/api/saved_objects/index-pattern/$patternId`?force=true" `
            -Method Delete -Headers $OsdHeaders -SkipCertificateCheck -ErrorAction Stop | Out-Null
    } catch {
        # 404 = not present yet, fine
    }
}
Import-Ndjson $SavedObjects

# Then every dashboard
Get-ChildItem (Join-Path $DashDir "gateway-*-dashboard.ndjson") | Sort-Object Name | ForEach-Object {
    Import-Ndjson $_.FullName
}

# --- 9. Summary ---------------------------------------------------------
Write-Step "Done!"
Write-Host ""
Write-Host "OpenSearch:    " -NoNewline; Write-Host "$OsUrl" -ForegroundColor Cyan
Write-Host "OSD:           " -NoNewline; Write-Host "$OsdUrl" -ForegroundColor Cyan
Write-Host "Admin user:    admin / (from .env.opensearch)"
Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. Open OSD: $OsdUrl"
Write-Host "  2. Login with admin / your password"
Write-Host "  3. Menu -> Dashboards -> filter 'Secure MCP Gateway'"
Write-Host "  4. (Optional) Emit synthetic data to populate widgets:"
Write-Host "       python observability/emit_dummy_telemetry.py"
Write-Host "  5. (Optional) Run the gateway locally pointed at this collector:"
Write-Host "       `$env:ENKRYPT_TELEMETRY_URL = 'http://localhost:4317'"
Write-Host "       secure-mcp-gateway"
