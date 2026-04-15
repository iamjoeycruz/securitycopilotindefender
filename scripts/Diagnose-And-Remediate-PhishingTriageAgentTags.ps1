<#
.SYNOPSIS
    Diagnose AND remediate the Phishing Triage Agent tag-removal issue.
    
.DESCRIPTION
    Enhanced version of the diagnostic script that can also restore missing tags.
    Run with no parameters for interactive mode, or use -DiagnosticOnly to skip remediation.
    
    WHAT THIS SCRIPT DOES:
      - All read-only diagnostics from the original script
      - OPTIONALLY restores missing tags on affected incidents (with confirmation)
      - Generates an HTML report with findings AND remediation results
    
    WHAT THIS SCRIPT CAN MODIFY (only during remediation):
      - Adds tags/labels back to Sentinel incidents that had them stripped
      - Does NOT remove any existing tags
      - Does NOT modify any other incident properties
      - Does NOT create or delete Azure resources
      
.EXAMPLE
    # Interactive mode (diagnostic + optional remediation)
    .\Diagnose-And-Remediate-PhishingTriageAgentTags.ps1
    
    # Diagnostic only (no changes)
    .\Diagnose-And-Remediate-PhishingTriageAgentTags.ps1 -DiagnosticOnly
    
    # Auto-remediate without prompts
    .\Diagnose-And-Remediate-PhishingTriageAgentTags.ps1 -AutoRemediate `
        -SubscriptionId "xxx" -ResourceGroupName "rg" -WorkspaceName "ws" `
        -ExpectedTags "Tag1","Tag2"

.NOTES
    DISCLAIMER: This script is provided "AS IS" without warranty of any kind.
    This is for educational and diagnostic purposes only. Not officially supported by Microsoft.
    REMEDIATION MODE WILL MODIFY SENTINEL INCIDENTS. Review and test in non-production first.

    KNOWN LIMITATIONS:
    1. DATA RETENTION - Tag history is limited to your Log Analytics workspace retention
       (default 90 days). Tags removed before this window CANNOT be recovered.
    2. AZURE ACTIVITY LOG - Fixed 90-day maximum. Older API-level evidence is unavailable.
    3. AGENT ATTRIBUTION - The script identifies the agent via ModifiedBy patterns in
       SecurityIncident logs. If Microsoft changes the agent's identity string, detection
       may miss some events until patterns are updated.
    4. TAG RESTORATION SCOPE - Only tags removed by the agent (matched via ModifiedBy)
       are restored. Tags intentionally removed by analysts are NOT touched.
    5. CONCURRENT MODIFICATIONS - If an incident is modified between the script's GET
       and PUT calls, the PUT uses etag concurrency. A 412 conflict will trigger a
       retry, but rapid concurrent edits may still cause transient failures.
    6. CLOSED INCIDENTS - Closed incidents require classification fields. The script
       preserves them from the fresh GET, but classification changes between GET/PUT
       are not merged.
    7. PAGINATION - The incident scan is capped at 10,000 incidents (50 pages). Larger
       environments may not be fully scanned. A warning is shown when the cap is hit.
    8. KQL RESULT LIMITS - Remediation candidates are capped at 500 per run. Re-run
       the script to process additional incidents.
    9. SOVEREIGN CLOUDS - API endpoints and versions are hardcoded for Azure public
       cloud. Sovereign/government clouds may require manual URI adjustments.
    10. RATE LIMITING - The script includes retry with backoff for 429/5xx but sustained
        high-volume remediation (500+ incidents) may still hit throttling limits.
#>

[CmdletBinding()]
param(
    [string]$SubscriptionId,
    [string]$ResourceGroupName,
    [string]$WorkspaceName,
    [string[]]$ExpectedTags,
    [int[]]$IncidentIds,
    [ValidateRange(1, 365)]
    [int]$LookbackDays = 7,
    [string]$ReportPath,
    [switch]$DiagnosticOnly,
    [switch]$AutoRemediate
)

#Requires -Version 7.0

if ($DiagnosticOnly -and $AutoRemediate) {
    Write-Error "-DiagnosticOnly and -AutoRemediate are mutually exclusive. Please use one or the other."
    exit 1
}

$ErrorActionPreference = "Continue"
Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

# Handle comma-separated tags passed as a single string (e.g. from CLI)
if ($ExpectedTags.Count -eq 1 -and $ExpectedTags[0] -match ',') {
    $ExpectedTags = $ExpectedTags[0] -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
}

# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  DISPLAY HELPERS                                                         ║
# ╚════════════════════════════════════════════════════════════════════════════╝

function Show-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║   Phishing Triage Agent — Diagnose & Remediate              ║" -ForegroundColor Cyan
    Write-Host "  ║   Detects AND fixes agent-caused tag removal on incidents   ║" -ForegroundColor Cyan
    Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    if ($DiagnosticOnly) {
        Write-Host "  Mode: DIAGNOSTIC ONLY (no changes will be made)" -ForegroundColor Yellow
    } elseif ($AutoRemediate) {
        Write-Host "  Mode: AUTO-REMEDIATE (will restore tags without prompting)" -ForegroundColor Magenta
    } else {
        Write-Host "  Mode: INTERACTIVE (will prompt before any changes)" -ForegroundColor Green
    }
    Write-Host ""
}

function Show-Step([int]$Num, [int]$Total, [string]$Text) {
    Write-Host ""
    Write-Host "  [$Num/$Total] $Text" -ForegroundColor Yellow
    Write-Host "  $('─' * 60)" -ForegroundColor DarkGray
}

function Show-Ok([string]$Text)   { Write-Host "  ✅ $Text" -ForegroundColor Green }
function Show-Warn([string]$Text) { Write-Host "  ⚠️  $Text" -ForegroundColor Yellow }
function Show-Fail([string]$Text) { Write-Host "  ❌ $Text" -ForegroundColor Red }
function Show-Info([string]$Text) { Write-Host "  ℹ️  $Text" -ForegroundColor Cyan }

function Pick-FromList {
    param([string]$Prompt, [object[]]$Items, [string]$DisplayProperty)
    Write-Host ""
    for ($i = 0; $i -lt $Items.Count; $i++) {
        $label = if ($DisplayProperty) { $Items[$i].$DisplayProperty } else { "$($Items[$i])" }
        Write-Host "    [$($i+1)] $label" -ForegroundColor White
    }
    Write-Host ""
    do {
        $sel = Read-Host "  $Prompt (1-$($Items.Count))"
    } while (-not ($sel -as [int]) -or [int]$sel -lt 1 -or [int]$sel -gt $Items.Count)
    return $Items[[int]$sel - 1]
}

# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  REPORT DATA COLLECTOR                                                   ║
# ╚════════════════════════════════════════════════════════════════════════════╝

$script:Report = [ordered]@{
    RunTime          = ""
    Subscription     = ""
    ResourceGroup    = ""
    Workspace        = ""
    WorkspaceId      = ""
    LookbackDays     = $LookbackDays
    ExpectedTags     = ""
    Findings         = [System.Collections.Generic.List[object]]::new()
    IncidentStats    = @{ Total=0; Phishing=0; WithTags=0; WithoutTags=0; TagDist=@(); MissingExp=@() }
    ActivityLog      = @{ Total=0; Agent=0; Samples=@() }
    KQL              = [ordered]@{}
    Verdict          = ""
    Remediation      = @{
        Attempted  = 0
        Succeeded  = 0
        Failed     = 0
        Skipped    = 0
        Details    = @()
        SkipReason = ""
    }
    Errors           = [System.Collections.Generic.List[string]]::new()
}

# ── Change Log ──────────────────────────────────────────────────────────────
# Every remediation action is logged to a JSON file for audit trail
$script:ChangeLog = [System.Collections.Generic.List[object]]::new()

function Write-ChangeLog {
    param(
        [string]$Action,          # "TAG_RESTORE", "SKIPPED", "FAILED"
        [string]$IncidentNumber,
        [string]$IncidentId,
        [string[]]$TagsBefore,
        [string[]]$TagsAfter,
        [string[]]$TagsAdded,
        [string]$ModifiedBy,
        [string]$Etag,
        [string]$ErrorMessage
    )
    $entry = [ordered]@{
        timestamp       = (Get-Date).ToUniversalTime().ToString("o")
        action          = $Action
        incidentNumber  = $IncidentNumber
        incidentId      = $IncidentId
        tagsBefore      = @($TagsBefore)
        tagsAfter       = @($TagsAfter)
        tagsAdded       = @($TagsAdded)
        lastModifiedBy  = $ModifiedBy
        etag            = $Etag
        error           = $ErrorMessage
        scriptVersion   = "1.0.0"
        operator        = $env:USERNAME
        machine         = $env:COMPUTERNAME
    }
    $script:ChangeLog.Add($entry)
}

function Invoke-AzRestWithRetry {
    param(
        [string]$Method,
        [string]$Path,
        [string]$Payload,
        [int]$MaxRetries = 3
    )
    $attempt = 0
    while ($true) {
        $attempt++
        $resp = if ($Payload) {
            Invoke-AzRestMethod -Method $Method -Path $Path -Payload $Payload -ErrorAction Stop
        } else {
            Invoke-AzRestMethod -Method $Method -Path $Path -ErrorAction Stop
        }

        if ($resp.StatusCode -eq 429 -or $resp.StatusCode -ge 500) {
            if ($attempt -le $MaxRetries) {
                $retryAfter = 2 * [Math]::Pow(2, $attempt - 1)  # 2, 4, 8 seconds
                $retryHeader = $resp.Headers | Where-Object { $_.Key -eq 'Retry-After' } | Select-Object -First 1
                if ($retryHeader) {
                    $retryAfter = [Math]::Max($retryAfter, [int]$retryHeader.Value[0])
                }
                Write-Host "    ⏳ HTTP $($resp.StatusCode) — retrying in ${retryAfter}s (attempt $attempt/$MaxRetries)..." -ForegroundColor Yellow
                Start-Sleep -Seconds $retryAfter
                continue
            }
        }
        return $resp
    }
}

function Add-Finding([string]$Severity, [string]$Title, [string]$Detail) {
    $script:Report.Findings.Add([PSCustomObject]@{ Severity=$Severity; Title=$Title; Detail=$Detail })
    switch ($Severity) {
        "CRITICAL" { Show-Fail "$Title" }
        "WARNING"  { Show-Warn "$Title" }
        "PASS"     { Show-Ok   "$Title" }
        default    { Show-Info "$Title" }
    }
    if ($Detail) { Write-Host "           $Detail" -ForegroundColor DarkGray }
}

# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  STEP 1 — PREREQUISITES                                                 ║
# ╚════════════════════════════════════════════════════════════════════════════╝

Show-Banner
Show-Step 1 8 "Checking prerequisites"

$neededModules = @('Az.Accounts','Az.SecurityInsights','Az.Monitor','Az.OperationalInsights')
foreach ($m in $neededModules) {
    if (Get-Module -ListAvailable -Name $m -ErrorAction SilentlyContinue) {
        Write-Host "  ✓ $m" -ForegroundColor DarkGray
    } else {
        Write-Host "  Installing $m ..." -ForegroundColor Yellow -NoNewline
        try {
            Install-Module $m -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
            Write-Host " done" -ForegroundColor Green
        } catch {
            Write-Host " FAILED" -ForegroundColor Red
            Write-Host "  Run as admin or install manually: Install-Module $m" -ForegroundColor Red
            exit 1
        }
    }
    Import-Module $m -ErrorAction SilentlyContinue | Out-Null
}
Show-Ok "All modules ready"

# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  STEP 2 — AZURE LOGIN + PICK SUBSCRIPTION                               ║
# ╚════════════════════════════════════════════════════════════════════════════╝

Show-Step 2 8 "Connecting to Azure"

$ctx = Get-AzContext -ErrorAction SilentlyContinue
if ($ctx) {
    Show-Ok "Already logged in as $($ctx.Account.Id)"
} else {
    Write-Host "  Opening login prompt..." -ForegroundColor Yellow
    Connect-AzAccount -ErrorAction Stop | Out-Null
    $ctx = Get-AzContext
    Show-Ok "Logged in as $($ctx.Account.Id)"
}

# --- Pick subscription ---
if (-not $SubscriptionId) {
    Write-Host ""
    Write-Host "  Loading subscriptions..." -ForegroundColor DarkGray
    $subs = Get-AzSubscription -ErrorAction Stop |
            Where-Object State -eq "Enabled" |
            Sort-Object Name |
            Select-Object @{N='Display';E={"$($_.Name)  ($($_.Id))"}}, Name, Id
    if ($subs.Count -eq 1) {
        $SubscriptionId = $subs[0].Id
        Show-Ok "Auto-selected subscription: $($subs[0].Name)"
    } else {
        $pick = Pick-FromList -Prompt "Select subscription" -Items $subs -DisplayProperty "Display"
        $SubscriptionId = $pick.Id
    }
}
Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop | Out-Null
Show-Ok "Subscription: $SubscriptionId"

# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  STEP 3 — DISCOVER SENTINEL WORKSPACE                                   ║
# ╚════════════════════════════════════════════════════════════════════════════╝

Show-Step 3 8 "Finding Sentinel workspaces"

if (-not $WorkspaceName -or -not $ResourceGroupName) {
    Write-Host "  Scanning for Log Analytics workspaces with Sentinel..." -ForegroundColor DarkGray

    $allWs = Get-AzOperationalInsightsWorkspace -ErrorAction Stop

    # Check which workspaces have Sentinel (SecurityInsights solution)
    $sentinelWorkspaces = foreach ($ws in $allWs) {
        $hasSentinel = $false
        try {
            $solutions = Get-AzMonitorLogAnalyticsSolution `
                -ResourceGroupName $ws.ResourceGroupName -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match "SecurityInsights" }
            if ($solutions) { $hasSentinel = $true }
        } catch { }

        if (-not $hasSentinel) {
            try {
                $null = Get-AzSentinelIncident -ResourceGroupName $ws.ResourceGroupName `
                    -WorkspaceName $ws.Name -ErrorAction Stop | Select-Object -First 1
                $hasSentinel = $true
            } catch { }
        }

        if ($hasSentinel) {
            [PSCustomObject]@{
                Display       = "$($ws.Name)  (RG: $($ws.ResourceGroupName))"
                Name          = $ws.Name
                ResourceGroup = $ws.ResourceGroupName
                CustomerId    = $ws.CustomerId
            }
        }
    }

    if (-not $sentinelWorkspaces -or $sentinelWorkspaces.Count -eq 0) {
        Show-Fail "No Sentinel-enabled workspaces found in this subscription."
        Write-Host "  Pass -ResourceGroupName and -WorkspaceName manually." -ForegroundColor Yellow
        exit 1
    }

    if ($sentinelWorkspaces.Count -eq 1) {
        $ws = $sentinelWorkspaces[0]
        Show-Ok "Auto-selected: $($ws.Name)"
    } else {
        $ws = Pick-FromList -Prompt "Select Sentinel workspace" -Items $sentinelWorkspaces -DisplayProperty "Display"
    }
    $WorkspaceName     = $ws.Name
    $ResourceGroupName = $ws.ResourceGroup
    $workspaceId       = $ws.CustomerId
} else {
    $wsObj = Get-AzOperationalInsightsWorkspace `
        -ResourceGroupName $ResourceGroupName -Name $WorkspaceName -ErrorAction Stop
    $workspaceId = $wsObj.CustomerId
}

Show-Ok "Workspace: $WorkspaceName  |  RG: $ResourceGroupName"

$script:Report.RunTime       = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss UTC")
$script:Report.Subscription  = $SubscriptionId
$script:Report.ResourceGroup = $ResourceGroupName
$script:Report.Workspace     = $WorkspaceName
$script:Report.WorkspaceId   = $workspaceId

# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  STEP 4 — ASK ABOUT EXPECTED TAGS + LOOKBACK                            ║
# ╚════════════════════════════════════════════════════════════════════════════╝

Show-Step 4 8 "Gathering scope info"

# ── 4a. Incident ID scoping ─────────────────────────────────────────────────
if (-not $IncidentIds) {
    Write-Host ""
    Write-Host "  Enter the incident number(s) to diagnose and remediate" -ForegroundColor Yellow
    Write-Host "  (comma-separated, e.g. 386033,386036)." -ForegroundColor Yellow
    Write-Host "  Press Enter to scan ALL recent phishing incidents (broader, slower)." -ForegroundColor DarkGray
    $input_ids = Read-Host "  Incident IDs"

    if ($input_ids -match '^\s*$') {
        $IncidentIds = @()
        Show-Info "No specific incidents — will scan all recent phishing incidents"
    } else {
        $IncidentIds = @($input_ids -split '[,;\s]+' | Where-Object { $_ -match '^\d+$' } | ForEach-Object { [int]$_ })
        if ($IncidentIds.Count -gt 0) {
            Show-Ok "Scoped to incident(s): $($IncidentIds -join ', ')"
        } else {
            Show-Warn "Could not parse incident IDs — will scan all"
            $IncidentIds = @()
        }
    }
}
$script:Report.IncidentIds = $IncidentIds -join ", "

# ── 4b. Expected tags (optional — for diagnostic reporting only) ────────────
if (-not $ExpectedTags) {
    Write-Host ""
    Write-Host "  Scanning existing incident tags for suggestions..." -ForegroundColor DarkGray
    $discoveredTags = @()
    try {
        $sampleUri = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName" +
            "/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName" +
            "/providers/Microsoft.SecurityInsights/incidents?api-version=2024-03-01&`$top=100" +
            "&`$orderby=properties/createdTimeUtc desc"
        $sampleResp = Invoke-AzRestMethod -Method GET -Path $sampleUri -ErrorAction Stop
        $sampleInc = ($sampleResp.Content | ConvertFrom-Json).value
        $discoveredTags = @($sampleInc.properties.labels.labelName |
            Where-Object { $_ } | Group-Object | Sort-Object Count -Descending |
            Select-Object -First 10 -ExpandProperty Name)
    } catch { }

    if ($discoveredTags.Count -gt 0) {
        Write-Host ""
        Write-Host "  Tags found in your environment:" -ForegroundColor White
        for ($i = 0; $i -lt $discoveredTags.Count; $i++) {
            Write-Host "    [$($i+1)] $($discoveredTags[$i])" -ForegroundColor White
        }
        Write-Host ""
        Write-Host "  (Optional) Select tags for diagnostic reporting." -ForegroundColor Yellow
        Write-Host "  Remediation will restore ALL removed tags regardless of selection." -ForegroundColor Yellow
        Write-Host "  Press Enter to skip." -ForegroundColor DarkGray
        $input_tags = Read-Host "  Selection"

        if ($input_tags -match '^\s*$') {
            $ExpectedTags = @()
            Show-Info "No expected tags filter — diagnostics will check all tags"
        } elseif ($input_tags -match '^\d[\d,\s]*$') {
            $indices = $input_tags -split '[,\s]+' | ForEach-Object { [int]$_ - 1 }
            $ExpectedTags = @($indices | Where-Object { $_ -ge 0 -and $_ -lt $discoveredTags.Count } |
                ForEach-Object { $discoveredTags[$_] })
            Show-Ok "Diagnostic filter: $($ExpectedTags -join ', ')"
        } else {
            $ExpectedTags = @($input_tags -split '[,;]+' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            Show-Ok "Custom diagnostic filter: $($ExpectedTags -join ', ')"
        }
    } else {
        Write-Host ""
        Write-Host "  (Optional) Enter tag names for diagnostic reporting" -ForegroundColor Yellow
        Write-Host "  (comma-separated, or press Enter to skip):" -ForegroundColor Yellow
        $input_tags = Read-Host "  Tags"
        if ($input_tags -match '^\s*$') {
            $ExpectedTags = @()
        } else {
            $ExpectedTags = @($input_tags -split '[,;]+' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        }
    }
}
$script:Report.ExpectedTags = $ExpectedTags -join ", "

Write-Host ""
Write-Host "  ℹ️  Remediation mode: DYNAMIC — ALL historically removed tags will be restored" -ForegroundColor Cyan

# Lookback
Write-Host ""
Write-Host "  How many days back should we scan? (default: $LookbackDays)" -ForegroundColor Yellow
try {
    $lb = Read-Host "  Days [press Enter for $LookbackDays]"
    if ($lb -as [int]) { $LookbackDays = [int]$lb }
} catch {
    # NonInteractive mode — use default
}
$script:Report.LookbackDays = $LookbackDays
Show-Ok "Scanning last $LookbackDays days"

# ── Data Retention Warning ──────────────────────────────────────────────────
Write-Host ""
Write-Host "  ┌──────────────────────────────────────────────────────────────────────┐" -ForegroundColor Yellow
Write-Host "  │  📊 DATA RETENTION & LOOKBACK LIMITATIONS                            │" -ForegroundColor Yellow
Write-Host "  ├──────────────────────────────────────────────────────────────────────┤" -ForegroundColor Yellow
Write-Host "  │                                                                      │" -ForegroundColor Yellow
Write-Host "  │  This script reconstructs tag history from two data sources:         │" -ForegroundColor Yellow
Write-Host "  │                                                                      │" -ForegroundColor Yellow
Write-Host "  │  1. SecurityIncident table (KQL)                                     │" -ForegroundColor Yellow
Write-Host "  │     Retention: Depends on your workspace settings (default 90 days)  │" -ForegroundColor Yellow
Write-Host "  │     Contains: Every incident state change (tags, status, severity)   │" -ForegroundColor Yellow
Write-Host "  │     ⚠ Tags removed BEFORE this retention window cannot be recovered  │" -ForegroundColor Yellow
Write-Host "  │                                                                      │" -ForegroundColor Yellow
Write-Host "  │  2. Azure Activity Log                                               │" -ForegroundColor Yellow
Write-Host "  │     Retention: Fixed 90-day maximum (Azure platform limit)           │" -ForegroundColor Yellow
Write-Host "  │     Contains: REST API write operations (who called PUT/PATCH)       │" -ForegroundColor Yellow
Write-Host "  │                                                                      │" -ForegroundColor Yellow
Write-Host "  │  Your lookback: $("$LookbackDays days".PadRight(51))│" -ForegroundColor Yellow
Write-Host "  │  Maximum recoverable: min(workspace retention, 90 days)              │" -ForegroundColor Yellow
Write-Host "  │                                                                      │" -ForegroundColor Yellow
Write-Host "  │  ⚠ IMPORTANT: If tags were stripped MORE than your retention days    │" -ForegroundColor Yellow
Write-Host "  │    ago, the original tags CANNOT be determined and will NOT be        │" -ForegroundColor Yellow
Write-Host "  │    restored. Only tags visible in the log history can be recovered.   │" -ForegroundColor Yellow
Write-Host "  └──────────────────────────────────────────────────────────────────────┘" -ForegroundColor Yellow
Write-Host ""

# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  STEP 5 — RUN DIAGNOSTICS                                               ║
# ╚════════════════════════════════════════════════════════════════════════════╝

Show-Step 5 8 "Running diagnostics (this may take a minute)"

$startUtc = (Get-Date).AddDays(-$LookbackDays).ToUniversalTime()
$endUtc   = (Get-Date).ToUniversalTime()

# ── 5a. Activity Log ────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  [5a] Azure Activity Log ..." -ForegroundColor White

$agentPatterns = @("Security Copilot","SecurityInsights","Microsoft Threat Protection",
                   "Phishing Triage","WindowsDefenderATP","Copilot","MTP")

try {
    $actLogs = Get-AzActivityLog `
        -StartTime $startUtc.ToString("o") -EndTime $endUtc.ToString("o") `
        -ResourceGroupName $ResourceGroupName -ErrorAction Stop |
        Where-Object { $_.ResourceId -like "*Microsoft.SecurityInsights/incidents*" -and
                       $_.ResourceId -like "*$WorkspaceName*" -and
                       $_.OperationName.Value -match "incidents/write" }

    $agentWrites = @($actLogs | Where-Object {
        $text = "$($_.Caller) $(($_.Claims | Out-String))"
        ($agentPatterns | Where-Object { $text -match [regex]::Escape($_) }).Count -gt 0
    })

    $script:Report.ActivityLog = @{
        Total   = ($actLogs | Measure-Object).Count
        Agent   = $agentWrites.Count
        Samples = @($agentWrites | Select-Object -First 20 |
                    ForEach-Object { [PSCustomObject]@{
                        Time=($_.EventTimestamp); Caller=$_.Caller;
                        Incident=($_.ResourceId -split '/')[-1]; Status=$_.Status.Value } })
    }

    if ($agentWrites.Count -gt 0) {
        Add-Finding "WARNING" `
            "$($agentWrites.Count) incident writes by agent identities" `
            "Out of $($actLogs.Count) total writes — these may be overwriting tags."
    } else {
        Add-Finding "INFO" "No agent-identity writes found in Activity Log" `
            "Agent may use a different identity — KQL will check further."
    }
} catch {
    $script:Report.Errors.Add("Activity Log: $_")
    Show-Warn "Activity Log query failed — continuing"
}

# ── 5b. Incident Statistics (KQL — server-side, scales to any tenant size) ──────────
Write-Host ""
Write-Host "  [5b] Sentinel incident statistics ..." -ForegroundColor White

try {
    if ($IncidentIds.Count -gt 0) {
        # ── Scoped mode: fetch only specific incidents via REST (already efficient) ──
        $allIncRaw = [System.Collections.Generic.List[object]]::new()
        Write-Host "    Fetching $($IncidentIds.Count) specific incident(s) via REST API..." -ForegroundColor DarkGray
        foreach ($iid in $IncidentIds) {
            try {
                $filterUri = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName" +
                    "/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName" +
                    "/providers/Microsoft.SecurityInsights/incidents?api-version=2024-03-01" +
                    "&`$filter=properties/incidentNumber eq $iid"
                $resp = Invoke-AzRestMethod -Method GET -Path $filterUri -ErrorAction Stop
                $data = ($resp.Content | ConvertFrom-Json).value
                if ($data) { $data | ForEach-Object { $allIncRaw.Add($_) } }
            } catch {
                Show-Warn "Could not fetch incident #$iid — $_"
            }
        }
        Write-Host "    Found $($allIncRaw.Count) incident(s)" -ForegroundColor DarkGray

        $phish = @($allIncRaw | ForEach-Object {
            [PSCustomObject]@{
                IncidentNumber      = $_.properties.incidentNumber
                Title               = $_.properties.title
                Description         = $_.properties.description
                Classification      = $_.properties.classification
                Status              = $_.properties.status
                Severity            = $_.properties.severity
                LastModifiedTimeUtc = $_.properties.lastModifiedTimeUtc
                Label               = @($_.properties.labels | ForEach-Object {
                    [PSCustomObject]@{ LabelName = $_.labelName; LabelType = $_.labelType }
                })
            }
        })

        $withTagsCount    = @($phish | Where-Object { $_.Label -and $_.Label.Count -gt 0 }).Count
        $withoutTagsCount = @($phish | Where-Object { -not $_.Label -or $_.Label.Count -eq 0 }).Count

        $tagDist = @($phish | ForEach-Object { $_.Label.LabelName } |
                     Where-Object { $_ } | Group-Object | Sort-Object Count -Descending |
                     Select-Object Name, Count)

        $missingExpected = @()
        if ($ExpectedTags.Count -gt 0) {
            $missingExpected = @($phish | Where-Object {
                $labels = @($_.Label.LabelName)
                ($ExpectedTags | Where-Object { $_ -notin $labels }).Count -gt 0
            } | Select-Object -First 30 IncidentNumber,
                @{N='Title';E={$t = $_.Title; if([string]::IsNullOrEmpty($t)){'(untitled)'}elseif($t.Length -gt 55){$t.Substring(0,55)+"..."}else{$t}}},
                @{N='CurrentTags';E={($_.Label.LabelName -join ", ") -replace '^$','(none)'}},
                Status, LastModifiedTimeUtc)
        }

        $script:Report.IncidentStats = @{
            Total        = $phish.Count
            Phishing     = $phish.Count
            WithTags     = $withTagsCount
            WithoutTags  = $withoutTagsCount
            TagDist      = $tagDist
            MissingExp   = $missingExpected
        }

        Write-Host "    Phishing incidents: $($phish.Count)  " -NoNewline
        Write-Host "With tags: $withTagsCount  " -ForegroundColor Green -NoNewline
        Write-Host "Without: $withoutTagsCount" -ForegroundColor $(if($withoutTagsCount){'Red'}else{'Green'})

        if ($withoutTagsCount -gt 0) {
            $pct = [math]::Round(($withoutTagsCount / [math]::Max($phish.Count,1)) * 100, 1)
            Add-Finding "CRITICAL" "$withoutTagsCount phishing incidents have NO tags ($pct%)" `
                "These won't trigger tag-based automation."
        } else {
            Add-Finding "PASS" "All phishing incidents have tags" $null
        }

        if ($ExpectedTags.Count -gt 0 -and $missingExpected.Count -gt 0) {
            Add-Finding "CRITICAL" `
                "$($missingExpected.Count) incidents missing expected tags ($($ExpectedTags -join ', '))" `
                "Automation depending on these tags will not fire."
        } elseif ($ExpectedTags.Count -gt 0) {
            Add-Finding "PASS" "All phishing incidents have the expected tags" $null
        }
    } else {
        # ── Broad mode: use KQL for server-side statistics (scales to any tenant) ──
        if (-not $workspaceId) {
            Show-Warn "No workspace ID — cannot run KQL incident statistics. Skipping step 5b."
            $script:Report.Errors.Add("Step 5b skipped: no workspace ID for KQL queries")
        } else {
            Write-Host "    Querying workspace for phishing incident statistics (KQL)..." -ForegroundColor DarkGray -NoNewline

            # KQL 1: Summary stats
            $kqlStats = @"
SecurityIncident
| where TimeGenerated >= ago(${LookbackDays}d)
| where Title has_any ("phish","user reported","submission") or Classification has "phish"
| extend LabelCount = coalesce(array_length(Labels), 0)
| extend LabelNames = extract_all(@'"labelName"\s*:\s*"([^"]+)"', tostring(Labels))
| summarize arg_max(TimeGenerated, Labels, LabelCount, LabelNames) by IncidentNumber, Title
| summarize
    TotalPhishing = count(),
    WithTags = countif(LabelCount > 0),
    WithoutTags = countif(LabelCount == 0),
    AllTags = make_list(LabelNames)
"@

            # KQL 2: Tag distribution (top 30)
            $kqlTagDist = @"
SecurityIncident
| where TimeGenerated >= ago(${LookbackDays}d)
| where Title has_any ("phish","user reported","submission") or Classification has "phish"
| summarize arg_max(TimeGenerated, Labels) by IncidentNumber
| mv-expand Label = Labels
| extend LabelName = tostring(Label.labelName)
| where isnotempty(LabelName)
| summarize Count = count() by Name = LabelName
| order by Count desc
| take 30
"@

            $statsRes = Invoke-AzOperationalInsightsQuery -WorkspaceId $workspaceId -Query $kqlStats -ErrorAction Stop
            $statsRow = $statsRes.Results | Select-Object -First 1

            $totalPhishing  = if ($statsRow) { [int]$statsRow.TotalPhishing }  else { 0 }
            $withTagsCount  = if ($statsRow) { [int]$statsRow.WithTags }       else { 0 }
            $withoutTagsCount = if ($statsRow) { [int]$statsRow.WithoutTags }  else { 0 }

            $tagDistRes = Invoke-AzOperationalInsightsQuery -WorkspaceId $workspaceId -Query $kqlTagDist -ErrorAction Stop
            $tagDist = @($tagDistRes.Results | ForEach-Object {
                [PSCustomObject]@{ Name = $_.Name; Count = [int]$_.Count }
            })

            # KQL 3: Missing expected tags (only when -ExpectedTags is provided)
            $missingExpected = @()
            if ($ExpectedTags.Count -gt 0) {
                $expectedTagConditions = @($ExpectedTags | ForEach-Object {
                    "LabelNames !has `"$_`""
                })
                $expectedTagsFilter = $expectedTagConditions -join " or "

                $kqlMissing = @"
SecurityIncident
| where TimeGenerated >= ago(${LookbackDays}d)
| where Title has_any ("phish","user reported","submission") or Classification has "phish"
| summarize arg_max(TimeGenerated, Labels, Status, Title) by IncidentNumber
| extend LabelNames = extract_all(@'"labelName"\s*:\s*"([^"]+)"', tostring(Labels))
| extend CurrentTags = strcat_array(LabelNames, ", ")
| where $expectedTagsFilter
| project IncidentNumber, Title, CurrentTags, Status
| take 30
"@
                $missingRes = Invoke-AzOperationalInsightsQuery -WorkspaceId $workspaceId -Query $kqlMissing -ErrorAction Stop
                $missingExpected = @($missingRes.Results | ForEach-Object {
                    [PSCustomObject]@{
                        IncidentNumber = $_.IncidentNumber
                        Title          = if ([string]::IsNullOrEmpty($_.Title)) { '(untitled)' }
                                         elseif ($_.Title.Length -gt 55) { $_.Title.Substring(0,55) + "..." }
                                         else { $_.Title }
                        CurrentTags    = if ([string]::IsNullOrEmpty($_.CurrentTags)) { '(none)' } else { $_.CurrentTags }
                        Status         = $_.Status
                    }
                })
            }

            Write-Host " done" -ForegroundColor Green
            Write-Host "    Phishing incidents: $totalPhishing  " -NoNewline
            Write-Host "With tags: $withTagsCount  " -ForegroundColor Green -NoNewline
            Write-Host "Without: $withoutTagsCount" -ForegroundColor $(if($withoutTagsCount){'Red'}else{'Green'})

            $script:Report.IncidentStats = @{
                Total        = $totalPhishing
                Phishing     = $totalPhishing
                WithTags     = $withTagsCount
                WithoutTags  = $withoutTagsCount
                TagDist      = $tagDist
                MissingExp   = $missingExpected
            }

            if ($withoutTagsCount -gt 0) {
                $pct = [math]::Round(($withoutTagsCount / [math]::Max($totalPhishing,1)) * 100, 1)
                Add-Finding "CRITICAL" "$withoutTagsCount phishing incidents have NO tags ($pct%)" `
                    "These won't trigger tag-based automation."
            } else {
                Add-Finding "PASS" "All phishing incidents have tags" $null
            }

            if ($ExpectedTags.Count -gt 0 -and $missingExpected.Count -gt 0) {
                Add-Finding "CRITICAL" `
                    "$($missingExpected.Count) incidents missing expected tags ($($ExpectedTags -join ', '))" `
                    "Automation depending on these tags will not fire."
            } elseif ($ExpectedTags.Count -gt 0) {
                Add-Finding "PASS" "All phishing incidents have the expected tags" $null
            }
        }
    }
} catch {
    $script:Report.Errors.Add("Incident statistics: $_")
    Show-Warn "Incident statistics failed — continuing"
}

# ── 5c. KQL Queries ────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  [5c] KQL deep-dive ..." -ForegroundColor White

# Build incident scope filter for KQL
$kqlIncidentFilter = ""
if ($IncidentIds.Count -gt 0) {
    $idList = ($IncidentIds | ForEach-Object { "$_" }) -join ","
    $kqlIncidentFilter = "| where IncidentNumber in ($idList)"
} else {
    $kqlIncidentFilter = '| where Title has_any ("phish","user reported","submission") or Classification has "phish"'
}

$kqlQueries = [ordered]@{
    "Tags Vanished" = @"
SecurityIncident
| where TimeGenerated >= ago(${LookbackDays}d)
${kqlIncidentFilter}
| extend LabelCount = coalesce(array_length(Labels), 0), LabelsJson = tostring(Labels)
| summarize FirstTime=min(TimeGenerated), LastTime=max(TimeGenerated),
            Updates=count(), MaxLabels=max(LabelCount)
    by IncidentNumber, Title
| join kind=inner (
    SecurityIncident
    | where TimeGenerated >= ago(${LookbackDays}d)
    | summarize arg_max(TimeGenerated, Labels) by IncidentNumber
    | extend LastLabelCnt = coalesce(array_length(Labels), 0), LastLabels = tostring(Labels)
) on IncidentNumber
| where MaxLabels > 0 and LastLabelCnt == 0
| project IncidentNumber, Title, FirstTime, LastTime, Updates,
          TagsAtPeak=MaxLabels, TagsNow=LastLabelCnt
| order by LastTime desc
"@
    "Who Removed Tags" = @"
SecurityIncident
| where TimeGenerated >= ago(${LookbackDays}d)
${kqlIncidentFilter}
| extend LabelNames = extract_all(@'"labelName"\s*:\s*"([^"]+)"', tostring(Labels))
| extend LabelCount = array_length(LabelNames)
| sort by IncidentNumber asc, TimeGenerated asc, ingestion_time() asc
| serialize
| extend PrevLabels = prev(LabelNames), PrevIncident = prev(IncidentNumber)
| where IncidentNumber == PrevIncident
| extend RemovedTags = set_difference(PrevLabels, LabelNames)
| extend RemovedCount = array_length(RemovedTags)
| where RemovedCount > 0
| summarize TotalUpdates=count(), TagsRemoved=sum(RemovedCount),
            Incidents=dcount(IncidentNumber),
            SampleIds=make_set(IncidentNumber,5),
            SampleRemoved=make_set(RemovedTags,5) by ModifiedBy
| order by TagsRemoved desc
"@
    "Agent Correlation" = @"
let Phish = SecurityIncident
| where TimeGenerated >= ago(${LookbackDays}d)
${kqlIncidentFilter}
| extend LabelCount = coalesce(array_length(Labels), 0), LabelsJson = tostring(Labels);
let HadTags = Phish | where LabelCount > 0
| summarize When=min(TimeGenerated), Tags=take_any(LabelsJson), Cnt=take_any(LabelCount) by IncidentNumber;
let LostTags = Phish | where LabelCount == 0
| where ModifiedBy contains "Copilot" or ModifiedBy contains "Security Copilot" or ModifiedBy contains "Threat Protection" or ModifiedBy contains "SecurityInsights" or ModifiedBy contains "MTP" or ModifiedBy contains "WindowsDefenderATP"
| summarize StrippedAt=min(TimeGenerated), Actor=take_any(ModifiedBy) by IncidentNumber;
HadTags | join kind=inner LostTags on IncidentNumber
| project IncidentNumber, OriginalTags=Tags, OriginalCount=Cnt, StrippedAt, Actor
| order by StrippedAt desc
"@
    "Change Timeline" = @"
SecurityIncident
| where TimeGenerated >= ago(${LookbackDays}d)
${kqlIncidentFilter}
| extend LabelCount = coalesce(array_length(Labels), 0), LabelsJson = tostring(Labels)
| project TimeGenerated, IncidentNumber, Title, Status, ModifiedBy, LabelCount, LabelsJson
| order by IncidentNumber asc, TimeGenerated asc
"@
    "Tag History Per Incident" = @"
SecurityIncident
| where TimeGenerated >= ago(${LookbackDays}d)
${kqlIncidentFilter}
| extend LabelNames = extract_all(@'"labelName"\s*:\s*"([^"]+)"', tostring(Labels))
| sort by IncidentNumber asc, TimeGenerated asc, ingestion_time() asc
| serialize
| extend PrevLabels = prev(LabelNames), PrevIncident = prev(IncidentNumber)
| where IncidentNumber == PrevIncident
| extend RemovedTags = set_difference(PrevLabels, LabelNames)
| where array_length(RemovedTags) > 0
| where ModifiedBy contains "Copilot" or ModifiedBy contains "SecurityCopilotAgent" or ModifiedBy contains "MTP" or ModifiedBy contains "Threat Protection" or ModifiedBy contains "WindowsDefenderATP" or ModifiedBy contains "Microsoft Defender XDR" or ModifiedBy contains "Incident created from alert" or ModifiedBy contains "Microsoft XDR"
| summarize AgentRemovedTags = make_set(RemovedTags),
            RemovalCount = count(),
            LastRemoval = max(TimeGenerated),
            Actors = make_set(ModifiedBy)
    by IncidentNumber
| join kind=inner (
    SecurityIncident
    | where TimeGenerated >= ago(${LookbackDays}d)
    | summarize arg_max(TimeGenerated, Labels, ModifiedBy, Status, Title) by IncidentNumber
    | extend CurrentLabels = tostring(Labels), CurrentLabelCount = coalesce(array_length(Labels), 0)
    | extend CurrentTagNames = iff(CurrentLabelCount > 0,
        extract_all(@'"labelName"\s*:\s*"([^"]+)"', tostring(Labels)),
        dynamic([]))
) on IncidentNumber
| extend MissingTags = set_difference(AgentRemovedTags, CurrentTagNames)
| where array_length(MissingTags) > 0
| project IncidentNumber, Title, AgentRemovedTags, MissingTags, CurrentLabels, CurrentLabelCount,
          LastModifiedBy = ModifiedBy, Status, RemovalCount, Actors
| order by IncidentNumber desc
| take 500
"@
}

if ($workspaceId) {
    foreach ($name in $kqlQueries.Keys) {
        Write-Host "    ▸ $name ..." -ForegroundColor DarkGray -NoNewline
        try {
            $res = Invoke-AzOperationalInsightsQuery -WorkspaceId $workspaceId `
                -Query $kqlQueries[$name] -ErrorAction Stop
            $count = ($res.Results | Measure-Object).Count
            $script:Report.KQL[$name] = @{ Query = $kqlQueries[$name]; Rows = $res.Results; Count = $count }
            Write-Host " $count rows" -ForegroundColor $(if($count){'Yellow'}else{'Green'})

            switch ($name) {
                "Tags Vanished" {
                    if ($count -gt 0) {
                        Add-Finding "CRITICAL" "KQL: $count incidents had tags removed" `
                            "Tags existed earlier but are now gone."
                    } else {
                        Add-Finding "PASS" "KQL: No tag-removal events detected" $null
                    }
                }
                "Who Removed Tags" {
                    foreach ($row in $res.Results) {
                        Add-Finding "WARNING" `
                            "'$($row.ModifiedBy)' removed tags from $($row.Incidents) incident(s)" `
                            "$($row.TotalUpdates) update(s) stripped $($row.TagsRemoved) tag(s) total."
                    }
                }
                "Agent Correlation" {
                    if ($count -gt 0) {
                        Add-Finding "CRITICAL" `
                            "Direct match: agent update → tag removal ($count incidents)" `
                            "Agent identity was last modifier when tags vanished."
                    }
                }
                "Tag History Per Incident" {
                    if ($count -gt 0) {
                        Add-Finding "INFO" `
                            "KQL: $count incidents have tag history data for remediation" `
                            "Historical tags tracked for potential restoration."
                    }
                }
            }
        } catch {
            Write-Host " failed" -ForegroundColor Red
            $script:Report.Errors.Add("KQL '$name': $_")
            $script:Report.KQL[$name] = @{ Query = $kqlQueries[$name]; Rows = @(); Count = 0 }
        }
    }
} else {
    Show-Warn "No workspace ID — KQL skipped. Queries will be in the report for manual use."
    foreach ($name in $kqlQueries.Keys) {
        $script:Report.KQL[$name] = @{ Query = $kqlQueries[$name]; Rows = @(); Count = 0 }
    }
}

# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  STEP 6 — VERDICT                                                       ║
# ╚════════════════════════════════════════════════════════════════════════════╝

Show-Step 6 8 "Verdict"

$critCount = @($script:Report.Findings | Where-Object Severity -eq "CRITICAL").Count
$warnCount = @($script:Report.Findings | Where-Object Severity -eq "WARNING").Count

$script:Report.Verdict = if ($critCount -gt 0) {
    "CONFIRMED — The Phishing Triage Agent is removing incident tags"
} elseif ($warnCount -gt 0) {
    "LIKELY — Agent writes detected; review KQL results to confirm"
} else {
    "NOT CONFIRMED — No evidence of tag removal found"
}

Write-Host ""
Write-Host "  ┌──────────────────────────────────────────────────────────────┐" -ForegroundColor White
Write-Host "  │  VERDICT: $($script:Report.Verdict.PadRight(50))│" -ForegroundColor $(
    if ($critCount) {'Red'} elseif ($warnCount) {'Yellow'} else {'Green'})
Write-Host "  └──────────────────────────────────────────────────────────────┘" -ForegroundColor White

# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  STEP 7 — REMEDIATION                                                   ║
# ╚════════════════════════════════════════════════════════════════════════════╝

Show-Step 7 8 "Remediation"

# Agent identity patterns for filtering
$agentModifierPatterns = @("Copilot","SecurityCopilotAgent","MTP","Threat Protection","WindowsDefenderATP","Microsoft Defender XDR","Incident created from alert","Microsoft XDR")

# Build remediation candidates from Tag History Per Incident KQL results (always, for reporting)
$tagHistoryData = $script:Report.KQL["Tag History Per Incident"]
$remediationCandidates = @()

if ($tagHistoryData -and $tagHistoryData.Rows -and $tagHistoryData.Count -gt 0) {
    Write-Host "  Analyzing tag history for remediation candidates..." -ForegroundColor DarkGray

    foreach ($row in $tagHistoryData.Rows) {
        $incNum       = $row.IncidentNumber
        $title        = if ([string]::IsNullOrEmpty($row.Title)) { '(untitled)' } else { $row.Title }
        $modifiedBy   = "$($row.LastModifiedBy)"
        $status       = "$($row.Status)"
        $currentCount = 0
        try { $currentCount = [int]$row.CurrentLabelCount } catch {}

        # Parse MissingTags — these are tags removed by agent that are still missing
        $missingTags = @()
        try {
            $rawMissing = "$($row.MissingTags)"
            if ($rawMissing -match '^\[') {
                $missingTags = @(($rawMissing | ConvertFrom-Json) | Where-Object { $_ })
            } elseif ($rawMissing) {
                $missingTags = @($rawMissing -split '[,;]+' | ForEach-Object { $_.Trim().Trim('"','[',']') } | Where-Object { $_ })
            }
        } catch {
            $missingTags = @()
        }

        # Parse current labels
        $currentTags = @()
        try {
            $rawCur = "$($row.CurrentLabels)"
            if ($rawCur -match '^\[' -and $rawCur -ne '[]') {
                $parsed = $rawCur | ConvertFrom-Json
                $currentTags = @($parsed | ForEach-Object {
                    if ($_.labelName) { $_.labelName } elseif ($_.PSObject.Properties['labelName']) { $_.labelName } else { "$_" }
                } | Where-Object { $_ })
            }
        } catch {
            $currentTags = @()
        }

        if ($missingTags.Count -gt 0) {
            $remediationCandidates += [PSCustomObject]@{
                IncidentNumber = $incNum
                Title          = $title
                MissingTags    = $missingTags
                CurrentTags    = $currentTags
                ModifiedBy     = $modifiedBy
                Status         = $status
            }
        }
    }
}

# Deduplicate by IncidentNumber (KQL may return multiple rows per incident)
$dedupedCandidates = @()
$seenIncidents = @{}
foreach ($c in $remediationCandidates) {
    $key = "$($c.IncidentNumber)"
    if (-not $seenIncidents.ContainsKey($key)) {
        $seenIncidents[$key] = $true
        $dedupedCandidates += $c
    }
}
$remediationCandidates = $dedupedCandidates

if ($DiagnosticOnly) {
    Show-Info "Skipping remediation — -DiagnosticOnly flag is set"
    $script:Report.Remediation.SkipReason = "DiagnosticOnly flag was set"
} else {
    # ── Present findings summary and ask admin to review before proceeding ──
    Write-Host ""
    Write-Host "  ┌──────────────────────────────────────────────────────────────────────┐" -ForegroundColor Cyan
    Write-Host "  │  📋 FINDINGS SUMMARY                                                 │" -ForegroundColor Cyan
    Write-Host "  ├──────────────────────────────────────────────────────────────────────┤" -ForegroundColor Cyan
    $critCount2 = @($script:Report.Findings | Where-Object Severity -eq "CRITICAL").Count
    $warnCount2 = @($script:Report.Findings | Where-Object Severity -eq "WARNING").Count
    $infoCount2 = @($script:Report.Findings | Where-Object Severity -eq "INFO").Count
    Write-Host "  │  Critical: $("$critCount2".PadRight(5)) Warning: $("$warnCount2".PadRight(5)) Info: $("$infoCount2".PadRight(20))│" -ForegroundColor $(
        if ($critCount2) {'Red'} elseif ($warnCount2) {'Yellow'} else {'Green'})
    Write-Host "  │                                                                      │" -ForegroundColor Cyan
    foreach ($f in ($script:Report.Findings | Where-Object { $_.Severity -in @("CRITICAL","WARNING") } | Select-Object -First 8)) {
        $icon = if ($f.Severity -eq "CRITICAL") { "🔴" } else { "🟡" }
        $truncMsg = if ($f.Title.Length -gt 62) { $f.Title.Substring(0,59) + "..." } else { $f.Title }
        Write-Host "  │  $icon $($truncMsg.PadRight(64))│" -ForegroundColor $(if($f.Severity -eq "CRITICAL"){'Red'}else{'Yellow'})
    }
    Write-Host "  │                                                                      │" -ForegroundColor Cyan
    Write-Host "  │  ⚠ LIMITATIONS:                                                      │" -ForegroundColor Yellow
    Write-Host "  │  • Only tags removed by the agent (via ModifiedBy) are restored       │" -ForegroundColor DarkGray
    Write-Host "  │  • Data limited to $("$LookbackDays-day".PadRight(8)) lookback (workspace retention applies)     │" -ForegroundColor DarkGray
    Write-Host "  │  • Remediation candidates capped at 500 per run                       │" -ForegroundColor DarkGray
    Write-Host "  │  • PUT calls may trigger downstream automation rules                  │" -ForegroundColor DarkGray
    Write-Host "  │  • Full report will be generated regardless of your choice below       │" -ForegroundColor DarkGray
    Write-Host "  └──────────────────────────────────────────────────────────────────────┘" -ForegroundColor Cyan
    Write-Host ""

    $adminApproval = $false
    if ($AutoRemediate) {
        Show-Info "Auto-remediate enabled — skipping findings review prompt"
        $adminApproval = $true
    } else {
        Write-Host "  Would you like to proceed to remediation?" -ForegroundColor White
        Write-Host "  Review the findings above. The HTML report will be generated either way." -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "    [Y] Yes — show remediation candidates and proceed" -ForegroundColor Green
        Write-Host "    [N] No  — generate report only (no changes)" -ForegroundColor Yellow
        Write-Host ""
        $choice = Read-Host "  Choice (Y/N)"
        if ($choice -match '^[Yy]') {
            $adminApproval = $true
            Show-Ok "Admin approved — analyzing remediation candidates..."
        } else {
            Show-Info "Admin chose report-only mode — no changes will be made"
            $script:Report.Remediation.SkipReason = "Admin declined remediation after reviewing findings"
        }
    }

    if (-not $adminApproval) {
        # Skip remediation but still generate report
        $script:Report.Remediation.Skipped = 0
    } else {

    if ($remediationCandidates.Count -eq 0) {
        Show-Info "No remediation candidates found"
        Write-Host "           Either no tags need restoration or the agent was not the last modifier." -ForegroundColor DarkGray
        $script:Report.Remediation.SkipReason = "No remediation candidates identified"
    } else {
        # Show the table of candidates
        Write-Host ""
        Write-Host "  Incidents to remediate:" -ForegroundColor White
        Write-Host ""
        Write-Host "  $('Incident#'.PadRight(12)) $('Title'.PadRight(30)) $('Tags to Restore'.PadRight(25)) $('Current Tags'.PadRight(18)) Last Modified By" -ForegroundColor Cyan
        Write-Host "  $('─' * 110)" -ForegroundColor DarkGray

        foreach ($c in $remediationCandidates) {
            $truncTitle = $safeTitle = if ([string]::IsNullOrEmpty($c.Title)) { '(untitled)' } else { $c.Title }
            $truncTitle = if ($safeTitle.Length -gt 28) { $safeTitle.Substring(0,25) + "..." } else { $safeTitle }
            $tagsToRestore = ($c.MissingTags -join ", ")
            if ($tagsToRestore.Length -gt 23) { $tagsToRestore = $tagsToRestore.Substring(0,20) + "..." }
            $curTags = if ($c.CurrentTags.Count -eq 0) { "(none)" } else { ($c.CurrentTags -join ", ") }
            if ($curTags.Length -gt 16) { $curTags = $curTags.Substring(0,13) + "..." }
            $mod = if ($c.ModifiedBy.Length -gt 30) { $c.ModifiedBy.Substring(0,27) + "..." } else { $c.ModifiedBy }

            Write-Host "  $("$($c.IncidentNumber)".PadRight(12)) $($truncTitle.PadRight(30)) $($tagsToRestore.PadRight(25)) $($curTags.PadRight(18)) $mod" -ForegroundColor White
        }
        Write-Host ""

        # Ask for confirmation — full warning + acceptance flow
        $proceed = $false
        if ($AutoRemediate) {
            Show-Info "Auto-remediate enabled — proceeding without confirmation"
            $proceed = $true
        } else {
            Write-Host ""
            Write-Host "  ╔══════════════════════════════════════════════════════════════════════╗" -ForegroundColor Red
            Write-Host "  ║                    ⚠️  REMEDIATION WARNING ⚠️                        ║" -ForegroundColor Red
            Write-Host "  ╠══════════════════════════════════════════════════════════════════════╣" -ForegroundColor Red
            Write-Host "  ║                                                                      ║" -ForegroundColor Red
            Write-Host "  ║  You are about to MODIFY Sentinel incidents in a LIVE environment.   ║" -ForegroundColor Red
            Write-Host "  ║                                                                      ║" -ForegroundColor Red
            Write-Host "  ║  WHAT WILL HAPPEN:                                                   ║" -ForegroundColor Red
            Write-Host "  ║  • $("$($remediationCandidates.Count) incidents will be updated via PUT API".PadRight(55))║" -ForegroundColor Yellow
            Write-Host "  ║  • Tags will be ADDED back (existing tags preserved)                 ║" -ForegroundColor Yellow
            Write-Host "  ║  • Each change is logged to a JSON audit file                        ║" -ForegroundColor Yellow
            Write-Host "  ║                                                                      ║" -ForegroundColor Red
            Write-Host "  ║  WHAT WILL NOT HAPPEN:                                               ║" -ForegroundColor Red
            Write-Host "  ║  • No tags will be removed                                           ║" -ForegroundColor Green
            Write-Host "  ║  • No incidents will be deleted or created                           ║" -ForegroundColor Green
            Write-Host "  ║  • No other incident properties will be changed                      ║" -ForegroundColor Green
            Write-Host "  ║                                                                      ║" -ForegroundColor Red
            Write-Host "  ║  RISKS:                                                              ║" -ForegroundColor Red
            Write-Host "  ║  • Tags restored from log history may include tags that were          ║" -ForegroundColor Yellow
            Write-Host "  ║    intentionally removed by a human analyst (not just the agent)      ║" -ForegroundColor Yellow
            Write-Host "  ║  • PUT operations may trigger downstream automation rules             ║" -ForegroundColor Yellow
            Write-Host "  ║  • If workspace retention < lookback, some tag history may be         ║" -ForegroundColor Yellow
            Write-Host "  ║    incomplete — not all original tags can be determined                ║" -ForegroundColor Yellow
            Write-Host "  ║                                                                      ║" -ForegroundColor Red
            Write-Host "  ║  DATA SCOPE:                                                         ║" -ForegroundColor Red
            Write-Host "  ║  • Lookback period: $("$LookbackDays days".PadRight(45))║" -ForegroundColor White
            Write-Host "  ║  • Only incidents where the agent was the last modifier               ║" -ForegroundColor White
            Write-Host "  ║  • Only tags that existed in the SecurityIncident log history          ║" -ForegroundColor White
            Write-Host "  ║                                                                      ║" -ForegroundColor Red
            Write-Host "  ║  All changes will be logged to:                                      ║" -ForegroundColor Red
            Write-Host "  ║  TagRemediation_ChangeLog_<timestamp>.json                           ║" -ForegroundColor Cyan
            Write-Host "  ║                                                                      ║" -ForegroundColor Red
            Write-Host "  ║  THIS SCRIPT IS PROVIDED 'AS IS' — NOT OFFICIALLY SUPPORTED.         ║" -ForegroundColor Red
            Write-Host "  ║  You are solely responsible for changes made to your environment.     ║" -ForegroundColor Red
            Write-Host "  ╚══════════════════════════════════════════════════════════════════════╝" -ForegroundColor Red
            Write-Host ""
            Write-Host "  To proceed, type 'I ACCEPT' (case-sensitive)." -ForegroundColor Yellow
            Write-Host "  To skip remediation and only generate the report, type anything else." -ForegroundColor DarkGray
            Write-Host ""
            $confirm = Read-Host "  Confirmation"
            if ($confirm -ceq 'I ACCEPT') {
                $proceed = $true
                Show-Ok "Acceptance confirmed — proceeding with remediation"
            } else {
                Show-Info "Remediation skipped by user (did not accept)"
                $script:Report.Remediation.SkipReason = "User declined remediation"
                $script:Report.Remediation.Skipped = $remediationCandidates.Count
            }
        }

        if ($proceed) {
            Write-Host ""
            Write-Host "  Starting remediation..." -ForegroundColor Yellow
            Write-Host ""

            $sentinelBasePath = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName" +
                "/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName" +
                "/providers/Microsoft.SecurityInsights/incidents"

            $total = $remediationCandidates.Count
            $script:Report.Remediation.Attempted = $total
            $idx = 0

            foreach ($candidate in $remediationCandidates) {
                $idx++
                $incNum = $candidate.IncidentNumber

                try {
                    # Step 1: Find the incident GUID (name) by filtering on incident number
                    $filterUri = "${sentinelBasePath}?api-version=2024-03-01&`$filter=properties/incidentNumber eq $incNum"
                    $filterResp = Invoke-AzRestWithRetry -Method GET -Path $filterUri
                    $filterData = ($filterResp.Content | ConvertFrom-Json).value

                    if (-not $filterData -or $filterData.Count -eq 0) {
                        throw "Could not find incident #$incNum via REST API filter"
                    }

                    $incident = $filterData[0]
                    $incidentName = $incident.name
                    $incidentEtag = $incident.etag

                    # Step 2: Get current incident details (fresh GET for latest etag)
                    $getUri = "${sentinelBasePath}/${incidentName}?api-version=2024-03-01"
                    $getResp = Invoke-AzRestWithRetry -Method GET -Path $getUri
                    $incidentFull = $getResp.Content | ConvertFrom-Json
                    $incidentEtag = $incidentFull.etag

                    # Step 3: Build merged labels (current ∪ missing)
                    $currentLabels = @()
                    if ($incidentFull.properties.labels) {
                        $currentLabels = @($incidentFull.properties.labels | ForEach-Object {
                            @{ labelName = $_.labelName; labelType = if ($_.labelType) { $_.labelType } else { "User" } }
                        })
                    }

                    # Existing label names for dedup
                    $existingNames = @($currentLabels | ForEach-Object { $_.labelName })

                    $newLabels = @($candidate.MissingTags | Where-Object { $_ -notin $existingNames } | ForEach-Object {
                        @{ labelName = $_; labelType = "User" }
                    })

                    $mergedLabels = @($currentLabels) + @($newLabels)

                    if ($newLabels.Count -eq 0) {
                        Write-Host "  [$idx/$total] Incident #$incNum — tags already present, skipping ⏭️" -ForegroundColor DarkGray
                        $script:Report.Remediation.Skipped++
                        $script:Report.Remediation.Details += [PSCustomObject]@{
                            IncidentNumber = $incNum
                            TagsRestored   = "(already present)"
                            Status         = "Skipped"
                            Error          = ""
                        }
                        Write-ChangeLog -Action "SKIPPED" -IncidentNumber "$incNum" `
                            -IncidentId $incidentName `
                            -TagsBefore @($existingNames) -TagsAfter @($existingNames) -TagsAdded @() `
                            -ModifiedBy $candidate.ModifiedBy -Etag $incidentEtag `
                            -ErrorMessage "Tags already present on incident"
                        continue
                    }

                    # Step 4: PUT with etag — round-trip all properties, only modify labels
                    $putBody = @{
                        etag = $incidentEtag
                        properties = @{}
                    }
                    # Copy all properties from fresh GET
                    $incidentFull.properties.PSObject.Properties | ForEach-Object {
                        $putBody.properties[$_.Name] = $_.Value
                    }
                    # Override labels with our merged set
                    $putBody.properties.labels = @($mergedLabels)
                    # Remove known read-only properties that can't be PUT
                    $readOnlyProps = @('incidentNumber','createdTimeUtc','lastModifiedTimeUtc','incidentUrl',
                                       'providerName','providerIncidentId','additionalData','relatedAnalyticRuleIds')
                    foreach ($f in $readOnlyProps) {
                        $putBody.properties.Remove($f)
                    }
                    $putBody = $putBody | ConvertTo-Json -Depth 10

                    $putUri = "${sentinelBasePath}/${incidentName}?api-version=2024-03-01"
                    $putResp = Invoke-AzRestWithRetry -Method PUT -Path $putUri -Payload $putBody

                    $mergedNames = @($mergedLabels | ForEach-Object { $_.labelName })
                    $addedNames = @($newLabels | ForEach-Object { $_.labelName })

                    if ($putResp.StatusCode -ge 200 -and $putResp.StatusCode -lt 300) {
                        $restoredNames = $addedNames -join ", "
                        Write-Host "  [$idx/$total] Incident #$incNum — restored $($newLabels.Count) tags ($restoredNames) ✅" -ForegroundColor Green
                        $script:Report.Remediation.Succeeded++
                        $script:Report.Remediation.Details += [PSCustomObject]@{
                            IncidentNumber = $incNum
                            TagsRestored   = $restoredNames
                            Status         = "Success"
                            Error          = ""
                        }
                        Write-ChangeLog -Action "TAG_RESTORE" -IncidentNumber "$incNum" `
                            -IncidentId $incidentName `
                            -TagsBefore @($existingNames) -TagsAfter $mergedNames -TagsAdded $addedNames `
                            -ModifiedBy $candidate.ModifiedBy -Etag $incidentEtag `
                            -ErrorMessage ""
                    } else {
                        $errMsg = "HTTP $($putResp.StatusCode): $($putResp.Content)"
                        Write-Host "  [$idx/$total] Incident #$incNum — FAILED ❌  ($errMsg)" -ForegroundColor Red
                        $script:Report.Remediation.Failed++
                        $script:Report.Remediation.Details += [PSCustomObject]@{
                            IncidentNumber = $incNum
                            TagsRestored   = ""
                            Status         = "Failed"
                            Error          = $errMsg
                        }
                        Write-ChangeLog -Action "FAILED" -IncidentNumber "$incNum" `
                            -IncidentId $incidentName `
                            -TagsBefore @($existingNames) -TagsAfter @($existingNames) -TagsAdded @() `
                            -ModifiedBy $candidate.ModifiedBy -Etag $incidentEtag `
                            -ErrorMessage $errMsg
                    }
                } catch {
                    $errMsg = "$_"
                    # Attempt verification GET to check actual state
                    $verifiedState = "Unknown"
                    try {
                        if ($incidentName) {
                            $verifyResp = Invoke-AzRestMethod -Method GET -Path "${sentinelBasePath}/${incidentName}?api-version=2024-03-01" -ErrorAction SilentlyContinue
                            if ($verifyResp -and $verifyResp.StatusCode -eq 200) {
                                $verifyInc = $verifyResp.Content | ConvertFrom-Json
                                $verifyLabels = @($verifyInc.properties.labels | ForEach-Object { $_.labelName } | Where-Object { $_ })
                                $allExpected = @($existingNames) + @($addedNames) | Select-Object -Unique
                                $missing = @($allExpected | Where-Object { $_ -notin $verifyLabels })
                                if ($missing.Count -eq 0) {
                                    $verifiedState = "Succeeded (verified post-error)"
                                    Write-Host "  [$idx/$total] Incident #$incNum — write succeeded despite error ✅" -ForegroundColor Yellow
                                } else {
                                    $verifiedState = "Failed (verified: missing $($missing -join ', '))"
                                }
                            }
                        }
                    } catch { }

                    if ($verifiedState -like "Succeeded*") {
                        $script:Report.Remediation.Succeeded++
                    } else {
                        Write-Host "  [$idx/$total] Incident #$incNum — FAILED ❌  ($errMsg)" -ForegroundColor Red
                        $script:Report.Remediation.Failed++
                    }
                    $script:Report.Remediation.Details += [PSCustomObject]@{
                        IncidentNumber = $incNum
                        TagsRestored   = if ($verifiedState -like "Succeeded*") { ($addedNames -join ", ") } else { "" }
                        Status         = if ($verifiedState -like "Succeeded*") { "Success" } else { "Failed" }
                        Error          = "$errMsg [$verifiedState]"
                    }
                    Write-ChangeLog -Action $(if ($verifiedState -like "Succeeded*") { "TAG_RESTORE_VERIFIED" } else { "FAILED" }) `
                        -IncidentNumber "$incNum" `
                        -IncidentId $(if ($incidentName) { $incidentName } else { "" }) `
                        -TagsBefore @(if ($existingNames) { $existingNames } else { @() }) `
                        -TagsAfter @(if ($verifiedState -like "Succeeded*") { @($existingNames) + @($addedNames) | Select-Object -Unique } else { @() }) `
                        -TagsAdded @(if ($verifiedState -like "Succeeded*") { $addedNames } else { @() }) `
                        -ModifiedBy $candidate.ModifiedBy `
                        -Etag $(if ($incidentEtag) { $incidentEtag } else { "" }) `
                        -ErrorMessage "$errMsg [$verifiedState]"
                }

                # Rate limit: 500ms delay between PUT calls
                if ($idx -lt $total) {
                    Start-Sleep -Milliseconds 500
                }
            }

            # Summary
            Write-Host ""
            Write-Host "  Remediation complete:" -ForegroundColor White
            Write-Host "    Attempted: $($script:Report.Remediation.Attempted)" -ForegroundColor White
            Write-Host "    Succeeded: $($script:Report.Remediation.Succeeded)" -ForegroundColor Green
            Write-Host "    Failed:    $($script:Report.Remediation.Failed)" -ForegroundColor $(if($script:Report.Remediation.Failed){'Red'}else{'Green'})
            Write-Host "    Skipped:   $($script:Report.Remediation.Skipped)" -ForegroundColor DarkGray

            # ── Write JSON Change Log ────────────────────────────────────────
            if ($script:ChangeLog.Count -gt 0) {
                $logTs = Get-Date -Format "yyyyMMdd_HHmmss"
                $changeLogPath = Join-Path (Get-Location) "TagRemediation_ChangeLog_$logTs.json"
                $logPayload = [ordered]@{
                    metadata = [ordered]@{
                        generatedAt    = (Get-Date).ToUniversalTime().ToString("o")
                        scriptName     = "Diagnose-And-Remediate-PhishingTriageAgentTags.ps1"
                        scriptVersion  = "1.0.0"
                        operator       = $env:USERNAME
                        machine        = $env:COMPUTERNAME
                        subscription   = $SubscriptionId
                        resourceGroup  = $ResourceGroupName
                        workspace      = $WorkspaceName
                        lookbackDays   = $LookbackDays
                        expectedTags   = @($ExpectedTags)
                        totalAttempted = $script:Report.Remediation.Attempted
                        totalSucceeded = $script:Report.Remediation.Succeeded
                        totalFailed    = $script:Report.Remediation.Failed
                        totalSkipped   = $script:Report.Remediation.Skipped
                    }
                    changes = @($script:ChangeLog)
                }
                try {
                    $logPayload | ConvertTo-Json -Depth 10 | Out-File -FilePath $changeLogPath -Encoding utf8 -Force
                    Write-Host ""
                    Show-Ok "Change log saved to: $changeLogPath"
                    Write-Host "           Every change is recorded with before/after state for audit." -ForegroundColor DarkGray
                    $script:Report.Remediation.ChangeLogPath = $changeLogPath
                } catch {
                    $fallbackLog = Join-Path $env:TEMP "TagRemediation_ChangeLog_$logTs.json"
                    $logPayload | ConvertTo-Json -Depth 10 | Out-File -FilePath $fallbackLog -Encoding utf8 -Force
                    Show-Warn "Could not write to working directory — log saved to: $fallbackLog"
                    $script:Report.Remediation.ChangeLogPath = $fallbackLog
                }
            }
        }
    } # end if ($adminApproval)
  } # end else (not DiagnosticOnly)
} # end if ($DiagnosticOnly) ... else

# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  STEP 8 — GENERATE HTML REPORT                                          ║
# ╚════════════════════════════════════════════════════════════════════════════╝

Show-Step 8 8 "Generating report"

if (-not $ReportPath) {
    $ts = Get-Date -Format "yyyyMMdd_HHmmss"
    $ReportPath = Join-Path (Get-Location) "PhishingTriageAgent_DiagnoseRemediate_$ts.html"
}

function To-HtmlTable($Data) {
    if (-not $Data -or ($Data | Measure-Object).Count -eq 0) { return "<p class='empty'>No data collected.</p>" }
    $rows = @($Data); $props = $rows[0].PSObject.Properties.Name
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append('<table><thead><tr>')
    foreach ($p in $props) { [void]$sb.Append("<th>$([System.Web.HttpUtility]::HtmlEncode($p))</th>") }
    [void]$sb.Append('</tr></thead><tbody>')
    foreach ($r in $rows | Select-Object -First 50) {
        [void]$sb.Append('<tr>')
        foreach ($p in $props) { [void]$sb.Append("<td>$([System.Web.HttpUtility]::HtmlEncode("$($r.$p)"))</td>") }
        [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</tbody></table>'); $sb.ToString()
}

# --- Build Affected Incidents table from $remediationCandidates ---
$affectedIncidentsHtml = ""
if ($remediationCandidates -and @($remediationCandidates).Count -gt 0) {
    $affectedIncidentsHtml = @"
<h3 style='margin-top:1.2rem'>&#128163; Affected Incidents &mdash; Tags Need Fixing ($(@($remediationCandidates).Count))</h3>
<p style='color:#64748b;font-size:.85rem;margin-bottom:.5rem'>These are the specific incidents where tags were stripped and need restoration.</p>
<table><thead><tr><th>Incident #</th><th>Title</th><th>Current Tags</th><th>Tags Missing</th><th>Tags After Fix</th><th>Last Modified By</th></tr></thead><tbody>
"@
    foreach ($rc in @($remediationCandidates) | Select-Object -First 50) {
        $currentStr  = if ($rc.CurrentTags -and @($rc.CurrentTags).Count -gt 0) { ($rc.CurrentTags -join ', ') } else { '(none)' }
        $missingStr  = if ($rc.MissingTags -and @($rc.MissingTags).Count -gt 0) { ($rc.MissingTags -join ', ') } else { '(none)' }
        $mergedTags  = @(@($rc.CurrentTags) + @($rc.MissingTags) | Select-Object -Unique)
        $afterStr    = if ($mergedTags.Count -gt 0) { ($mergedTags -join ', ') } else { '(none)' }
        $titleTrunc  = $safeTitle = if ([string]::IsNullOrEmpty($rc.Title)) { '(untitled)' } else { $rc.Title }
        $titleTrunc  = if ($safeTitle.Length -gt 60) { $safeTitle.Substring(0, 57) + '...' } else { $safeTitle }
        $modBy       = if ($rc.ModifiedBy) { $rc.ModifiedBy } else { 'Unknown' }
        $affectedIncidentsHtml += "<tr>" +
            "<td><strong>$([System.Web.HttpUtility]::HtmlEncode($rc.IncidentNumber))</strong></td>" +
            "<td>$([System.Web.HttpUtility]::HtmlEncode($titleTrunc))</td>" +
            "<td>$([System.Web.HttpUtility]::HtmlEncode($currentStr))</td>" +
            "<td style='color:var(--red);font-weight:600'>$([System.Web.HttpUtility]::HtmlEncode($missingStr))</td>" +
            "<td style='color:var(--grn);font-weight:600'>$([System.Web.HttpUtility]::HtmlEncode($afterStr))</td>" +
            "<td style='font-size:.78rem'>$([System.Web.HttpUtility]::HtmlEncode($modBy))</td></tr>"
    }
    $affectedIncidentsHtml += "</tbody></table>"
}

# --- Only CRITICAL and WARNING findings ---
$actionableFindings = @($script:Report.Findings | Where-Object { $_.Severity -eq 'CRITICAL' -or $_.Severity -eq 'WARNING' })
$findingsRows = ($actionableFindings | ForEach-Object {
    $cls = switch ($_.Severity) { "CRITICAL"{"critical"} "WARNING"{"warning"} default{"warning"} }
    "<tr><td><span class='badge $cls'>$($_.Severity)</span></td>" +
    "<td>$([System.Web.HttpUtility]::HtmlEncode($_.Title))</td>" +
    "<td>$([System.Web.HttpUtility]::HtmlEncode($_.Detail))</td></tr>"
}) -join "`n"

# --- Only KQL sections with results (Change Timeline = query only, no data table) ---
$kqlSections = foreach ($key in $script:Report.KQL.Keys) {
    $k = $script:Report.KQL[$key]
    if ($k.Count -gt 0) {
        $qEsc = [System.Web.HttpUtility]::HtmlEncode($k.Query)
        if ($key -eq "Change Timeline") {
            "<div class='kql'><h3>$key <span class='count'>($($k.Count) rows)</span></h3>" +
            "<details><summary>Show KQL query (copy to Sentinel &rarr; Logs)</summary><pre><code>$qEsc</code></pre></details>" +
            "<p style='color:#64748b;font-size:.85rem;margin:.5rem 0'>Run this query in <strong>Sentinel &rarr; Logs</strong> to see the full change timeline. Data table omitted from report to reduce noise.</p></div>"
        } else {
            $tbl = To-HtmlTable $k.Rows
            "<div class='kql'><h3>$key <span class='count'>($($k.Count) rows)</span></h3>" +
            "<details><summary>Show KQL query (copy to Sentinel &rarr; Logs)</summary><pre><code>$qEsc</code></pre></details>$tbl</div>"
        }
    }
}

$verdictCls = if ($critCount) {"critical"} elseif ($warnCount) {"warning"} else {"pass"}
$verdictIcon = if ($critCount) {"&#10060;"} elseif ($warnCount) {"&#9888;&#65039;"} else {"&#9989;"}

# Build executive summary narrative
$execNarrative = ""
$kqlTagsVanished = $script:Report.KQL["Tags Vanished"]
$kqlWhoRemoved   = $script:Report.KQL["Who Removed Tags"]

$vanishedCount = if ($kqlTagsVanished) { $kqlTagsVanished.Count } else { 0 }
$actorsWithStripping = @()
if ($kqlWhoRemoved -and $kqlWhoRemoved.Rows) {
    $actorsWithStripping = @($kqlWhoRemoved.Rows)
}

# Scope indicator text
$scopeText = if ($script:Report.IncidentIds -and $script:Report.IncidentIds.Trim()) {
    "Scoped to incident(s): <code>$([System.Web.HttpUtility]::HtmlEncode($script:Report.IncidentIds))</code>"
} else {
    "Scoped to <strong>all phishing incidents</strong> in workspace"
}

if ($critCount -gt 0) {
    $execNarrative = "This diagnostic <strong>confirms the customer's report</strong>. "
    if ($remediationCandidates -and @($remediationCandidates).Count -gt 0) {
        $execNarrative += "<strong>$(@($remediationCandidates).Count) incident(s)</strong> need tag restoration (see table below). "
    }
    if ($script:Report.IncidentStats.WithoutTags -gt 0) {
        $execNarrative += "<strong>$($script:Report.IncidentStats.WithoutTags)</strong> phishing incidents currently have <strong>zero tags</strong>. "
    }
    if ($vanishedCount -gt 0) {
        $execNarrative += "KQL analysis found <strong>$vanishedCount incidents</strong> that previously had tags but now have none. "
    }
    if ($actorsWithStripping.Count -gt 0) {
        $topActor = ($actorsWithStripping | Sort-Object { [int]$_.TagsRemoved } -Descending | Select-Object -First 1)
        $execNarrative += "The top actor removing tags is <strong>$([System.Web.HttpUtility]::HtmlEncode($topActor.ModifiedBy))</strong> ($([System.Web.HttpUtility]::HtmlEncode($topActor.TagsRemoved)) tags stripped across $([System.Web.HttpUtility]::HtmlEncode($topActor.Incidents)) incident(s)). "
    }
    $execNarrative += "This is <strong>expected behavior</strong> caused by Sentinel's PUT API overwriting the labels array. Re-run this script without <code>-DiagnosticOnly</code> to restore the missing tags."
} elseif ($warnCount -gt 0) {
    $execNarrative = "Agent activity was detected but tag removal is not yet confirmed as critical. Review the KQL results below to verify."
} else {
    $execNarrative = "No evidence of tag removal was found in the last <strong>$LookbackDays days</strong>. If the customer reports intermittent issues, try increasing the lookback window or checking a different workspace."
}

# Build "Who is Removing Tags" summary for executive section
$actorsSummaryHtml = ""
if ($actorsWithStripping.Count -gt 0) {
    $actorsSummaryHtml = "<h3 style='margin-top:1.2rem'>&#128373; Who is Removing Tags?</h3><table><thead><tr><th>Actor / Service</th><th>Updates That Removed Tags</th><th>Tags Stripped</th><th>Incidents Affected</th><th>Sample Removed Tags</th></tr></thead><tbody>"
    foreach ($a in ($actorsWithStripping | Sort-Object { [int]$_.TagsRemoved } -Descending | Select-Object -First 10)) {
        $sampleTags = if ($a.SampleRemoved) { [System.Web.HttpUtility]::HtmlEncode($a.SampleRemoved) } else { "-" }
        $actorsSummaryHtml += "<tr><td><strong>$([System.Web.HttpUtility]::HtmlEncode($a.ModifiedBy))</strong></td>" +
            "<td>$($a.TotalUpdates)</td><td style='color:var(--red)'>$($a.TagsRemoved)</td>" +
            "<td>$($a.Incidents)</td><td style='font-size:0.85em'>$sampleTags</td></tr>"
    }
    $actorsSummaryHtml += "</tbody></table>"
}

# Build non-zero stats grid items
$statsItems = [System.Collections.Generic.List[string]]::new()
if ($script:Report.IncidentStats.Phishing -gt 0) {
    $statsItems.Add("<div class='stat'><div class='n'>$($script:Report.IncidentStats.Phishing)</div><div class='l'>Phishing Incidents</div></div>")
}
if ($script:Report.IncidentStats.WithTags -gt 0) {
    $statsItems.Add("<div class='stat'><div class='n' style='color:var(--grn)'>$($script:Report.IncidentStats.WithTags)</div><div class='l'>&#9989; Have Tags</div></div>")
}
if ($script:Report.IncidentStats.WithoutTags -gt 0) {
    $statsItems.Add("<div class='stat'><div class='n' style='color:var(--red)'>$($script:Report.IncidentStats.WithoutTags)</div><div class='l'>&#10060; Tags Missing</div></div>")
}
if ($vanishedCount -gt 0) {
    $statsItems.Add("<div class='stat'><div class='n' style='color:var(--purple)'>$vanishedCount</div><div class='l'>&#128163; Tags Were Stripped (KQL)</div></div>")
}
$remData = $script:Report.Remediation
if ($remData.Attempted -gt 0 -and $remData.Succeeded -gt 0) {
    $statsItems.Add("<div class='stat'><div class='n' style='color:var(--grn)'>$($remData.Succeeded)</div><div class='l'>&#128736;&#65039; Tags Restored</div></div>")
}
$statsGridHtml = if ($statsItems.Count -gt 0) { "<div class='stats'>`n" + ($statsItems -join "`n") + "`n</div>" } else { "" }

# Build Activity Log section (only if there are results)
$activityLogHtml = ""
if ($script:Report.ActivityLog.Total -gt 0 -or $script:Report.ActivityLog.Agent -gt 0) {
    $activityLogHtml = @"
<details>
<summary>&#128220; Activity Log &mdash; Agent Writes (Total: $($script:Report.ActivityLog.Total) | Agent: $($script:Report.ActivityLog.Agent))</summary>
$(To-HtmlTable $script:Report.ActivityLog.Samples)
</details>
"@
}

# Build Remediation HTML section
$remediationHtml = ""
if ($DiagnosticOnly) {
    if ($remediationCandidates -and @($remediationCandidates).Count -gt 0) {
        $candidateCount = @($remediationCandidates).Count
        $totalMissingTags = ($remediationCandidates | ForEach-Object { @($_.MissingTags).Count } | Measure-Object -Sum).Sum
        $diagRemRows = ""
        foreach ($rc in @($remediationCandidates) | Select-Object -First 50) {
            $rcTitle = if ([string]::IsNullOrEmpty($rc.Title)) { '(untitled)' } else { $rc.Title }
            if ($rcTitle.Length -gt 60) { $rcTitle = $rcTitle.Substring(0, 57) + '...' }
            $rcMissing = if ($rc.MissingTags -and @($rc.MissingTags).Count -gt 0) { ($rc.MissingTags -join ', ') } else { '(none)' }
            $rcCurrent = if ($rc.CurrentTags -and @($rc.CurrentTags).Count -gt 0) { ($rc.CurrentTags -join ', ') } else { '(none)' }
            $diagRemRows += "<tr>" +
                "<td><strong>$([System.Web.HttpUtility]::HtmlEncode("$($rc.IncidentNumber)"))</strong></td>" +
                "<td>$([System.Web.HttpUtility]::HtmlEncode($rcTitle))</td>" +
                "<td style='color:var(--red)'>$([System.Web.HttpUtility]::HtmlEncode($rcMissing))</td>" +
                "<td>$([System.Web.HttpUtility]::HtmlEncode($rcCurrent))</td></tr>"
        }
        $remediationHtml = @"
<h2 id="remediation">&#128295; Remediation Summary</h2>
<div class="card">
<div class="stats">
<div class="stat"><div class="n" style="color:var(--red)">$candidateCount</div><div class="l">Incidents Need Tag Restoration</div></div>
<div class="stat"><div class="n">$totalMissingTags</div><div class="l">Tags to Restore</div></div>
</div>

<table>
<thead><tr><th>Incident #</th><th>Title</th><th>Missing Tags</th><th>Current Tags</th></tr></thead>
<tbody>$diagRemRows</tbody>
</table>

<div class="rc" style="margin-top:1rem;border-left-color:var(--amber);background:#fffbeb">
<strong>&#9889; How to Fix:</strong> Re-run this script <strong>without</strong> the <code>-DiagnosticOnly</code> flag to restore these tags:<br/>
<code style="display:block;margin:.5rem 0;padding:.5rem;background:#1e293b;color:#e2e8f0;border-radius:4px;font-size:.85rem">pwsh -ExecutionPolicy Bypass -File "Diagnose-And-Remediate-PhishingTriageAgentTags.ps1"</code>
<span style="font-size:.85rem;color:#64748b">The script will show all candidates and ask for approval before making any changes.</span>
</div>
</div>
"@
    } else {
        $remediationHtml = @"
<h2 id="remediation">&#128295; Remediation Summary</h2>
<div class="card">
<p class="empty"><strong>No remediation needed.</strong> All previously stripped tags have already been restored.</p>
</div>
"@
    }
} elseif ($remData.SkipReason -and $remData.Attempted -eq 0) {
    $remediationHtml = @"
<h2 id="remediation">&#128736;&#65039; Remediation Results</h2>
<div class="card">
<p class="empty"><strong>Remediation was not performed.</strong> Reason: $([System.Web.HttpUtility]::HtmlEncode($remData.SkipReason))</p>
</div>
"@
} elseif ($remData.Attempted -gt 0) {
    $remSuccessColor = if ($remData.Succeeded -gt 0) { "var(--grn)" } else { "#64748b" }
    $remFailColor    = if ($remData.Failed -gt 0) { "var(--red)" } else { "#64748b" }

    $remDetailRows = ""
    foreach ($d in $remData.Details) {
        $rowCls = switch ($d.Status) { "Success" { "rem-success" } "Failed" { "rem-failed" } default { "rem-skipped" } }
        $statusIcon = switch ($d.Status) { "Success" { "&#9989;" } "Failed" { "&#10060;" } default { "&#9197;" } }
        # Find matching candidate to show before/after
        $matchCandidate = $remediationCandidates | Where-Object { $_.IncidentNumber -eq $d.IncidentNumber } | Select-Object -First 1
        $beforeTags = if ($matchCandidate -and $matchCandidate.CurrentTags -and @($matchCandidate.CurrentTags).Count -gt 0) { ($matchCandidate.CurrentTags -join ', ') } else { '(none)' }
        $afterTags  = if ($matchCandidate) {
            $merged = @(@($matchCandidate.CurrentTags) + @($matchCandidate.MissingTags) | Select-Object -Unique)
            if ($merged.Count -gt 0) { ($merged -join ', ') } else { '(none)' }
        } else { $d.TagsRestored }
        $remDetailRows += "<tr class='$rowCls'>" +
            "<td><strong>$([System.Web.HttpUtility]::HtmlEncode($d.IncidentNumber))</strong></td>" +
            "<td>$([System.Web.HttpUtility]::HtmlEncode($beforeTags))</td>" +
            "<td style='color:var(--grn);font-weight:600'>$([System.Web.HttpUtility]::HtmlEncode($afterTags))</td>" +
            "<td>$statusIcon $([System.Web.HttpUtility]::HtmlEncode($d.Status))</td>" +
            "<td>$([System.Web.HttpUtility]::HtmlEncode($d.Error))</td></tr>"
    }

    $remNonZeroStats = [System.Collections.Generic.List[string]]::new()
    $remNonZeroStats.Add("<div class='stat'><div class='n'>$($remData.Attempted)</div><div class='l'>Attempted</div></div>")
    if ($remData.Succeeded -gt 0) { $remNonZeroStats.Add("<div class='stat'><div class='n' style='color:$remSuccessColor'>$($remData.Succeeded)</div><div class='l'>&#9989; Succeeded</div></div>") }
    if ($remData.Failed -gt 0) { $remNonZeroStats.Add("<div class='stat'><div class='n' style='color:$remFailColor'>$($remData.Failed)</div><div class='l'>&#10060; Failed</div></div>") }
    if ($remData.Skipped -gt 0) { $remNonZeroStats.Add("<div class='stat'><div class='n'>$($remData.Skipped)</div><div class='l'>&#9197; Skipped</div></div>") }

    $remediationHtml = @"
<h2 id="remediation">&#128736;&#65039; Remediation Results</h2>
<div class="card">
<div class="stats">
$($remNonZeroStats -join "`n")
</div>
<table>
<thead><tr><th>Incident #</th><th>Tags Before</th><th>Tags After</th><th>Status</th><th>Error</th></tr></thead>
<tbody>$remDetailRows</tbody>
</table>
$(if($remData.ChangeLogPath){
"<div class='rc' style='margin-top:1rem;border-left-color:var(--blu);background:#eff6ff'>
<strong>&#128221; Audit Trail:</strong> All changes were logged with before/after tag state to:<br/>
<code>$([System.Web.HttpUtility]::HtmlEncode($remData.ChangeLogPath))</code><br/>
<span style='font-size:.8rem;color:#64748b'>This JSON file contains timestamps, incident IDs, tags before/after, etag values, the operator identity, and any errors. Retain this file for your change management records.</span>
</div>"
})
</div>
"@
}

# Determine if there are any KQL sections to show
$hasKqlResults = $false
foreach ($key in $script:Report.KQL.Keys) {
    if ($script:Report.KQL[$key].Count -gt 0) { $hasKqlResults = $true; break }
}

$html = @"
<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"/>
<title>Phishing Triage Agent — Diagnose &amp; Remediate Report</title>
<style>
:root{--bg:#ffffff;--fg:#1e293b;--card:#f8fafc;--border:#e2e8f0;
--red:#dc2626;--yel:#d97706;--grn:#059669;--blu:#2563eb;--purple:#7c3aed}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--fg);padding:2rem;line-height:1.6;max-width:1200px;margin:0 auto}
h1{color:var(--blu);font-size:1.6rem;margin-bottom:.3rem}
h2{color:var(--fg);border-bottom:1px solid var(--border);padding-bottom:.4rem;margin:2.5rem 0 1rem;font-size:1.2rem}
h3{color:var(--blu);margin:1rem 0 .5rem;font-size:1rem}
.meta{color:#64748b;font-size:.85rem;margin-bottom:1.5rem}
.verdict{font-size:1.2rem;font-weight:700;padding:1rem 1.5rem;border-radius:8px;margin:1.5rem 0;text-align:center}
.verdict.critical{background:#fef2f2;color:var(--red);border:1px solid var(--red)}
.verdict.warning{background:#fffbeb;color:var(--yel);border:1px solid var(--yel)}
.verdict.pass{background:#f0fdf4;color:var(--grn);border:1px solid var(--grn)}
table{width:100%;border-collapse:collapse;margin:.8rem 0 1.2rem;font-size:.82rem}
th{background:#f1f5f9;color:var(--blu);text-align:left;padding:.45rem .6rem;border:1px solid var(--border)}
td{padding:.35rem .6rem;border:1px solid var(--border);vertical-align:top}
tr:nth-child(even) td{background:#f8fafc}
tr.rem-success td{background:#f0fdf4}
tr.rem-failed td{background:#fef2f2}
tr.rem-skipped td{background:#f8fafc;color:#64748b}
.badge{padding:2px 8px;border-radius:4px;font-weight:600;font-size:.72rem;text-transform:uppercase}
.badge.critical{background:#fef2f2;color:var(--red)}.badge.warning{background:#fffbeb;color:var(--yel)}
.badge.info{background:#eff6ff;color:var(--blu)}.badge.pass{background:#f0fdf4;color:var(--grn)}
details{margin:.5rem 0}summary{cursor:pointer;color:var(--blu);font-size:.85rem}
pre{background:#f8fafc;border:1px solid var(--border);padding:.8rem;overflow-x:auto;font-size:.78rem;border-radius:6px;margin-top:.4rem}
code{color:#1e293b;background:#f1f5f9;padding:1px 5px;border-radius:3px}
.card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:1.2rem 1.5rem;margin:1rem 0}
.rc{background:#fffbeb;border-left:4px solid var(--yel);padding:1rem 1.2rem;margin:1rem 0;border-radius:0 6px 6px 0}
.exec-summary{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:1.5rem 2rem;margin:1.5rem 0}
.exec-summary p{margin:.5rem 0;font-size:.95rem}
.quick-action{background:#eff6ff;border:1px solid var(--blu);border-radius:8px;padding:1rem 1.5rem;margin:1rem 0;display:flex;align-items:center;gap:.8rem}
.quick-action .icon{font-size:1.5rem;flex-shrink:0}
.quick-action .text{font-size:.9rem}
.quick-action .text strong{color:var(--blu)}
.num-circle{display:inline-flex;align-items:center;justify-content:center;width:26px;height:26px;border-radius:50%;background:var(--blu);color:#fff;font-weight:700;font-size:.8rem;margin-right:.6rem;flex-shrink:0}
.rec{display:flex;align-items:flex-start;margin:.9rem 0}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:.8rem;margin:1rem 0}
.stat{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:.8rem;text-align:center}
.stat .n{font-size:1.8rem;font-weight:700}.stat .l{font-size:.75rem;color:#64748b}
.kql{margin:1rem 0 1.5rem}.count{font-size:.8rem;color:#64748b;font-weight:400}
.empty{color:#64748b;font-style:italic}
ol.steps{margin:.5rem 0 0 1.2rem}ol.steps li{margin:.3rem 0}
.section-nav{display:flex;flex-wrap:wrap;gap:.5rem;margin:1rem 0}
.section-nav a{background:#f1f5f9;color:var(--blu);padding:.3rem .8rem;border-radius:4px;text-decoration:none;font-size:.8rem}
.section-nav a:hover{background:#e2e8f0}
.highlight-box{border:1px solid var(--red);border-radius:8px;padding:1rem;margin:.5rem 0;background:#fef2f2}
.toc-section{margin:.3rem 0}
.disclaimer{background:#fffbeb;border:1px solid #d97706;border-radius:6px;padding:.8rem 1rem;margin:.8rem 0;font-size:.78rem;color:#92400e}
.disclaimer strong{color:#b45309}
.limitations{background:#f0f9ff;border:1px solid var(--blu);border-radius:8px;padding:1rem 1.2rem;margin:1rem 0}
.limitations h3{color:var(--blu);margin:0 0 .5rem;font-size:.95rem}
.limitations ul{margin:.3rem 0 0 1.2rem;font-size:.85rem;color:#334155}
.limitations li{margin:.25rem 0}
.scope-badge{display:inline-block;background:#f1f5f9;border:1px solid var(--border);border-radius:4px;padding:2px 10px;font-size:.82rem;color:#475569;margin-top:.3rem}
</style></head><body>

<h1>&#128270; Phishing Triage Agent &mdash; Diagnose &amp; Remediate Report</h1>
<p class="meta">$($script:Report.RunTime) &bull; Subscription <code>$([System.Web.HttpUtility]::HtmlEncode($SubscriptionId))</code> &bull;
Workspace <code>$([System.Web.HttpUtility]::HtmlEncode($WorkspaceName))</code> &bull; Lookback: <strong>$LookbackDays days</strong>
$(if($script:Report.ExpectedTags){" &bull; Expected tags: <code>$([System.Web.HttpUtility]::HtmlEncode($script:Report.ExpectedTags))</code>"})
&bull; Mode: <strong>$(if($DiagnosticOnly){'Diagnostic Only'}elseif($AutoRemediate){'Auto-Remediate'}else{'Interactive'})</strong></p>

<div class="disclaimer">
<strong>&#9888;&#65039; DISCLAIMER:</strong> This report and associated scripts are provided <strong>&ldquo;AS IS&rdquo;</strong>
without warranty of any kind, express or implied. This is for <strong>educational and diagnostic
purposes only</strong> and is NOT an officially supported Microsoft tool or product.
$(if(-not $DiagnosticOnly -and $remData.Attempted -gt 0){
"<br/><strong>&#128736;&#65039; REMEDIATION WAS PERFORMED:</strong> $($remData.Attempted) incidents were modified ($($remData.Succeeded) succeeded, $($remData.Failed) failed). Tags were only ADDED; no existing tags were removed."
} else {
"The diagnostic script performed <strong>read-only</strong> operations against your Azure environment &mdash; no incidents, tags, or resources were modified."
})
Always review scripts before running them. The authors assume no liability for any damage or disruption.
</div>

<!-- ═══════ VERDICT ═══════ -->
<div class="verdict $verdictCls">$verdictIcon $($script:Report.Verdict)</div>

<!-- ═══════ LIMITATIONS ═══════ -->
<div class="limitations">
<h3>&#9888;&#65039; Known Limitations</h3>
<ul>
<li><strong>Data Retention:</strong> SecurityIncident table governed by workspace retention (default 90 days). Azure Activity Log capped at 90 days. Tags removed before the retention window <strong>cannot be recovered</strong>.</li>
<li><strong>Lookback Window:</strong> This report analyzed only the last <strong>$LookbackDays day(s)</strong>. Actual affected incidents may exceed what is shown.</li>
<li><strong>Agent Attribution:</strong> The agent is identified via <code>ModifiedBy</code> patterns (e.g., <code>SecurityCopilotAgent</code>, <code>Microsoft Defender XDR</code>). If Microsoft changes the agent identity string, detection may miss events.</li>
<li><strong>Tag Restoration Scope:</strong> Only tags specifically removed by the agent are restored. Tags intentionally removed by human analysts are <strong>not</strong> re-added.</li>
<li><strong>Concurrent Modifications:</strong> If an incident is modified between the diagnostic scan and remediation PUT, etag concurrency prevents blind overwrites. Conflicting writes trigger a retry, but rapid concurrent edits may still cause transient failures.</li>
<li><strong>Closed Incidents:</strong> Closed incidents require classification fields in the PUT body. The script preserves them from a fresh GET, but changes between GET and PUT are not merged.</li>
<li><strong>Pagination Caps:</strong> Incident scan: 10,000 max (50 pages). Remediation candidates: 500 per run. Re-run for additional incidents.</li>
<li><strong>Sovereign Clouds:</strong> API endpoints and versions target Azure public cloud. Government/sovereign clouds may require manual URI adjustments.</li>
<li><strong>Rate Limiting:</strong> The script includes retry with exponential backoff for HTTP 429/5xx, but large-scale remediation (500+ incidents) may still encounter throttling.</li>
<li><strong>PUT Semantics:</strong> Sentinel uses full-replace PUT. The script round-trips all writable properties from a fresh GET, but read-only fields are stripped. Unrecognized new fields may not be preserved.</li>
</ul>
</div>

<!-- ═══════ EXECUTIVE SUMMARY ═══════ -->
<div class="exec-summary">
<h2 style="margin-top:0;border:none;padding:0">&#128221; Executive Summary</h2>
<p class="scope-badge">&#127919; $scopeText</p>
<p>$execNarrative</p>

$statsGridHtml

$affectedIncidentsHtml

$actorsSummaryHtml
</div>

<!-- ═══════ QUICK ACTION ═══════ -->
$(if ($DiagnosticOnly -and $remediationCandidates -and @($remediationCandidates).Count -gt 0) {
@"
<div class="quick-action">
<div class="icon">&#9889;</div>
<div class="text">
<strong>$(@($remediationCandidates).Count) incident(s) need tag restoration.</strong> Re-run this script without <code>-DiagnosticOnly</code> to fix.
The script will show each candidate and ask for admin approval before making changes.
</div>
</div>
"@
} elseif (-not $DiagnosticOnly -and $remData.Attempted -gt 0) {
@"
<div class="quick-action">
<div class="icon">&#9989;</div>
<div class="text">
<strong>Remediation complete.</strong> See the <a href="#remediation" style="color:var(--blu)">Remediation Results</a> section for details.
</div>
</div>
"@
})

<!-- ═══════ TABLE OF CONTENTS ═══════ -->
<div class="section-nav">
<a href="#rootcause">&#128269; Root Cause</a>
$(if ($actionableFindings.Count -gt 0) { '<a href="#findings">&#9888;&#65039; Findings</a>' })
$(if ($hasKqlResults) { '<a href="#kql">&#128270; KQL Evidence</a>' })
<a href="#remediation">&#128295; Remediation</a>
</div>

<!-- ═══════ ROOT CAUSE ═══════ -->
<h2 id="rootcause">&#128269; Why Are Tags Disappearing?</h2>
<div class="rc">
<strong>Root Cause:</strong> The Sentinel <code>Incidents &ndash; Create Or Update</code> API uses
<strong>PUT (full-replace) semantics</strong>. When <em>any</em> service (including the Phishing Triage Agent)
updates an incident, the entire incident object is replaced.  If the <code>labels</code>
array is omitted or empty in the PUT body, <strong>all existing labels are deleted</strong>.<br/><br/>
The Defender XDR <code>PATCH /api/incidents</code> endpoint behaves similarly &mdash; it <strong>overwrites</strong> the
<code>tags</code> array rather than merging.  <strong>This is by-design API behavior, not a bug.</strong>
The agent is not intentionally removing tags; it simply doesn&rsquo;t preserve fields it didn&rsquo;t set.
</div>

<!-- ═══════ DETAILED FINDINGS ═══════ -->
$(if ($actionableFindings.Count -gt 0) {
@"
<h2 id="findings">&#9888;&#65039; Diagnostic Findings</h2>
<table><thead><tr><th style="width:90px">Severity</th><th>Finding</th><th>Detail</th></tr></thead>
<tbody>$findingsRows</tbody></table>
"@
})

$(if($script:Report.IncidentStats.TagDist){
"<details><summary>&#127991;&#65039; Tag Distribution (which tags exist on phishing incidents)</summary>" +
(To-HtmlTable $script:Report.IncidentStats.TagDist) + "</details>"
})

$(if($ExpectedTags -and $script:Report.IncidentStats.MissingExp){
$missingCount = ($script:Report.IncidentStats.MissingExp | Measure-Object).Count
"<details open><summary>&#127991;&#65039; Incidents Missing Expected Tags &mdash; $missingCount incident(s) lack <code>$($ExpectedTags -join ', ')</code></summary>" +
(To-HtmlTable $script:Report.IncidentStats.MissingExp) + "</details>"
})

<!-- ═══════ ACTIVITY LOG (only if results) ═══════ -->
$activityLogHtml

<!-- ═══════ KQL EVIDENCE ═══════ -->
$(if ($hasKqlResults) {
@"
<h2 id="kql">&#128270; KQL Evidence (Deep-Dive)</h2>
<p style="color:#64748b;font-size:.85rem;margin-bottom:.5rem">
These queries ran against your Log Analytics workspace. Expand any query to copy it into <strong>Sentinel &rarr; Logs</strong> for further investigation.
Only sections with results are shown.
</p>
$($kqlSections -join "`n")
"@
})

<!-- ═══════ REMEDIATION RESULTS ═══════ -->
$remediationHtml

<!-- ═══════ ERRORS ═══════ -->
$(if($script:Report.Errors.Count -gt 0){
"<details><summary>&#128679; Errors During Collection ($($script:Report.Errors.Count))</summary><ul style='margin:.5rem 0 0 1.2rem'>" +
($script:Report.Errors | ForEach-Object { "<li style='margin:.2rem 0'>$([System.Web.HttpUtility]::HtmlEncode($_))</li>" }) + "</ul></details>"
})

<hr style="border-color:var(--border);margin:2rem 0"/>
<div class="disclaimer">
<strong>&#9888;&#65039; DISCLAIMER:</strong> This report and all associated scripts are provided <strong>&ldquo;AS IS&rdquo;</strong>
without warranty of any kind, express or implied. They are for <strong>educational and
experimental purposes only</strong> and are NOT officially supported Microsoft tools or products.
Use at your own risk. The authors assume no liability for any damage, data loss, cost, or
disruption caused by using these scripts. Always review all code before running in your
environment. Test in non-production environments first.
</div>
<p class="meta" style="text-align:center;margin-top:.5rem">Generated by <strong>Diagnose-And-Remediate-PhishingTriageAgentTags.ps1</strong> &bull;
Share this report with your Microsoft support contact or SOC team.</p>
</body></html>
"@

try {
    $html | Out-File -FilePath $ReportPath -Encoding utf8 -Force
} catch {
    $fallback = Join-Path $env:TEMP "PhishingTriageAgent_DiagnoseRemediate_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    Write-Host "  ⚠  Could not write to $ReportPath — writing to $fallback" -ForegroundColor Yellow
    $html | Out-File -FilePath $fallback -Encoding utf8 -Force
    $ReportPath = $fallback
}

# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  DONE                                                                    ║
# ╚════════════════════════════════════════════════════════════════════════════╝

Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "  ║  Done! Report saved to:                                     ║" -ForegroundColor Green
Write-Host "  ║  $($ReportPath.PadRight(59))║" -ForegroundColor Green
Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "  Open it with:" -ForegroundColor White
Write-Host "    Start-Process `"$ReportPath`"" -ForegroundColor Cyan
Write-Host ""
