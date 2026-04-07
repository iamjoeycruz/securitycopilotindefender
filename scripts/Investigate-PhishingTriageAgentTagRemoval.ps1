<#
.SYNOPSIS
    Zero-config diagnostic for the Phishing Triage Agent tag-removal issue.
    Just run it — the script walks you through everything.

.DESCRIPTION
    Run with no parameters. The script will:
      1. Install any missing Az modules automatically.
      2. Log you in (or reuse your session).
      3. Let you pick your subscription and Sentinel workspace from a menu.
      4. Ask which tags your automation depends on.
      5. Run all diagnostics (Activity Log, Incident scan, KQL queries).
      6. Generate a one-click HTML report with findings + fix steps.

    WHAT THIS SCRIPT DOES (read-only):
      - Reads Azure Activity Log entries (read-only)
      - Reads Sentinel incident metadata via REST API (read-only)
      - Runs KQL queries against your Log Analytics workspace (read-only)
      - Generates an HTML report file on your local machine
      - Does NOT modify, create, or delete any Azure resources
      - Does NOT modify any Sentinel incidents, tags, or automation rules
      - Does NOT send data to any external service

.EXAMPLE
    .\Investigate-PhishingTriageAgentTagRemoval.ps1

    # Or skip the wizard by passing parameters directly:
    .\Investigate-PhishingTriageAgentTagRemoval.ps1 `
        -SubscriptionId "xxxx" -ResourceGroupName "rg" `
        -WorkspaceName "ws"   -ExpectedTags "Tag1","Tag2"

.NOTES
    DISCLAIMER: This script is provided "AS IS" without warranty of any kind,
    express or implied. This is for educational and diagnostic purposes only.
    It is NOT an officially supported Microsoft tool. Use at your own risk.
    Always review scripts before running them in your environment. The authors
    assume no liability for any damage or disruption caused by using this script.
    Test in a non-production environment first when possible.
#>

[CmdletBinding()]
param(
    [string]$SubscriptionId,
    [string]$ResourceGroupName,
    [string]$WorkspaceName,
    [string[]]$ExpectedTags,
    [int]$LookbackDays = 7,
    [string]$ReportPath
)

#Requires -Version 7.0

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
    Write-Host "  ║   Phishing Triage Agent — Tag Removal Diagnostic            ║" -ForegroundColor Cyan
    Write-Host "  ║   Detects if the agent is stripping Sentinel incident tags   ║" -ForegroundColor Cyan
    Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
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
    Errors           = [System.Collections.Generic.List[string]]::new()
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
Show-Step 1 6 "Checking prerequisites"

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

Show-Step 2 6 "Connecting to Azure"

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

Show-Step 3 6 "Finding Sentinel workspaces"

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
                # Fallback: try listing an incident — if it works, Sentinel is enabled
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

Show-Step 4 6 "Gathering tag info"

if (-not $ExpectedTags) {
    # Try to auto-discover common tags from a small sample via REST API (fast)
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
        Write-Host "  Enter the numbers of tags your automation depends on" -ForegroundColor Yellow
        Write-Host "  (comma-separated, e.g. 1,3,5) or type custom tag names." -ForegroundColor Yellow
        Write-Host "  Press Enter to skip." -ForegroundColor DarkGray
        $input_tags = Read-Host "  Selection"

        if ($input_tags -match '^\s*$') {
            $ExpectedTags = @()
            Show-Info "No expected tags specified — will scan all tags"
        } elseif ($input_tags -match '^\d[\d,\s]*$') {
            $indices = $input_tags -split '[,\s]+' | ForEach-Object { [int]$_ - 1 }
            $ExpectedTags = @($indices | Where-Object { $_ -ge 0 -and $_ -lt $discoveredTags.Count } |
                ForEach-Object { $discoveredTags[$_] })
            Show-Ok "Selected: $($ExpectedTags -join ', ')"
        } else {
            $ExpectedTags = @($input_tags -split '[,;]+' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            Show-Ok "Custom tags: $($ExpectedTags -join ', ')"
        }
    } else {
        Write-Host ""
        Write-Host "  Enter the tag names your automation depends on" -ForegroundColor Yellow
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

# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  STEP 5 — RUN DIAGNOSTICS                                               ║
# ╚════════════════════════════════════════════════════════════════════════════╝

Show-Step 5 6 "Running diagnostics (this may take a minute)"

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

# ── 5b. Incident Scan (uses REST API with pagination cap for speed) ──────────
Write-Host ""
Write-Host "  [5b] Sentinel incident scan ..." -ForegroundColor White

try {
    # Sentinel OData $filter doesn't support 'contains' on title — so we fetch
    # recent incidents (capped) and filter client-side. $top + $orderby keeps it fast.
    $incBaseUri = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName" +
        "/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName" +
        "/providers/Microsoft.SecurityInsights/incidents?api-version=2024-03-01" +
        "&`$top=200&`$orderby=properties/createdTimeUtc desc"

    Write-Host "    Fetching recent incidents via REST API (max 1000)..." -ForegroundColor DarkGray
    $allIncRaw = [System.Collections.Generic.List[object]]::new()
    $nextUri = $incBaseUri
    $pageCount = 0
    do {
        $resp = Invoke-AzRestMethod -Method GET -Path $nextUri -ErrorAction Stop
        $data = $resp.Content | ConvertFrom-Json
        if ($data.value) { $data.value | ForEach-Object { $allIncRaw.Add($_) } }
        $nextUri = $data.nextLink
        $pageCount++
        Write-Host "    Page $pageCount — $($allIncRaw.Count) incidents loaded..." -ForegroundColor DarkGray
    } while ($nextUri -and $pageCount -lt 5)  # cap at ~1000 incidents

    Write-Host "    Filtering for phishing-related incidents..." -ForegroundColor DarkGray

    # Client-side filter for phishing-related incidents
    $phishRaw = @($allIncRaw | Where-Object {
        $_.properties.title -match "phish|user.reported|submission" -or
        $_.properties.classification -match "phish" -or
        $_.properties.description -match "phish"
    })

    # Normalize to PSCustomObjects
    $phish = @($phishRaw | ForEach-Object {
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

    $withTags    = @($phish | Where-Object { $_.Label -and $_.Label.Count -gt 0 })
    $withoutTags = @($phish | Where-Object { -not $_.Label -or $_.Label.Count -eq 0 })

    $tagDist = @($phish | ForEach-Object { $_.Label.LabelName } |
                 Where-Object { $_ } | Group-Object | Sort-Object Count -Descending |
                 Select-Object Name, Count)

    $missingExpected = @()
    if ($ExpectedTags.Count -gt 0) {
        $missingExpected = @($phish | Where-Object {
            $labels = @($_.Label.LabelName)
            ($ExpectedTags | Where-Object { $_ -notin $labels }).Count -gt 0
        } | Select-Object -First 30 IncidentNumber,
            @{N='Title';E={if($_.Title.Length -gt 55){$_.Title.Substring(0,55)+"..."}else{$_.Title}}},
            @{N='CurrentTags';E={($_.Label.LabelName -join ", ") -replace '^$','(none)'}},
            Status, LastModifiedTimeUtc)
    }

    $script:Report.IncidentStats = @{
        Total        = $allIncRaw.Count
        Phishing     = $phish.Count
        WithTags     = $withTags.Count
        WithoutTags  = $withoutTags.Count
        TagDist      = $tagDist
        MissingExp   = $missingExpected
    }

    Write-Host "    Total: $($allIncRaw.Count)  Phishing: $($phish.Count)  " -NoNewline
    Write-Host "With tags: $($withTags.Count)  " -ForegroundColor Green -NoNewline
    Write-Host "Without: $($withoutTags.Count)" -ForegroundColor $(if($withoutTags.Count){'Red'}else{'Green'})

    if ($withoutTags.Count -gt 0) {
        $pct = [math]::Round(($withoutTags.Count / [math]::Max($phish.Count,1)) * 100, 1)
        Add-Finding "CRITICAL" "$($withoutTags.Count) phishing incidents have NO tags ($pct%)" `
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
} catch {
    $script:Report.Errors.Add("Incident scan: $_")
    Show-Warn "Incident scan failed — continuing"
}

# ── 5c. KQL Queries ────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  [5c] KQL deep-dive ..." -ForegroundColor White

$kqlQueries = [ordered]@{
    "Tags Vanished" = @"
SecurityIncident
| where TimeGenerated >= ago(${LookbackDays}d)
| where Title has_any ("phish","user reported","submission") or Classification has "phish"
| extend LabelCount = array_length(Labels), LabelsJson = tostring(Labels)
| summarize FirstTime=min(TimeGenerated), LastTime=max(TimeGenerated),
            Updates=count(), MaxLabels=max(LabelCount)
    by IncidentNumber, Title
| join kind=inner (
    SecurityIncident
    | where TimeGenerated >= ago(${LookbackDays}d)
    | summarize arg_max(TimeGenerated, Labels) by IncidentNumber
    | extend LastLabelCnt = array_length(Labels), LastLabels = tostring(Labels)
) on IncidentNumber
| where MaxLabels > 0 and LastLabelCnt == 0
| project IncidentNumber, Title, FirstTime, LastTime, Updates,
          TagsAtPeak=MaxLabels, TagsNow=LastLabelCnt
| order by LastTime desc
"@
    "Who Removed Tags" = @"
SecurityIncident
| where TimeGenerated >= ago(${LookbackDays}d)
| where Title has_any ("phish","user reported","submission") or Classification has "phish"
| extend LabelCount = array_length(Labels)
| where isnotempty(ModifiedBy)
| summarize TotalUpdates=count(), NoTagUpdates=countif(LabelCount==0),
            WithTagUpdates=countif(LabelCount>0), Incidents=dcount(IncidentNumber),
            SampleIds=make_set(IncidentNumber,5) by ModifiedBy
| extend TagRemovalPct = round(100.0 * NoTagUpdates / TotalUpdates, 1)
| order by NoTagUpdates desc
"@
    "Agent Correlation" = @"
let Phish = SecurityIncident
| where TimeGenerated >= ago(${LookbackDays}d)
| where Title has_any ("phish","user reported","submission") or Classification has "phish"
| extend LabelCount = array_length(Labels), LabelsJson = tostring(Labels);
let HadTags = Phish | where LabelCount > 0
| summarize When=min(TimeGenerated), Tags=take_any(LabelsJson), Cnt=take_any(LabelCount) by IncidentNumber;
let LostTags = Phish | where LabelCount == 0
| where ModifiedBy has_any ("Copilot","Security Copilot","Threat Protection","SecurityInsights","MTP","WindowsDefenderATP")
| summarize StrippedAt=min(TimeGenerated), Actor=take_any(ModifiedBy) by IncidentNumber;
HadTags | join kind=inner LostTags on IncidentNumber
| project IncidentNumber, OriginalTags=Tags, OriginalCount=Cnt, StrippedAt, Actor
| order by StrippedAt desc
"@
    "Change Timeline" = @"
SecurityIncident
| where TimeGenerated >= ago(${LookbackDays}d)
| where Title has_any ("phish","user reported","submission") or Classification has "phish"
| extend LabelCount = array_length(Labels), LabelsJson = tostring(Labels)
| project TimeGenerated, IncidentNumber, Title, Status, ModifiedBy, LabelCount, LabelsJson
| order by IncidentNumber asc, TimeGenerated asc
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
                        if ([int]$row.NoTagUpdates -gt 0) {
                            Add-Finding "WARNING" `
                                "'$($row.ModifiedBy)' left $($row.NoTagUpdates) incidents tagless" `
                                "$($row.TotalUpdates) total updates, $($row.TagRemovalPct)% resulted in no tags."
                        }
                    }
                }
                "Agent Correlation" {
                    if ($count -gt 0) {
                        Add-Finding "CRITICAL" `
                            "Direct match: agent update → tag removal ($count incidents)" `
                            "Agent identity was last modifier when tags vanished."
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

# ── 5d. Verdict ─────────────────────────────────────────────────────────────
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
# ║  STEP 6 — GENERATE HTML REPORT                                          ║
# ╚════════════════════════════════════════════════════════════════════════════╝

Show-Step 6 6 "Generating report"

if (-not $ReportPath) {
    $ts = Get-Date -Format "yyyyMMdd_HHmmss"
    $ReportPath = Join-Path (Get-Location) "PhishingTriageAgent_Report_$ts.html"
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

$findingsRows = ($script:Report.Findings | ForEach-Object {
    $cls = switch ($_.Severity) { "CRITICAL"{"critical"} "WARNING"{"warning"} "PASS"{"pass"} default{"info"} }
    "<tr><td><span class='badge $cls'>$($_.Severity)</span></td>" +
    "<td>$([System.Web.HttpUtility]::HtmlEncode($_.Title))</td>" +
    "<td>$([System.Web.HttpUtility]::HtmlEncode($_.Detail))</td></tr>"
}) -join "`n"

$kqlSections = foreach ($key in $script:Report.KQL.Keys) {
    $k = $script:Report.KQL[$key]
    $qEsc = [System.Web.HttpUtility]::HtmlEncode($k.Query)
    $tbl = To-HtmlTable $k.Rows
    "<div class='kql'><h3>$key <span class='count'>($($k.Count) rows)</span></h3>" +
    "<details><summary>Show KQL query (copy to Sentinel &rarr; Logs)</summary><pre><code>$qEsc</code></pre></details>$tbl</div>"
}

$verdictCls = if ($critCount) {"critical"} elseif ($warnCount) {"warning"} else {"pass"}
$verdictIcon = if ($critCount) {"&#10060;"} elseif ($warnCount) {"&#9888;&#65039;"} else {"&#9989;"}

# Build executive summary narrative
$execNarrative = ""
$kqlTagsVanished = $script:Report.KQL["Tags Vanished"]
$kqlWhoRemoved   = $script:Report.KQL["Who Removed Tags"]
$kqlTimeline     = $script:Report.KQL["Change Timeline"]

$vanishedCount = if ($kqlTagsVanished) { $kqlTagsVanished.Count } else { 0 }
$actorsWithStripping = @()
if ($kqlWhoRemoved -and $kqlWhoRemoved.Rows) {
    $actorsWithStripping = @($kqlWhoRemoved.Rows | Where-Object {
        [int]$_.NoTagUpdates -gt 0
    })
}

if ($critCount -gt 0) {
    $execNarrative = "This diagnostic <strong>confirms the customer's report</strong>. "
    if ($script:Report.IncidentStats.WithoutTags -gt 0) {
        $execNarrative += "<strong>$($script:Report.IncidentStats.WithoutTags)</strong> phishing incidents currently have <strong>zero tags</strong>. "
    }
    if ($vanishedCount -gt 0) {
        $execNarrative += "KQL analysis found <strong>$vanishedCount incidents</strong> that previously had tags but now have none. "
    }
    if ($actorsWithStripping.Count -gt 0) {
        $topActor = ($actorsWithStripping | Sort-Object { [int]$_.NoTagUpdates } -Descending | Select-Object -First 1)
        $execNarrative += "The top actor removing tags is <strong>$($topActor.ModifiedBy)</strong> ($($topActor.TagRemovalPct)% of its updates strip tags). "
    }
    $execNarrative += "This is <strong>expected behavior</strong> caused by Sentinel's PUT API overwriting the labels array. See the <strong>Recommended Actions</strong> section below for fixes."
} elseif ($warnCount -gt 0) {
    $execNarrative = "Agent activity was detected but tag removal is not yet confirmed as critical. Review the KQL results below to verify. Proactively implementing a tag-restoration playbook is recommended."
} else {
    $execNarrative = "No evidence of tag removal was found in the last <strong>$LookbackDays days</strong>. If the customer reports intermittent issues, try increasing the lookback window or checking a different workspace."
}

# Build "Who is Removing Tags" summary for executive section
$actorsSummaryHtml = ""
if ($actorsWithStripping.Count -gt 0) {
    $actorsSummaryHtml = "<h3 style='margin-top:1.2rem'>&#128373; Who is Removing Tags?</h3><table><thead><tr><th>Actor / Service</th><th>Total Updates</th><th>Updates That Stripped Tags</th><th>Tag Removal Rate</th><th>Incidents Affected</th></tr></thead><tbody>"
    foreach ($a in ($actorsWithStripping | Sort-Object { [int]$_.NoTagUpdates } -Descending | Select-Object -First 10)) {
        $pctColor = if ([double]$a.TagRemovalPct -ge 50) { "var(--red)" } elseif ([double]$a.TagRemovalPct -ge 20) { "var(--yel)" } else { "var(--grn)" }
        $actorsSummaryHtml += "<tr><td><strong>$([System.Web.HttpUtility]::HtmlEncode($a.ModifiedBy))</strong></td>" +
            "<td>$($a.TotalUpdates)</td><td style='color:var(--red)'>$($a.NoTagUpdates)</td>" +
            "<td style='color:$pctColor;font-weight:600'>$($a.TagRemovalPct)%</td>" +
            "<td>$($a.Incidents)</td></tr>"
    }
    $actorsSummaryHtml += "</tbody></table>"
}

# Build "Impacted Incidents" table for executive summary
$impactedIncidentsHtml = ""
if ($kqlTagsVanished -and $kqlTagsVanished.Count -gt 0) {
    $impactedIncidentsHtml = @"
<h3 style='margin-top:1.2rem'>&#128163; Incidents With Tags Stripped (Confirmed by KQL)</h3>
<p style='color:#64748b;font-size:.85rem;margin-bottom:.5rem'>These incidents <strong>had tags</strong> at some point but currently have <strong>zero tags</strong>. This is your evidence that tag stripping is occurring.</p>
<table><thead><tr><th>Incident #</th><th>Title</th><th>Tags At Peak</th><th>Tags Now</th><th>Updates</th><th>Last Modified</th></tr></thead><tbody>
"@
    foreach ($row in $kqlTagsVanished.Rows | Select-Object -First 25) {
        $impactedIncidentsHtml += "<tr><td><strong>$([System.Web.HttpUtility]::HtmlEncode($row.IncidentNumber))</strong></td>" +
            "<td>$([System.Web.HttpUtility]::HtmlEncode($row.Title))</td>" +
            "<td style='color:var(--grn)'>$($row.TagsAtPeak)</td>" +
            "<td style='color:var(--red);font-weight:700'>$($row.TagsNow)</td>" +
            "<td>$($row.Updates)</td>" +
            "<td style='font-size:.78rem'>$($row.LastTime)</td></tr>"
    }
    $impactedIncidentsHtml += "</tbody></table>"
}

# Build Activity Log note
$activityNote = ""
if ($script:Report.ActivityLog.Total -eq 0 -and $script:Report.ActivityLog.Agent -eq 0) {
    $activityNote = "<p class='empty'><strong>Note:</strong> The Activity Log may show 0 writes if the agent uses internal service identities that are not tracked in the Azure Activity Log. The KQL analysis above is the more reliable data source for detecting tag removal.</p>"
}

$html = @"
<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"/>
<title>Phishing Triage Agent Diagnostic Report</title>
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
</style></head><body>

<h1>&#128270; Phishing Triage Agent &mdash; Tag Removal Diagnostic Report</h1>
<p class="meta">$($script:Report.RunTime) &bull; Subscription <code>$SubscriptionId</code> &bull;
Workspace <code>$WorkspaceName</code> &bull; Lookback: <strong>$LookbackDays days</strong>
$(if($script:Report.ExpectedTags){" &bull; Expected tags: <code>$($script:Report.ExpectedTags)</code>"})</p>

<div class="disclaimer">
<strong>&#9888;&#65039; DISCLAIMER:</strong> This report and associated scripts are provided <strong>&ldquo;AS IS&rdquo;</strong>
without warranty of any kind, express or implied. This is for <strong>educational and diagnostic
purposes only</strong> and is NOT an officially supported Microsoft tool or product.
The diagnostic script performed <strong>read-only</strong> operations against your Azure environment &mdash;
no incidents, tags, or resources were modified. Always review scripts before running them.
The authors assume no liability for any damage or disruption. Test in non-production environments first.
</div>

<!-- ═══════ VERDICT ═══════ -->
<div class="verdict $verdictCls">$verdictIcon $($script:Report.Verdict)</div>

<!-- ═══════ EXECUTIVE SUMMARY ═══════ -->
<div class="exec-summary">
<h2 style="margin-top:0;border:none;padding:0">&#128221; Executive Summary</h2>
<p>$execNarrative</p>

<div class="stats">
<div class="stat"><div class="n">$($script:Report.IncidentStats.Total)</div><div class="l">Total Incidents Scanned</div></div>
<div class="stat"><div class="n">$($script:Report.IncidentStats.Phishing)</div><div class="l">Phishing Related</div></div>
<div class="stat"><div class="n" style="color:var(--grn)">$($script:Report.IncidentStats.WithTags)</div><div class="l">&#9989; Have Tags</div></div>
<div class="stat"><div class="n" style="color:var(--red)">$($script:Report.IncidentStats.WithoutTags)</div><div class="l">&#10060; Tags Missing</div></div>
$(if ($vanishedCount -gt 0) {
"<div class='stat'><div class='n' style='color:var(--purple)'>$vanishedCount</div><div class='l'>&#128163; Tags Were Stripped (KQL)</div></div>"
})
</div>

$actorsSummaryHtml

$impactedIncidentsHtml
</div>

<!-- ═══════ QUICK ACTION ═══════ -->
$(if ($critCount -gt 0) {
@"
<div class="quick-action">
<div class="icon">&#9889;</div>
<div class="text">
<strong>Fastest Fix:</strong> Deploy a tag-restoration Automation Rule (see <a href="#fix" style="color:var(--blu)">Step 1 below</a>).
This auto-heals stripped tags within seconds and requires no changes to your existing automation.
</div>
</div>
"@
})

<!-- ═══════ TABLE OF CONTENTS ═══════ -->
<div class="section-nav">
<a href="#rootcause">&#128269; Root Cause</a>
<a href="#findings">&#9888;&#65039; Findings</a>
<a href="#kql">&#128270; KQL Evidence</a>
<a href="#fix">&#9989; How to Fix</a>
<a href="#playbook">&#128736;&#65039; Deploy Fix</a>
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
<h2 id="findings">&#9888;&#65039; Diagnostic Findings</h2>
<table><thead><tr><th style="width:90px">Severity</th><th>Finding</th><th>Detail</th></tr></thead>
<tbody>$findingsRows</tbody></table>

$(if($script:Report.IncidentStats.TagDist){
"<details><summary>&#127991;&#65039; Tag Distribution (which tags exist on phishing incidents)</summary>" +
(To-HtmlTable $script:Report.IncidentStats.TagDist) + "</details>"
})

$(if($ExpectedTags -and $script:Report.IncidentStats.MissingExp){
$missingCount = ($script:Report.IncidentStats.MissingExp | Measure-Object).Count
"<details open><summary>&#127991;&#65039; Incidents Missing Expected Tags &mdash; $missingCount incident(s) lack <code>$($ExpectedTags -join ', ')</code></summary>" +
(To-HtmlTable $script:Report.IncidentStats.MissingExp) + "</details>"
})

<!-- ═══════ ACTIVITY LOG ═══════ -->
<details>
<summary>&#128220; Activity Log &mdash; Agent Writes (Total: $($script:Report.ActivityLog.Total) | Agent: $($script:Report.ActivityLog.Agent))</summary>
$activityNote
$(To-HtmlTable $script:Report.ActivityLog.Samples)
</details>

<!-- ═══════ KQL EVIDENCE ═══════ -->
<h2 id="kql">&#128270; KQL Evidence (Deep-Dive)</h2>
<p style="color:#64748b;font-size:.85rem;margin-bottom:.5rem">
These queries ran against your Log Analytics workspace. Expand any query to copy it into <strong>Sentinel &rarr; Logs</strong> for further investigation.
</p>
$($kqlSections -join "`n")

<!-- ═══════ HOW TO FIX ═══════ -->
<h2 id="fix">&#9989; Recommended Actions</h2>
<div class="card">

<p style="color:#64748b;margin-bottom:1rem">Listed in order of effectiveness. Action 1 alone will resolve the immediate issue.</p>

<div class="rec"><span class="num-circle">1</span><div>
<strong>Deploy a Tag-Restoration Automation Rule (Immediate Fix)</strong><br/>
Create an Automation Rule in <em>Sentinel &rarr; Automation</em> that triggers on <strong>Incident Updated</strong> and runs a Logic App / Playbook:
<ol class="steps">
<li><strong>GET</strong> the incident to read current labels.</li>
<li><strong>Compare</strong> against your required tags (e.g., <code>AutoRemediate</code>, <code>PhishingReview</code>).</li>
<li>If any are missing, <strong>PUT</strong> the incident back with the full merged label set.</li>
</ol>
This auto-heals tags <strong>within seconds</strong> of removal. See the <a href="#playbook" style="color:var(--blu)">sample playbook</a> below.
</div></div>

<div class="rec"><span class="num-circle">2</span><div>
<strong>Re-prioritize Automation Rules</strong><br/>
In <em>Sentinel &rarr; Automation</em>, give your tag-dependent rules a <strong>lower priority number</strong>
(= higher priority) so they execute <strong>before</strong> the Phishing Triage Agent runs.
This ensures your automation reads tags before they get stripped.
</div></div>

<div class="rec"><span class="num-circle">3</span><div>
<strong>Move Automation Triggers to Immutable Properties</strong><br/>
Tags are fragile because any PUT can overwrite them. More reliable trigger options:
<ul style="margin:.4rem 0 0 1.2rem">
<li><strong>Incident classification / determination</strong> &mdash; set by the agent, never cleared.</li>
<li><strong>Alert product name</strong> &mdash; immutable after creation.</li>
<li><strong>Incident comments</strong> &mdash; append-only, never overwritten.</li>
</ul>
</div></div>

<div class="rec"><span class="num-circle">4</span><div>
<strong>Use Sentinel Watchlists for Automation Flags</strong><br/>
Store automation flags in a <a href="https://learn.microsoft.com/azure/sentinel/watchlists" style="color:var(--blu)">Watchlist</a>
keyed by Incident ID. Playbooks query the watchlist instead of relying on tags. Tags can be informational only.
</div></div>

<div class="rec"><span class="num-circle">5</span><div>
<strong>File Feedback with Microsoft</strong><br/>
Request &ldquo;protected tags&rdquo; or merge-style tag semantics via the
<a href="https://feedbackportal.microsoft.com/feedback/forum/ad198462-1c1c-ec11-b6e7-0022481f8472" style="color:var(--blu)">Defender Feedback Portal</a>.
This would prevent the issue at the platform level.
</div></div>

</div>

<!-- ═══════ SAMPLE PLAYBOOK ═══════ -->
<h2 id="playbook">&#128736;&#65039; Deploy the Fix</h2>
<div class="card">

<h3>Option A: One-Click Deploy to Azure (Recommended)</h3>
<p style="margin-bottom:.8rem">Click the button below to deploy the tag-restoration Logic App directly from GitHub:</p>
<p style="text-align:center;margin:1rem 0">
<a href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fiamjoeycruz%2Fsecuritycopilotindefender%2Fmain%2Fremediation%2Frestore-sentinel-incident-tags%2Fazuredeploy.json"
   style="display:inline-block;background:#0078d4;color:#fff;padding:.6rem 1.5rem;border-radius:6px;text-decoration:none;font-weight:600;font-size:.95rem">
&#9729;&#65039; Deploy to Azure
</a>
</p>
<p style="color:#64748b;font-size:.85rem">
Source: <a href="https://github.com/iamjoeycruz/securitycopilotindefender/tree/main/remediation/restore-sentinel-incident-tags" style="color:var(--blu)">github.com/iamjoeycruz/securitycopilotindefender</a>
</p>

<p style="margin-top:.8rem"><strong>Fill in these parameters:</strong></p>
<table style="width:auto;font-size:.85rem">
<tr><td><strong>Resource Group</strong></td><td>Same resource group as your Sentinel workspace (<code>$ResourceGroupName</code>)</td></tr>
<tr><td><strong>Playbook Name</strong></td><td><code>Restore-SentinelIncidentTags</code> (default)</td></tr>
<tr><td><strong>Required Tags</strong></td><td><code>$(if($ExpectedTags){$ExpectedTags -join ','}else{'AutoRemediate,PhishingReview'})</code></td></tr>
</table>

<h3>Option B: Azure CLI</h3>
<pre><code>az deployment group create \
  --resource-group "$ResourceGroupName" \
  --template-uri "https://raw.githubusercontent.com/iamjoeycruz/securitycopilotindefender/main/remediation/restore-sentinel-incident-tags/azuredeploy.json" \
  --parameters RequiredTags="$(if($ExpectedTags){$ExpectedTags -join ','}else{'AutoRemediate,PhishingReview'})"</code></pre>

<h3 style="margin-top:1.5rem">Post-Deployment Steps (Required)</h3>
<ol class="steps" style="margin-left:1.2rem">
<li><strong>Authorize the API Connection:</strong> Azure Portal &rarr; Resource Group &rarr; open <code>azuresentinel-Restore-*</code> &rarr; Edit API connection &rarr; Authorize &rarr; Save</li>
<li><strong>Grant RBAC:</strong> Log Analytics Workspace &rarr; Access control (IAM) &rarr; Add role assignment &rarr; <strong>Microsoft Sentinel Responder</strong> &rarr; Managed Identity &rarr; Logic App &rarr; <code>Restore-SentinelIncidentTags</code></li>
<li><strong>Create Automation Rule:</strong> Sentinel &rarr; Automation &rarr; Create &rarr;
  <ul>
    <li>Trigger: <em>When incident is updated</em></li>
    <li>Condition: <em>Incident provider contains Microsoft 365 Defender</em> (or leave blank for all)</li>
    <li>Action: <em>Run playbook &rarr; Restore-SentinelIncidentTags</em></li>
    <li>Order: <code>100</code></li>
  </ul>
</li>
</ol>

<h3>What the Playbook Does</h3>
<pre><code>Trigger:  Sentinel Automation Rule fires on "Incident Updated"
          &darr;
Step 1:   GET /incidents/{id} &mdash; reads the full incident with current labels
          &darr;
Step 2:   Compare current labels against your required tags list
          (e.g., $(if($ExpectedTags){$ExpectedTags -join ', '}else{'AutoRemediate, PhishingReview'}))
          &darr;
Step 3:   IF any required tags are missing:
            - Merge: current labels &cup; missing tags
            - PUT /incidents/{id} with etag &mdash; writes the full label set back
            - Log: "Restored [missing tags]"
          ELSE:
            - Log: "Tags intact, no action needed"</code></pre>
<p style="color:#64748b;font-size:.85rem;margin-top:.5rem">Uses <strong>System Managed Identity</strong> (no credentials). The <code>etag</code> header prevents race conditions. Cost: &lt; &#36;1/month.</p>

<h3>After Deployment — Verify It Works</h3>
<ol class="steps" style="margin-left:1.2rem">
<li>Open any phishing incident in Sentinel</li>
<li>Manually remove a required tag (e.g., <code>AutoRemediate</code>)</li>
<li>Wait ~30 seconds and refresh &mdash; the tag should reappear</li>
<li>Check the Logic App <strong>Run History</strong> to confirm the playbook fired</li>
</ol>

<h3>What Gets Deployed to Your Environment</h3>
<table style="font-size:.82rem">
<thead><tr><th>Resource</th><th>Type</th><th>Purpose</th><th>Cost</th></tr></thead>
<tbody>
<tr><td><code>Restore-SentinelIncidentTags</code></td><td>Logic App (Consumption)</td><td>Runs on each incident update to check and restore tags</td><td>~&#36;0.000025/action; typically &lt; &#36;1/month</td></tr>
<tr><td><code>azuresentinel-Restore-*</code></td><td>API Connection</td><td>Connects Logic App to Sentinel trigger webhook</td><td>Free</td></tr>
<tr><td>RBAC Assignment</td><td>Role Assignment</td><td>Grants Logic App &ldquo;Sentinel Responder&rdquo; to read/write incidents</td><td>Free</td></tr>
<tr><td>Automation Rule</td><td>Sentinel Automation Rule</td><td>Triggers the Logic App when any incident is updated</td><td>Free (included with Sentinel)</td></tr>
</tbody></table>
<p style="color:#64748b;font-size:.8rem;margin-top:.5rem">&#9888;&#65039; <strong>To remove:</strong> Delete the Logic App and Automation Rule from the Azure Portal. The RBAC assignment is automatically cleaned up when the Logic App identity is deleted.</p>

<div class="disclaimer" style="margin-top:1rem">
<strong>&#9888;&#65039; DEPLOYMENT DISCLAIMER:</strong> The tag-restoration playbook is provided <strong>&ldquo;AS IS&rdquo;</strong>
for educational and experimental purposes only. It is NOT an officially supported Microsoft tool.
Deploying it will create billable Azure resources (Logic App). Review the ARM template and deployment
script before running. You are solely responsible for any resources created, costs incurred, and
operational impact. Test in a non-production environment first. The authors assume no liability.
</div>
</div>

<!-- ═══════ ERRORS ═══════ -->
$(if($script:Report.Errors.Count -gt 0){
"<details><summary>&#128679; Errors During Collection ($($script:Report.Errors.Count))</summary><ul style='margin:.5rem 0 0 1.2rem'>" +
($script:Report.Errors | ForEach-Object { "<li style='margin:.2rem 0'>$([System.Web.HttpUtility]::HtmlEncode($_))</li>" }) + "</ul></details>"
})

<hr style="border-color:var(--border);margin:2rem 0"/>
<div class="disclaimer">
<strong>&#9888;&#65039; DISCLAIMER:</strong> This report and all associated scripts
(<code>Investigate-PhishingTriageAgentTagRemoval.ps1</code>,
<code>Deploy-TagRestorationPlaybook.ps1</code>,
<code>Restore-SentinelTags-Playbook.json</code>) are provided <strong>&ldquo;AS IS&rdquo;</strong>
without warranty of any kind, express or implied. They are for <strong>educational and
experimental purposes only</strong> and are NOT officially supported Microsoft tools or products.
Use at your own risk. The authors assume no liability for any damage, data loss, cost, or
disruption caused by using these scripts. Always review all code before running in your
environment. Test in non-production environments first.
</div>
<p class="meta" style="text-align:center;margin-top:.5rem">Generated by <strong>Investigate-PhishingTriageAgentTagRemoval.ps1</strong> &bull;
Share this report with your Microsoft support contact or SOC team.</p>
</body></html>
"@

try {
    $html | Out-File -FilePath $ReportPath -Encoding utf8 -Force
} catch {
    $fallback = Join-Path $env:TEMP "PhishingTriageAgent_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
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
