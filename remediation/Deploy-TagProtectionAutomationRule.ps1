<#
.SYNOPSIS
    Deploys a Microsoft Sentinel Automation Rule to protect incident tags from being
    stripped by the Phishing Triage Agent (or any automation that uses PUT semantics).

.DESCRIPTION
    When the Security Copilot Phishing Triage Agent updates a Sentinel incident, the
    underlying REST API uses PUT (full-replace) semantics. If the update payload omits
    the existing labels/tags array, all tags are deleted.

    This script deploys a Sentinel Automation Rule that automatically re-applies your
    specified critical tags whenever an incident is updated. Since adding a tag that
    already exists is a no-op, this is safe to run on every update.

    The script is interactive (zero parameters required) — it walks you through:
      1. Selecting your Azure subscription
      2. Selecting your Log Analytics workspace (Sentinel-enabled)
      3. Entering the tags you want to protect
      4. Deploying the automation rule
      5. Generating an HTML report of what was deployed

.NOTES
    DISCLAIMER - FOR EDUCATIONAL AND EXPERIMENTAL PURPOSES ONLY

    This script is provided "AS IS" without warranty of any kind, express or implied,
    including but not limited to the warranties of merchantability, fitness for a
    particular purpose, and noninfringement.

    This script is intended for educational and experimental purposes only. It is NOT
    an official Microsoft product or service. Microsoft does not endorse, support, or
    guarantee the accuracy, reliability, or completeness of this script.

    By using this script, you acknowledge that:
      - You use it at your own risk
      - You are responsible for testing in a non-production environment first
      - You are responsible for any changes made to your Azure environment
      - No warranty or support is provided
      - The authors and contributors are not liable for any damages

    Always review scripts before running them in your environment.

.EXAMPLE
    .\Deploy-TagProtectionAutomationRule.ps1

    Runs the interactive wizard to deploy the automation rule.

.EXAMPLE
    .\Deploy-TagProtectionAutomationRule.ps1 -SubscriptionId "abc-123" -ResourceGroupName "my-rg" -WorkspaceName "my-workspace" -TagsToProtect "AutoEscalate","Tier2","VIP"

    Deploys non-interactively with the specified parameters.
#>

#Requires -Version 7.0

[CmdletBinding()]
param(
    [string]$SubscriptionId,
    [string]$ResourceGroupName,
    [string]$WorkspaceName,
    [string[]]$TagsToProtect,
    [string]$RuleName = "Protect Critical Incident Tags",
    [int]$RuleOrder = 1,
    [string]$ReportPath
)

$ErrorActionPreference = 'Continue'
Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

# ── Report tracking ─────────────────────────────────────────────────────────
$script:Steps = [System.Collections.Generic.List[object]]::new()
function Add-Step([string]$Name, [string]$Status, [string]$Detail) {
    $script:Steps.Add([PSCustomObject]@{
        Timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss UTC")
        Step      = $Name
        Status    = $Status
        Detail    = $Detail
    })
}

# ── Banner ──────────────────────────────────────────────────────────────────
$banner = @"

╔══════════════════════════════════════════════════════════════════════════════╗
║          Sentinel Tag Protection — Automation Rule Deployment              ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  This script deploys a Sentinel Automation Rule that re-applies your       ║
║  critical tags whenever an incident is updated. This protects against      ║
║  the Phishing Triage Agent (or any PUT-based update) stripping tags.       ║
║                                                                            ║
║  ⚠  FOR EDUCATIONAL AND EXPERIMENTAL PURPOSES ONLY                        ║
║  ⚠  No warranty is provided. Test in non-production first.                ║
╚══════════════════════════════════════════════════════════════════════════════╝

"@
Write-Host $banner -ForegroundColor Cyan

# ── Disclaimer confirmation ─────────────────────────────────────────────────
Write-Host "DISCLAIMER:" -ForegroundColor Yellow
Write-Host "This script is for educational and experimental purposes only." -ForegroundColor Yellow
Write-Host "It will create an Automation Rule in your Sentinel workspace." -ForegroundColor Yellow
Write-Host "No warranty is provided. You are responsible for any changes." -ForegroundColor Yellow
Write-Host ""

$isNonInteractive = [Environment]::GetCommandLineArgs() -match '-NonInteractive'
if (-not $isNonInteractive -and -not $TagsToProtect) {
    try {
        $confirm = Read-Host "Type YES to continue"
        if ($confirm -ne "YES") {
            Write-Host "Aborted by user." -ForegroundColor Red
            return
        }
    } catch {
        # Non-interactive session — skip confirmation
    }
}

# ── Helper: get bearer token (handles both plain string and SecureString) ──
function Get-BearerToken {
    $tokenObj = Get-AzAccessToken -ResourceUrl "https://management.azure.com" -ErrorAction Stop
    $tok = $tokenObj.Token
    if ($tok -is [securestring]) {
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($tok)
        try   { $tok = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
        finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    }
    return $tok
}

# ── Helper: generate the HTML report ────────────────────────────────────────
function Write-DeploymentReport {
    param(
        [string]$Path,
        [string]$Subscription, [string]$RG, [string]$Workspace,
        [string]$SignedInAs,
        [string[]]$Tags,
        [string]$UpdateRuleId, [bool]$UpdateRuleOk,
        [string]$CreateRuleId, [bool]$CreateRuleOk,
        [string]$RuleDisplayName,
        [object[]]$ExistingTags,
        [object[]]$Steps,
        [string[]]$Errors
    )

    $ts = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss UTC")
    $overallStatus = if ($UpdateRuleOk) { "SUCCESS" } else { "FAILED" }
    $statusCls     = if ($UpdateRuleOk) { "pass" } else { "critical" }
    $statusIcon    = if ($UpdateRuleOk) { "&#9989;" } else { "&#10060;" }

    $tagsHtml = ($Tags | ForEach-Object { "<code>$([System.Web.HttpUtility]::HtmlEncode($_))</code>" }) -join ", "

    $stepsHtml = ($Steps | ForEach-Object {
        $cls = switch ($_.Status) { "OK" { "pass" } "SKIP" { "warning" } "FAIL" { "critical" } default { "info" } }
        "<tr><td style='font-size:.78rem'>$([System.Web.HttpUtility]::HtmlEncode($_.Timestamp))</td>" +
        "<td><span class='badge $cls'>$($_.Status)</span></td>" +
        "<td>$([System.Web.HttpUtility]::HtmlEncode($_.Step))</td>" +
        "<td>$([System.Web.HttpUtility]::HtmlEncode($_.Detail))</td></tr>"
    }) -join "`n"

    $existingTagsHtml = ""
    if ($ExistingTags -and $ExistingTags.Count -gt 0) {
        $existingTagsHtml = "<h3>Tags Found in Workspace</h3><table><thead><tr><th>Tag Name</th><th>Incidents Using</th></tr></thead><tbody>"
        foreach ($t in $ExistingTags) {
            $existingTagsHtml += "<tr><td><code>$([System.Web.HttpUtility]::HtmlEncode($t.Name))</code></td><td>$($t.Count)</td></tr>"
        }
        $existingTagsHtml += "</tbody></table>"
    }

    $errorsHtml = ""
    if ($Errors -and $Errors.Count -gt 0) {
        $errorsHtml = "<h2>&#128679; Errors</h2><ul>"
        foreach ($e in $Errors) { $errorsHtml += "<li>$([System.Web.HttpUtility]::HtmlEncode($e))</li>" }
        $errorsHtml += "</ul>"
    }

    $html = @"
<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"/>
<title>Tag Protection Automation Rule — Deployment Report</title>
<style>
:root{--bg:#0d1117;--fg:#c9d1d9;--card:#161b22;--border:#30363d;
--red:#f85149;--yel:#d29922;--grn:#3fb950;--blu:#58a6ff}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--fg);padding:2rem;line-height:1.6;max-width:1000px;margin:0 auto}
h1{color:var(--blu);font-size:1.5rem;margin-bottom:.3rem}
h2{color:var(--fg);border-bottom:1px solid var(--border);padding-bottom:.4rem;margin:2rem 0 1rem;font-size:1.15rem}
h3{color:var(--blu);margin:1rem 0 .5rem;font-size:1rem}
.meta{color:#8b949e;font-size:.85rem;margin-bottom:1.5rem}
table{width:100%;border-collapse:collapse;margin:.8rem 0;font-size:.82rem}
th{background:#21262d;color:var(--blu);text-align:left;padding:.45rem .6rem;border:1px solid var(--border)}
td{padding:.35rem .6rem;border:1px solid var(--border);vertical-align:top}
tr:nth-child(even) td{background:#0d1117}
.badge{padding:2px 8px;border-radius:4px;font-weight:600;font-size:.72rem;text-transform:uppercase}
.badge.pass{background:#0d2818;color:var(--grn)}
.badge.critical{background:#3d1114;color:var(--red)}
.badge.warning{background:#3d2e00;color:var(--yel)}
.badge.info{background:#0c2d6b;color:var(--blu)}
.verdict{font-size:1.15rem;font-weight:700;padding:1rem 1.5rem;border-radius:8px;margin:1.5rem 0;text-align:center}
.verdict.pass{background:#0d2818;color:var(--grn);border:1px solid var(--grn)}
.verdict.critical{background:#3d1114;color:var(--red);border:1px solid var(--red)}
.card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:1.2rem 1.5rem;margin:1rem 0}
code{background:#21262d;padding:1px 5px;border-radius:3px;font-size:.85rem}
.disclaimer{background:#1a1500;border:1px solid #5a4a00;border-radius:6px;padding:.8rem 1rem;margin:.8rem 0;font-size:.78rem;color:#d29922}
.disclaimer strong{color:#f0c040}
ol.steps{margin:.5rem 0 0 1.2rem}ol.steps li{margin:.4rem 0}
</style></head><body>

<h1>&#128737; Tag Protection Automation Rule &mdash; Deployment Report</h1>
<p class="meta">$ts &bull; Signed in as <code>$([System.Web.HttpUtility]::HtmlEncode($SignedInAs))</code></p>

<div class="disclaimer">
<strong>&#9888;&#65039; DISCLAIMER:</strong> This report and the associated deployment script are provided
<strong>&ldquo;AS IS&rdquo;</strong> for <strong>educational and experimental purposes only</strong>. Not an
officially supported Microsoft tool. Use at your own risk. The authors assume no liability.
</div>

<div class="verdict $statusCls">$statusIcon Deployment: $overallStatus</div>

<!-- WHAT WAS DEPLOYED -->
<h2>&#128203; What Was Deployed</h2>
<div class="card">
<table>
<tr><th style="width:200px">Setting</th><th>Value</th></tr>
<tr><td><strong>Subscription</strong></td><td><code>$([System.Web.HttpUtility]::HtmlEncode($Subscription))</code></td></tr>
<tr><td><strong>Resource Group</strong></td><td><code>$([System.Web.HttpUtility]::HtmlEncode($RG))</code></td></tr>
<tr><td><strong>Workspace</strong></td><td><code>$([System.Web.HttpUtility]::HtmlEncode($Workspace))</code></td></tr>
<tr><td><strong>Tags Protected</strong></td><td>$tagsHtml</td></tr>
<tr><td><strong>Update Rule</strong></td><td>$(if($UpdateRuleOk){"<span class='badge pass'>DEPLOYED</span> &mdash; <code>$UpdateRuleId</code>"}else{"<span class='badge critical'>FAILED</span>"})</td></tr>
<tr><td><strong>Create Rule</strong></td><td>$(if($CreateRuleOk){"<span class='badge pass'>DEPLOYED</span> &mdash; <code>$CreateRuleId</code>"}else{"<span class='badge warning'>SKIPPED</span> (non-critical)"})</td></tr>
<tr><td><strong>Rule Display Name</strong></td><td>$([System.Web.HttpUtility]::HtmlEncode($RuleDisplayName))</td></tr>
</table>
</div>

<!-- HOW IT WORKS -->
<h2>&#9881; How It Works</h2>
<div class="card">
<p><strong>Update Rule</strong> &mdash; Triggers when an incident is updated and severity changes
(High, Medium, Low, or Informational). The Phishing Triage Agent typically changes severity,
so this catches most agent updates. The action <strong>adds your protected tags</strong> back.</p>
<p style="margin-top:.6rem"><strong>Create Rule</strong> &mdash; Triggers when a new incident is created.
Stamps your protected tags on every new incident.</p>
<p style="margin-top:.6rem"><strong>Idempotent:</strong> Adding a tag that already exists is a no-op.
If the tag was stripped, it gets re-added. Safe to run on every update.</p>
</div>

<!-- LIMITATIONS -->
<h2>&#9888;&#65039; Limitations</h2>
<div class="card">
<ul style="margin-left:1.2rem">
<li>Only protects the <strong>specific tags</strong> you configured &mdash; not dynamic.</li>
<li>Update rule fires on <strong>severity changes</strong>. If an update doesn't change severity,
that specific update won't trigger tag restoration.</li>
<li>For full dynamic tag restoration (any tag, any trigger), use the
<a href="https://github.com/iamjoeycruz/securitycopilotindefender/tree/main/remediation/restore-sentinel-incident-tags" style="color:var(--blu)">Logic App approach</a>.</li>
</ul>
</div>

$existingTagsHtml

<!-- DEPLOYMENT LOG -->
<h2>&#128196; Deployment Log</h2>
<table>
<thead><tr><th style="width:180px">Timestamp</th><th style="width:70px">Status</th><th>Step</th><th>Detail</th></tr></thead>
<tbody>$stepsHtml</tbody>
</table>

$errorsHtml

<!-- NEXT STEPS -->
<h2>&#9989; Next Steps</h2>
<div class="card">
<ol class="steps">
<li><strong>Verify in Azure Portal:</strong> Go to <em>Microsoft Sentinel &rarr; Automation</em> and confirm the rule(s) show as <strong>Enabled</strong>.</li>
<li><strong>Test:</strong> Open a phishing incident, change its severity. After the update, check that your tags are present.</li>
<li><strong>Monitor:</strong> Check back after 24-48 hours to confirm tags are being preserved on new incidents.</li>
</ol>
</div>

<!-- REMOVAL -->
<h2>&#128465; How to Remove</h2>
<div class="card">
<ol class="steps">
<li>Go to <em>Microsoft Sentinel &rarr; Automation</em></li>
<li>Find and delete <strong>&ldquo;$([System.Web.HttpUtility]::HtmlEncode($RuleDisplayName))&rdquo;</strong> and the companion <strong>&ldquo;(New Incidents)&rdquo;</strong> rule</li>
<li>No other resources to clean up &mdash; automation rules are free and leave no residual artifacts</li>
</ol>
</div>

<hr style="border-color:var(--border);margin:2rem 0"/>
<div class="disclaimer">
<strong>&#9888;&#65039; DISCLAIMER:</strong> This deployment and report are provided <strong>&ldquo;AS IS&rdquo;</strong>
without warranty. For educational and experimental purposes only. Not an officially supported
Microsoft tool. You are responsible for any changes made to your environment.
Test in non-production first.
</div>
<p class="meta" style="text-align:center;margin-top:.5rem">Generated by <strong>Deploy-TagProtectionAutomationRule.ps1</strong></p>
</body></html>
"@

    try {
        $html | Out-File -FilePath $Path -Encoding utf8 -Force
        return $true
    } catch {
        $fallback = Join-Path $env:TEMP "TagProtection_DeployReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
        Write-Host "  ⚠  Could not write to $Path — writing to $fallback" -ForegroundColor Yellow
        $html | Out-File -FilePath $fallback -Encoding utf8 -Force
        return $fallback
    }
}

# ── Step 1: Ensure Az modules ──────────────────────────────────────────────
Write-Host "`n[1/6] Checking Azure PowerShell modules..." -ForegroundColor White
try {
    if (-not (Get-Module -ListAvailable -Name 'Az.Accounts' -ErrorAction SilentlyContinue)) {
        Write-Host "  Installing Az.Accounts..." -ForegroundColor Yellow
        Install-Module -Name 'Az.Accounts' -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
    }
    Import-Module Az.Accounts -ErrorAction Stop
    Add-Step "Check modules" "OK" "Az.Accounts loaded"
    Write-Host "  ✅ Az.Accounts ready" -ForegroundColor Green
} catch {
    Add-Step "Check modules" "FAIL" "$_"
    Write-Host "  ❌ Failed to load Az.Accounts: $_" -ForegroundColor Red
    Write-Host "  Run: Install-Module Az.Accounts -Scope CurrentUser" -ForegroundColor Yellow
    return
}

# ── Step 2: Authenticate ────────────────────────────────────────────────────
Write-Host "[2/6] Authenticating to Azure..." -ForegroundColor White
$ctx = Get-AzContext -ErrorAction SilentlyContinue
if (-not $ctx) {
    Write-Host "  No active session. Launching browser login..." -ForegroundColor Yellow
    try {
        Connect-AzAccount -ErrorAction Stop | Out-Null
        $ctx = Get-AzContext -ErrorAction Stop
    } catch {
        Add-Step "Authentication" "FAIL" "$_"
        Write-Host "  ❌ Login failed: $_" -ForegroundColor Red
        return
    }
}
$signedInAs = $ctx.Account.Id
Add-Step "Authentication" "OK" "Signed in as $signedInAs"
Write-Host "  ✅ Signed in as: $signedInAs" -ForegroundColor Green

# ── Step 3: Select subscription + workspace ─────────────────────────────────
Write-Host "[3/6] Selecting subscription and workspace..." -ForegroundColor White

if (-not $SubscriptionId) {
    $subs = @(Get-AzSubscription -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Enabled' })
    if ($subs.Count -eq 0) {
        Add-Step "Select subscription" "FAIL" "No enabled subscriptions found"
        Write-Host "  ❌ No enabled subscriptions found." -ForegroundColor Red
        return
    }
    if ($subs.Count -eq 1) {
        $SubscriptionId = $subs[0].Id
        Write-Host "  Auto-selected subscription: $($subs[0].Name)" -ForegroundColor Green
    } else {
        Write-Host "`n  Available subscriptions:" -ForegroundColor Cyan
        for ($i = 0; $i -lt $subs.Count; $i++) {
            Write-Host "    [$($i+1)] $($subs[$i].Name) ($($subs[$i].Id))"
        }
        $choice = Read-Host "  Select subscription (1-$($subs.Count))"
        $idx = [int]$choice - 1
        if ($idx -lt 0 -or $idx -ge $subs.Count) {
            Add-Step "Select subscription" "FAIL" "Invalid selection: $choice"
            Write-Host "  ❌ Invalid selection." -ForegroundColor Red
            return
        }
        $SubscriptionId = $subs[$idx].Id
    }
}
try {
    Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop | Out-Null
    Add-Step "Select subscription" "OK" $SubscriptionId
} catch {
    Add-Step "Select subscription" "FAIL" "$_"
    Write-Host "  ❌ Could not set subscription: $_" -ForegroundColor Red
    return
}

# Discover Sentinel workspaces via REST API
if (-not $WorkspaceName -or -not $ResourceGroupName) {
    Write-Host "  Discovering Sentinel-enabled workspaces..." -ForegroundColor Yellow
    try {
        $token = Get-BearerToken
        $headers = @{ Authorization = "Bearer $token"; 'Content-Type' = 'application/json' }

        $wsUrl = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.OperationalInsights/workspaces?api-version=2023-09-01"
        $wsResponse = Invoke-RestMethod -Uri $wsUrl -Headers $headers -Method Get -ErrorAction Stop
        $workspaces = @($wsResponse.value)

        if ($workspaces.Count -eq 0) {
            Add-Step "Discover workspaces" "FAIL" "No Log Analytics workspaces found"
            Write-Host "  ❌ No Log Analytics workspaces found." -ForegroundColor Red
            return
        }

        # Check which have Sentinel enabled
        $sentinelWorkspaces = @()
        foreach ($ws in $workspaces) {
            $wsName = $ws.name
            $wsRg = ($ws.id -split '/')[4]
            $solUrl = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$wsRg/providers/Microsoft.OperationsManagement/solutions/SecurityInsights($wsName)?api-version=2015-11-01-preview"
            try {
                Invoke-RestMethod -Uri $solUrl -Headers $headers -Method Get -ErrorAction Stop | Out-Null
                $sentinelWorkspaces += @{ Name = $wsName; ResourceGroup = $wsRg; Location = $ws.location }
            } catch { }
        }

        if ($sentinelWorkspaces.Count -eq 0) {
            Write-Host "  No Sentinel-enabled workspaces found. Showing all workspaces:" -ForegroundColor Yellow
            $sentinelWorkspaces = @($workspaces | ForEach-Object {
                @{ Name = $_.name; ResourceGroup = ($_.id -split '/')[4]; Location = $_.location }
            })
        }

        if ($sentinelWorkspaces.Count -eq 1) {
            $WorkspaceName = $sentinelWorkspaces[0].Name
            $ResourceGroupName = $sentinelWorkspaces[0].ResourceGroup
            Write-Host "  Auto-selected: $WorkspaceName (RG: $ResourceGroupName)" -ForegroundColor Green
        } else {
            Write-Host "`n  Sentinel-enabled workspaces:" -ForegroundColor Cyan
            for ($i = 0; $i -lt $sentinelWorkspaces.Count; $i++) {
                Write-Host "    [$($i+1)] $($sentinelWorkspaces[$i].Name) (RG: $($sentinelWorkspaces[$i].ResourceGroup))"
            }
            $choice = Read-Host "  Select workspace (1-$($sentinelWorkspaces.Count))"
            $idx = [int]$choice - 1
            if ($idx -lt 0 -or $idx -ge $sentinelWorkspaces.Count) {
                Add-Step "Select workspace" "FAIL" "Invalid selection: $choice"
                Write-Host "  ❌ Invalid selection." -ForegroundColor Red
                return
            }
            $WorkspaceName = $sentinelWorkspaces[$idx].Name
            $ResourceGroupName = $sentinelWorkspaces[$idx].ResourceGroup
        }
    } catch {
        Add-Step "Discover workspaces" "FAIL" "$_"
        Write-Host "  ❌ Workspace discovery failed: $_" -ForegroundColor Red
        return
    }
}
Add-Step "Select workspace" "OK" "$WorkspaceName (RG: $ResourceGroupName)"
Write-Host "  ✅ Workspace: $WorkspaceName | RG: $ResourceGroupName" -ForegroundColor Green

# ── Step 4: Collect tags to protect ─────────────────────────────────────────
Write-Host "`n[4/6] Configuring tags to protect..." -ForegroundColor White

$existingTagsList = @()
if (-not $TagsToProtect) {
    Write-Host "  Enter the tags your automation depends on." -ForegroundColor Cyan
    Write-Host "  These tags will be re-applied automatically whenever an incident is updated." -ForegroundColor Cyan
    Write-Host "  (Comma-separated, e.g.: AutoEscalate, Tier2-Review, VIP-Customer)`n" -ForegroundColor Cyan

    # Show existing tags to help the user pick
    Write-Host "  Scanning workspace for existing tags in use..." -ForegroundColor Yellow
    try {
        $token = Get-BearerToken
        $headers = @{ Authorization = "Bearer $token"; 'Content-Type' = 'application/json' }
        $incUrl = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/incidents?api-version=2024-09-01&`$top=200&`$orderby=properties/createdTimeUtc desc"
        $incResponse = Invoke-RestMethod -Uri $incUrl -Headers $headers -Method Get -ErrorAction Stop
        $allTags = @{}
        foreach ($inc in $incResponse.value) {
            if ($inc.properties.labels) {
                foreach ($label in $inc.properties.labels) {
                    $tagName = $label.labelName
                    if ($tagName) {
                        if ($allTags.ContainsKey($tagName)) { $allTags[$tagName]++ }
                        else { $allTags[$tagName] = 1 }
                    }
                }
            }
        }
        if ($allTags.Count -gt 0) {
            $existingTagsList = @($allTags.GetEnumerator() | Sort-Object Value -Descending |
                ForEach-Object { [PSCustomObject]@{ Name = $_.Key; Count = $_.Value } })
            Write-Host "`n  Tags found in recent incidents:" -ForegroundColor Cyan
            foreach ($t in $existingTagsList) {
                Write-Host "    • $($t.Name) (used on $($t.Count) incidents)" -ForegroundColor White
            }
            Write-Host ""
        } else {
            Write-Host "  No tags found on recent incidents.`n" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "  Could not scan existing tags (non-critical, continuing).`n" -ForegroundColor Yellow
    }

    $tagInput = Read-Host "  Tags to protect"
    $TagsToProtect = @($tagInput -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

# Handle comma-separated string from CLI
if ($TagsToProtect.Count -eq 1 -and $TagsToProtect[0] -match ',') {
    $TagsToProtect = @($TagsToProtect[0] -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

if ($TagsToProtect.Count -eq 0) {
    Add-Step "Configure tags" "FAIL" "No tags specified"
    Write-Host "  ❌ No tags specified. Aborting." -ForegroundColor Red
    return
}

Add-Step "Configure tags" "OK" ($TagsToProtect -join ', ')
Write-Host "  ✅ Tags to protect: $($TagsToProtect -join ', ')" -ForegroundColor Green

# ── Step 5: Deploy automation rules ─────────────────────────────────────────
Write-Host "`n[5/6] Deploying automation rules..." -ForegroundColor White

$token = Get-BearerToken
$headers = @{ Authorization = "Bearer $token"; 'Content-Type' = 'application/json' }
$labelsArray = @($TagsToProtect | ForEach-Object { @{ labelName = $_ } })

$updateRuleId = [guid]::NewGuid().ToString()
$updateRuleOk = $false
$createRuleId = [guid]::NewGuid().ToString()
$createRuleOk = $false
$deployErrors = @()

# Rule 1: Update trigger (severity change)
$ruleBody = @{
    properties = @{
        displayName    = $RuleName
        order          = $RuleOrder
        triggeringLogic = @{
            isEnabled    = $true
            triggersOn   = "Incidents"
            triggersWhen = "Updated"
            conditions   = @(
                @{
                    conditionType       = "PropertyChanged"
                    conditionProperties = @{
                        propertyName   = "IncidentSeverity"
                        changeType     = "ChangedTo"
                        operator       = "Equals"
                        propertyValues = @("High", "Medium", "Low", "Informational")
                    }
                }
            )
        }
        actions = @(
            @{
                actionType          = "ModifyProperties"
                order               = 1
                actionConfiguration = @{ labels = $labelsArray }
            }
        )
    }
} | ConvertTo-Json -Depth 10

$ruleUrl = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/automationRules/${updateRuleId}?api-version=2024-09-01"

Write-Host "  Creating update rule: $RuleName" -ForegroundColor Yellow
try {
    $null = Invoke-RestMethod -Uri $ruleUrl -Headers $headers -Method Put -Body $ruleBody -ErrorAction Stop
    $updateRuleOk = $true
    Add-Step "Deploy update rule" "OK" "Rule ID: $updateRuleId"
    Write-Host "  ✅ Update rule deployed: $updateRuleId" -ForegroundColor Green
} catch {
    $errDetail = if ($_.ErrorDetails.Message) { $_.ErrorDetails.Message } else { $_.Exception.Message }
    $deployErrors += "Update rule: $errDetail"
    Add-Step "Deploy update rule" "FAIL" $errDetail
    Write-Host "  ❌ Failed: $errDetail" -ForegroundColor Red
    Write-Host "`n  Troubleshooting:" -ForegroundColor Yellow
    Write-Host "    - Ensure you have Microsoft Sentinel Contributor role" -ForegroundColor Yellow
    Write-Host "    - Verify Sentinel is enabled on the workspace" -ForegroundColor Yellow
}

# Rule 2: Create trigger (new incidents)
if ($updateRuleOk) {
    Write-Host "  Creating companion rule for new incidents..." -ForegroundColor Yellow
    $createRuleBody = @{
        properties = @{
            displayName    = "$RuleName (New Incidents)"
            order          = $RuleOrder + 1
            triggeringLogic = @{
                isEnabled    = $true
                triggersOn   = "Incidents"
                triggersWhen = "Created"
                conditions   = @()
            }
            actions = @(
                @{
                    actionType          = "ModifyProperties"
                    order               = 1
                    actionConfiguration = @{ labels = $labelsArray }
                }
            )
        }
    } | ConvertTo-Json -Depth 10

    $createUrl = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/automationRules/${createRuleId}?api-version=2024-09-01"
    try {
        $null = Invoke-RestMethod -Uri $createUrl -Headers $headers -Method Put -Body $createRuleBody -ErrorAction Stop
        $createRuleOk = $true
        Add-Step "Deploy create rule" "OK" "Rule ID: $createRuleId"
        Write-Host "  ✅ Companion rule deployed: $createRuleId" -ForegroundColor Green
    } catch {
        Add-Step "Deploy create rule" "SKIP" $_.Exception.Message
        Write-Host "  ⚠  Companion rule skipped (non-critical): $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# ── Step 6: Generate report ─────────────────────────────────────────────────
Write-Host "`n[6/6] Generating deployment report..." -ForegroundColor White

if (-not $ReportPath) {
    $ts = Get-Date -Format "yyyyMMdd_HHmmss"
    $ReportPath = Join-Path (Get-Location) "TagProtection_DeployReport_$ts.html"
}

Add-Step "Generate report" "OK" $ReportPath

$null = Write-DeploymentReport `
    -Path $ReportPath `
    -Subscription $SubscriptionId -RG $ResourceGroupName -Workspace $WorkspaceName `
    -SignedInAs $signedInAs `
    -Tags $TagsToProtect `
    -UpdateRuleId $updateRuleId -UpdateRuleOk $updateRuleOk `
    -CreateRuleId $createRuleId -CreateRuleOk $createRuleOk `
    -RuleDisplayName $RuleName `
    -ExistingTags $existingTagsList `
    -Steps @($script:Steps) `
    -Errors $deployErrors

# ── Summary ─────────────────────────────────────────────────────────────────
if ($updateRuleOk) {
    Write-Host "`n╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║                       ✅ Deployment Complete                                ║" -ForegroundColor Green
    Write-Host "╠══════════════════════════════════════════════════════════════════════════════╣" -ForegroundColor Green
    Write-Host "║  Update Rule:  $($updateRuleId.PadRight(57))║" -ForegroundColor Green
    if ($createRuleOk) {
    Write-Host "║  Create Rule:  $($createRuleId.PadRight(57))║" -ForegroundColor Green
    }
    Write-Host "║  Tags:         $(($TagsToProtect -join ', ').PadRight(57))║" -ForegroundColor Green
    Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
} else {
    Write-Host "`n  ❌ Deployment failed. See report for details." -ForegroundColor Red
}

Write-Host "`n  📄 Report: $ReportPath" -ForegroundColor Cyan
Write-Host "  Open it:  Start-Process `"$ReportPath`"`n" -ForegroundColor Gray
