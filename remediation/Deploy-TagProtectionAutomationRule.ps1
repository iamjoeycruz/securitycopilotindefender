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

[CmdletBinding()]
param(
    [string]$SubscriptionId,
    [string]$ResourceGroupName,
    [string]$WorkspaceName,
    [string[]]$TagsToProtect,
    [string]$RuleName = "Protect Critical Incident Tags",
    [int]$RuleOrder = 1
)

#Requires -Version 7.0

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

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
        # Non-interactive session (e.g., piped input) — skip confirmation
    }
}

# ── Ensure Az modules ──────────────────────────────────────────────────────
Write-Host "`n[1/5] Checking Azure PowerShell modules..." -ForegroundColor White
$requiredModules = @('Az.Accounts', 'Az.Resources')
foreach ($mod in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $mod)) {
        Write-Host "  Installing $mod..." -ForegroundColor Yellow
        Install-Module -Name $mod -Scope CurrentUser -Force -AllowClobber
    }
}
Import-Module Az.Accounts -ErrorAction Stop

# ── Authenticate ────────────────────────────────────────────────────────────
Write-Host "[2/5] Authenticating to Azure..." -ForegroundColor White
$ctx = Get-AzContext
if (-not $ctx) {
    Write-Host "  No active session. Launching browser login..." -ForegroundColor Yellow
    Connect-AzAccount | Out-Null
    $ctx = Get-AzContext
}
Write-Host "  Signed in as: $($ctx.Account.Id)" -ForegroundColor Green

# ── Helper: get bearer token ───────────────────────────────────────────────
function Get-BearerToken {
    $tokenObj = Get-AzAccessToken -ResourceUrl "https://management.azure.com"
    $tok = $tokenObj.Token
    if ($tok -is [securestring]) {
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($tok)
        try { $tok = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
        finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    }
    return $tok
}

# ── Select subscription ────────────────────────────────────────────────────
Write-Host "[3/5] Selecting subscription and workspace..." -ForegroundColor White

if (-not $SubscriptionId) {
    $subs = @(Get-AzSubscription | Where-Object { $_.State -eq 'Enabled' })
    if ($subs.Count -eq 0) { Write-Error "No enabled subscriptions found."; return }
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
        if ($idx -lt 0 -or $idx -ge $subs.Count) { Write-Error "Invalid selection."; return }
        $SubscriptionId = $subs[$idx].Id
    }
}
Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop | Out-Null

# ── Discover Sentinel workspaces ───────────────────────────────────────────
if (-not $WorkspaceName -or -not $ResourceGroupName) {
    Write-Host "  Discovering Sentinel-enabled workspaces..." -ForegroundColor Yellow
    $token = Get-BearerToken
    $headers = @{ Authorization = "Bearer $token"; 'Content-Type' = 'application/json' }

    # Get all Log Analytics workspaces
    $wsUrl = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.OperationalInsights/workspaces?api-version=2023-09-01"
    $wsResponse = Invoke-RestMethod -Uri $wsUrl -Headers $headers -Method Get
    $workspaces = $wsResponse.value

    if ($workspaces.Count -eq 0) { Write-Error "No Log Analytics workspaces found."; return }

    # Check which have Sentinel enabled (SecurityInsights solution)
    $sentinelWorkspaces = @()
    foreach ($ws in $workspaces) {
        $wsName = $ws.name
        $wsRg = ($ws.id -split '/')[4]
        $solUrl = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$wsRg/providers/Microsoft.OperationsManagement/solutions/SecurityInsights($wsName)?api-version=2015-11-01-preview"
        try {
            Invoke-RestMethod -Uri $solUrl -Headers $headers -Method Get -ErrorAction Stop | Out-Null
            $sentinelWorkspaces += @{ Name = $wsName; ResourceGroup = $wsRg; Location = $ws.location }
        } catch {
            # Not Sentinel-enabled, skip
        }
    }

    if ($sentinelWorkspaces.Count -eq 0) {
        Write-Host "  No Sentinel-enabled workspaces found. Showing all workspaces:" -ForegroundColor Yellow
        $sentinelWorkspaces = $workspaces | ForEach-Object {
            @{ Name = $_.name; ResourceGroup = ($_.id -split '/')[4]; Location = $_.location }
        }
    }

    if ($sentinelWorkspaces.Count -eq 1) {
        $WorkspaceName = $sentinelWorkspaces[0].Name
        $ResourceGroupName = $sentinelWorkspaces[0].ResourceGroup
        Write-Host "  Auto-selected workspace: $WorkspaceName (RG: $ResourceGroupName)" -ForegroundColor Green
    } else {
        Write-Host "`n  Sentinel-enabled workspaces:" -ForegroundColor Cyan
        for ($i = 0; $i -lt $sentinelWorkspaces.Count; $i++) {
            Write-Host "    [$($i+1)] $($sentinelWorkspaces[$i].Name) (RG: $($sentinelWorkspaces[$i].ResourceGroup))"
        }
        $choice = Read-Host "  Select workspace (1-$($sentinelWorkspaces.Count))"
        $idx = [int]$choice - 1
        if ($idx -lt 0 -or $idx -ge $sentinelWorkspaces.Count) { Write-Error "Invalid selection."; return }
        $WorkspaceName = $sentinelWorkspaces[$idx].Name
        $ResourceGroupName = $sentinelWorkspaces[$idx].ResourceGroup
    }
}

Write-Host "  Workspace: $WorkspaceName | RG: $ResourceGroupName" -ForegroundColor Green

# ── Collect tags to protect ─────────────────────────────────────────────────
Write-Host "`n[4/5] Configuring tags to protect..." -ForegroundColor White

if (-not $TagsToProtect) {
    Write-Host "  Enter the tags your automation depends on." -ForegroundColor Cyan
    Write-Host "  These tags will be re-applied automatically whenever an incident is updated." -ForegroundColor Cyan
    Write-Host "  (Comma-separated, e.g.: AutoEscalate, Tier2-Review, VIP-Customer)`n" -ForegroundColor Cyan

    # Show existing tags in the workspace to help the user
    Write-Host "  Scanning workspace for existing tags in use..." -ForegroundColor Yellow
    $token = Get-BearerToken
    $headers = @{ Authorization = "Bearer $token"; 'Content-Type' = 'application/json' }
    $incUrl = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/incidents?api-version=2024-09-01&`$top=200&`$orderby=properties/createdTimeUtc desc"
    try {
        $incResponse = Invoke-RestMethod -Uri $incUrl -Headers $headers -Method Get
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
            Write-Host "`n  Tags found in recent incidents:" -ForegroundColor Cyan
            $allTags.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object {
                Write-Host "    • $($_.Key) (used on $($_.Value) incidents)" -ForegroundColor White
            }
            Write-Host ""
        } else {
            Write-Host "  No tags found on recent incidents.`n" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "  Could not scan existing tags (non-critical, continuing).`n" -ForegroundColor Yellow
    }

    $tagInput = Read-Host "  Tags to protect"
    $TagsToProtect = $tagInput -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
}

if ($TagsToProtect.Count -eq 0) {
    Write-Error "No tags specified. Aborting."
    return
}

Write-Host "  Tags to protect: $($TagsToProtect -join ', ')" -ForegroundColor Green

# ── Deploy automation rule ──────────────────────────────────────────────────
Write-Host "`n[5/5] Deploying automation rule..." -ForegroundColor White

$token = Get-BearerToken
$headers = @{ Authorization = "Bearer $token"; 'Content-Type' = 'application/json' }

$ruleId = [guid]::NewGuid().ToString()

# Build the labels array for the action
$labelsArray = $TagsToProtect | ForEach-Object { @{ labelName = $_ } }

# Build the automation rule body
# Strategy: We create TWO actions approaches combined:
#   - Trigger on incident UPDATED with PropertyChanged conditions
#   - Action: ModifyProperties to add the protected tags
#
# For the trigger condition, we use PropertyChanged on IncidentSeverity 
# with ChangedTo all four severity values. This catches any update where
# the agent sets/changes severity (which phishing triage typically does).
#
# Limitation: If an update does NOT change severity, this rule won't fire
# for that specific update. For full dynamic coverage, use the Logic App approach.

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
                actionConfiguration = @{
                    labels = $labelsArray
                }
            }
        )
    }
} | ConvertTo-Json -Depth 10

$ruleUrl = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/automationRules/$($ruleId)?api-version=2024-09-01"

Write-Host "  Creating automation rule: $RuleName" -ForegroundColor Yellow
Write-Host "  Rule ID: $ruleId" -ForegroundColor Gray

try {
    $response = Invoke-RestMethod -Uri $ruleUrl -Headers $headers -Method Put -Body $ruleBody -ErrorAction Stop
    Write-Host "`n  ✅ Automation rule deployed successfully!" -ForegroundColor Green
    Write-Host "  Rule Name:  $($response.properties.displayName)" -ForegroundColor White
    Write-Host "  Rule ID:    $ruleId" -ForegroundColor White
    Write-Host "  Status:     Enabled" -ForegroundColor White
    Write-Host "  Tags:       $($TagsToProtect -join ', ')" -ForegroundColor White
    Write-Host "  Trigger:    On incident updated (severity change)" -ForegroundColor White
    Write-Host "  Action:     Add protected tags back to incident" -ForegroundColor White

    # Try to also create a rule for incident creation (no conditions needed)
    Write-Host "`n  Deploying companion rule for new incidents..." -ForegroundColor Yellow
    $createRuleId = [guid]::NewGuid().ToString()
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
                    actionConfiguration = @{
                        labels = $labelsArray
                    }
                }
            )
        }
    } | ConvertTo-Json -Depth 10

    $createRuleUrl = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/automationRules/$($createRuleId)?api-version=2024-09-01"

    try {
        $createResponse = Invoke-RestMethod -Uri $createRuleUrl -Headers $headers -Method Put -Body $createRuleBody -ErrorAction Stop
        Write-Host "  ✅ Companion rule for new incidents deployed!" -ForegroundColor Green
        Write-Host "  Rule ID: $createRuleId" -ForegroundColor White
    } catch {
        Write-Host "  ⚠  Companion rule for new incidents skipped (non-critical): $($_.Exception.Message)" -ForegroundColor Yellow
    }

} catch {
    $errBody = $_.ErrorDetails.Message
    Write-Host "`n  ❌ Failed to create automation rule." -ForegroundColor Red
    Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Red
    if ($errBody) {
        Write-Host "  Details: $errBody" -ForegroundColor Red
    }
    Write-Host "`n  Troubleshooting:" -ForegroundColor Yellow
    Write-Host "    - Ensure you have Microsoft Sentinel Contributor role on the workspace" -ForegroundColor Yellow
    Write-Host "    - Verify Sentinel is enabled on the workspace" -ForegroundColor Yellow
    Write-Host "    - Check the subscription and workspace names are correct" -ForegroundColor Yellow
    return
}

# ── Summary ─────────────────────────────────────────────────────────────────
Write-Host "`n╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                          Deployment Complete                                ║" -ForegroundColor Cyan
Write-Host "╠══════════════════════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
Write-Host "║                                                                              ║" -ForegroundColor Cyan
Write-Host "║  What was deployed:                                                          ║" -ForegroundColor Cyan
Write-Host "║    • Automation Rule (Update trigger) — re-applies tags when incidents       ║" -ForegroundColor Cyan
Write-Host "║      are updated and severity changes (catches Phishing Triage Agent)        ║" -ForegroundColor Cyan
Write-Host "║    • Automation Rule (Create trigger) — stamps tags on new incidents         ║" -ForegroundColor Cyan
Write-Host "║                                                                              ║" -ForegroundColor Cyan
Write-Host "║  How it works:                                                               ║" -ForegroundColor Cyan
Write-Host "║    The 'Add tags' action is idempotent — if the tag already exists, it's     ║" -ForegroundColor Cyan
Write-Host "║    a no-op. If it was stripped by an agent update, it gets re-added.          ║" -ForegroundColor Cyan
Write-Host "║                                                                              ║" -ForegroundColor Cyan
Write-Host "║  Limitations:                                                                ║" -ForegroundColor Cyan
Write-Host "║    • Only protects the specific tags you configured (not dynamic)            ║" -ForegroundColor Cyan
Write-Host "║    • Update rule fires on severity changes — if an update doesn't change     ║" -ForegroundColor Cyan
Write-Host "║      severity, tags won't be re-applied for that specific update             ║" -ForegroundColor Cyan
Write-Host "║    • For full dynamic tag restoration, use the Logic App approach:            ║" -ForegroundColor Cyan
Write-Host "║      github.com/iamjoeycruz/securitycopilotindefender/remediation            ║" -ForegroundColor Cyan
Write-Host "║                                                                              ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

Write-Host "`n  To verify in Azure Portal:" -ForegroundColor White
Write-Host "    1. Go to Microsoft Sentinel → Your workspace → Automation" -ForegroundColor Gray
Write-Host "    2. Look for '$RuleName'" -ForegroundColor Gray
Write-Host "    3. The rule should show as Enabled" -ForegroundColor Gray

Write-Host "`n  To remove later:" -ForegroundColor White
Write-Host "    Delete the automation rules from Sentinel → Automation → Rules" -ForegroundColor Gray
Write-Host "    Or run: Invoke-RestMethod -Uri `"$ruleUrl`" -Headers `$headers -Method Delete`n" -ForegroundColor Gray
