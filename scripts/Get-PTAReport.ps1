<#
.SYNOPSIS
    Generates a Phishing Triage Agent (PTA) Gap Analysis Report from Microsoft Defender incidents.

.DESCRIPTION
    This script queries the Microsoft Graph Security API to retrieve all user-reported phishing
    incidents from the last N days, analyzes Phishing Triage Agent processing status for each,
    calculates MTTT/MTTR metrics, and generates an interactive HTML dashboard plus CSV export.

    KEY FEATURES:
    - Bulk retrieval of phishing incidents via Graph API (v1.0 + beta)
    - PTA detection via system tags, custom tags, and alert classification
    - MTTT (Median Time to Triage) and MTTR (Median Time to Resolve) calculations
    - Interactive HTML report with Chart.js daily activity charts
    - Clickable incident links to Microsoft Defender portal
    - Sortable/filterable tables with incident detail breakdowns
    - CSV data export for integration with other tools

    REQUIREMENTS:
    - Microsoft.Graph.Security PowerShell module
    - Microsoft.Graph.Authentication PowerShell module
    - Permissions: SecurityIncident.Read.All, SecurityAlert.Read.All
    - PowerShell 7+ recommended

.PARAMETER Days
    Number of days to look back for incidents. Default: 30.

.PARAMETER TenantId
    Optional Azure AD Tenant ID (GUID) for multi-tenant environments.

.PARAMETER OutputPath
    Optional output directory. Default: Desktop\Performance Dashboard Analysis.

.EXAMPLE
    .\Get-PTAReport.ps1
    Generates a report for the last 30 days.

.EXAMPLE
    .\Get-PTAReport.ps1 -Days 14 -OutputPath "C:\Reports"
    Generates a 14-day report in C:\Reports.

.NOTES
    Reconstructed from report output PTAReport_20260330_201246.html
    Original script: Get-PTAReport.ps1

.DISCLAIMER
    THIS SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT
    WARRANTY OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
    TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
    PARTICULAR PURPOSE.

    This script is a community/field-developed sample shared for educational
    and demonstration purposes. It is NOT an official Microsoft product, is
    NOT supported by Microsoft Support, and does NOT represent a Microsoft
    commitment or service-level agreement. Microsoft disclaims all implied
    warranties including, without limitation, any implied warranties of
    merchantability or of fitness for a particular purpose. The entire risk
    arising out of the use or performance of the sample and documentation
    remains with you.

    In no event shall Microsoft, its authors, or anyone else involved in the
    creation, production, or delivery of the script be liable for any
    damages whatsoever (including, without limitation, damages for loss of
    business profits, business interruption, loss of business information,
    or other pecuniary loss) arising out of the use of or inability to use
    the sample or documentation, even if Microsoft has been advised of the
    possibility of such damages.

    Review the script and validate its behavior in a non-production tenant
    before running it against production data. You are responsible for
    ensuring compliance with your organization's data-handling, privacy,
    and security policies.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [int]$Days = 30,

    [Parameter(Mandatory = $false)]
    [string]$TenantId,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath,

    [Parameter(Mandatory = $false)]
    [string]$SubmissionsCsv,

    # Restrict the report to a single reporter (UPN or SMTP). Useful for
    # validating numbers against a known test mailbox. Case-insensitive,
    # exact match against the resolved reporter UPN/email.
    [Parameter(Mandatory = $false)]
    [string]$ReporterUpn,

    # Opt-in: fetch authoritative submissions via Get-ReportSubmission. Requires
    # a WAM-capable host or will spawn an external pwsh window from VS Code.
    [Parameter(Mandatory = $false)]
    [switch]$FetchSubmissions,

    # Deprecated: retained for backward compatibility. The default flow no
    # longer connects to Exchange Online, so this switch is now a no-op.
    [Parameter(Mandatory = $false)]
    [switch]$SkipExoConnect,

    # Restrict the report to incidents where the Phishing Triage Agent failed
    # to produce a verdict (PTAStatus = 'Failed'). Useful for triaging agent
    # health without the noise of successful/missed runs. Output filenames are
    # suffixed with '_Failures' so they don't overwrite full reports.
    [Parameter(Mandatory = $false)]
    [switch]$FailuresOnly
)

Set-StrictMode -Off
$ErrorActionPreference = 'Stop'

# Graph responses are hashtables; helper to safely read optional keys
function Get-HashValue {
    param($Hash, [string]$Key)
    if ($null -eq $Hash) { return $null }
    if ($Hash -is [System.Collections.IDictionary] -and $Hash.Contains($Key)) { return $Hash[$Key] }
    try { return $Hash.$Key } catch { return $null }
}

# ─────────────────────────────────────────────────────────────────────────────
#region Authentication
# ─────────────────────────────────────────────────────────────────────────────

function Connect-DefenderGraph {
    param(
        [string]$TenantId,
        # Only request ThreatSubmission.Read.All when the caller actually needs it.
        # Requesting unused scopes triggers an extra MSAL interactive prompt the
        # first time the SDK silently re-acquires a token (incremental consent).
        [switch]$IncludeThreatSubmission
    )

    # Ensure modules
    foreach ($mod in @('Microsoft.Graph.Authentication', 'Microsoft.Graph.Security')) {
        if (-not (Get-Module -ListAvailable -Name $mod)) {
            Write-Host "Installing $mod..." -ForegroundColor Yellow
            Install-Module $mod -Scope CurrentUser -Force -AllowClobber
        }
        Import-Module $mod -ErrorAction SilentlyContinue
    }

    $requiredScopes = @('SecurityIncident.Read.All', 'SecurityAlert.Read.All')
    if ($IncludeThreatSubmission) { $requiredScopes += 'ThreatSubmission.Read.All' }

    $ctx = Get-MgContext
    if ($ctx) {
        $hasScopes = $true
        foreach ($s in $requiredScopes) { if ($ctx.Scopes -notcontains $s) { $hasScopes = $false; break } }
        if ($hasScopes) {
            Write-Host "[OK] Reusing existing Graph connection ($($ctx.Account))" -ForegroundColor Green
            return $true
        }
        Write-Host "[!] Missing scopes — reconnecting..." -ForegroundColor Yellow
        Disconnect-MgGraph | Out-Null
    }

    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
    $connectParams = @{ Scopes = $requiredScopes; NoWelcome = $true }
    if ($TenantId) { $connectParams['TenantId'] = $TenantId }
    Connect-MgGraph @connectParams

    $ctx = Get-MgContext
    Write-Host "[OK] Connected as $($ctx.Account) to tenant $($ctx.TenantId)" -ForegroundColor Green
    return $true
}

function Connect-SecurityCompliance {
    <#
    .SYNOPSIS
        Connects to Security & Compliance PowerShell for Get-ReportSubmission.
        Reuses existing session if present.
    #>
    param(
        [string]$UserPrincipalName,
        [int]$Days = 30
    )

    if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
        Write-Host "Installing ExchangeOnlineManagement module..." -ForegroundColor Yellow
        Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force -AllowClobber
    }
    Import-Module ExchangeOnlineManagement -ErrorAction SilentlyContinue

    # Check if Get-ReportSubmission is already reachable
    if (Get-Command Get-ReportSubmission -ErrorAction SilentlyContinue) {
        try {
            [void](Get-ReportSubmission -ResultSize 1 -ErrorAction Stop)
            Write-Host "[OK] Reusing existing Security & Compliance session" -ForegroundColor Green
            return $true
        } catch {
            Write-Verbose "Existing S&C session not usable; reconnecting"
        }
    }

    Write-Host "Connecting to Exchange Online for Get-ReportSubmission..." -ForegroundColor Cyan

    $base = @{ ShowBanner = $false }
    if ($UserPrincipalName) { $base['UserPrincipalName'] = $UserPrincipalName }

    # Tier 1: in-process Connect-ExchangeOnline (WAM). Works if script is launched
    # from Windows Terminal / standalone pwsh where MSAL can get a window handle.
    try {
        Connect-ExchangeOnline @base -ErrorAction Stop 4>$null
        if (Get-Command Get-ReportSubmission -ErrorAction SilentlyContinue) {
            Write-Host "[OK] Connected to Exchange Online" -ForegroundColor Green
            return $true
        }
    } catch {
        $err1 = $_.Exception.Message
        Write-Verbose "Connect-ExchangeOnline failed in-process: $err1"
        if ($err1 -notmatch 'RuntimeBroker|NullReference|Object reference|WAM|broker|parent window') {
            Write-Warning "Exchange Online connect failed: $err1"
            return $false
        }
        Write-Host "  In-process WAM broker has no window handle (VS Code terminal bug)." -ForegroundColor Yellow
    }

    # Tier 2: spawn an external pwsh window — it has a real HWND so WAM succeeds there.
    # The child process fetches submissions, writes a CSV, and we import it.
    $csvPath = Join-Path $env:TEMP ("pta-submissions-{0}.csv" -f (Get-Date -Format 'yyyyMMddHHmmss'))
    $errPath = "$csvPath.err"
    Write-Host "  Launching external pwsh window to complete sign-in via WAM..." -ForegroundColor Cyan
    Write-Host "  A new window will open. Sign in if prompted." -ForegroundColor Gray

    # Build child script — use single-quoted here-string (no interpolation) + param block
    # so quoting of $UserPrincipalName / $csvPath / $Days is bulletproof.
    $childScript = @'
param(
    [string]$Upn,
    [int]$Days,
    [string]$OutCsv,
    [string]$ErrFile
)
$ErrorActionPreference = 'Stop'
try {
    Write-Host "Importing ExchangeOnlineManagement..." -ForegroundColor Cyan
    Import-Module ExchangeOnlineManagement -ErrorAction Stop

    Write-Host "Connecting to Security & Compliance (IPPS, WAM)..." -ForegroundColor Cyan
    $p = @{ ShowBanner = $false }
    if ($Upn) { $p['UserPrincipalName'] = $Upn }
    Connect-IPPSSession @p

    $start = (Get-Date).AddDays(-$Days).ToUniversalTime()
    $end   = (Get-Date).ToUniversalTime()
    Write-Host ("Fetching submissions {0} to {1}..." -f $start.ToString('yyyy-MM-dd'), $end.ToString('yyyy-MM-dd')) -ForegroundColor Cyan

    # EXO v3 REST proxies cmdlets lazily — invoke directly, don't gate on Get-Command.
    $subs = $null
    try {
        $subs = Get-ReportSubmission -StartDate $start -EndDate $end -ResultSize Unlimited -ErrorAction Stop
    } catch {
        $msg = $_.Exception.Message
        Write-Host ("S&C Get-ReportSubmission failed: {0}" -f $msg) -ForegroundColor Yellow
        Write-Host "Trying Exchange Online session instead..." -ForegroundColor Cyan
        try { Disconnect-ExchangeOnline -Confirm:$false | Out-Null } catch {}
        Connect-ExchangeOnline @p
        $subs = Get-ReportSubmission -StartDate $start -EndDate $end -ResultSize Unlimited -ErrorAction Stop
    }

    Write-Host ("Retrieved {0} total submissions" -f @($subs).Count) -ForegroundColor Green

    $subs | Export-Csv -NoTypeInformation -LiteralPath $OutCsv
    Write-Host "Exported to $OutCsv" -ForegroundColor Green

    try { Disconnect-ExchangeOnline -Confirm:$false | Out-Null } catch {}
    Write-Host "Done. Closing window in 3 seconds..." -ForegroundColor Gray
    Start-Sleep -Seconds 3
} catch {
    $msg = $_.Exception.Message
    Write-Host "`nERROR: $msg" -ForegroundColor Red
    Set-Content -LiteralPath $ErrFile -Value $msg -Encoding UTF8
    Write-Host "`nPress Enter to close this window..." -ForegroundColor Yellow
    [void][Console]::ReadLine()
}
'@

    $childFile = Join-Path $env:TEMP ("pta-submissions-fetch-{0}.ps1" -f (Get-Date -Format 'yyyyMMddHHmmss'))
    Set-Content -LiteralPath $childFile -Value $childScript -Encoding UTF8

    $upnArg = if ($UserPrincipalName) { $UserPrincipalName } else { '' }
    $argList = @(
        '-NoProfile',
        '-ExecutionPolicy','Bypass',
        '-File', $childFile,
        '-Upn', $upnArg,
        '-Days', $Days,
        '-OutCsv', $csvPath,
        '-ErrFile', $errPath
    )

    $proc = Start-Process -FilePath 'pwsh' -ArgumentList $argList -WindowStyle Normal -PassThru

    Write-Host "  Waiting for sign-in and submission export (external window)..." -ForegroundColor Gray
    $timeout = (Get-Date).AddMinutes(5)
    while (-not (Test-Path -LiteralPath $csvPath) -and -not (Test-Path -LiteralPath $errPath) -and (Get-Date) -lt $timeout) {
        if ($proc.HasExited) { break }
        Start-Sleep -Seconds 2
    }
    Remove-Item -LiteralPath $childFile -ErrorAction SilentlyContinue

    if (Test-Path -LiteralPath $csvPath) {
        Write-Host "[OK] Submissions exported by external window: $csvPath" -ForegroundColor Green
        $script:ExternalSubmissionsCsv = $csvPath
        return $true
    }

    if (Test-Path -LiteralPath $errPath) {
        $childErr = Get-Content -LiteralPath $errPath -Raw
        Remove-Item -LiteralPath $errPath -ErrorAction SilentlyContinue
        Write-Warning "External window reported: $childErr"
    } else {
        Write-Warning "External window closed without producing CSV or error file."
    }

    Write-Host ""
    Write-Host "  Fallback — portal export:" -ForegroundColor Yellow
    Write-Host "    1. Open https://security.microsoft.com/reportsubmission" -ForegroundColor Gray
    Write-Host "    2. Filter: User reported, last $Days days" -ForegroundColor Gray
    Write-Host "    3. Click Export, save the CSV" -ForegroundColor Gray
    Write-Host "    4. Re-run: .\Get-PTAReport.ps1 -SubmissionsCsv `"<path-to-export.csv>`"" -ForegroundColor Gray
    Write-Host ""
    return $false
}

function Get-UserReportedSubmissionsViaGraph {
    <#
    .SYNOPSIS
        Fallback path — returns user-reported email submissions via the Microsoft
        Graph Security beta API (/beta/security/threatSubmission/emailThreats).

        WARNING: As of 2026-04, this beta endpoint is known to return incomplete
        data on many tenants (frequently 0–1 results even when the Defender
        portal Submissions page shows dozens). It is retained ONLY as a fallback
        when Security & Compliance PowerShell is unavailable. The authoritative
        path is Get-ReportSubmission via Connect-IPPSSession (see
        Get-UserReportedSubmissions).

        Requires the ThreatSubmission.Read.All scope.
        Docs: https://learn.microsoft.com/graph/api/security-emailthreatsubmission-list
    #>
    param([int]$Days)

    $startDate = (Get-Date).AddDays(-$Days).ToUniversalTime()
    $endDate   = (Get-Date).ToUniversalTime()
    $startIso  = $startDate.ToString('yyyy-MM-ddTHH:mm:ssZ')
    $endIso    = $endDate.ToString('yyyy-MM-ddTHH:mm:ssZ')
    Write-Host "Querying user-reported submissions from $($startDate.ToString('yyyy-MM-dd')) to $($endDate.ToString('yyyy-MM-dd')) via Graph..." -ForegroundColor Cyan

    # Server-side filter by source=user and date window. Graph $filter on this
    # endpoint supports source eq, createdDateTime ge/lt, and category eq.
    $filter = "source eq 'user' and createdDateTime ge $startIso and createdDateTime lt $endIso"
    $encoded = [System.Uri]::EscapeDataString($filter)
    $uri = "https://graph.microsoft.com/beta/security/threatSubmission/emailThreats?`$filter=$encoded&`$top=100"

    $all = [System.Collections.Generic.List[object]]::new()
    try {
        while ($uri) {
            $page = Invoke-GraphRequestWithRetry -Uri $uri -Method GET
            if ($page.value) { foreach ($v in $page.value) { [void]$all.Add($v) } }
            $uri = $page.'@odata.nextLink'
        }
    } catch {
        Write-Warning "Graph emailThreats query failed: $($_.Exception.Message)"
        return @()
    }

    # Normalize to the shape the rest of the script expects (matches the CSV
    # importer's column names).
    $normalized = foreach ($s in $all) {
        $createdBy = Get-HashValue $s 'createdBy'
        $user      = if ($createdBy) { Get-HashValue $createdBy 'user' } else { $null }
        $result    = Get-HashValue $s 'result'
        $cat       = [string](Get-HashValue $s 'category')
        $reportType = switch ($cat) {
            'phishing' { 'Phish' }
            'malware'  { 'Malware' }
            'spam'     { 'Spam' }
            'notJunk'  { 'Not junk' }
            default    { $cat }
        }
        [pscustomobject]@{
            NetworkMessageId = Get-HashValue $s 'networkMessageId'  # usually $null on this API
            InternetMessageId = Get-HashValue $s 'internetMessageId'
            Subject          = Get-HashValue $s 'subject'
            SenderAddress    = Get-HashValue $s 'sender'
            ReceivedBy       = Get-HashValue $s 'recipientEmailAddress'
            ReportedBy       = if ($user) { Get-HashValue $user 'email' } else { $null }
            Source           = 'User'
            Type             = 'Email'
            ReportType       = $reportType
            Category         = $cat
            ReceivedDate     = Get-HashValue $s 'receivedDateTime'
            SubmittedDate    = Get-HashValue $s 'createdDateTime'
            Status           = Get-HashValue $s 'status'
            Result           = if ($result) { Get-HashValue $result 'category' } else { $null }
            ResultDetail     = if ($result) { [string](Get-HashValue $result 'detail') } else { '' }
            OriginalCategory = [string](Get-HashValue $s 'originalCategory')
            Id               = Get-HashValue $s 'id'
        }
    }

    Write-Host "[OK] Retrieved $($normalized.Count) user-reported email submissions from Graph" -ForegroundColor Green
    return @($normalized)
}

function ConvertTo-NormalizedSubmission {
    <#
    .SYNOPSIS
        Normalizes a Get-ReportSubmission row (or imported CSV row) into the
        unified shape consumed by Get-PTAMetrics. Get-ReportSubmission column
        names vary across tenants and EXO module versions, so this handles all
        known variants (Recipient/ReceivedBy, UserReported/ReportedBy,
        ReceivedDate/SubmittedDate, Identity/Id, etc.).
    #>
    param($Row)

    function _Prop($obj, [string[]]$names) {
        foreach ($n in $names) {
            if ($obj.PSObject.Properties[$n] -and $null -ne $obj.$n -and "$($obj.$n)" -ne '') {
                return $obj.$n
            }
        }
        return $null
    }

    $type = _Prop $Row @('Type')
    if (-not $type) { $type = 'Email' }
    $resultDetail = _Prop $Row @('ResultDetail','RescanResult','ResultReason')
    if (-not $resultDetail) { $resultDetail = '' }
    $originalCategory = _Prop $Row @('OriginalCategory')
    if (-not $originalCategory) { $originalCategory = '' }

    [pscustomobject]@{
        NetworkMessageId  = _Prop $Row @('NetworkMessageId','MessageId')
        InternetMessageId = _Prop $Row @('InternetMessageId')
        Subject           = _Prop $Row @('Subject')
        SenderAddress     = _Prop $Row @('SenderAddress','Sender')
        ReceivedBy        = _Prop $Row @('ReceivedBy','Recipient','RecipientEmailAddress')
        ReportedBy        = _Prop $Row @('ReportedBy','UserReported','ReportedByUser')
        Source            = _Prop $Row @('Source')
        Type              = $type
        ReportType        = _Prop $Row @('ReportType','Category')
        Category          = _Prop $Row @('Category','ReportType')
        ReceivedDate      = _Prop $Row @('ReceivedDate','SubmittedDate')
        SubmittedDate     = _Prop $Row @('SubmittedDate','ReceivedDate')
        Status            = _Prop $Row @('Status')
        Result            = _Prop $Row @('Result')
        ResultDetail      = $resultDetail
        OriginalCategory  = $originalCategory
        Id                = _Prop $Row @('Identity','Id','SubmissionId')
    }
}

function Get-UserReportedSubmissions {
    <#
    .SYNOPSIS
        Returns all user-reported email submissions for the last N days using
        the authoritative Security & Compliance cmdlet Get-ReportSubmission
        (the same data source the Defender portal Submissions → User reported
        view uses). Falls back to Microsoft Graph emailThreats only if S&C
        PowerShell is unreachable.

        Get-ReportSubmission is exposed by the EXO / S&C v3 REST cmdlets and
        is reachable via Connect-IPPSSession or Connect-ExchangeOnline.
        Connect-SecurityCompliance handles both the in-process WAM path (used
        when running from a host with a window handle) and the external-window
        fallback (used by VS Code's integrated terminal, which lacks an HWND).
    #>
    param(
        [int]$Days,
        [string]$UserPrincipalName
    )

    $startDate = (Get-Date).AddDays(-$Days).ToUniversalTime()
    $endDate   = (Get-Date).ToUniversalTime()
    Write-Host "Querying user-reported submissions from $($startDate.ToString('yyyy-MM-dd')) to $($endDate.ToString('yyyy-MM-dd')) via Get-ReportSubmission..." -ForegroundColor Cyan

    $script:ExternalSubmissionsCsv = $null
    $connected = $false
    try {
        $connected = Connect-SecurityCompliance -UserPrincipalName $UserPrincipalName -Days $Days
    } catch {
        Write-Verbose "Connect-SecurityCompliance threw: $($_.Exception.Message)"
        $connected = $false
    }

    $rawSubs = $null
    if ($connected) {
        # Tier 2 produced an external CSV — import that.
        if ($script:ExternalSubmissionsCsv -and (Test-Path -LiteralPath $script:ExternalSubmissionsCsv)) {
            try {
                $rawSubs = Import-Csv -LiteralPath $script:ExternalSubmissionsCsv
                Write-Host "[OK] Imported $((@($rawSubs)).Count) submission rows from external window CSV" -ForegroundColor Green
            } catch {
                Write-Warning "Failed to read external submissions CSV: $($_.Exception.Message)"
            }
        }
        # Tier 1 — in-process cmdlet call.
        if (-not $rawSubs -and (Get-Command Get-ReportSubmission -ErrorAction SilentlyContinue)) {
            try {
                $rawSubs = @(Get-ReportSubmission -StartDate $startDate -EndDate $endDate -ResultSize Unlimited -ErrorAction Stop)
                Write-Host "[OK] Retrieved $((@($rawSubs)).Count) submission rows via Get-ReportSubmission" -ForegroundColor Green
            } catch {
                Write-Warning "Get-ReportSubmission failed: $($_.Exception.Message)"
            }
        }
    }

    if ($rawSubs) {
        # Filter to user-reported emails (PTA only acts on user-reported phish;
        # admin submissions and non-email reports are out of scope).
        $filtered = @($rawSubs | Where-Object {
            ($null -eq $_.Type   -or [string]$_.Type   -eq '' -or [string]$_.Type   -eq 'Email') -and
            ($null -eq $_.Source -or [string]$_.Source -eq '' -or [string]$_.Source -match '^(User|EndUser)$')
        })
        $normalized = foreach ($row in $filtered) { ConvertTo-NormalizedSubmission -Row $row }
        Write-Host "[OK] Filtered to $((@($normalized)).Count) user-reported email submissions" -ForegroundColor Green
        return @($normalized)
    }

    Write-Warning "Security & Compliance PowerShell unavailable — falling back to Graph beta emailThreats (may return incomplete data)."
    return Get-UserReportedSubmissionsViaGraph -Days $Days
}

#endregion

# ─────────────────────────────────────────────────────────────────────────────
#region Data Retrieval
# ─────────────────────────────────────────────────────────────────────────────

function Invoke-GraphRequestWithRetry {
    <#
    .SYNOPSIS
        Invoke-MgGraphRequest wrapper with throttling/backoff handling.
    #>
    param(
        [string]$Uri,
        [string]$Method = 'GET',
        $Body = $null,
        [int]$MaxAttempts = 5
    )
    $attempt = 0
    while ($true) {
        $attempt++
        try {
            if ($Body) {
                return Invoke-MgGraphRequest -Uri $Uri -Method $Method -Body $Body -ContentType 'application/json'
            }
            return Invoke-MgGraphRequest -Uri $Uri -Method $Method
        }
        catch {
            $msg = $_.Exception.Message
            $isThrottle = $msg -match '429|503|timeout|throttl'
            if ($attempt -ge $MaxAttempts -or -not $isThrottle) { throw }
            $wait = [math]::Min(60, [math]::Pow(2, $attempt))
            Write-Verbose "Throttled on attempt $attempt; sleeping ${wait}s"
            Start-Sleep -Seconds $wait
        }
    }
}

function Get-PhishingIncidents {
    <#
    .SYNOPSIS
        Retrieves user-reported phishing incidents by paging /security/incidents
        with server-side date filter and $expand=alerts, then filtering
        client-side on alert title / incident displayName.
    #>
    param([int]$Days)

    $cutoff = (Get-Date).AddDays(-$Days).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    Write-Host "Querying incidents created since $cutoff..." -ForegroundColor Cyan

    $phishIncidents = New-Object System.Collections.Generic.List[object]
    $seenIds = [System.Collections.Generic.HashSet[string]]::new()
    $totalScanned = 0
    $pageNum = 0
    # Only match alerts the Phishing Triage Agent actually scopes over: alerts
    # raised because a user reported a message via Outlook's Report button
    # (Defender alert title "Email reported by user as <category>"). System-
    # detected alerts like "Phish delivered" or InitialAccess phish detections
    # are anti-phish policy hits, not user reports, and PTA never sees them —
    # including them inflates the report and produces misleading "Not Processed"
    # counts.
    $phishPatterns = @(
        'Email reported by user'
    )

    # Graph /security/incidents doesn't return @odata.nextLink reliably;
    # paginate via time-window using oldest createdDateTime as upper bound.
    $upperBound = $null
    while ($true) {
        $pageNum++
        if ($upperBound) {
            $filter = "createdDateTime ge $cutoff and createdDateTime lt $upperBound"
        } else {
            $filter = "createdDateTime ge $cutoff"
        }
        $enc = [uri]::EscapeDataString($filter)
        $uri = "https://graph.microsoft.com/v1.0/security/incidents?`$filter=$enc&`$top=50&`$orderby=createdDateTime desc&`$expand=alerts"

        $response = Invoke-GraphRequestWithRetry -Uri $uri
        $values = Get-HashValue $response 'value'
        if (-not $values -or $values.Count -eq 0) { break }

        $pageNewCount = 0
        $oldestCreated = $null
        foreach ($inc in $values) {
            $id = [string](Get-HashValue $inc 'id')
            if (-not $seenIds.Add($id)) { continue }   # skip dupes across pages
            $pageNewCount++
            $totalScanned++

            $created = Get-HashValue $inc 'createdDateTime'
            # Normalize to ISO 8601 UTC string for comparison / next filter
            if ($created -is [DateTime]) {
                $createdIso = $created.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
            } else {
                $createdIso = [string]$created
            }
            if (-not $oldestCreated -or $createdIso -lt $oldestCreated) { $oldestCreated = $createdIso }

            $isPhish = $false
            $dn = Get-HashValue $inc 'displayName'
            foreach ($p in $phishPatterns) {
                if ($dn -and $dn -match [regex]::Escape($p)) { $isPhish = $true; break }
            }
            if (-not $isPhish) {
                $alerts = Get-HashValue $inc 'alerts'
                if ($alerts) {
                    foreach ($a in $alerts) {
                        $t = Get-HashValue $a 'title'
                        if (-not $t) { continue }
                        foreach ($p in $phishPatterns) {
                            if ($t -match [regex]::Escape($p)) { $isPhish = $true; break }
                        }
                        if ($isPhish) { break }
                    }
                }
            }
            if ($isPhish) { $phishIncidents.Add($inc) }
        }

        Write-Host ("  Page {0}: scanned {1} new ({2} total), {3} phishing so far, oldest={4}" -f `
            $pageNum, $pageNewCount, $totalScanned, $phishIncidents.Count, $oldestCreated) -ForegroundColor Gray

        # If we got fewer than $top new items, we've reached the end
        if ($pageNewCount -lt 50) { break }
        if (-not $oldestCreated) { break }

        # Advance upper bound to just-older-than the oldest we saw
        # (ISO 8601 strings sort lexicographically; strict lt is fine)
        $upperBound = $oldestCreated
    }

    Write-Host "[OK] Found $($phishIncidents.Count) user-reported phishing incidents (scanned $totalScanned total over $pageNum pages)" -ForegroundColor Green
    return $phishIncidents.ToArray()
}

function Get-IncidentPTADetails {
    <#
    .SYNOPSIS
        Enriches an incident with PTA indicators from beta endpoint and alert details.
        Accepts optional pre-fetched lookups to avoid per-incident API calls.
    #>
    param(
        $Incident,
        [hashtable]$BetaIncidentMap = $null,
        [hashtable]$BetaAlertMap = $null,
        [string]$TenantId = $null
    )

    $result = [PSCustomObject]@{
        IncidentId          = $Incident.id
        Title               = $Incident.displayName
        Severity            = $Incident.severity
        Status              = $Incident.status
        CreatedDateTime     = $Incident.createdDateTime
        LastUpdateDateTime  = $Incident.lastUpdateDateTime
        AssignedTo          = $Incident.assignedTo
        Classification      = $null
        Determination       = $null
        AlertCount          = if ($Incident.alerts) { $Incident.alerts.Count } else { 0 }
        SubmissionCount     = 0     # analyzedMessageEvidence count across phish alerts (matches portal)
        PhishAlertCount     = 0     # number of "Email reported by user" alerts in this incident
        NetworkMessageIds   = @()   # NetworkMessageIds from analyzedMessageEvidence (for Submissions join)
        InternetMessageIds  = @()   # RFC-822 Message-IDs from analyzedMessageEvidence (primary join key for Graph submissions)
        EvidenceFingerprints = @()  # sender|recipient|subject tuples as a last-resort join key
        PTAStatus           = 'Missed'  # Default: Not Processed
        PTAIndicators       = ''
        ReportedBy          = ''
        ReporterDisplayName = ''
        ReporterUpn         = ''
        TriageMinutes       = $null
        ResolveMinutes      = $null
        PhishingAlertResolved = $null
        PortalLink          = "https://security.microsoft.com/incidents/$($Incident.id)"
        UserLink            = ''
        FailureReason       = ''   # inferred root-cause text for Failed incidents (full detail)
        RootCause           = ''   # short categorized root-cause label
    }

    # ── Get reported-by from alert evidence ──
    # userEvidence is the richest source (has displayName + UPN + azureAdUserId);
    # mailboxEvidence often has only accountName. Prefer userEvidence when available.
    if ($Incident.alerts) {
        foreach ($alert in $Incident.alerts) {
            if ($alert.title -notmatch 'Email reported by user') { continue }
            if (-not $alert.evidence) { continue }
            # Pass 1: userEvidence (richest)
            foreach ($ev in $alert.evidence) {
                $odt = [string]$ev.'@odata.type'
                if ($odt -match 'userEvidence' -and $ev.userAccount) {
                    $ua = $ev.userAccount
                    if ($ua.userPrincipalName) { $result.ReporterUpn = [string]$ua.userPrincipalName }
                    if ($ua.displayName)       { $result.ReporterDisplayName = [string]$ua.displayName }
                    if ($ua.accountName)       { $result.ReportedBy = [string]$ua.accountName }
                    if ($ua.azureAdUserId) {
                        $tid = if ($TenantId) { $TenantId } else { (Get-MgContext).TenantId }
                        $aad = [string]$ua.azureAdUserId
                        $acctName = [string]$ua.accountName
                        $upn = [string]$ua.userPrincipalName
                        $domain = ''
                        if ($upn -and $upn -match '@') { $domain = ($upn -split '@',2)[1] }
                        $qs = "aad=$aad"
                        if ($acctName) { $qs += "&accountName=" + [uri]::EscapeDataString($acctName) }
                        if ($domain)   { $qs += "&accountDomain=" + [uri]::EscapeDataString($domain) }
                        if ($upn)      { $qs += "&upn=" + [uri]::EscapeDataString($upn) }
                        $qs += "&tab=overview&tid=$tid"
                        $result.UserLink = "https://security.microsoft.com/user?$qs"
                    }
                    break
                }
            }
            # Pass 2: mailboxEvidence fallback (only if we didn't get anything from userEvidence)
            if (-not $result.UserLink) {
                foreach ($ev in $alert.evidence) {
                    $odt = [string]$ev.'@odata.type'
                    if ($odt -match 'mailboxEvidence' -and $ev.userAccount) {
                        $ua = $ev.userAccount
                        if (-not $result.ReportedBy -and $ua.accountName) { $result.ReportedBy = [string]$ua.accountName }
                        if (-not $result.ReporterUpn -and $ev.primaryAddress) { $result.ReporterUpn = [string]$ev.primaryAddress }
                        if ($ua.azureAdUserId) {
                            $tid = if ($TenantId) { $TenantId } else { (Get-MgContext).TenantId }
                            $aad = [string]$ua.azureAdUserId
                            $acctName = [string]$ua.accountName
                            $upn = if ($result.ReporterUpn) { $result.ReporterUpn } else { [string]$ev.primaryAddress }
                            $domain = ''
                            if ($upn -and $upn -match '@') { $domain = ($upn -split '@',2)[1] }
                            $qs = "aad=$aad"
                            if ($acctName) { $qs += "&accountName=" + [uri]::EscapeDataString($acctName) }
                            if ($domain)   { $qs += "&accountDomain=" + [uri]::EscapeDataString($domain) }
                            if ($upn)      { $qs += "&upn=" + [uri]::EscapeDataString($upn) }
                            $qs += "&tab=overview&tid=$tid"
                            $result.UserLink = "https://security.microsoft.com/user?$qs"
                        }
                        break
                    }
                }
            }
            break
        }
    }

    # ── Enrich with beta endpoint (tags) ──
    $ptaDetected = $false    # any PTA indicator at all (agent took ownership)
    $ptaFailed = $false      # explicit failure signal
    $ptaAssigned = $false    # agent was assigned but may or may not have produced a verdict
    $ptaGotVerdict = $false  # agent actually wrote alert.classification
    $indicators = @()

    try {
        $detailed = $null
        if ($BetaIncidentMap -and $BetaIncidentMap.ContainsKey([string]$Incident.id)) {
            $detailed = $BetaIncidentMap[[string]$Incident.id]
        }
        else {
            $betaUri = "https://graph.microsoft.com/beta/security/incidents/$($Incident.id)"
            $detailed = Invoke-MgGraphRequest -Uri $betaUri -Method GET -ErrorAction SilentlyContinue
        }

        if ($detailed) {
            # Check system tags
            if ($detailed.systemTags) {
                $ptaTags = $detailed.systemTags | Where-Object { $_ -like '*Phish*' -or $_ -like '*Triage*' -or $_ -like '*Agent*' }
                if ($ptaTags) {
                    $ptaDetected = $true
                    $indicators += $ptaTags | ForEach-Object { "SystemTag: $_" }
                }
            }

            # Check custom tags
            if ($detailed.customTags) {
                $agentTags = $detailed.customTags | Where-Object { $_ -like '*Agent*' -or $_ -like '*PTA*' -or $_ -like '*Triage*' }
                if ($agentTags) {
                    $ptaDetected = $true
                    $ptaAssigned = $true
                    foreach ($tag in $agentTags) {
                        $indicators += "CustomTag: $tag"
                        if ($tag -match 'FAILED|ERROR') { $ptaFailed = $true }
                    }
                }
            }

            # Check standard tags
            if ($detailed.tags) {
                $agentTags = $detailed.tags | Where-Object { $_ -like '*Agent*' -or $_ -like '*PTA*' }
                if ($agentTags) {
                    $ptaDetected = $true
                    $indicators += $agentTags | ForEach-Object { "Tag: $_" }
                }
            }
        }
    }
    catch {
        Write-Verbose "  Could not retrieve beta tags for $($Incident.id): $($_.Exception.Message)"
    }

    # ── Check alert-level classification + count submissions ──
    # A "submission" = one analyzedMessageEvidence item. This matches the
    # Defender portal's "Submissions" metric which counts individual reported
    # emails, not incidents or alerts.
    if ($Incident.alerts) {
        $firstPhishAlertProcessed = $false
        foreach ($alert in $Incident.alerts) {
            if ($alert.title -notmatch 'Email reported by user') { continue }
            $result.PhishAlertCount++

            # Get detailed alert info (evidence only available here)
            $detailedAlert = $null
            try {
                if ($BetaAlertMap -and $BetaAlertMap.ContainsKey([string]$alert.id)) {
                    $detailedAlert = $BetaAlertMap[[string]$alert.id]
                }
                else {
                    $betaAlertUri = "https://graph.microsoft.com/beta/security/alerts_v2/$($alert.id)"
                    $detailedAlert = Invoke-MgGraphRequest -Uri $betaAlertUri -Method GET -ErrorAction SilentlyContinue
                }
            } catch {
                Write-Verbose "  Could not get alert details: $($_.Exception.Message)"
            }

            # Count analyzedMessageEvidence = # of submissions this alert represents
            $msgCount = 0
            if ($detailedAlert -and $detailedAlert.evidence) {
                foreach ($ev in $detailedAlert.evidence) {
                    if ([string](Get-HashValue $ev '@odata.type') -eq '#microsoft.graph.security.analyzedMessageEvidence') {
                        $msgCount++
                        $nmid = Get-HashValue $ev 'networkMessageId'
                        if ($nmid) { $result.NetworkMessageIds += [string]$nmid }
                        $imid = Get-HashValue $ev 'internetMessageId'
                        if ($imid) { $result.InternetMessageIds += [string]$imid }
                        # p1Sender / p2Sender are OBJECTS (emailAddress, displayName, domainName).
                        # Pull the actual address for fingerprinting.
                        $sndr = $null
                        $p2 = Get-HashValue $ev 'p2Sender'
                        if ($p2) { $sndr = [string](Get-HashValue $p2 'emailAddress') }
                        if (-not $sndr) {
                            $p1 = Get-HashValue $ev 'p1Sender'
                            if ($p1) { $sndr = [string](Get-HashValue $p1 'emailAddress') }
                        }
                        if (-not $sndr) { $sndr = [string](Get-HashValue $ev 'senderFromAddress') }
                        # Alert evidence uses recipientEmailAddress (singular);
                        # older tenants may expose recipientEmailAddresses (plural).
                        $recips = Get-HashValue $ev 'recipientEmailAddresses'
                        if (-not $recips) {
                            $single = Get-HashValue $ev 'recipientEmailAddress'
                            if ($single) { $recips = @($single) }
                        }
                        $subj = [string](Get-HashValue $ev 'subject')
                        if ($recips) {
                            foreach ($r in @($recips)) {
                                $fp = ('{0}|{1}|{2}' -f $sndr, $r, $subj).ToLowerInvariant()
                                $result.EvidenceFingerprints += $fp
                            }
                        } elseif ($sndr -or $subj) {
                            $result.EvidenceFingerprints += ('{0}||{1}' -f $sndr, $subj).ToLowerInvariant()
                        }
                        # Also a subject-only fallback (last resort)
                        if ($subj) {
                            $result.EvidenceFingerprints += ('||{0}' -f $subj).ToLowerInvariant()
                        }
                    }
                }
            }
            # If no evidence found, assume 1 submission (the reported email itself)
            if ($msgCount -eq 0) { $msgCount = 1 }
            $result.SubmissionCount += $msgCount

            # Only take classification/timing from the FIRST phish alert
            # (additional alerts on same incident are parallel submissions)
            if (-not $firstPhishAlertProcessed) {
                $firstPhishAlertProcessed = $true
                if ($detailedAlert) {
                    if ($detailedAlert.classification) {
                        $result.Classification = $detailedAlert.classification
                        $result.Determination = $detailedAlert.determination
                        $ptaDetected = $true
                        $ptaGotVerdict = $true
                        $resolvedStr = if ($detailedAlert.resolvedDateTime) {
                            (Get-Date $detailedAlert.resolvedDateTime).ToString('MM/dd/yyyy HH:mm:ss')
                        } else { '' }
                        $indicators += "AlertClassified: $($detailedAlert.classification)/$($detailedAlert.determination) (resolved $resolvedStr)"
                    }
                    if ($detailedAlert.resolvedDateTime) {
                        $result.PhishingAlertResolved = $detailedAlert.resolvedDateTime
                    } elseif ($detailedAlert.lastUpdateDateTime) {
                        $result.PhishingAlertResolved = $detailedAlert.lastUpdateDateTime
                    } elseif ($alert.lastUpdateDateTime) {
                        $result.PhishingAlertResolved = $alert.lastUpdateDateTime
                    }
                }
                else {
                    # Fallback to v1.0 alert data
                    if ($alert.classification) {
                        $result.Classification = $alert.classification
                        $result.Determination = $alert.determination
                        $ptaDetected = $true
                        $ptaGotVerdict = $true
                    }
                    if ($alert.resolvedDateTime) { $result.PhishingAlertResolved = $alert.resolvedDateTime }
                    elseif ($alert.lastUpdateDateTime) { $result.PhishingAlertResolved = $alert.lastUpdateDateTime }
                }
            }
        }
    }

    # Also check incident-level classification if alert didn't have one
    if (-not $result.Classification -and $Incident.classification -and $Incident.classification -ne 'unknown') {
        $result.Classification = $Incident.classification
        $result.Determination = $Incident.determination
        $ptaDetected = $true
        $ptaGotVerdict = $true
    }

    # ── Assign PTA status ──
    # Heuristic for "Failed": the Phishing Triage Agent task exists as a
    # Security Copilot Task (visible in portal Tasks panel) but the agent
    # never wrote an alert.classification. Graph does NOT expose the
    # task-level failure state, so we infer it from:
    #   - Agent was assigned (CustomTag 'Agent' or similar), AND
    #   - No alert classification was produced, AND
    #   - Enough time has passed that the agent would have finished.
    # We use a 60-minute gate to avoid flagging in-flight runs. The portal
    # surface for a still-running agent is "In progress", not "Failed".
    $ageMin = try { ((Get-Date).ToUniversalTime() - [DateTime]::Parse($Incident.createdDateTime).ToUniversalTime()).TotalMinutes } catch { 9999 }
    if (-not $ptaFailed -and $ptaAssigned -and -not $ptaGotVerdict -and $ageMin -gt 60) {
        $ptaFailed = $true
        $indicators += "InferredFailure: Agent assigned but no verdict after $([int]$ageMin) min"
    }

    if ($ptaFailed) {
        $result.PTAStatus = 'Failed'
    }
    elseif ($ptaDetected -and $ptaGotVerdict) {
        $result.PTAStatus = 'Processed'
    }
    elseif ($ptaDetected) {
        # Agent took ownership but no verdict yet and under the 60-min gate:
        # treat as in-flight / processed to avoid false Failed flags.
        $result.PTAStatus = 'Processed'
    }
    else {
        $result.PTAStatus = 'Missed'
    }

    # ── Root-cause inference for Failed incidents ──
    # Graph does not expose the Security Copilot task failure reason directly
    # (portal shows "Phishing Triage Agent failed to run" with no further detail).
    # We surface the most likely cause based on available signals.
    if ($result.PTAStatus -eq 'Failed') {
        $reasons = @()
        $lastMod   = [string]$detailed.lastModifiedBy
        $comments  = @($detailed.comments)
        $alertStat = if ($Incident.alerts) { [string]$Incident.alerts[0].status } else { '' }

        # ── Signal 0 (highest confidence): "stub-only" analyzedMessageEvidence ──
        # When the original email is no longer retrievable (deleted, quarantined,
        # recalled, retention-expired, or replication lag), Defender still creates
        # an analyzedMessageEvidence record from the submission stub but every
        # field that requires fetching the MIME body is empty/unknown. PTA's
        # "Investigate email message" / detonation step cannot run, so the agent
        # never produces a verdict. Confirmed pattern from incident 54890:
        #   deliveryLocation = 'unknown'   (mailbox lookup failed)
        #   deliveryAction   = 'unknown'
        #   antiSpamDirection = null       (headers never inspected)
        #   urlCount = 0 AND attachmentsCount = 0
        #   threatDetectionMethods = []    (analysis pipeline produced nothing)
        #   senderIp = '255.255.255.255'   (sentinel for unresolved)
        #   verdict  = 'noThreatsFound'    (placeholder default)
        $stubOnly = $false
        $ame = $null
        if ($Incident.alerts -and $Incident.alerts[0].evidence) {
            $ame = @($Incident.alerts[0].evidence | Where-Object {
                $_.'@odata.type' -eq '#microsoft.graph.security.analyzedMessageEvidence'
            }) | Select-Object -First 1
        }
        if ($ame) {
            $stubFlags = 0
            if ([string]$ame.deliveryLocation  -in @('unknown','')) { $stubFlags++ }
            if ([string]$ame.deliveryAction    -in @('unknown','')) { $stubFlags++ }
            if (-not $ame.antiSpamDirection)                        { $stubFlags++ }
            if ([int]($ame.urlCount)         -eq 0)                 { $stubFlags++ }
            if ([int]($ame.attachmentsCount) -eq 0)                 { $stubFlags++ }
            if (-not @($ame.threatDetectionMethods))                { $stubFlags++ }
            if ([string]$ame.senderIp -eq '255.255.255.255')        { $stubFlags++ }
            # 5+ of 7 diagnostic flags => high-confidence stub-only pattern.
            if ($stubFlags -ge 5) {
                $stubOnly = $true
                $reasons += "Reported email could not be retrieved for analysis/detonation (high confidence): analyzedMessageEvidence is a stub [deliveryLocation=$([string]$ame.deliveryLocation), deliveryAction=$([string]$ame.deliveryAction), urls=$([int]$ame.urlCount), attachments=$([int]$ame.attachmentsCount), senderIp=$([string]$ame.senderIp), antiSpamDirection=$(if($ame.antiSpamDirection){$ame.antiSpamDirection}else{'null'}), threatDetectionMethods=empty]. Likely causes: original message was deleted/quarantined/recalled/retention-expired before the agent ran, or mailbox replication lag."
                $indicators += "StubOnlyMessage: $stubFlags/7 diagnostic flags match"
            }
        }

        # Signal 1: another automation modified the incident after agent was assigned.
        # Suppressed when stub-only fires (the playbook comment is usually a red herring).
        if (-not $stubOnly -and $lastMod -and $lastMod -notmatch '(?i)agent|phishing|triage|copilot') {
            $reasons += "Incident was last modified by '$lastMod' (another playbook/automation may have preempted the agent)"
        }

        # Signal 2: playbook comments referencing failure / error.
        # Suppressed when stub-only fires.
        if (-not $stubOnly) {
            foreach ($c in $comments) {
                $ctext = [string]$c.comment
                if ($ctext -match '(?i)could not|failed|error|permission|denied|unable') {
                    $who = [string]$c.createdByDisplayName
                    $snippet = ($ctext -replace '<[^>]+>','').Trim()
                    if ($snippet.Length -gt 140) { $snippet = $snippet.Substring(0,140) + '...' }
                    $reasons += "Comment from '$who': $snippet"
                }
            }
        }

        # Signal 3: incident age vs alert state.
        if ($alertStat -eq 'inProgress' -and $ageMin -gt 1440) {
            $reasons += "Alert has been stuck in 'inProgress' for $([int]($ageMin/60))h (agent run did not complete)"
        } elseif ($alertStat -eq 'new' -and $ageMin -gt 60) {
            $reasons += "Alert still in 'new' state after $([int]$ageMin) min (agent may not have been invoked)"
        }

        # Signal 4: sparse evidence (often correlates with insufficient signal for agent).
        $evCount = 0
        if ($Incident.alerts -and $Incident.alerts[0].evidence) { $evCount = @($Incident.alerts[0].evidence).Count }
        if (-not $stubOnly -and $evCount -le 2) {
            $reasons += "Only $evCount evidence item(s) — agent may have had insufficient signal"
        }

        # ── Derive a short categorized RootCause label (priority order) ──
        # The detailed $reasons list is preserved in FailureReason for drill-down;
        # RootCause is the simplified bucket used in summary views.
        $shortCause = $null
        if ($stubOnly) {
            $shortCause = 'Reported email unavailable for analysis'
        }
        elseif ($reasons -match '(?i)preempt|last modified by') {
            $shortCause = 'Preempted by other automation'
        }
        elseif ($reasons -match '(?i)could not|failed|error|permission|denied|unable') {
            $shortCause = 'Agent error (see comments)'
        }
        elseif ($reasons -match "(?i)stuck in 'inProgress'|did not complete|may not have been invoked") {
            $shortCause = 'Agent did not complete'
        }
        elseif ($reasons -match '(?i)insufficient signal') {
            $shortCause = 'Insufficient signal'
        }

        if (-not $reasons) {
            $shortCause = 'Investigation Required'
            $reasons += 'No root-cause signals could be inferred from Graph data. Manual investigation required: review the incident Tasks panel in the Defender portal for the exact Copilot message (commonly SCU capacity exhausted, URBAC/Defender permissions missing for the agent identity, Conditional Access blocking the agent, or transient backend error).'
        }
        if (-not $shortCause) { $shortCause = 'Investigation Required' }

        $result.RootCause = $shortCause
        $result.FailureReason = ($reasons -join ' | ')
        $indicators += "RootCause: $shortCause"
        $indicators += "FailureReason: $($result.FailureReason)"
    }

    $result.PTAIndicators = ($indicators -join '; ')

    # ── Calculate timing metrics ──
    $created = [DateTime]::Parse($Incident.createdDateTime)

    # MTTT: alert resolved/updated - incident created
    if ($result.PhishingAlertResolved) {
        try {
            $triaged = [DateTime]::Parse($result.PhishingAlertResolved)
            $result.TriageMinutes = [math]::Round(($triaged - $created).TotalMinutes, 1)
        }
        catch { }
    }

    # MTTR: incident lastUpdate - incident created (only for resolved)
    if ($Incident.status -eq 'resolved' -and $Incident.lastUpdateDateTime) {
        try {
            $resolved = [DateTime]::Parse($Incident.lastUpdateDateTime)
            $result.ResolveMinutes = [math]::Round(($resolved - $created).TotalMinutes, 1)
        }
        catch { }
    }

    return $result
}

#endregion

# ─────────────────────────────────────────────────────────────────────────────
#region Metrics Calculation
# ─────────────────────────────────────────────────────────────────────────────

function Get-MedianValue {
    param([double[]]$Values)
    if ($Values.Count -eq 0) { return 0 }
    $sorted = $Values | Sort-Object
    $mid = [math]::Floor($sorted.Count / 2)
    if ($sorted.Count % 2 -eq 0) {
        return ($sorted[$mid - 1] + $sorted[$mid]) / 2
    }
    return $sorted[$mid]
}

function Format-MinutesToHHMMSS {
    param([double]$Minutes)
    $ts = [TimeSpan]::FromMinutes([math]::Abs($Minutes))
    if ($ts.TotalHours -ge 1) {
        return "{0}:{1:D2}:{2:D2}" -f [math]::Floor($ts.TotalHours), $ts.Minutes, $ts.Seconds
    }
    return "{0:D2}:{1:D2}" -f $ts.Minutes, $ts.Seconds
}

function Get-PTAMetrics {
    param(
        $Incidents,
        $Submissions = @()   # from Get-ReportSubmission (authoritative)
    )

    # ── Submission-level counts ──
    # If we have authoritative submissions from Get-ReportSubmission, use that
    # as the total and map each submission to an incident by NetworkMessageId.
    # Otherwise fall back to summing SubmissionCount from incident evidence.
    $useAuthoritative = ($Submissions -and $Submissions.Count -gt 0)

    $totalSubmissions = 0; $addressedSubmissions = 0; $resolvedSubmissions = 0
    $fpSubmissions = 0; $tpSubmissions = 0; $failedSubmissions = 0; $missedSubmissions = 0

    if ($useAuthoritative) {
        # Build lookups from alert evidence. Graph emailThreatSubmission exposes
        # internetMessageId (RFC-822 Message-ID), not networkMessageId, so we
        # need both maps plus a sender|recipient|subject fingerprint fallback.
        $nmidToIncident = @{}
        $imidToIncident = @{}
        $fpToIncident   = @{}
        foreach ($inc in $Incidents) {
            foreach ($nmid in $inc.NetworkMessageIds) {
                if ($nmid -and -not $nmidToIncident.ContainsKey([string]$nmid)) {
                    $nmidToIncident[[string]$nmid] = $inc
                }
            }
            foreach ($imid in $inc.InternetMessageIds) {
                if ($imid -and -not $imidToIncident.ContainsKey([string]$imid)) {
                    $imidToIncident[[string]$imid] = $inc
                }
            }
            foreach ($fp in $inc.EvidenceFingerprints) {
                if ($fp -and -not $fpToIncident.ContainsKey($fp)) {
                    $fpToIncident[$fp] = $inc
                }
            }
        }

        Write-Verbose ("Evidence keys collected: nmid={0} imid={1} fp={2}" -f $nmidToIncident.Count, $imidToIncident.Count, $fpToIncident.Count)

        $totalSubmissions = $Submissions.Count
        $matchStats = @{ nmid=0; imid=0; fp=0; none=0 }
        $subOutcomes = New-Object System.Collections.Generic.List[object]
        foreach ($sub in $Submissions) {
            $matchedInc = $null
            $matchedBy = $null

            # 1) Try NetworkMessageId (unlikely from Graph, but CSV imports may have it)
            foreach ($prop in 'NetworkMessageId','MessageId','ObjectId') {
                if ($sub.PSObject.Properties[$prop] -and $sub.$prop) {
                    $key = [string]$sub.$prop
                    if ($nmidToIncident.ContainsKey($key)) { $matchedInc = $nmidToIncident[$key]; $matchedBy='nmid'; break }
                }
            }

            # 2) Try InternetMessageId (primary key for Graph-sourced submissions)
            if (-not $matchedInc -and $sub.PSObject.Properties['InternetMessageId'] -and $sub.InternetMessageId) {
                $key = [string]$sub.InternetMessageId
                if ($imidToIncident.ContainsKey($key)) { $matchedInc = $imidToIncident[$key]; $matchedBy='imid' }
            }

            # 3) Fallback: sender|recipient|subject fingerprint
            if (-not $matchedInc) {
                $sndr = [string]$sub.SenderAddress
                $rcpt = [string]$sub.ReceivedBy
                $subj = [string]$sub.Subject
                $fp = ('{0}|{1}|{2}' -f $sndr, $rcpt, $subj).ToLowerInvariant()
                if ($fpToIncident.ContainsKey($fp)) { $matchedInc = $fpToIncident[$fp]; $matchedBy='fp' }
                if (-not $matchedInc) {
                    $fp2 = ('{0}||{1}' -f $sndr, $subj).ToLowerInvariant()
                    if ($fpToIncident.ContainsKey($fp2)) { $matchedInc = $fpToIncident[$fp2]; $matchedBy='fp' }
                }
                if (-not $matchedInc -and $subj) {
                    $fp3 = ('||{0}' -f $subj).ToLowerInvariant()
                    if ($fpToIncident.ContainsKey($fp3)) { $matchedInc = $fpToIncident[$fp3]; $matchedBy='fp' }
                }
            }

            if ($matchedBy) { $matchStats[$matchedBy]++ } else { $matchStats['none']++ }

            # Build a per-submission outcome record for the detailed report section.
            $outcomeCategory = 'NotProcessed'   # default bucket
            $outcomeReason   = ''
            $incidentId      = $null
            $incidentStatus  = $null
            $ptaClass        = $null
            $ptaDet          = $null

            if ($matchedInc) {
                $incidentId     = $matchedInc.IncidentId
                $incidentStatus = $matchedInc.Status
                $ptaClass       = $matchedInc.Classification
                $ptaDet         = $matchedInc.Determination
                switch ($matchedInc.PTAStatus) {
                    'Processed' {
                        $addressedSubmissions++
                        if ($matchedInc.Classification -eq 'falsePositive') {
                            $fpSubmissions++
                            $outcomeCategory = 'AddressedFP'
                            $outcomeReason   = 'Agent classified as false positive'
                            if ($matchedInc.Status -eq 'resolved') {
                                $resolvedSubmissions++
                                $outcomeReason = 'Agent classified as false positive and resolved the incident'
                            }
                        } elseif ($matchedInc.Classification -eq 'truePositive') {
                            $tpSubmissions++
                            $outcomeCategory = 'AddressedTP'
                            $outcomeReason   = 'Agent confirmed as true positive phishing'
                        } else {
                            $outcomeCategory = 'AddressedOther'
                            $outcomeReason   = "Agent addressed (classification: $($matchedInc.Classification))"
                        }
                    }
                    'Failed' {
                        $failedSubmissions++
                        $addressedSubmissions++
                        $outcomeCategory = 'Failed'
                        $outcomeReason   = 'Agent assigned to incident but never produced a verdict (Phishing Triage Agent failed to run)'
                    }
                    'Missed' {
                        $missedSubmissions++
                        $outcomeCategory = 'NotProcessed'
                        $outcomeReason   = 'Incident created but agent did not take action (auto-resolved upstream, ineligible, or duplicate)'
                    }
                }
            } else {
                # No matching Defender incident at all — typically pre-ZAPed, user-deleted, or no alert was raised.
                $missedSubmissions++
                $rd   = [string](Get-HashValue $sub 'ResultDetail')
                $oc   = [string](Get-HashValue $sub 'OriginalCategory')
                $rcat = [string](Get-HashValue $sub 'Result')
                if ($rd -match '(?i)zap')               { $outcomeCategory = 'ZAPed';        $outcomeReason = 'Message was zapped (post-delivery auto-remediated); no user-reported phish incident raised' }
                elseif ($rd -match '(?i)deletedByUser') { $outcomeCategory = 'UserDeleted';  $outcomeReason = 'User deleted the message before analysis could complete' }
                elseif ($rd -match '(?i)notFound|notExist') { $outcomeCategory = 'NotFound'; $outcomeReason = 'Message not found in mailbox at analysis time (moved, deleted, or hard-deleted)' }
                elseif ($rcat -eq 'notJunk' -or $oc -eq 'notJunk') { $outcomeCategory = 'NotJunk'; $outcomeReason = 'Reported as "not junk" — not a phishing submission, no PTA incident expected' }
                elseif ($rd)                            { $outcomeCategory = 'NoIncident';   $outcomeReason = "No matching incident (submission result: $rd)" }
                else                                    { $outcomeCategory = 'NoIncident';   $outcomeReason = 'No matching Defender phishing incident created for this submission' }
            }

            [void]$subOutcomes.Add([pscustomobject]@{
                SubmissionId      = [string](Get-HashValue $sub 'Id')
                Subject           = [string](Get-HashValue $sub 'Subject')
                SenderAddress     = [string](Get-HashValue $sub 'SenderAddress')
                ReportedBy        = [string](Get-HashValue $sub 'ReportedBy')
                ReceivedBy        = [string](Get-HashValue $sub 'ReceivedBy')
                ReporterDisplayName = if ($matchedInc -and $matchedInc.PSObject.Properties['ReporterDisplayName']) { [string]$matchedInc.ReporterDisplayName } else { '' }
                ReporterUpn       = if ($matchedInc -and $matchedInc.PSObject.Properties['ReporterUpn']) { [string]$matchedInc.ReporterUpn } else { '' }
                UserLink          = if ($matchedInc -and $matchedInc.PSObject.Properties['UserLink']) { [string]$matchedInc.UserLink } else { '' }
                SubmittedDate     = Get-HashValue $sub 'SubmittedDate'
                ReportType        = [string](Get-HashValue $sub 'ReportType')
                SubmissionStatus  = [string](Get-HashValue $sub 'Status')
                SubmissionResult  = [string](Get-HashValue $sub 'Result')
                SubmissionDetail  = [string](Get-HashValue $sub 'ResultDetail')
                MatchedBy         = if ($matchedBy) { $matchedBy } else { 'none' }
                IncidentId        = $incidentId
                IncidentStatus    = $incidentStatus
                AlertClassification = $ptaClass
                AlertDetermination  = $ptaDet
                OutcomeCategory   = $outcomeCategory
                OutcomeReason     = $outcomeReason
            })
        }
        Write-Host ("    Match breakdown:    nmid={0}, imid={1}, fingerprint={2}, unmatched={3}" -f `
            $matchStats['nmid'], $matchStats['imid'], $matchStats['fp'], $matchStats['none']) -ForegroundColor DarkGray
    } else {
        $subOutcomes = New-Object System.Collections.Generic.List[object]
        foreach ($inc in $Incidents) {
            $s = [int]$inc.SubmissionCount
            if ($s -le 0) { $s = 1 }
            $totalSubmissions += $s
            switch ($inc.PTAStatus) {
                'Processed' {
                    $addressedSubmissions += $s
                    if ($inc.Classification -eq 'falsePositive') {
                        $fpSubmissions += $s
                        if ($inc.Status -eq 'resolved') { $resolvedSubmissions += $s }
                    } elseif ($inc.Classification -eq 'truePositive') {
                        $tpSubmissions += $s
                    }
                }
                'Failed'   { $failedSubmissions += $s; $addressedSubmissions += $s }
                'Missed'   { $missedSubmissions += $s }
            }
        }
    }

    # Incident-level counts (kept for detail tables)
    $total = $Incidents.Count
    $processed = @($Incidents | Where-Object PTAStatus -eq 'Processed')
    $missed = @($Incidents | Where-Object PTAStatus -eq 'Missed')
    $failed = @($Incidents | Where-Object PTAStatus -eq 'Failed')

    # Classification breakdown (within processed)
    $fp = @($processed | Where-Object { $_.Classification -eq 'falsePositive' })
    $tp = @($processed | Where-Object {
        $_.Classification -eq 'truePositive'
    })

    # Resolved = FP incidents that are actually resolved status
    $resolvedByPTA = @($fp | Where-Object Status -eq 'resolved')
    $allResolved = @($Incidents | Where-Object Status -eq 'resolved')

    # MTTT — triage times (all incidents with valid TriageMinutes)
    $triageTimes = @($Incidents | Where-Object { $null -ne $_.TriageMinutes -and $_.TriageMinutes -ge 0 } | ForEach-Object { $_.TriageMinutes })
    $mtttMedian = if ($triageTimes.Count -gt 0) { Get-MedianValue $triageTimes } else { 0 }
    $mtttAvg = if ($triageTimes.Count -gt 0) { ($triageTimes | Measure-Object -Average).Average } else { 0 }
    $mtttMin = if ($triageTimes.Count -gt 0) { ($triageTimes | Measure-Object -Minimum).Minimum } else { 0 }
    $mtttMax = if ($triageTimes.Count -gt 0) { ($triageTimes | Measure-Object -Maximum).Maximum } else { 0 }

    # MTTR — resolve times (resolved incidents only)
    $resolveTimes = @($allResolved | Where-Object { $null -ne $_.ResolveMinutes -and $_.ResolveMinutes -ge 0 } | ForEach-Object { $_.ResolveMinutes })
    $mttrMedian = if ($resolveTimes.Count -gt 0) { Get-MedianValue $resolveTimes } else { 0 }
    $mttrAvg = if ($resolveTimes.Count -gt 0) { ($resolveTimes | Measure-Object -Average).Average } else { 0 }
    $mttrMin = if ($resolveTimes.Count -gt 0) { ($resolveTimes | Measure-Object -Minimum).Minimum } else { 0 }
    $mttrMax = if ($resolveTimes.Count -gt 0) { ($resolveTimes | Measure-Object -Maximum).Maximum } else { 0 }

    # Use SUBMISSION counts as primary (portal-matching). Incident counts kept under *Incidents.
    $addressedPct = if ($totalSubmissions -gt 0) { [math]::Round(($addressedSubmissions / $totalSubmissions) * 100, 1) } else { 0 }
    $resolvedPct = if ($addressedSubmissions -gt 0) { [math]::Round(($resolvedSubmissions / $addressedSubmissions) * 100, 0) } else { 0 }

    return [PSCustomObject]@{
        # Portal-aligned (submission-level) — PRIMARY
        Total              = $totalSubmissions
        Addressed          = $addressedSubmissions
        ResolvedByPTA      = $resolvedSubmissions
        Missed             = $missedSubmissions
        Failed             = $failedSubmissions
        FalsePositive      = $fpSubmissions
        TruePositive       = $tpSubmissions
        AddressedPct       = $addressedPct
        ResolvedPct        = $resolvedPct
        Processed          = $addressedSubmissions - $failedSubmissions

        # Incident-level — for detail tables
        TotalIncidents     = $total
        ProcessedIncidents = $processed.Count
        MissedIncidents    = $missed.Count
        FailedIncidents    = $failed.Count
        FPIncidents        = $fp.Count
        TPIncidents        = $tp.Count
        ResolvedIncidents  = $resolvedByPTA.Count
        AllResolved        = $allResolved.Count

        # Timing
        MTTTMedian         = $mtttMedian
        MTTTAvg            = $mtttAvg
        MTTTMin            = $mtttMin
        MTTTMax            = $mtttMax
        MTTTSamples        = $triageTimes.Count
        MTTRMedian         = $mttrMedian
        MTTRAvg            = $mttrAvg
        MTTRMin            = $mttrMin
        MTTRMax            = $mttrMax
        MTTRSamples        = $resolveTimes.Count
        SubmissionOutcomes = $subOutcomes.ToArray()
    }
}

#endregion

# ─────────────────────────────────────────────────────────────────────────────
#region CSV Export
# ─────────────────────────────────────────────────────────────────────────────

function Export-PTACsv {
    param($Incidents, [string]$Path)

    $Incidents | Select-Object `
        IncidentId, Title, Severity, Status, PTAStatus, RootCause, FailureReason,
        @{N='AlertClassification';E={$_.Classification}},
        @{N='AlertDetermination';E={$_.Determination}},
        ReportedBy, CreatedDateTime, TriageMinutes, ResolveMinutes,
        AssignedTo, AlertCount, PhishAlertCount, SubmissionCount, PortalLink, UserLink |
        Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8

    Write-Host "[OK] CSV exported: $Path" -ForegroundColor Green
}

#endregion

# ─────────────────────────────────────────────────────────────────────────────
#region HTML Report Generation
# ─────────────────────────────────────────────────────────────────────────────

function New-PTAHtmlReport {
    param(
        $Incidents,
        $Metrics,
        [int]$Days,
        [string]$Path
    )

    $genTime = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

    # ── Classify incidents for daily chart ──
    $startDate = (Get-Date).AddDays(-$Days).Date
    $endDate = (Get-Date).Date
    $dateLabels = @()
    $fpByDay = @{}; $tpByDay = @{}; $missedByDay = @{}; $failedByDay = @{}
    $fpIdsByDay = @{}; $tpIdsByDay = @{}; $missedIdsByDay = @{}; $failedIdsByDay = @{}

    $d = $startDate
    while ($d -le $endDate) {
        $key = $d.ToString('MM/dd')
        $dateLabels += $key
        $fpByDay[$key] = 0; $tpByDay[$key] = 0; $missedByDay[$key] = 0; $failedByDay[$key] = 0
        $fpIdsByDay[$key] = @(); $tpIdsByDay[$key] = @(); $missedIdsByDay[$key] = @(); $failedIdsByDay[$key] = @()
        $d = $d.AddDays(1)
    }

    foreach ($inc in $Incidents) {
        $created = [DateTime]::Parse($inc.CreatedDateTime)
        $key = $created.ToString('MM/dd')
        if (-not $fpByDay.ContainsKey($key)) { continue }

        switch ($inc.PTAStatus) {
            'Processed' {
                if ($inc.Classification -eq 'truePositive') {
                    $tpByDay[$key]++; $tpIdsByDay[$key] += $inc.IncidentId
                } else {
                    $fpByDay[$key]++; $fpIdsByDay[$key] += $inc.IncidentId
                }
            }
            'Missed'  { $missedByDay[$key]++; $missedIdsByDay[$key] += $inc.IncidentId }
            'Failed'  { $failedByDay[$key]++; $failedIdsByDay[$key] += $inc.IncidentId }
        }
    }

    # Build JS arrays
    $labelsJs = "'" + ($dateLabels -join "','") + "'"
    $fpDataJs = ($dateLabels | ForEach-Object { $fpByDay[$_] }) -join ','
    $tpDataJs = ($dateLabels | ForEach-Object { $tpByDay[$_] }) -join ','
    $missedDataJs = ($dateLabels | ForEach-Object { $missedByDay[$_] }) -join ','
    $failedDataJs = ($dateLabels | ForEach-Object { $failedByDay[$_] }) -join ','

    # Build ID arrays for click-through
    function ConvertTo-JsIdArray($dict, $keys) {
        $parts = foreach ($k in $keys) {
            $ids = $dict[$k]
            if ($ids.Count -eq 0) { '[]' }
            else { "['" + ($ids -join "','") + "']" }
        }
        return '[' + ($parts -join ',') + ']'
    }
    $fpIdsJs = ConvertTo-JsIdArray $fpIdsByDay $dateLabels
    $tpIdsJs = ConvertTo-JsIdArray $tpIdsByDay $dateLabels
    $missedIdsJs = ConvertTo-JsIdArray $missedIdsByDay $dateLabels
    $failedIdsJs = ConvertTo-JsIdArray $failedIdsByDay $dateLabels

    # ── Build incident tables ──
    $processed = $Incidents | Where-Object PTAStatus -eq 'Processed' | Sort-Object CreatedDateTime -Descending
    $missed = $Incidents | Where-Object PTAStatus -eq 'Missed' | Sort-Object CreatedDateTime -Descending
    $failed = $Incidents | Where-Object PTAStatus -eq 'Failed' | Sort-Object CreatedDateTime -Descending

    function Get-SeverityClass($sev) {
        switch ($sev) {
            'high' { 'severity-high' }
            'medium' { 'severity-medium' }
            'low' { 'severity-low' }
            'informational' { 'severity-informational' }
            default { '' }
        }
    }

    function Get-ClassificationBadge($classification, $determination) {
        if ($classification -eq 'falsePositive') {
            return '<span class="badge badge-processed">False Positive / Not Malicious</span>'
        }
        elseif ($classification -eq 'truePositive') {
            return '<span class="badge badge-missed">True Positive / ' + [System.Web.HttpUtility]::HtmlEncode($determination) + '</span>'
        }
        return '<span class="badge" style="background:#e8e8e8;color:#555;">N/A</span>'
    }

    # Helper: render the reporter cell as a link to the Defender user page when
    # we have a UserLink; otherwise fall back to plain text. Prefers the
    # display name (e.g. "Abbi Davletova") with the accountName in parens.
    function Get-ReporterCell {
        param($Incident)
        $label = ''
        if ($Incident.PSObject.Properties['ReporterDisplayName'] -and $Incident.ReporterDisplayName) {
            $label = [string]$Incident.ReporterDisplayName
            if ($Incident.ReportedBy -and $Incident.ReportedBy -ne $label) {
                $label = "$label ($($Incident.ReportedBy))"
            }
        } elseif ($Incident.ReportedBy) {
            $label = [string]$Incident.ReportedBy
        } elseif ($Incident.PSObject.Properties['ReporterUpn'] -and $Incident.ReporterUpn) {
            $label = [string]$Incident.ReporterUpn
        }
        if (-not $label) { return '' }
        $safe = [System.Web.HttpUtility]::HtmlEncode($label)
        if ($Incident.UserLink) {
            $tip = ''
            if ($Incident.ReporterUpn) { $tip = " title='$([System.Web.HttpUtility]::HtmlEncode([string]$Incident.ReporterUpn))'" }
            return "<a class='link' href='$([System.Web.HttpUtility]::HtmlEncode([string]$Incident.UserLink))' target='_blank'$tip>$safe</a>"
        }
        return $safe
    }

    # Build processed rows
    $processedRows = ""
    foreach ($inc in $processed) {
        $sevClass = Get-SeverityClass $inc.Severity
        $classBadge = Get-ClassificationBadge $inc.Classification $inc.Determination
        $safeTitle = [System.Web.HttpUtility]::HtmlEncode($inc.Title)
        $reporterCell = Get-ReporterCell $inc
        $safePTA = [System.Web.HttpUtility]::HtmlEncode($inc.PTAIndicators)
        $safeSeverity = [System.Web.HttpUtility]::HtmlEncode($inc.Severity)
        $safeStatus = [System.Web.HttpUtility]::HtmlEncode($inc.Status)
        $created = ([DateTime]::Parse($inc.CreatedDateTime)).ToString('MM/dd/yyyy HH:mm')
        $processedRows += "<tr>"
        $processedRows += "<td><a class='link' href='$($inc.PortalLink)' target='_blank'>$($inc.IncidentId)</a></td>"
        $processedRows += "<td>$safeTitle</td>"
        $processedRows += "<td class='$sevClass'>$safeSeverity</td>"
        $processedRows += "<td>$safeStatus</td>"
        $processedRows += "<td>$classBadge</td>"
        $processedRows += "<td>$reporterCell</td>"
        $processedRows += "<td>$created</td>"
        $processedRows += "<td style='font-size:11px;'>$safePTA</td>"
        $processedRows += "<td>Medium</td>"
        $processedRows += "</tr>`n"
    }

    # Build missed rows
    $missedRows = ""
    foreach ($inc in $missed) {
        $sevClass = Get-SeverityClass $inc.Severity
        $safeTitle = [System.Web.HttpUtility]::HtmlEncode($inc.Title)
        $reporterCell = Get-ReporterCell $inc
        $safeSeverity = [System.Web.HttpUtility]::HtmlEncode($inc.Severity)
        $safeStatus = [System.Web.HttpUtility]::HtmlEncode($inc.Status)
        $safeClassification = [System.Web.HttpUtility]::HtmlEncode($inc.Classification)
        $safeAssignedTo = [System.Web.HttpUtility]::HtmlEncode($inc.AssignedTo)
        $created = ([DateTime]::Parse($inc.CreatedDateTime)).ToString('MM/dd/yyyy HH:mm')
        $missedRows += "<tr>"
        $missedRows += "<td><a class='link' href='$($inc.PortalLink)' target='_blank'>$($inc.IncidentId)</a></td>"
        $missedRows += "<td>$safeTitle</td>"
        $missedRows += "<td class='$sevClass'>$safeSeverity</td>"
        $missedRows += "<td>$safeStatus</td>"
        $missedRows += "<td>$safeClassification</td>"
        $missedRows += "<td>$reporterCell</td>"
        $missedRows += "<td>$created</td>"
        $missedRows += "<td>$safeAssignedTo</td>"
        $missedRows += "<td>$($inc.AlertCount)</td>"
        $missedRows += "<td><a class='link' href='$($inc.PortalLink)' target='_blank'>Open</a></td>"
        $missedRows += "</tr>`n"
    }

    # Build failed rows — include an inferred Root Cause column.
    $failedRows = ""
    foreach ($inc in $failed) {
        $sevClass = Get-SeverityClass $inc.Severity
        $safeTitle = [System.Web.HttpUtility]::HtmlEncode($inc.Title)
        $reporterCell = Get-ReporterCell $inc
        $safePTA = [System.Web.HttpUtility]::HtmlEncode($inc.PTAIndicators)
        $safeSeverity = [System.Web.HttpUtility]::HtmlEncode($inc.Severity)
        $safeStatus = [System.Web.HttpUtility]::HtmlEncode($inc.Status)
        $rootCauseShortRaw = if ($inc.PSObject.Properties['RootCause']) { [string]$inc.RootCause } else { '' }
        if (-not $rootCauseShortRaw) { $rootCauseShortRaw = 'Investigation Required' }
        $rootCauseDetailRaw = if ($inc.PSObject.Properties['FailureReason']) { [string]$inc.FailureReason } else { '' }
        $rootCauseShort  = [System.Web.HttpUtility]::HtmlEncode($rootCauseShortRaw)
        $rootCauseDetail = [System.Web.HttpUtility]::HtmlEncode($rootCauseDetailRaw)
        $rootCauseClass  = if ($rootCauseShortRaw -eq 'Investigation Required') { 'sev-high' } else { '' }
        $created = ([DateTime]::Parse($inc.CreatedDateTime)).ToString('MM/dd/yyyy HH:mm')
        $failedRows += "<tr>"
        $failedRows += "<td><a class='link' href='$($inc.PortalLink)' target='_blank'>$($inc.IncidentId)</a></td>"
        $failedRows += "<td>$safeTitle</td>"
        $failedRows += "<td class='$sevClass'>$safeSeverity</td>"
        $failedRows += "<td>$safeStatus</td>"
        $failedRows += "<td>$reporterCell</td>"
        $failedRows += "<td>$created</td>"
        $failedRows += "<td class='$rootCauseClass' style='font-size:12px;font-weight:600;' title='$rootCauseDetail'>$rootCauseShort</td>"
        $failedRows += "<td style='font-size:11px;'>$safePTA</td>"
        $failedRows += "<td><a class='link' href='$($inc.PortalLink)' target='_blank'>Open</a></td>"
        $failedRows += "</tr>`n"
    }

    # ── Metrics formatted ──
    $m = $Metrics
    $mtttMedianFmt = Format-MinutesToHHMMSS $m.MTTTMedian
    $mtttAvgFmt    = Format-MinutesToHHMMSS $m.MTTTAvg
    $mtttMinFmt    = Format-MinutesToHHMMSS $m.MTTTMin
    $mtttMaxFmt    = Format-MinutesToHHMMSS $m.MTTTMax
    $mttrMedianFmt = Format-MinutesToHHMMSS $m.MTTRMedian
    $mttrAvgFmt    = Format-MinutesToHHMMSS $m.MTTRAvg
    $mttrMinFmt    = Format-MinutesToHHMMSS $m.MTTRMin
    $mttrMaxFmt    = Format-MinutesToHHMMSS $m.MTTRMax

    # ── Build Submission Outcomes section ──
    # Group every user-reported submission by what happened to it so the report
    # clearly explains why X/Y was addressed, and what fell through.
    $outcomes = @($m.SubmissionOutcomes)
    $escHtml = { param($s) if ($null -eq $s) { '' } else { [string]$s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;' } }

    $catMeta = [ordered]@{
        'AddressedFP'    = @{ Label='Addressed - False positive (safe)';   Color='#2b579a'; Desc='Agent analyzed the reported message, classified it as false positive. If the incident status is resolved, the agent also closed it automatically.' }
        'AddressedTP'    = @{ Label='Addressed - True positive (phish)';   Color='#0078d4'; Desc='Agent confirmed the reported message as phishing. These typically stay open for analyst action (containment, user coaching, etc.).' }
        'AddressedOther' = @{ Label='Addressed - other classification';    Color='#5c2e91'; Desc='Agent took ownership and set a classification other than false/true positive (for example, informational).' }
        'Failed'         = @{ Label='Failed (agent error)';                Color='#d83b01'; Desc='Agent was assigned to the incident but never produced a verdict. Portal shows this as "Phishing Triage Agent failed to run" (permissions, SCU capacity, or transient backend error).' }
        'NotProcessed'   = @{ Label='Incident not processed by agent';     Color='#ff8c00'; Desc='Incident was created for the submission but the agent did not act on it. Usually means it was auto-resolved upstream, deemed ineligible, or closed before the agent ran.' }
        'ZAPed'          = @{ Label='ZAPed (post-delivery remediated)';    Color='#8764b8'; Desc='Defender zero-hour auto-purge removed the message after delivery. Because the mail was already remediated, no user-reported phish incident was raised.' }
        'UserDeleted'    = @{ Label='Deleted by user before analysis';     Color='#6b6b6b'; Desc='The reporting user deleted the message before the backend could analyze it.' }
        'NotFound'       = @{ Label='Message not found in mailbox';        Color='#6b6b6b'; Desc='The message was moved, deleted, or hard-deleted before analysis reached the mailbox.' }
        'NotJunk'        = @{ Label='Reported as not-junk';                Color='#107c10'; Desc='User reported the message as "not junk" / legitimate. No PTA phishing incident is expected.' }
        'NoIncident'     = @{ Label='No matching Defender incident';       Color='#ff8c00'; Desc='No user-reported-phish incident exists for this submission in Defender. Possible causes: auto-remediated before detection, ingestion delay, outside the incident scan window, or suppressed by policy.' }
    }

    $outcomeGroups = $outcomes | Group-Object OutcomeCategory
    $outcomeSummaryRows = ''
    foreach ($key in $catMeta.Keys) {
        $grp = $outcomeGroups | Where-Object { $_.Name -eq $key }
        $count = if ($grp) { $grp.Count } else { 0 }
        if ($count -eq 0) { continue }
        $meta = $catMeta[$key]
        $pct = if ($outcomes.Count -gt 0) { [math]::Round(($count / $outcomes.Count) * 100, 1) } else { 0 }
        $outcomeSummaryRows += "<tr><td><span class='outcome-pill' style='background:$($meta.Color)'>$(& $escHtml $meta.Label)</span></td><td style='text-align:right'><strong>$count</strong></td><td style='text-align:right'>$pct%</td><td style='font-size:12px;color:#555'>$(& $escHtml $meta.Desc)</td></tr>"
    }

    # Per-submission detail rows, ordered by category then date desc
    $orderedOutcomes = $outcomes | Sort-Object @{E={ if ($catMeta.Contains($_.OutcomeCategory)) { [array]::IndexOf(@($catMeta.Keys), $_.OutcomeCategory) } else { 999 } }}, @{E='SubmittedDate'; Descending=$true}
    $outcomeDetailRows = ''
    foreach ($o in $orderedOutcomes) {
        $meta = if ($catMeta.Contains($o.OutcomeCategory)) { $catMeta[$o.OutcomeCategory] } else { @{ Label=$o.OutcomeCategory; Color='#888' } }
        $subj = & $escHtml $o.Subject; if (-not $subj) { $subj = '<em style="color:#999">(no subject)</em>' }
        $sender = & $escHtml $o.SenderAddress
        # Prefer display name from incident userEvidence when available, then ReportedBy,
        # then fall back to the submission's reporter email.
        $reporterLabel = ''
        if ($o.PSObject.Properties['ReporterDisplayName'] -and $o.ReporterDisplayName) {
            $reporterLabel = [string]$o.ReporterDisplayName
        } elseif ($o.ReportedBy) {
            $reporterLabel = [string]$o.ReportedBy
        } elseif ($o.PSObject.Properties['ReporterUpn'] -and $o.ReporterUpn) {
            $reporterLabel = [string]$o.ReporterUpn
        }
        $reportedBy = & $escHtml $reporterLabel
        if ($o.PSObject.Properties['UserLink'] -and $o.UserLink -and $reportedBy) {
            $upnTip = if ($o.ReporterUpn) { " title='$(& $escHtml $o.ReporterUpn)'" } else { '' }
            $reportedBy = "<a class='link' href='$(& $escHtml $o.UserLink)' target='_blank'$upnTip>$reportedBy</a>"
        }
        $submitted = ''
        if ($o.SubmittedDate) {
            try { $submitted = ([DateTime]$o.SubmittedDate).ToString('yyyy-MM-dd HH:mm') } catch { $submitted = [string]$o.SubmittedDate }
        }
        $incLink = ''
        if ($o.IncidentId) {
            $incLink = "<a href='https://security.microsoft.com/incidents/$(& $escHtml $o.IncidentId)' target='_blank'>$(& $escHtml $o.IncidentId)</a>"
        } else {
            $incLink = "<span style='color:#999'>-</span>"
        }
        $reason = & $escHtml $o.OutcomeReason
        $detail = & $escHtml $o.SubmissionDetail
        if ($detail) { $reason = "$reason <span style='color:#888;font-size:11px'>($detail)</span>" }
        $outcomeDetailRows += "<tr><td><span class='outcome-pill' style='background:$($meta.Color)'>$(& $escHtml $meta.Label)</span></td><td>$submitted</td><td>$subj</td><td style='font-size:12px'>$sender</td><td style='font-size:12px'>$reportedBy</td><td>$incLink</td><td style='font-size:12px'>$reason</td></tr>"
    }

    # Reconciliation totals
    $recAddressed = ($outcomes | Where-Object { $_.OutcomeCategory -like 'Addressed*' -or $_.OutcomeCategory -eq 'Failed' }).Count
    $recNotProcessed = $outcomes.Count - $recAddressed

    # ── Build full HTML ──
    $html = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Phishing Triage Agent - Gap Analysis Report</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js"></script>
<style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: 'Segoe UI', Tahoma, sans-serif; background: #f5f5f5; color: #333; padding: 30px; }
    .container { max-width: 1200px; margin: 0 auto; }
    .header { background: linear-gradient(135deg, #1a3c6e, #2b579a); color: white; padding: 30px; border-radius: 10px; margin-bottom: 25px; }
    .header h1 { font-size: 28px; font-weight: 300; margin-bottom: 5px; }
    .header .subtitle { font-size: 14px; opacity: 0.8; }
    .stats-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 15px; margin-bottom: 25px; }
    .stat-card { background: white; border-radius: 8px; padding: 20px; text-align: center; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }
    .stat-card .number { font-size: 36px; font-weight: 700; }
    .stat-card .label { font-size: 13px; color: #666; margin-top: 5px; }
    .stat-card.total .number { color: #2b579a; }
    .stat-card.processed .number { color: #107c10; }
    .stat-card.missed .number { color: #ff8c00; }
    .stat-card.coverage .number { color: #0078d4; }
    .section { background: white; border-radius: 8px; padding: 25px; margin-bottom: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }
    .section h2 { font-size: 18px; color: #1a3c6e; margin-bottom: 15px; padding-bottom: 10px; border-bottom: 2px solid #f0f0f0; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th { background: #2b579a; color: white; padding: 10px 12px; text-align: left; }
    td { padding: 10px 12px; border-bottom: 1px solid #eee; }
    tr:hover { background: #f8f9fa; }
    .severity-high { color: #d83b01; font-weight: 600; }
    .severity-medium { color: #ff8c00; font-weight: 600; }
    .severity-low { color: #107c10; font-weight: 600; }
    .severity-informational { color: #0078d4; font-weight: 600; }
    .badge { display: inline-block; padding: 3px 10px; border-radius: 12px; font-size: 11px; font-weight: 600; }
    .badge-missed { background: #fde7e7; color: #d83b01; }
    .badge-processed { background: #e7f4e7; color: #107c10; }
    .reason-list { margin-top: 10px; padding-left: 20px; }
    .reason-list li { margin-bottom: 5px; font-size: 13px; }
    .link { color: #0078d4; text-decoration: none; }
    .link:hover { text-decoration: underline; }
    .footer { text-align: center; font-size: 12px; color: #999; margin-top: 30px; }
    .alert-bar { padding: 12px 18px; border-radius: 6px; margin-bottom: 20px; font-size: 14px; }
    .alert-bar.warning { background: #fff4ce; border-left: 4px solid #ff8c00; }
    .alert-bar.success { background: #e7f4e7; border-left: 4px solid #107c10; }
    .alert-bar.danger { background: #fde7e7; border-left: 4px solid #d83b01; }
    .chart-container { background: white; border-radius: 8px; padding: 25px; margin-bottom: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }
    .chart-container h2 { font-size: 18px; color: #1a3c6e; margin-bottom: 15px; padding-bottom: 10px; border-bottom: 2px solid #f0f0f0; }
    .chart-wrapper { position: relative; height: 280px; }
    .outcome-pill { display: inline-block; padding: 3px 10px; border-radius: 10px; font-size: 11px; font-weight: 600; color: white; white-space: nowrap; }
    .outcome-summary-table td { vertical-align: top; }
    .explainer { background: #f8fbff; border-left: 4px solid #0078d4; padding: 14px 18px; border-radius: 4px; margin: 14px 0; font-size: 13px; line-height: 1.55; }
    .explainer strong { color: #1a3c6e; }
    .filter-bar { margin: 10px 0 14px; display: flex; flex-wrap: wrap; gap: 6px; align-items: center; font-size: 12px; }
    .filter-bar button { background: #f0f0f0; border: 1px solid #ddd; color: #333; padding: 5px 12px; border-radius: 14px; cursor: pointer; font-size: 12px; }
    .filter-bar button.active { background: #2b579a; color: white; border-color: #2b579a; }
    .incident-picker-overlay { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.3); z-index: 1000; }
    .incident-picker { position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%); background: white; border-radius: 10px; padding: 20px 25px; box-shadow: 0 8px 32px rgba(0,0,0,0.2); z-index: 1001; min-width: 340px; max-width: 500px; max-height: 70vh; overflow-y: auto; }
    .incident-picker h3 { font-size: 16px; color: #1a3c6e; margin-bottom: 12px; padding-bottom: 8px; border-bottom: 2px solid #f0f0f0; }
    .incident-picker .pick-item { display: flex; align-items: center; padding: 8px 12px; margin: 4px 0; border-radius: 6px; cursor: pointer; text-decoration: none; color: #333; font-size: 13px; transition: background 0.15s; }
    .incident-picker .pick-item:hover { background: #e8f0fe; }
    .incident-picker .pick-item .pick-id { font-weight: 600; color: #0078d4; min-width: 60px; }
    .incident-picker .pick-close { display: block; text-align: center; margin-top: 12px; padding: 8px; border-radius: 6px; background: #f0f0f0; color: #666; cursor: pointer; font-size: 13px; }
    .incident-picker .pick-close:hover { background: #e0e0e0; }
    .incident-picker .pick-all { display: block; text-align: center; margin-top: 6px; padding: 8px; border-radius: 6px; background: #2b579a; color: white; cursor: pointer; font-size: 13px; text-decoration: none; }
    .incident-picker .pick-all:hover { background: #1a3c6e; }
    th.sortable { cursor: pointer; user-select: none; position: relative; padding-right: 20px !important; }
    th.sortable:hover { background: #1a3c6e; }
    th.sortable::after { content: '\21C5'; position: absolute; right: 6px; top: 50%; transform: translateY(-50%); font-size: 11px; opacity: 0.6; }
    th.sortable.sort-asc::after { content: '\25B2'; opacity: 1; }
    th.sortable.sort-desc::after { content: '\25BC'; opacity: 1; }
    .table-controls { display: flex; justify-content: flex-end; margin-bottom: 10px; gap: 10px; }
    .table-filter { padding: 6px 12px; border: 1px solid #ddd; border-radius: 6px; font-size: 13px; width: 250px; }
    .table-filter:focus { outline: none; border-color: #0078d4; box-shadow: 0 0 0 2px rgba(0,120,212,0.15); }
    .info-btn { display: inline-flex; align-items: center; justify-content: center; width: 18px; height: 18px; border-radius: 50%; background: #0078d4; color: white; font-size: 11px; font-weight: 700; cursor: pointer; border: none; vertical-align: middle; margin-left: 4px; line-height: 1; font-family: serif; }
    .info-btn:hover { background: #106ebe; }
    .info-modal-overlay { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.35); z-index: 2000; }
    .info-modal { position: fixed; top: 50%; left: 50%; transform: translate(-50%,-50%); background: white; border-radius: 12px; padding: 30px 35px; box-shadow: 0 12px 48px rgba(0,0,0,0.25); z-index: 2001; max-width: 680px; width: 90%; max-height: 80vh; overflow-y: auto; }
    .info-modal h3 { font-size: 18px; color: #1a3c6e; margin-bottom: 16px; padding-bottom: 10px; border-bottom: 2px solid #f0f0f0; }
    .info-modal .info-section { margin-bottom: 18px; }
    .info-modal .info-section h4 { font-size: 14px; color: #2b579a; margin-bottom: 6px; }
    .info-modal .info-section p, .info-modal .info-section li { font-size: 13px; color: #444; line-height: 1.6; }
    .info-modal .info-section ul { margin: 6px 0 0 20px; }
    .info-modal .info-highlight { background: #e8f4e8; border-left: 4px solid #107c10; padding: 10px 14px; border-radius: 4px; font-size: 13px; margin: 10px 0; }
    .info-modal .info-warn { background: #fff8e1; border-left: 4px solid #ff8c00; padding: 10px 14px; border-radius: 4px; font-size: 13px; margin: 10px 0; }
    .info-modal .info-close { display: block; text-align: center; margin-top: 16px; padding: 10px; border-radius: 6px; background: #2b579a; color: white; cursor: pointer; font-size: 13px; border: none; width: 100%; }
    .info-modal .info-close:hover { background: #1a3c6e; }
    .info-modal .info-link { color: #0078d4; text-decoration: none; }
    .info-modal .info-link:hover { text-decoration: underline; }
</style>
</head>
<body>
<div class="container">

<div class="header">
    <h1>&#x1F6E1;&#xFE0F; Phishing Triage Agent &#x2014; Analysis Report</h1>
    <div class="subtitle">Generated: $genTime | Period: Last $Days days | Submissions: $($m.Total) across $($m.TotalIncidents) incidents</div>
</div>
<div style="background:#fff4ce;border:1px solid #f0c419;border-left:6px solid #d83b01;border-radius:6px;padding:12px 16px;margin:0 0 16px 0;font-size:13px;color:#333;line-height:1.55;">
    <strong style="color:#d83b01;">&#x26A0;&#xFE0F; NOTICE &mdash; Data Accuracy Disclaimer:</strong>
    This report is generated from a community PowerShell sample provided <strong>"AS IS"</strong> without warranty of any kind.
    It is <strong>NOT an official Microsoft product</strong> and is <strong>NOT supported by Microsoft Support</strong>.
    Numbers, classifications, and inferred root causes shown below <strong>may not be accurate or complete</strong> &mdash; they are
    derived from Microsoft Graph data that may be incomplete (paging limits, throttling, API surface gaps),
    and from heuristics that approximate the Phishing Triage Agent's behavior. Always validate findings against the
    Microsoft Defender portal before acting on them. You are responsible for compliance with your organization's
    data-handling, privacy, and security policies.
</div><div class="stats-grid">
    <div class="stat-card total"><div class="number">$($m.Total) <button class="info-btn" onclick="document.getElementById('infoSubmissions').style.display='block'">i</button></div><div class="label">User-Reported Submissions</div></div>
    <div class="stat-card processed"><div class="number">$($m.Addressed)/$($m.Total) <button class="info-btn" onclick="document.getElementById('infoAddressed').style.display='block'">i</button></div><div class="label">Submissions Addressed ($($m.AddressedPct)%)</div></div>
    <div class="stat-card coverage"><div class="number">$($m.ResolvedByPTA)/$($m.Addressed) <button class="info-btn" onclick="document.getElementById('infoResolved').style.display='block'">i</button></div><div class="label">Submissions Resolved ($($m.ResolvedPct)%)</div></div>
    <div class="stat-card missed" style="border-top: 3px solid #ff8c00;"><div class="number">$($m.Missed) <button class="info-btn" onclick="document.getElementById('infoNotProcessed').style.display='block'">i</button></div><div class="label">Not Processed</div></div>
    <div class="stat-card" style="border-top: 3px solid #d83b01;"><div class="number" style="color: #d83b01;">$($m.Failed) <button class="info-btn" onclick="document.getElementById('infoFailed').style.display='block'">i</button></div><div class="label">PTA Failed (Errors)</div></div>
</div>
<div class="stats-grid" style="grid-template-columns: repeat(2, 1fr);">
    <div class="stat-card" style="border-top: 3px solid #0078d4;"><div class="number" style="color: #0078d4; font-size: 28px;">$mtttMedianFmt <button class="info-btn" onclick="document.getElementById('infoMTTT').style.display='block'">i</button></div><div class="label">Median Time to Triage (MTTT)</div><div style="font-size: 11px; color: #999; margin-top: 4px;">Avg: $mtttAvgFmt &middot; $($m.MTTTSamples) samples</div></div>
    <div class="stat-card" style="border-top: 3px solid #107c10;"><div class="number" style="color: #107c10; font-size: 28px;">$mttrMedianFmt <button class="info-btn" onclick="document.getElementById('infoMTTR').style.display='block'">i</button></div><div class="label">Median Time to Resolve (MTTR)</div><div style="font-size: 11px; color: #999; margin-top: 4px;">Avg: $mttrAvgFmt &middot; $($m.MTTRSamples) resolved</div></div>
</div>

<!-- Info Modals -->
<div id="infoSubmissions" class="info-modal-overlay" onclick="if(event.target===this)this.style.display='none'">
<div class="info-modal">
    <h3>&#x1F4CA; What the numbers mean</h3>
    <div class="info-section">
        <h4>Submissions: $($m.Total)</h4>
        <p>Total number of user-reported email messages (analyzedMessageEvidence) across $($m.TotalIncidents) phishing incidents in the last $Days days. Matches the Defender portal's Submissions metric.</p>
    </div>
    <div class="info-highlight">&#x1F4D6; For official metric definitions, see <a class="info-link" href="https://learn.microsoft.com/en-us/defender-xdr/phishing-triage-agent" target="_blank">Phishing Triage Agent documentation</a>.</div>
    <button class="info-close" onclick="this.closest('.info-modal-overlay').style.display='none'">Close</button>
</div>
</div>
<div id="infoAddressed" class="info-modal-overlay" onclick="if(event.target===this)this.style.display='none'">
<div class="info-modal">
    <h3>&#x1F4CA; Incidents Addressed: $($m.Addressed) / $($m.Total) ($($m.AddressedPct)%)</h3>
    <div class="info-section">
        <p>The Phishing Triage Agent actively attempted to analyze <strong>$($m.Addressed)</strong> of the <strong>$($m.Total)</strong> incidents. The remaining were not addressed, typically because the alert was auto-resolved upstream or didn't meet eligibility criteria.</p>
    </div>
    <div class="info-highlight">&#x2705; The agent does not override pre-resolved alerts.</div>
    <button class="info-close" onclick="this.closest('.info-modal-overlay').style.display='none'">Close</button>
</div>
</div>
<div id="infoResolved" class="info-modal-overlay" onclick="if(event.target===this)this.style.display='none'">
<div class="info-modal">
    <h3>&#x1F4CA; Incidents Resolved: $($m.ResolvedByPTA) / $($m.Addressed) ($($m.ResolvedPct)%)</h3>
    <div class="info-section">
        <p>Out of <strong>$($m.Addressed)</strong> addressed incidents, <strong>$($m.ResolvedByPTA)</strong> were autonomously resolved as False Positive (benign). True positives are intentionally left open for analyst review.</p>
    </div>
    <div class="info-warn">&#x26A0;&#xFE0F; Resolution percentages are not expected to be 100%. True positives are left open by design.</div>
    <button class="info-close" onclick="this.closest('.info-modal-overlay').style.display='none'">Close</button>
</div>
</div>
<div id="infoNotProcessed" class="info-modal-overlay" onclick="if(event.target===this)this.style.display='none'">
<div class="info-modal">
    <h3>&#x1F4CA; Not Processed: $($m.Missed)</h3>
    <div class="info-section"><p>These incidents had no detectable PTA activity. Typically auto-resolved upstream or didn't meet eligibility criteria.</p></div>
    <button class="info-close" onclick="this.closest('.info-modal-overlay').style.display='none'">Close</button>
</div>
</div>
<div id="infoFailed" class="info-modal-overlay" onclick="if(event.target===this)this.style.display='none'">
<div class="info-modal">
    <h3>&#x1F4CA; PTA Failed (Errors): $($m.Failed)</h3>
    <div class="info-section"><p>These incidents show PTA was triggered but didn't complete. Common causes: service errors, permission issues, SCU exhaustion, signal gaps.</p></div>
    <div class="info-warn">&#x26A0;&#xFE0F; Review the "PTA Failed" table below for details.</div>
    <button class="info-close" onclick="this.closest('.info-modal-overlay').style.display='none'">Close</button>
</div>
</div>
<div id="infoMTTT" class="info-modal-overlay" onclick="if(event.target===this)this.style.display='none'">
<div class="info-modal">
    <h3>&#x1F4CA; Median Time to Triage (MTTT): $mtttMedianFmt</h3>
    <div class="info-section">
        <h4>How it's calculated</h4>
        <p><code>alert.resolvedDateTime - incident.createdDateTime</code> (fallback: <code>alert.lastUpdateDateTime</code>)</p>
        <p>Samples: $($m.MTTTSamples) of $($m.Total) | Min: $mtttMinFmt | Max: $mtttMaxFmt</p>
    </div>
    <button class="info-close" onclick="this.closest('.info-modal-overlay').style.display='none'">Close</button>
</div>
</div>
<div id="infoMTTR" class="info-modal-overlay" onclick="if(event.target===this)this.style.display='none'">
<div class="info-modal">
    <h3>&#x1F4CA; Median Time to Resolve (MTTR): $mttrMedianFmt</h3>
    <div class="info-section">
        <h4>How it's calculated</h4>
        <p><code>incident.lastUpdateDateTime - incident.createdDateTime</code> (resolved incidents only)</p>
        <p>Samples: $($m.MTTRSamples) resolved | Min: $mttrMinFmt | Max: $mttrMaxFmt</p>
    </div>
    <button class="info-close" onclick="this.closest('.info-modal-overlay').style.display='none'">Close</button>
</div>
</div>

<!-- Daily Activity Chart -->
<div class="chart-container">
    <h2>&#x1F4CA; Daily Activity</h2>
    <div class="chart-wrapper"><canvas id="dailyChart"></canvas></div>
</div>
<script>
const datasetIds = [$fpIdsJs, $tpIdsJs, $missedIdsJs, $failedIdsJs];
const datasetLabels = ['False Positive', 'True Positive', 'Not Processed', 'Errors'];
const ctx = document.getElementById('dailyChart').getContext('2d');
const dailyChart = new Chart(ctx, {
    type: 'bar',
    data: {
        labels: [$labelsJs],
        datasets: [
            { label: 'False Positive', data: [$fpDataJs], backgroundColor: '#2b579a', borderRadius: 3 },
            { label: 'True Positive', data: [$tpDataJs], backgroundColor: '#0078d4', borderRadius: 3 },
            { label: 'Not Processed', data: [$missedDataJs], backgroundColor: '#ff8c00', borderRadius: 3 },
            { label: 'Errors', data: [$failedDataJs], backgroundColor: '#d83b01', borderRadius: 3 }
        ]
    },
    options: {
        responsive: true, maintainAspectRatio: false,
        onClick: (evt) => {
            const exact = dailyChart.getElementsAtEventForMode(evt, 'nearest', { intersect: true }, false);
            if (exact.length > 0) {
                const dsIdx = exact[0].datasetIndex, dayIdx = exact[0].index;
                const ids = datasetIds[dsIdx][dayIdx];
                const dateLabel = dailyChart.data.labels[dayIdx];
                const catLabel = datasetLabels[dsIdx];
                if (ids && ids.length === 1) window.open('https://security.microsoft.com/incidents/' + ids[0], '_blank');
                else if (ids && ids.length > 1) showIncidentPicker(ids, dateLabel + ' \u2014 ' + catLabel);
            }
        },
        plugins: {
            legend: { position: 'bottom', labels: { usePointStyle: true, padding: 20 } },
            tooltip: { callbacks: { afterBody: function(c) { const ids = datasetIds[c[0].datasetIndex][c[0].dataIndex]; return ids && ids.length > 0 ? 'Click to open: ' + ids.join(', ') : ''; } } }
        },
        scales: {
            x: { stacked: true, grid: { display: false } },
            y: { stacked: true, beginAtZero: true, ticks: { stepSize: 1, precision: 0 }, title: { display: true, text: 'Alerts Triaged' } }
        }
    }
});
document.getElementById('dailyChart').addEventListener('mousemove', function(evt) {
    const points = dailyChart.getElementsAtEventForMode(evt, 'nearest', { intersect: true }, false);
    this.style.cursor = (points.length > 0 && datasetIds[points[0].datasetIndex][points[0].index]?.length > 0) ? 'pointer' : 'default';
});
</script>
<div class="incident-picker-overlay" id="pickerOverlay" onclick="closeIncidentPicker()"></div>
<div class="incident-picker" id="incidentPicker" style="display:none;"></div>
<script>
function showIncidentPicker(ids, dateLabel) {
    const picker = document.getElementById('incidentPicker'), overlay = document.getElementById('pickerOverlay');
    let html = '<h3>\uD83D\uDCC5 ' + dateLabel + ' \u2014 ' + ids.length + ' Incidents</h3>';
    ids.forEach(id => { html += '<a class="pick-item" href="https://security.microsoft.com/incidents/' + id + '" target="_blank"><span class="pick-id">' + id + '</span><span>Open in Defender</span></a>'; });
    html += '<div class="pick-all" onclick="openAllIncidents([' + ids.map(i => "'" + i + "'").join(',') + '])">Open All (' + ids.length + ')</div>';
    html += '<div class="pick-close" onclick="closeIncidentPicker()">Close</div>';
    picker.innerHTML = html; picker.style.display = 'block'; overlay.style.display = 'block';
}
function closeIncidentPicker() { document.getElementById('incidentPicker').style.display = 'none'; document.getElementById('pickerOverlay').style.display = 'none'; }
function openAllIncidents(ids) { ids.forEach(id => window.open('https://security.microsoft.com/incidents/' + id, '_blank')); closeIncidentPicker(); }
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeIncidentPicker(); });
function makeSortable(table) {
    const headers = table.querySelectorAll('th.sortable');
    headers.forEach((th, colIdx) => {
        th.addEventListener('click', () => {
            const tbody = table.querySelector('tbody') || table;
            const rows = Array.from(tbody.querySelectorAll('tr')).filter(r => r.querySelector('td'));
            const isAsc = th.classList.contains('sort-asc');
            headers.forEach(h => { h.classList.remove('sort-asc', 'sort-desc'); });
            th.classList.add(isAsc ? 'sort-desc' : 'sort-asc');
            const dir = isAsc ? -1 : 1;
            rows.sort((a, b) => { const aT = a.children[colIdx]?.textContent.trim() || '', bT = b.children[colIdx]?.textContent.trim() || ''; const aN = parseFloat(aT), bN = parseFloat(bT); if (!isNaN(aN) && !isNaN(bN)) return (aN - bN) * dir; return aT.localeCompare(bT) * dir; });
            rows.forEach(r => tbody.appendChild(r));
        });
    });
}
function makeFilterable(section) {
    const table = section.querySelector('table'); if (!table) return;
    const div = document.createElement('div'); div.className = 'table-controls';
    const input = document.createElement('input'); input.className = 'table-filter'; input.placeholder = '\uD83D\uDD0D Filter rows...';
    input.addEventListener('input', () => { const term = input.value.toLowerCase(); table.querySelectorAll('tr').forEach((r, i) => { if (i === 0) return; r.style.display = r.textContent.toLowerCase().includes(term) ? '' : 'none'; }); });
    div.appendChild(input); table.parentNode.insertBefore(div, table);
}
document.addEventListener('DOMContentLoaded', () => { document.querySelectorAll('table').forEach(t => makeSortable(t)); document.querySelectorAll('.section').forEach(s => makeFilterable(s)); });
</script>

<!-- Dashboard Summary -->
<div class="section">
    <h2>&#x1F4CB; Dashboard Summary &#x2014; How to Interpret Unresolved Incidents</h2>
    <p style="font-size: 13px; color: #555; line-height: 1.7; margin-bottom: 16px;">Not all incidents are resolved automatically &#x2014; <strong>by design</strong>. When the Phishing Triage Agent identifies an incident as a <strong>True Positive (TP)</strong> or lacks enough evidence, it leaves the incident <em>open</em> for analyst review.</p>
    <table style="margin-bottom: 20px;">
        <tr><th>Agent Outcome</th><th>What It Means</th><th>Incident State</th><th>Why This Is Expected</th></tr>
        <tr><td><span class="badge badge-processed">False Positive (FP)</span></td><td>Agent is confident the submission is benign</td><td><strong>Resolved / Closed</strong></td><td>Safe to auto-close</td></tr>
        <tr><td><span class="badge badge-missed">True Positive (TP)</span></td><td>Agent identifies a real or likely phishing threat</td><td><strong>Open</strong></td><td>Requires analyst investigation</td></tr>
        <tr><td><span class="badge" style="background:#fff4ce;color:#8a6d00;">Insufficient Evidence</span></td><td>Evidence is missing or inconclusive</td><td><strong>Open</strong></td><td>Defers to human review</td></tr>
        <tr><td><span class="badge" style="background:#e8e8e8;color:#555;">Pre-resolved Upstream</span></td><td>Resolved by other Defender controls before agent ran</td><td><strong>Closed</strong></td><td>Agent does not override</td></tr>
    </table>
</div>

$(if ($missed.Count -gt 0) { @"
<!-- Not Processed Table -->
<div class="section">
    <h2>&#x26A0;&#xFE0F; Incidents NOT Processed by PTA ($($m.Missed))</h2>
    <table>
        <tr><th class="sortable">Incident ID</th><th class="sortable">Title</th><th class="sortable">Severity</th><th class="sortable">Status</th><th class="sortable">Classification</th><th class="sortable">Reported By</th><th class="sortable">Created</th><th class="sortable">Assigned To</th><th>Alerts</th><th>Link</th></tr>
        $missedRows
    </table>
</div>
"@})

$(if ($failed.Count -gt 0) { @"
<!-- Failed Table -->
<div class="section">
    <h2>&#x274C; PTA Failed / Errored ($($m.Failed))</h2>
    <p style="font-size:12px;color:#666;margin-bottom:12px">Graph does not expose the Phishing Triage Agent's failure reason directly (the portal shows "Phishing Triage Agent failed to run" under Tasks with no further detail). The <strong>Inferred Root Cause</strong> column shows a short category derived from incident signals &mdash; hover the cell for the full diagnostic detail. Categories: <strong>Reported email unavailable for analysis</strong> (stub-only analyzedMessageEvidence &mdash; highest confidence), <strong>Preempted by other automation</strong>, <strong>Agent error (see comments)</strong>, <strong>Agent did not complete</strong>, <strong>Insufficient signal</strong>, and <strong>Investigation Required</strong> (no signals could be inferred &mdash; open the incident's Tasks panel in the Defender portal for the Copilot message).</p>
    <table>
        <tr><th class="sortable">Incident ID</th><th class="sortable">Title</th><th class="sortable">Severity</th><th class="sortable">Status</th><th class="sortable">Reported By</th><th class="sortable">Created</th><th>Inferred Root Cause</th><th>PTA Indicators</th><th>Link</th></tr>
        $failedRows
    </table>
</div>
"@})

<!-- Processed Table -->
<div class="section">
    <h2>&#x2705; Incidents Successfully Processed by PTA ($($m.Processed))</h2>
    <table>
        <tr><th class="sortable">Incident ID</th><th class="sortable">Title</th><th class="sortable">Severity</th><th class="sortable">Status</th><th class="sortable">Classification</th><th class="sortable">Reported By</th><th class="sortable">Created</th><th>PTA Indicators</th><th>Confidence</th></tr>
        $processedRows
    </table>
</div>

<!-- Methodology -->
<div class="section">
    <h2>&#x1F4D0; Methodology: Time Metrics</h2>
    <p style="font-size: 13px; color: #666; margin-bottom: 15px;">How Mean Time to Triage (MTTT) and Mean Time to Resolve (MTTR) are calculated for PTA-processed incidents.</p>
    <table style="margin-bottom: 15px;">
        <tr><th>Metric</th><th>Definition</th><th>Calculation</th><th>Median</th><th>Average</th><th>Min</th><th>Max</th><th>Samples</th></tr>
        <tr>
            <td><strong>MTTT</strong></td>
            <td>Time from incident creation to PTA classification</td>
            <td style="font-size: 12px;"><code>alert.resolvedDateTime</code> &#x2212; <code>incident.createdDateTime</code><br>(falls back to <code>alert.lastUpdateDateTime</code>)</td>
            <td><strong>$mtttMedianFmt</strong></td><td>$mtttAvgFmt</td><td>$mtttMinFmt</td><td>$mtttMaxFmt</td><td>$($m.MTTTSamples)</td>
        </tr>
        <tr>
            <td><strong>MTTR</strong></td>
            <td>Time from incident creation to fully resolved</td>
            <td style="font-size: 12px;"><code>incident.lastUpdateDateTime</code> &#x2212; <code>incident.createdDateTime</code><br>(only resolved incidents)</td>
            <td><strong>$mttrMedianFmt</strong></td><td>$mttrAvgFmt</td><td>$mttrMinFmt</td><td>$mttrMaxFmt</td><td>$($m.MTTRSamples)</td>
        </tr>
    </table>
    <div style="background: #f8f9fa; border-radius: 6px; padding: 15px; font-size: 13px;">
        <strong>&#x1F4DD; Notes:</strong>
        <ul style="margin: 8px 0 0 20px;">
            <li><strong>MTTT</strong> measures how quickly PTA classifies the phishing alert.</li>
            <li><strong>MTTR</strong> measures end-to-end resolution. Only resolved incidents are included.</li>
            <li><strong>Median is reported</strong> because multi-stage incidents can skew the average significantly.</li>
            <li><strong>Data source:</strong> Graph API <code>v1.0/security/incidents</code> and <code>v1.0/security/alerts_v2</code>.</li>
        </ul>
    </div>
</div>

<!-- Submission Outcomes: explain where each user-reported submission ended up -->
<div class="section">
    <h2>&#x1F4E7; Submission Outcomes &mdash; What Happened to Each Reported Email</h2>
    <div class="explainer">
        <strong>How to read these numbers.</strong>
        <strong>Submissions</strong> is message-level: it counts every user-reported email, so duplicates across users inflate it.
        <strong>Addressed</strong> means the agent took ownership of the correlated incident and set a classification.
        <strong>Resolved</strong> is a subset of Addressed where the agent also closed the incident (typically false positives).
        The table below breaks every submission into one bucket so you can see exactly why <strong>$($m.Addressed) of $($m.Total)</strong> were addressed and why <strong>$recNotProcessed</strong> fell through.
        <br><br>
        <em>Not every submission becomes an incident, and not every incident is resolved automatically &mdash; by design. The agent does not override incidents that were auto-resolved by ZAP, attack disruption, or other upstream protections.</em>
    </div>
    <h3 style="font-size:14px;color:#1a3c6e;margin:18px 0 8px">Outcome summary</h3>
    <table class="outcome-summary-table">
        <tr><th>Outcome</th><th style="text-align:right">Count</th><th style="text-align:right">%</th><th>What it means</th></tr>
        $outcomeSummaryRows
        <tr style="background:#f8f9fa;font-weight:600"><td>Totals</td><td style="text-align:right">$($outcomes.Count)</td><td style="text-align:right">100%</td><td style="font-size:12px;color:#555">Addressed: $recAddressed | Not processed / unmatched: $recNotProcessed</td></tr>
    </table>

    <h3 style="font-size:14px;color:#1a3c6e;margin:22px 0 8px">Per-submission detail</h3>
    <div class="filter-bar">
        <span style="color:#666">Filter:</span>
        <button class="active" data-filter="all" onclick="filterOutcomes(this,'all')">All</button>
        <button data-filter="Addressed" onclick="filterOutcomes(this,'Addressed')">Addressed</button>
        <button data-filter="NotProcessed" onclick="filterOutcomes(this,'NotProcessed')">Not processed</button>
        <button data-filter="NoIncident" onclick="filterOutcomes(this,'NoIncident')">No incident</button>
        <button data-filter="ZAPed" onclick="filterOutcomes(this,'ZAPed')">ZAPed</button>
        <button data-filter="Failed" onclick="filterOutcomes(this,'Failed')">Failed</button>
    </div>
    <div style="overflow-x:auto">
    <table id="submissionOutcomeTable">
        <tr><th>Outcome</th><th>Submitted (UTC)</th><th>Subject</th><th>Sender</th><th>Reported by</th><th>Incident</th><th>Why</th></tr>
        $outcomeDetailRows
    </table>
    </div>
</div>
<script>
function filterOutcomes(btn, category) {
    document.querySelectorAll('.filter-bar button').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    const rows = document.querySelectorAll('#submissionOutcomeTable tr');
    rows.forEach((row, idx) => {
        if (idx === 0) return; // header
        if (category === 'all') { row.style.display = ''; return; }
        const pill = row.querySelector('.outcome-pill');
        if (!pill) { row.style.display = ''; return; }
        const label = pill.textContent || '';
        let show = false;
        if (category === 'Addressed')    show = label.startsWith('Addressed');
        else if (category === 'NotProcessed') show = label.includes('not processed') || label.includes('Deleted') || label.includes('not found');
        else if (category === 'NoIncident')   show = label.includes('No matching');
        else if (category === 'ZAPed')        show = label.includes('ZAPed');
        else if (category === 'Failed')       show = label.includes('Failed') || label.includes('error');
        row.style.display = show ? '' : 'none';
    });
}
</script>

<!-- Common Reasons -->
<div class="section">
    <h2>&#x1F4CB; Common Reasons Incidents Are Not Processed by PTA</h2>
    <ul class="reason-list">
        <li><strong>Missing URBAC / permissions</strong> &#x2014; PTA requires Defender URBAC for its workload.</li>
        <li><strong>Agent identity misconfiguration</strong> &#x2014; The assigned identity does not have required permissions.</li>
        <li><strong>Conditional Access policies</strong> &#x2014; CA rules blocking the agent identity sign-in.</li>
        <li><strong>SCU capacity exhausted</strong> &#x2014; Security Compute Unit limits reached.</li>
        <li><strong>Service or execution errors</strong> &#x2014; Transient backend failures or request timeouts.</li>
        <li><strong>Alert pre-classified</strong> &#x2014; Another automation classified the alert before PTA could process it.</li>
        <li><strong>Tag changes after processing</strong> &#x2014; Agent indicators may be removed by downstream automations.</li>
    </ul>
</div>

<div class="footer">
    Phishing Triage Agent &#x2014; Analysis Report | Generated by Get-PTAReport.ps1 | $genTime<br>
    <span style="font-size: 11px;">&#x26A0;&#xFE0F; This report is provided as-is for informational purposes. For official metrics, see <a href="https://learn.microsoft.com/en-us/defender-xdr/phishing-triage-agent" target="_blank" style="color: #0078d4;">Phishing Triage Agent documentation</a>.</span>
</div>

</div>
</body>
</html>
"@

    $html | Out-File -FilePath $Path -Encoding UTF8 -Force
    Write-Host "[OK] HTML report saved: $Path" -ForegroundColor Green
}

#endregion

# ─────────────────────────────────────────────────────────────────────────────
#region Main Execution
# ─────────────────────────────────────────────────────────────────────────────

function Main {
    Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'

    # Determine output directory
    if (-not $OutputPath) {
        $OutputPath = Join-Path ([Environment]::GetFolderPath('Desktop')) "Performance Dashboard Analysis"
    }
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

    $fileSuffix = if ($FailuresOnly) { "_Failures_$timestamp" } else { "_$timestamp" }
    $htmlPath = Join-Path $OutputPath "PTAReport$fileSuffix.html"
    $csvPath  = Join-Path $OutputPath "PTAReport$fileSuffix.csv"

    Write-Host ""
    Write-Host "=============================================" -ForegroundColor Cyan
    $titleSuffix = if ($FailuresOnly) { ' (Failures Only)' } else { '' }
    Write-Host "  Phishing Triage Agent - Gap Analysis Report$titleSuffix" -ForegroundColor Cyan
    Write-Host "  Period: Last $Days days" -ForegroundColor Gray
    if ($FailuresOnly) {
        Write-Host "  Scope:  Failed PTA runs only" -ForegroundColor Yellow
    }
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "NOTICE / DISCLAIMER" -ForegroundColor Yellow
    Write-Host "-------------------" -ForegroundColor Yellow
    Write-Host "This script is a community sample provided 'AS IS' without warranty of any kind." -ForegroundColor Gray
    Write-Host "It is NOT an official Microsoft product and is NOT supported by Microsoft Support." -ForegroundColor Gray
    Write-Host "Microsoft disclaims all implied warranties including merchantability and fitness" -ForegroundColor Gray
    Write-Host "for a particular purpose. Review the code and validate behavior in a non-production" -ForegroundColor Gray
    Write-Host "tenant before relying on its output. You are responsible for compliance with your" -ForegroundColor Gray
    Write-Host "organization's data-handling, privacy, and security policies." -ForegroundColor Gray
    Write-Host ""

    # Step 1: Authenticate
    # Only request ThreatSubmission.Read.All when -FetchSubmissions is set;
    # otherwise the unused scope causes an MSAL incremental-consent re-prompt.
    $connectArgs = @{ TenantId = $TenantId }
    if ($FetchSubmissions) { $connectArgs['IncludeThreatSubmission'] = $true }
    $connected = Connect-DefenderGraph @connectArgs
    if (-not $connected) {
        Write-Error "Failed to connect to Microsoft Graph. Aborting."
        return
    }

    # Step 1b/1c: Obtain user-reported submissions (authoritative portal source)
    $submissions = @()
    if ($SubmissionsCsv) {
        if (Test-Path -LiteralPath $SubmissionsCsv) {
            Write-Host ""
            Write-Host "Importing submissions from CSV: $SubmissionsCsv" -ForegroundColor Cyan
            try {
                $raw = Import-Csv -LiteralPath $SubmissionsCsv
                # Normalize property names — Get-ReportSubmission | Export-Csv produces typical columns.
                $submissions = foreach ($row in $raw) {
                    [pscustomobject]@{
                        NetworkMessageId  = $row.NetworkMessageId
                        Subject           = $row.Subject
                        SenderAddress     = $row.SenderAddress
                        ReceivedBy        = if ($row.PSObject.Properties['ReceivedBy']) { $row.ReceivedBy } else { $row.Recipient }
                        ReportedBy        = if ($row.PSObject.Properties['ReportedBy']) { $row.ReportedBy } else { $row.UserReported }
                        Source            = $row.Source
                        Type              = $row.Type
                        ReportType        = if ($row.PSObject.Properties['ReportType']) { $row.ReportType } else { $null }
                        ReceivedDate      = if ($row.PSObject.Properties['ReceivedDate']) { $row.ReceivedDate } else { $row.SubmittedDate }
                        SubmittedDate     = $row.SubmittedDate
                        Status            = if ($row.PSObject.Properties['Status']) { $row.Status } else { $null }
                        Result            = if ($row.PSObject.Properties['Result']) { $row.Result } else { $null }
                    }
                }
                # Apply type/source filter consistent with Get-UserReportedSubmissions
                $submissions = @($submissions | Where-Object {
                    ($_.Type -eq 'Email' -or -not $_.Type) -and
                    ($_.Source -match 'User|EndUser' -or -not $_.Source)
                })
                Write-Host "[OK] Imported $($submissions.Count) user-reported submissions from CSV" -ForegroundColor Green
            } catch {
                Write-Warning "Failed to import submissions CSV: $($_.Exception.Message)"
            }
        } else {
            Write-Warning "SubmissionsCsv path not found: $SubmissionsCsv"
        }
    } elseif ($FetchSubmissions) {
        # Opt-in path: fetch authoritative user-reported submissions via the
        # Security & Compliance cmdlet Get-ReportSubmission. This requires a
        # WAM-capable host (Windows Terminal / standalone pwsh) or will spawn
        # an external pwsh window from VS Code, so it's off by default to keep
        # the customer-facing flow popup-free. When omitted, submission counts
        # are derived from incident analyzedMessageEvidence (matches the
        # Defender portal's per-incident submission count).
        Write-Host ""
        $upn = $null
        $mgCtx = Get-MgContext
        if ($mgCtx -and $mgCtx.Account) { $upn = [string]$mgCtx.Account }
        $submissions = Get-UserReportedSubmissions -Days $Days -UserPrincipalName $upn
    }
    # Default path (no -SubmissionsCsv, no -FetchSubmissions): leave
    # $submissions empty. Get-PTAMetrics falls back to summing SubmissionCount
    # from each incident's analyzedMessageEvidence — same behavior that
    # produced the working 2026-04-20 report.

    # Step 2: Retrieve phishing incidents
    Write-Host ""
    $incidents = Get-PhishingIncidents -Days $Days
    if ($incidents.Count -eq 0 -and $submissions.Count -eq 0) {
        Write-Warning "No phishing incidents or submissions found in the last $Days days."
        return
    }

    # Step 3: Batch pre-fetch beta incident + beta alert details (20 reqs per $batch)
    Write-Host ""
    Write-Host "Pre-fetching beta details for $($incidents.Count) incidents..." -ForegroundColor Cyan
    $betaIncidentMap = @{}
    $betaAlertMap = @{}
    $phishAlertIds = @()
    foreach ($inc in $incidents) {
        if ($inc.alerts) {
            foreach ($alert in $inc.alerts) {
                if ($alert.title -match 'Email reported by user') { $phishAlertIds += [string]$alert.id; break }
            }
        }
    }

    $batchUri = 'https://graph.microsoft.com/$batch'
    $allCalls = @()
    foreach ($inc in $incidents) { $allCalls += @{ kind = 'inc'; id = [string]$inc.id; url = "/security/incidents/$($inc.id)" } }
    foreach ($aid in $phishAlertIds) { $allCalls += @{ kind = 'alert'; id = $aid; url = "/security/alerts_v2/$aid" } }

    # Use beta for both (beta URL requires beta batch endpoint)
    $betaBatchUri = 'https://graph.microsoft.com/beta/$batch'
    $chunkSize = 20
    for ($i = 0; $i -lt $allCalls.Count; $i += $chunkSize) {
        $chunk = $allCalls[$i..([math]::Min($i + $chunkSize - 1, $allCalls.Count - 1))]
        $requests = @()
        $rid = 0
        foreach ($c in $chunk) {
            $rid++
            $requests += [ordered]@{ id = "$rid"; method = 'GET'; url = $c.url }
        }
        $body = @{ requests = $requests } | ConvertTo-Json -Depth 6 -Compress
        try {
            $resp = Invoke-GraphRequestWithRetry -Uri $betaBatchUri -Method POST -Body $body
            foreach ($r in $resp.responses) {
                $origIdx = [int]$r.id - 1
                $orig = $chunk[$origIdx]
                if ($r.status -ge 200 -and $r.status -lt 300 -and $r.body) {
                    if ($orig.kind -eq 'inc') { $betaIncidentMap[$orig.id] = $r.body }
                    else { $betaAlertMap[$orig.id] = $r.body }
                }
            }
        }
        catch {
            Write-Warning "Beta batch failed: $($_.Exception.Message)"
        }
        $pct = [math]::Min(100, [int](($i + $chunk.Count) / $allCalls.Count * 100))
        Write-Progress -Activity "Pre-fetching beta details" -Status "$($i + $chunk.Count)/$($allCalls.Count)" -PercentComplete $pct
    }
    Write-Progress -Activity "Pre-fetching beta details" -Completed
    Write-Host "  Cached $($betaIncidentMap.Count) incidents, $($betaAlertMap.Count) alerts" -ForegroundColor Gray

    # Step 4: Enrich each incident with PTA details
    Write-Host ""
    Write-Host "Analyzing PTA status for $($incidents.Count) incidents..." -ForegroundColor Cyan
    $tid = (Get-MgContext).TenantId
    $enriched = @()
    $i = 0
    foreach ($inc in $incidents) {
        $i++
        Write-Progress -Activity "Analyzing incidents" -Status "$i of $($incidents.Count): $($inc.id)" -PercentComplete (($i / $incidents.Count) * 100)
        try {
            $detail = Get-IncidentPTADetails -Incident $inc -BetaIncidentMap $betaIncidentMap -BetaAlertMap $betaAlertMap -TenantId $tid
            $enriched += $detail
        }
        catch {
            Write-Warning "Failed to analyze incident $($inc.id): $($_.Exception.Message)"
            # Add a minimal record so it's not lost
            $enriched += [PSCustomObject]@{
                IncidentId         = $inc.id
                Title              = $inc.displayName
                Severity           = $inc.severity
                Status             = $inc.status
                CreatedDateTime    = $inc.createdDateTime
                LastUpdateDateTime = $inc.lastUpdateDateTime
                AssignedTo         = $inc.assignedTo
                Classification     = $null
                Determination      = $null
                AlertCount         = if ($inc.alerts) { $inc.alerts.Count } else { 0 }
                SubmissionCount    = 0
                PhishAlertCount    = 0
                NetworkMessageIds  = @()
                PTAStatus          = 'Missed'
                PTAIndicators      = "Error: $($_.Exception.Message)"
                ReportedBy         = ''
                TriageMinutes      = $null
                ResolveMinutes     = $null
                PhishingAlertResolved = $null
                PortalLink         = "https://security.microsoft.com/incidents/$($inc.id)"
                UserLink           = ''
            }
        }
    }
    Write-Progress -Activity "Analyzing incidents" -Completed

    # Optional reporter filter (testing/validation). Apply after enrichment so
    # ReporterUpn / ReportedBy are populated from alert evidence.
    if ($ReporterUpn) {
        $needle = $ReporterUpn.ToLowerInvariant()
        $before = $enriched.Count
        $enriched = @($enriched | Where-Object {
            ($_.ReporterUpn -and $_.ReporterUpn.ToLowerInvariant() -eq $needle) -or
            ($_.ReportedBy  -and $_.ReportedBy.ToLowerInvariant()  -eq $needle)
        })
        Write-Host "[OK] Reporter filter '$ReporterUpn' kept $($enriched.Count) of $before incidents" -ForegroundColor Yellow
        if ($submissions -and $submissions.Count -gt 0) {
            $beforeSubs = $submissions.Count
            $submissions = @($submissions | Where-Object {
                ($_.ReportedBy -and $_.ReportedBy.ToLowerInvariant() -eq $needle)
            })
            Write-Host "[OK] Reporter filter '$ReporterUpn' kept $($submissions.Count) of $beforeSubs submissions" -ForegroundColor Yellow
        }
        if ($enriched.Count -eq 0 -and $submissions.Count -eq 0) {
            Write-Warning "No incidents or submissions matched reporter '$ReporterUpn'."
            return
        }
    }

    # Optional failures-only filter. Apply after enrichment so PTAStatus is set.
    # Drops submissions too — they don't apply to a failures-only view and
    # would otherwise skew the totals/percentages in the metrics block.
    if ($FailuresOnly) {
        $beforeF = $enriched.Count
        $enriched = @($enriched | Where-Object { $_.PTAStatus -eq 'Failed' })
        Write-Host "[OK] FailuresOnly filter kept $($enriched.Count) of $beforeF incidents (PTAStatus = Failed)" -ForegroundColor Yellow
        if ($submissions -and $submissions.Count -gt 0) {
            Write-Host "     Dropping $($submissions.Count) submissions — not applicable in failures-only mode" -ForegroundColor DarkYellow
            $submissions = @()
        }
        if ($enriched.Count -eq 0) {
            Write-Host "No failed PTA runs found in the last $Days days. Nothing to report." -ForegroundColor Green
            return
        }
    }

    # Step 5: Calculate metrics
    Write-Host ""
    $metrics = Get-PTAMetrics -Incidents $enriched -Submissions $submissions

    Write-Host ""
    Write-Host "  Results Summary:" -ForegroundColor White
    if ($submissions.Count -gt 0) {
        Write-Host "    Source:             Microsoft Graph threatSubmission (authoritative)" -ForegroundColor Gray
    } else {
        Write-Host "    Source:             Graph alert evidence (fallback)" -ForegroundColor DarkYellow
    }
    Write-Host "    Submissions:        $($metrics.Total) (across $($metrics.TotalIncidents) incidents)" -ForegroundColor Gray
    Write-Host "    Addressed by PTA:   $($metrics.Addressed)/$($metrics.Total) ($($metrics.AddressedPct)%)" -ForegroundColor Green
    Write-Host "    Resolved (FP):      $($metrics.ResolvedByPTA)/$($metrics.Addressed) ($($metrics.ResolvedPct)%)" -ForegroundColor Green
    Write-Host "    True Positives:     $($metrics.TruePositive)" -ForegroundColor Yellow
    Write-Host "    Not Processed:      $($metrics.Missed)" -ForegroundColor $(if ($metrics.Missed -gt 0) { 'Yellow' } else { 'Green' })
    Write-Host "    Failed:             $($metrics.Failed)" -ForegroundColor $(if ($metrics.Failed -gt 0) { 'Red' } else { 'Green' })
    Write-Host "    MTTT (median):      $(Format-MinutesToHHMMSS $metrics.MTTTMedian)" -ForegroundColor Cyan
    Write-Host "    MTTR (median):      $(Format-MinutesToHHMMSS $metrics.MTTRMedian)" -ForegroundColor Cyan
    Write-Host ""

    # Step 6: Export CSV
    Export-PTACsv -Incidents $enriched -Path $csvPath

    # Step 7: Generate HTML report
    New-PTAHtmlReport -Incidents $enriched -Metrics $metrics -Days $Days -Path $htmlPath

    # Step 8: Open report
    Write-Host ""
    Write-Host "Opening report in browser..." -ForegroundColor Cyan
    Start-Process $htmlPath

    Write-Host ""
    Write-Host "Done! Reports saved to:" -ForegroundColor Green
    Write-Host "  HTML: $htmlPath" -ForegroundColor White
    Write-Host "  CSV:  $csvPath" -ForegroundColor White
    Write-Host ""
}

Main
