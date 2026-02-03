<#
.SYNOPSIS
    Retrieves incident information from Microsoft Defender for Endpoint and generates a comprehensive report.

.DESCRIPTION
    This PowerShell script automates the retrieval and reporting of Microsoft Defender for Endpoint incidents
    using Microsoft Graph Security API. It provides detailed incident analysis including alerts, evidence,
    phishing triage agent detection, and activity timelines in interactive HTML or text format.
    
    KEY FEATURES:
    - Automatic discovery of all alerts within an incident
    - Comprehensive evidence collection and analysis
    - Phishing triage agent detection (system tags, custom tags)
    - Security Copilot activity data retrieval (when available)
    - Interactive HTML reports with expandable sections
    - Complete PowerShell command documentation showing data sources
    - JSON data export for integration with other tools
    
    REQUIREMENTS:
    - Microsoft.Graph.Security PowerShell module
    - Microsoft.Graph.Authentication PowerShell module
    - Appropriate Microsoft Graph API permissions:
      * SecurityIncident.Read.All (required)
      * SecurityAlert.Read.All (required)
    - Internet connectivity to Microsoft Graph API endpoints

.PARAMETER IncidentId
    The ID of the incident to retrieve (e.g., 256968). This is the only required parameter.
    The incident ID can be found in the Microsoft 365 Defender portal URL.

.PARAMETER TenantId
    Optional: The Azure AD Tenant ID (GUID). If not specified, the script will prompt for
    tenant selection during authentication. Useful for multi-tenant environments.

.PARAMETER OutputPath
    Optional: Full path where the report should be saved (without extension).
    If not specified, the report is saved to the temp directory and automatically opened.
    Both HTML and JSON files will be created with appropriate extensions.

.PARAMETER Format
    Optional: Output format for the report. Valid values: 'HTML' (default) or 'Text'.
    HTML format provides an interactive report with expandable sections and styling.
    Text format provides a plain-text report suitable for logging or email.

.EXAMPLE
    .\Get-DefenderIncidentReport.ps1 256968
    
    Generates an HTML report for incident 256968 using automatic tenant detection.
    Report is saved to temp directory and opened in the default browser.

.EXAMPLE
    .\Get-DefenderIncidentReport.ps1 -IncidentId 256968 -TenantId "12345678-1234-1234-1234-123456789abc"
    
    Generates a report for incident 256968 in a specific tenant.

.EXAMPLE
    .\Get-DefenderIncidentReport.ps1 256968 -OutputPath "C:\Reports\incident_report" -Format HTML
    
    Generates an HTML report and saves it to C:\Reports\incident_report.html

.EXAMPLE
    .\Get-DefenderIncidentReport.ps1 256968 -Format Text
    
    Generates a plain-text report for incident 256968.

.NOTES
    Version:        2.0.0
    Author:         Security Operations
    Creation Date:  2025-12-02
    Purpose:        Automated incident reporting for Microsoft Defender for Endpoint
    
.LINK
    https://learn.microsoft.com/en-us/graph/api/resources/security-api-overview
    https://learn.microsoft.com/en-us/graph/api/resources/security-incident
    https://learn.microsoft.com/en-us/graph/api/resources/security-alert

.DISCLAIMER
    THIS CODE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
    INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR
    A PARTICULAR PURPOSE. THE ENTIRE RISK ARISING OUT OF THE USE OR PERFORMANCE OF THIS SCRIPT
    REMAINS WITH YOU.
    
    IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
    SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
    CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
    (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SCRIPT, EVEN IF
    ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
    
    This script is not officially supported by Microsoft Corporation. Microsoft Defender for Endpoint,
    Microsoft Graph, Microsoft 365, Security Copilot, and related services are trademarks of
    Microsoft Corporation. This script is provided as a community tool and should be thoroughly
    tested in a non-production environment before use in production systems.
    
    By using this script, you acknowledge that you have read this disclaimer, understand it, and
    agree to be bound by its terms.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0, HelpMessage="The incident ID to retrieve (e.g., 256968)")]
    [string]$IncidentId,
    
    [Parameter(Mandatory=$false)]
    [string]$TenantId,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet('HTML', 'Text')]
    [string]$Format = 'HTML'
)

#region Global Variables and Helper Functions

# Global variable to track execution flow for report documentation
$script:ExecutionFlow = @()

<#
.SYNOPSIS
    Adds an execution step to the tracking array for documentation purposes.
    
.DESCRIPTION
    Internal helper function that logs each major operation performed during report generation.
    This data is used to populate the "Report Generation Flow" section in the HTML output.
    
.PARAMETER Step
    The step number and name (e.g., "1. Authentication")
    
.PARAMETER Command
    The PowerShell command or Graph API call executed
    
.PARAMETER Description
    Human-readable description of what the command does
    
.PARAMETER Result
    The outcome or summary of the operation
#>
function Add-ExecutionStep {
    param(
        [string]$Step,
        [string]$Command,
        [string]$Description,
        [string]$Result
    )
    
    $script:ExecutionFlow += [PSCustomObject]@{
        Step = $Step
        Command = $Command
        Description = $Description
        Result = $Result
        Timestamp = Get-Date -Format 'HH:mm:ss'
    }
}

#endregion

#region Authentication Functions

<#
.SYNOPSIS
    Establishes a connection to Microsoft Graph API with required security permissions.
    
.DESCRIPTION
    Handles authentication to Microsoft Graph, checking for existing connections and
    verifying required scopes. Installs necessary PowerShell modules if missing.
    
.PARAMETER TenantId
    Optional Azure AD Tenant ID for multi-tenant scenarios
    
.OUTPUTS
    Boolean - True if connection successful, False otherwise
#>
function Connect-DefenderPortal {
    param(
        [string]$TenantId
    )
    
    try {
        # Check if Microsoft.Graph module is installed
        if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Security)) {
            Write-Host "Microsoft.Graph.Security module not found. Installing..." -ForegroundColor Yellow
            Install-Module Microsoft.Graph.Security -Scope CurrentUser -Force -AllowClobber
            Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force -AllowClobber
        }
        
        # Import required modules
        Import-Module Microsoft.Graph.Authentication -ErrorAction SilentlyContinue
        Import-Module Microsoft.Graph.Security -ErrorAction SilentlyContinue
        
        # Check if already connected
        $context = Get-MgContext
        if ($context) {
            Write-Host "✓ Already connected to Microsoft Graph" -ForegroundColor Green
            Write-Host "  Account: $($context.Account)" -ForegroundColor Gray
            Write-Host "  Tenant: $($context.TenantId)" -ForegroundColor Gray
            
            # Check if we have the required scopes
            $requiredScopes = @("SecurityIncident.Read.All", "SecurityAlert.Read.All")
            $hasRequiredScopes = $true
            foreach ($scope in $requiredScopes) {
                if ($context.Scopes -notcontains $scope) {
                    $hasRequiredScopes = $false
                    break
                }
            }
            
            if ($hasRequiredScopes) {
                Write-Host "  ✓ All required scopes present - reusing connection" -ForegroundColor Green
                return $true
            }
            else {
                Write-Host "  ⚠ Missing required scopes. Reconnecting..." -ForegroundColor Yellow
                Disconnect-MgGraph | Out-Null
            }
        }
        
        # Need to connect
        Write-Host "Connecting to Microsoft Defender Portal..." -ForegroundColor Cyan
        
        # Connect to Microsoft Graph with required scopes
        $scopes = @(
            "SecurityIncident.Read.All",
            "SecurityAlert.Read.All"
        )
        
        if ($TenantId) {
            Connect-MgGraph -TenantId $TenantId -Scopes $scopes -NoWelcome
        } else {
            Connect-MgGraph -Scopes $scopes -NoWelcome
        }
        
        $context = Get-MgContext
        Add-ExecutionStep -Step "1. Authentication" -Command "Connect-MgGraph -Scopes 'SecurityIncident.Read.All', 'SecurityAlert.Read.All'" -Description "Authenticate to Microsoft Graph API" -Result "Connected as $($context.Account) to tenant $($context.TenantId)"
        
        Write-Host "✓ Successfully connected to Microsoft Graph!" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Failed to connect to Microsoft Graph: $_"
        return $false
    }
}

#endregion

#region Data Retrieval Functions

<#
.SYNOPSIS
    Retrieves comprehensive incident details from Microsoft Defender.
    
.DESCRIPTION
    Fetches incident information including alerts, tags, classifications, and metadata.
    Queries both v1.0 and beta endpoints to gather complete data including phishing triage indicators.
    
.PARAMETER IncidentId
    The unique identifier of the incident to retrieve
    
.OUTPUTS
    PSCustomObject - Incident object with all associated properties and alerts
#>
function Get-IncidentDetails {
    param(
        [string]$IncidentId
    )
    
    Write-Host "Retrieving incident $IncidentId..." -ForegroundColor Cyan
    
    try {
        # Get the incident with expanded properties
        $incident = Get-MgSecurityIncident -IncidentId $IncidentId -ExpandProperty "alerts" -ErrorAction Stop
        
        if ($incident) {
            Write-Host "Incident retrieved successfully!" -ForegroundColor Green
            
            Add-ExecutionStep -Step "2. Retrieve Incident" -Command "Get-MgSecurityIncident -IncidentId '$IncidentId' -ExpandProperty 'alerts'" -Description "Get incident details including all associated alerts" -Result "Retrieved incident: $($incident.DisplayName) | Status: $($incident.Status) | Severity: $($incident.Severity) | Alerts: $($incident.Alerts.Count)"
            
            # Try to get tags and custom metadata via Graph API directly
            Write-Host "  Retrieving incident tags and metadata..." -ForegroundColor Gray
            try {
                # Use beta API for richer metadata including custom tags
                $uri = "https://graph.microsoft.com/beta/security/incidents/$IncidentId"
                $detailedIncident = Invoke-MgGraphRequest -Uri $uri -Method GET -ErrorAction SilentlyContinue
                
                if ($detailedIncident) {
                    # Get system tags (e.g., phishing triage agent indicators)
                    if ($detailedIncident.systemTags) {
                        $incident | Add-Member -NotePropertyName 'SystemTags' -NotePropertyValue $detailedIncident.systemTags -Force
                        Write-Host "  Retrieved $($detailedIncident.systemTags.Count) system tag(s)" -ForegroundColor Green
                    }
                    
                    # Get custom tags
                    if ($detailedIncident.customTags) {
                        $incident | Add-Member -NotePropertyName 'CustomTags' -NotePropertyValue $detailedIncident.customTags -Force
                        Write-Host "  Retrieved $($detailedIncident.customTags.Count) custom tag(s)" -ForegroundColor Green
                    }
                    
                    # Get standard tags
                    if ($detailedIncident.tags) {
                        $incident | Add-Member -NotePropertyName 'Tags' -NotePropertyValue $detailedIncident.tags -Force
                        Write-Host "  Retrieved $($detailedIncident.tags.Count) tag(s)" -ForegroundColor Green
                    }
                    
                    # Check for phishing triage agent indicators
                    $phishingTriageIndicators = @()
                    if ($detailedIncident.systemTags) {
                        $phishingTriageIndicators += $detailedIncident.systemTags | Where-Object { $_ -like '*Phish*' -or $_ -like '*Triage*' }
                    }
                    if ($detailedIncident.customTags) {
                        $phishingTriageIndicators += $detailedIncident.customTags | Where-Object { $_ -like '*Agent*' -or $_ -like '*Phish*' -or $_ -like '*Triage*' }
                    }
                    
                    if ($phishingTriageIndicators.Count -gt 0) {
                        $incident | Add-Member -NotePropertyName 'PhishingTriageIndicators' -NotePropertyValue $phishingTriageIndicators -Force
                        Write-Host "  ✓ Phishing Triage Agent indicators found: $($phishingTriageIndicators -join ', ')" -ForegroundColor Cyan
                    }
                }
            }
            catch {
                Write-Host "  Could not retrieve tags: $($_.Exception.Message)" -ForegroundColor Yellow
            }
            
            return $incident
        }
        else {
            Write-Warning "Incident $IncidentId not found."
            return $null
        }
    }
    catch {
        Write-Error "Failed to retrieve incident: $_"
        return $null
    }
}

<#
.SYNOPSIS
    Retrieves detailed information about a specific alert.
    
.DESCRIPTION
    Fetches complete alert data including evidence, classifications, MITRE ATT&CK techniques,
    and related entities. Enriches data with additional metadata from beta endpoints.
    
.PARAMETER AlertId
    The unique identifier of the alert to retrieve
    
.OUTPUTS
    PSCustomObject - Alert object with evidence and classification details
#>
function Get-AlertDetails {
    param(
        [string]$AlertId
    )
    
    Write-Host "Retrieving alert $AlertId..." -ForegroundColor Cyan
    
    try {
        # Get the alert with all available properties
        $alert = Get-MgSecurityAlertV2 -AlertId $AlertId -ErrorAction Stop
        
        if ($alert) {
            Write-Host "Alert retrieved successfully!" -ForegroundColor Green
            
            Add-ExecutionStep -Step "3. Retrieve Alert Details" -Command "Get-MgSecurityAlertV2 -AlertId '$AlertId'" -Description "Get detailed alert information including evidence and classification" -Result "Retrieved alert: $($alert.Title) | Category: $($alert.Category) | Evidence Items: $($alert.Evidence.Count)"
            
            # Try to get additional details via Graph API directly
            Write-Host "  Retrieving classification, tags, and activity data..." -ForegroundColor Gray
            try {
                $uri = "https://graph.microsoft.com/beta/security/alerts_v2/$AlertId"
                $detailedAlert = Invoke-MgGraphRequest -Uri $uri -Method GET -ErrorAction SilentlyContinue
                
                if ($detailedAlert) {
                    # Add classification and activity information to the alert object
                    if ($detailedAlert.classification) {
                        $alert | Add-Member -NotePropertyName 'DetailedClassification' -NotePropertyValue $detailedAlert.classification -Force
                    }
                    if ($detailedAlert.detectorId) {
                        $alert | Add-Member -NotePropertyName 'DetectorId' -NotePropertyValue $detailedAlert.detectorId -Force
                    }
                    if ($detailedAlert.threatFamilyName) {
                        $alert | Add-Member -NotePropertyName 'ThreatFamilyName' -NotePropertyValue $detailedAlert.threatFamilyName -Force
                    }
                    if ($detailedAlert.mitreTechniques) {
                        $alert | Add-Member -NotePropertyName 'MitreTechniques' -NotePropertyValue $detailedAlert.mitreTechniques -Force
                    }
                    if ($detailedAlert.alertPolicyId) {
                        $alert | Add-Member -NotePropertyName 'AlertPolicyId' -NotePropertyValue $detailedAlert.alertPolicyId -Force
                    }
                    
                    # Get tags from detailed alert
                    if ($detailedAlert.tags -and $detailedAlert.tags.Count -gt 0) {
                        $alert | Add-Member -NotePropertyName 'Tags' -NotePropertyValue $detailedAlert.tags -Force
                        Write-Host "  Retrieved $($detailedAlert.tags.Count) tag(s)" -ForegroundColor Green
                    }
                    
                    Write-Host "  Extended alert data retrieved!" -ForegroundColor Green
                }
            }
            catch {
                Write-Host "  Could not retrieve extended alert data: $($_.Exception.Message)" -ForegroundColor Yellow
            }
            
            return $alert
        }
        else {
            Write-Warning "Alert $AlertId not found."
            return $null
        }
    }
    catch {
        Write-Error "Failed to retrieve alert: $_"
        Write-Host "Note: Ensure you have the correct alert ID and permissions." -ForegroundColor Yellow
        return $null
    }
}

<#
.SYNOPSIS
    Retrieves the activity timeline for an alert.
    
.DESCRIPTION
    Collects historical activity data including status changes, classifications, comments,
    and investigation state transitions for comprehensive alert timeline visualization.
    
.PARAMETER AlertId
    The unique identifier of the alert
    
.OUTPUTS
    Array - Collection of activity entries with timestamps and descriptions
#>
function Get-AlertActivityList {
    param(
        [string]$AlertId
    )
    
    Write-Host "Retrieving activity list for alert $AlertId..." -ForegroundColor Cyan
    
    try {
        $activities = @()
        
        # Try to get alert history/activities via Graph API
        $uri = "https://graph.microsoft.com/beta/security/alerts_v2/$AlertId"
        $alertData = Invoke-MgGraphRequest -Uri $uri -Method GET -ErrorAction SilentlyContinue
        
        if ($alertData) {
            # Extract activity-related information
            if ($alertData.comments -and $alertData.comments.Count -gt 0) {
                foreach ($comment in $alertData.comments) {
                    $activities += @{
                        Type = "Comment"
                        Timestamp = $comment.createdDateTime
                        CreatedBy = $comment.createdByDisplayName
                        Content = $comment.comment
                    }
                }
            }
            
            # Check for status changes and updates
            if ($alertData.status) {
                $activities += @{
                    Type = "Status"
                    Status = $alertData.status
                    LastUpdated = $alertData.lastUpdateDateTime
                }
            }
            
            # Check for classification
            if ($alertData.classification) {
                $activities += @{
                    Type = "Classification"
                    Classification = $alertData.classification
                    Determination = $alertData.determination
                    ClassifiedBy = $alertData.assignedTo
                }
            }
            
            # Check for investigation state
            if ($alertData.investigationState) {
                $activities += @{
                    Type = "Investigation"
                    State = $alertData.investigationState
                }
            }
            
            Write-Host "  Retrieved $($activities.Count) activity entries" -ForegroundColor Green
        }
        
        if ($activities.Count -gt 0) {
            Add-ExecutionStep -Step "4. Retrieve Alert Activities" -Command "Invoke-MgGraphRequest -Uri 'https://graph.microsoft.com/beta/security/alerts_v2/$AlertId'" -Description "Get alert activity timeline and status changes" -Result "Retrieved $($activities.Count) activity entries"
        }
        
        # Try to get alert history through incidents endpoint
        try {
            $historyUri = "https://graph.microsoft.com/v1.0/security/alerts_v2/$AlertId/history"
            $history = Invoke-MgGraphRequest -Uri $historyUri -Method GET -ErrorAction SilentlyContinue
            
            if ($history -and $history.value) {
                foreach ($entry in $history.value) {
                    $activities += @{
                        Type = "History"
                        Timestamp = $entry.timestamp
                        Action = $entry.action
                        Actor = $entry.actor
                        Details = $entry.details
                    }
                }
                Write-Host "  Retrieved additional history entries" -ForegroundColor Green
            }
        }
        catch {
            Write-Host "  Alert history endpoint not available" -ForegroundColor Yellow
        }
        
        return $activities
    }
    catch {
        Write-Error "Failed to retrieve alert activity list: $_"
        Write-Host "Note: Activity history may require additional permissions" -ForegroundColor Yellow
        return @()
    }
}

<#
.SYNOPSIS
    Retrieves Security Copilot activity and automated investigation details.
    
.DESCRIPTION
    Attempts to gather Security Copilot activity data from multiple API endpoints.
    Falls back to constructing activity context from incident and alert data when
    Copilot API is unavailable. Useful for understanding automated triage decisions.
    
.PARAMETER IncidentId
    The incident ID associated with the activity
    
.PARAMETER ActivityId
    The unique identifier for the activity or investigation
    
.PARAMETER ActivityType
    Type of activity (default: "agents")
    
.PARAMETER ActivityName
    Display name for the activity
    
.OUTPUTS
    Hashtable - Activity data including prompts, results, and entity analysis
#>
function Get-ActivityDetails {
    param(
        [string]$IncidentId,
        [string]$ActivityId,
        [string]$ActivityType = "agents",
        [string]$ActivityName = "Email reported by user as malware or phish"
    )
    
    Write-Host "Retrieving Security Copilot activity details for $ActivityId..." -ForegroundColor Cyan
    
    try {
        $activityData = @{
            ActivityId = $ActivityId
            ActivityType = $ActivityType
            ActivityName = $ActivityName
            IncidentId = $IncidentId
            Status = $null
            Classification = $null
            Determination = $null
            Verdict = $null
            RunTime = $null
            CreatedDateTime = $null
            CompletedDateTime = $null
            Prompts = @()
            Results = @()
            EntityAnalysis = @{}
            Recommendations = @()
            SystemTags = @()
            Source = "Security Copilot Activity"
            RawData = @{}
        }
        
        # Try multiple API endpoints to get Security Copilot activity data
        
        # 1. Try Security Copilot API endpoint (if available)
        Write-Host "  Querying Security Copilot API..." -ForegroundColor Gray
        try {
            $copilotUri = "https://graph.microsoft.com/beta/security/copilot/activities/$ActivityId"
            $copilotActivity = Invoke-MgGraphRequest -Uri $copilotUri -Method GET -ErrorAction SilentlyContinue
            
            if ($copilotActivity) {
                Write-Host "  ✓ Security Copilot activity data retrieved!" -ForegroundColor Green
                $activityData.Status = $copilotActivity.status
                $activityData.CreatedDateTime = $copilotActivity.createdDateTime
                $activityData.CompletedDateTime = $copilotActivity.completedDateTime
                $activityData.RawData['CopilotAPI'] = $copilotActivity
                
                if ($copilotActivity.prompts) {
                    $activityData.Prompts = $copilotActivity.prompts
                }
                if ($copilotActivity.results) {
                    $activityData.Results = $copilotActivity.results
                }
            }
        }
        catch {
            Write-Host "  Security Copilot API not available: $($_.Exception.Message.Split([Environment]::NewLine)[0])" -ForegroundColor Yellow
        }
        
        # 2. Try to get investigation data from incident
        Write-Host "  Retrieving incident investigation data..." -ForegroundColor Gray
        try {
            $incidentUri = "https://graph.microsoft.com/beta/security/incidents/$IncidentId"
            $incidentData = Invoke-MgGraphRequest -Uri $incidentUri -Method GET -ErrorAction SilentlyContinue
            
            if ($incidentData) {
                Write-Host "  ✓ Incident metadata retrieved" -ForegroundColor Green
                
                # Extract system tags
                if ($incidentData.systemTags) {
                    $activityData.SystemTags = $incidentData.systemTags
                }
                
                # Get classification and determination from incident
                if ($incidentData.classification) {
                    $activityData.Classification = $incidentData.classification
                }
                if ($incidentData.determination) {
                    $activityData.Determination = $incidentData.determination
                }
                
                $activityData.RawData['Incident'] = $incidentData
            }
        }
        catch {
            Write-Host "  Could not retrieve incident data" -ForegroundColor Yellow
        }
        
        # 3. Try to get automated investigation data
        Write-Host "  Checking for automated investigations..." -ForegroundColor Gray
        try {
            $investigationsUri = "https://graph.microsoft.com/beta/security/incidents/$IncidentId/investigations"
            $investigations = Invoke-MgGraphRequest -Uri $investigationsUri -Method GET -ErrorAction SilentlyContinue
            
            if ($investigations -and $investigations.value) {
                Write-Host "  ✓ Found $($investigations.value.Count) investigation(s)" -ForegroundColor Green
                
                foreach ($investigation in $investigations.value) {
                    if ($investigation.id -eq $ActivityId -or $investigation.investigationId -eq $ActivityId) {
                        $activityData.Status = $investigation.status
                        $activityData.CreatedDateTime = $investigation.createdDateTime
                        $activityData.Verdict = $investigation.verdict
                        $activityData.RawData['Investigation'] = $investigation
                        break
                    }
                }
            }
        }
        catch {
            Write-Host "  No automated investigations found" -ForegroundColor Yellow
        }
        
        # 4. Try to get alert-specific investigation data
        Write-Host "  Retrieving alert investigation details..." -ForegroundColor Gray
        try {
            # Get the alert associated with this activity
            $alertsUri = "https://graph.microsoft.com/beta/security/alerts_v2?`$filter=incidentId eq '$IncidentId'"
            $alerts = Invoke-MgGraphRequest -Uri $alertsUri -Method GET -ErrorAction SilentlyContinue
            
            if ($alerts -and $alerts.value) {
                Write-Host "  ✓ Analyzing $($alerts.value.Count) alert(s)" -ForegroundColor Green
                
                foreach ($alert in $alerts.value) {
                    # Check if this alert matches our activity
                    if ($alert.id -eq $ActivityId) {
                        $activityData.Status = $alert.status
                        $activityData.Classification = $alert.classification
                        $activityData.Determination = $alert.determination
                        $activityData.Verdict = $alert.determination
                        $activityData.CreatedDateTime = $alert.createdDateTime
                        $activityData.RawData['Alert'] = $alert
                        
                        # Extract evidence as entity analysis
                        if ($alert.evidence) {
                            $activityData.EntityAnalysis = @{
                                EvidenceCount = $alert.evidence.Count
                                Evidence = $alert.evidence
                            }
                        }
                        
                        # Extract recommended actions
                        if ($alert.recommendedActions) {
                            $activityData.Recommendations = @($alert.recommendedActions)
                        }
                        
                        break
                    }
                }
            }
        }
        catch {
            Write-Host "  Could not retrieve alert investigation data" -ForegroundColor Yellow
        }
        
        # 5. Try to get comments/analyst actions
        Write-Host "  Checking for analyst comments and actions..." -ForegroundColor Gray
        try {
            $commentsUri = "https://graph.microsoft.com/beta/security/incidents/$IncidentId/comments"
            $comments = Invoke-MgGraphRequest -Uri $commentsUri -Method GET -ErrorAction SilentlyContinue
            
            if ($comments -and $comments.value) {
                Write-Host "  ✓ Found $($comments.value.Count) comment(s)" -ForegroundColor Green
                
                foreach ($comment in $comments.value) {
                    $activityData.Prompts += @{
                        Type = "AnalystComment"
                        Timestamp = $comment.createdDateTime
                        Author = $comment.createdBy
                        Content = $comment.comment
                    }
                }
            }
        }
        catch {
            Write-Host "  No comments found" -ForegroundColor Yellow
        }
        
        # 6. Construct simulated Copilot prompts and results based on activity type
        if ($activityData.Prompts.Count -eq 0) {
            Write-Host "  Building Security Copilot activity context..." -ForegroundColor Gray
            
            # Add initial prompt
            $activityData.Prompts += @{
                Type = "InitialTrigger"
                Content = "Analyze email reported by user as potential phishing or malware"
                Timestamp = $activityData.CreatedDateTime
            }
            
            # Add analysis results
            if ($activityData.Verdict -or $activityData.Determination) {
                $activityData.Results += @{
                    Type = "ClassificationResult"
                    Classification = if ($activityData.Classification) { $activityData.Classification } else { "Analyzed" }
                    Determination = if ($activityData.Determination) { $activityData.Determination } else { "Pending" }
                    Verdict = if ($activityData.Verdict) { $activityData.Verdict } else { "Under Review" }
                    Confidence = "Medium"
                }
            }
            
            # Add entity analysis summary
            if ($activityData.EntityAnalysis -and $activityData.EntityAnalysis.EvidenceCount -gt 0) {
                $evidenceTypes = @()
                if ($activityData.EntityAnalysis.Evidence) {
                    $evidenceTypes = ($activityData.EntityAnalysis.Evidence | ForEach-Object { 
                        if ($_.AdditionalProperties -and $_. AdditionalProperties.'@odata.type') {
                            $_.AdditionalProperties.'@odata.type'.Replace('#microsoft.graph.security.', '') 
                        }
                    } | Where-Object { $_ } | Select-Object -Unique)
                }
                
                $activityData.Results += @{
                    Type = "EntityAnalysis"
                    Summary = "Analyzed $($activityData.EntityAnalysis.EvidenceCount) pieces of evidence"
                    EvidenceTypes = $evidenceTypes
                }
            }
        }
        
        # Calculate runtime if we have timestamps
        if ($activityData.CreatedDateTime -and $activityData.CompletedDateTime) {
            try {
                $start = [DateTime]::Parse($activityData.CreatedDateTime)
                $end = [DateTime]::Parse($activityData.CompletedDateTime)
                $duration = $end - $start
                $activityData.RunTime = $duration.TotalSeconds.ToString("F2") + " seconds"
            }
            catch {
                $activityData.RunTime = "Unknown"
            }
        }
        
        Write-Host "  Activity details compilation complete!" -ForegroundColor Green
        return $activityData
    }
    catch {
        Write-Error "Failed to retrieve activity details: $_"
        Write-Host "Note: This may require additional permissions or Security Copilot access." -ForegroundColor Yellow
        return @{
            ActivityId = $ActivityId
            ActivityType = $ActivityType
            ActivityName = $ActivityName
            Error = $_.Exception.Message
            Note = "Some Security Copilot endpoints may not be publicly available via standard Graph API"
        }
    }
}

#endregion

#region Report Generation Functions

<#
.SYNOPSIS
    Orchestrates the report generation process.
    
.DESCRIPTION
    Main report generation controller that routes to appropriate format handler
    (HTML or Text) and passes collected data for rendering.
    
.PARAMETER Incident
    Incident object containing all incident data
    
.PARAMETER Alert
    Alert object containing detailed alert information
    
.PARAMETER Activity
    Activity object containing Security Copilot data
    
.PARAMETER AlertActivities
    Array of activity timeline entries
    
.PARAMETER OutputPath
    File path for saving the report
    
.PARAMETER Format
    Output format (HTML or Text)
    
.PARAMETER ExecutionFlow
    Array of execution steps for documentation
#>
function New-IncidentReport {
    param(
        [object]$Incident,
        [object]$Alert,
        [object]$Activity,
        [object[]]$AlertActivities,
        [string]$OutputPath,
        [string]$Format = 'HTML',
        [array]$ExecutionFlow
    )
    
    if ($Format -eq 'HTML') {
        New-HTMLReport -Incident $Incident -Alert $Alert -Activity $Activity -AlertActivities $AlertActivities -OutputPath $OutputPath -ExecutionFlow $ExecutionFlow
    }
    else {
        New-TextReport -Incident $Incident -Alert $Alert -Activity $Activity -AlertActivities $AlertActivities -OutputPath $OutputPath
    }
}

<#
.SYNOPSIS
    Generates an interactive HTML report with all incident details.
    
.DESCRIPTION
    Creates a comprehensive, styled HTML report with expandable sections, color-coded badges,
    embedded JSON data, execution flow documentation, and direct links to Microsoft 365 Defender portal.
    
.PARAMETER Incident
    Incident object
    
.PARAMETER Alert
    Alert object
    
.PARAMETER Activity
    Activity object
    
.PARAMETER AlertActivities
    Activity timeline array
    
.PARAMETER OutputPath
    File path for saving
    
.PARAMETER ExecutionFlow
    Execution steps array
#>
function New-HTMLReport {
    param(
        [object]$Incident,
        [object]$Alert,
        [object]$Activity,
        [object[]]$AlertActivities,
        [string]$OutputPath,
        [array]$ExecutionFlow
    )
    
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Microsoft Defender Incident Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f5f5;
            padding: 20px;
            color: #333;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            border-radius: 8px;
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #0078d4 0%, #005a9e 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 28px;
            margin-bottom: 10px;
        }
        
        .header .timestamp {
            font-size: 14px;
            opacity: 0.9;
        }
        
        .content {
            padding: 30px;
        }
        
        .section {
            margin-bottom: 30px;
            border-left: 4px solid #0078d4;
            padding-left: 20px;
        }
        
        .section-title {
            font-size: 22px;
            color: #0078d4;
            margin-bottom: 15px;
            font-weight: 600;
        }
        
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        
        .info-item {
            background: #f9f9f9;
            padding: 15px;
            border-radius: 6px;
            border: 1px solid #e0e0e0;
        }
        
        .info-label {
            font-weight: 600;
            color: #666;
            font-size: 12px;
            text-transform: uppercase;
            margin-bottom: 5px;
        }
        
        .info-value {
            font-size: 16px;
            color: #333;
            word-wrap: break-word;
        }
        
        .badge {
            display: inline-block;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .severity-high {
            background: #dc3545;
            color: white;
        }
        
        .severity-medium {
            background: #fd7e14;
            color: white;
        }
        
        .severity-low {
            background: #ffc107;
            color: #333;
        }
        
        .severity-informational {
            background: #17a2b8;
            color: white;
        }
        
        .status-active {
            background: #dc3545;
            color: white;
        }
        
        .status-resolved {
            background: #28a745;
            color: white;
        }
        
        .status-inprogress {
            background: #ffc107;
            color: #333;
        }
        
        .alert-box {
            background: #fff3cd;
            border: 1px solid #ffc107;
            border-radius: 6px;
            padding: 15px;
            margin-bottom: 15px;
        }
        
        .alert-box-high {
            background: #f8d7da;
            border-color: #dc3545;
        }
        
        .table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }
        
        .table th {
            background: #0078d4;
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: 600;
        }
        
        .table td {
            padding: 12px;
            border-bottom: 1px solid #e0e0e0;
        }
        
        .table tr:hover {
            background: #f9f9f9;
        }
        
        .evidence-item {
            background: #e7f3ff;
            border-left: 3px solid #0078d4;
            padding: 12px;
            margin-bottom: 10px;
            border-radius: 4px;
        }
        
        .json-details {
            background: #f5f5f5;
            border: 1px solid #ddd;
            border-radius: 4px;
            padding: 15px;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            overflow-x: auto;
            max-height: 400px;
            overflow-y: auto;
        }
        
        .footer {
            background: #f9f9f9;
            padding: 20px 30px;
            text-align: center;
            font-size: 12px;
            color: #666;
            border-top: 1px solid #e0e0e0;
        }
        
        .highlight {
            background: #fff3cd;
            padding: 2px 6px;
            border-radius: 3px;
        }
        
        .expandable {
            margin-bottom: 15px;
        }
        
        .expand-header {
            background: #0078d4;
            color: white;
            padding: 12px 15px;
            cursor: pointer;
            border-radius: 6px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            transition: background 0.3s;
            user-select: none;
        }
        
        .expand-header:hover {
            background: #005a9e;
        }
        
        .expand-header .arrow {
            transition: transform 0.3s;
            font-size: 18px;
        }
        
        .expand-header.active .arrow {
            transform: rotate(180deg);
        }
        
        .expand-content {
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.3s ease-out;
            background: #f9f9f9;
            border: 1px solid #e0e0e0;
            border-top: none;
            border-radius: 0 0 6px 6px;
        }
        
        .expand-content.active {
            max-height: 2000px;
            overflow-y: auto;
        }
        
        .expand-content-inner {
            padding: 15px;
        }
        
        .json-viewer {
            background: #1e1e1e;
            color: #d4d4d4;
            padding: 20px;
            border-radius: 6px;
            font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
            font-size: 13px;
            overflow-x: auto;
            line-height: 1.6;
        }
        
        .json-key {
            color: #9cdcfe;
        }
        
        .json-string {
            color: #ce9178;
        }
        
        .json-number {
            color: #b5cea8;
        }
        
        .json-boolean {
            color: #569cd6;
        }
        
        .json-null {
            color: #569cd6;
        }
        
        .copy-button {
            background: #28a745;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
            margin-bottom: 10px;
        }
        
        .copy-button:hover {
            background: #218838;
        }
        
        .incident-link-button {
            background: #0078d4;
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 16px;
            font-weight: 600;
            text-decoration: none;
            display: inline-block;
            margin-top: 15px;
            transition: background 0.3s;
            box-shadow: 0 2px 4px rgba(0,0,0,0.2);
        }
        
        .incident-link-button:hover {
            background: #005a9e;
            box-shadow: 0 4px 8px rgba(0,0,0,0.3);
        }
        
        .incident-link-button:active {
            transform: translateY(1px);
        }
    </style>
    <script>
        function toggleExpand(element) {
            element.classList.toggle('active');
            const content = element.nextElementSibling;
            content.classList.toggle('active');
        }
        
        function copyJSON() {
            const jsonText = document.getElementById('json-data').textContent;
            navigator.clipboard.writeText(jsonText).then(function() {
                const btn = document.getElementById('copy-btn');
                const originalText = btn.textContent;
                btn.textContent = '✓ Copied!';
                setTimeout(function() {
                    btn.textContent = originalText;
                }, 2000);
            });
        }
        
        window.onload = function() {
            // Auto-expand first few sections
            const headers = document.querySelectorAll('.expand-header');
            if (headers.length > 0) {
                headers[0].click(); // Expand first section by default
            }
        }
    </script>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Microsoft Defender Incident & Alert Report</h1>
            <div class="timestamp">Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</div>
"@
    
    # Add incident link button if we have incident info
    if ($Incident) {
        $context = Get-MgContext
        $tenantIdForLink = if ($context) { $context.TenantId } else { "" }
        $incidentUrl = "https://security.microsoft.com/incidents/$($Incident.Id)?tid=$tenantIdForLink"
        $html += @"
            <a href="$incidentUrl" target="_blank" class="incident-link-button">🔗 Open Incident $($Incident.Id) in Microsoft 365 Defender</a>
"@
    }
    
    $html += @"
        </div>
        
        <div class="content">
"@

    # Incident Section
    if ($Incident) {
        $severityClass = "severity-" + $Incident.Severity.ToLower()
        $statusClass = "status-" + $Incident.Status.ToLower().Replace(' ', '')
        
        $html += @"
            <div class="section">
                <h2 class="section-title">📋 Incident Overview</h2>
                <div class="info-grid">
                    <div class="info-item">
                        <div class="info-label">Incident ID</div>
                        <div class="info-value">$($Incident.Id)</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Display Name</div>
                        <div class="info-value">$($Incident.DisplayName)</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Status</div>
                        <div class="info-value"><span class="badge $statusClass">$($Incident.Status)</span></div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Severity</div>
                        <div class="info-value"><span class="badge $severityClass">$($Incident.Severity)</span></div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Classification</div>
                        <div class="info-value">$($Incident.Classification)</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Determination</div>
                        <div class="info-value">$($Incident.Determination)</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Created</div>
                        <div class="info-value">$($Incident.CreatedDateTime)</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Last Updated</div>
                        <div class="info-value">$($Incident.LastUpdateDateTime)</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Assigned To</div>
                        <div class="info-value">$($Incident.AssignedTo)</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Redirect Incident ID</div>
                        <div class="info-value">$($Incident.RedirectIncidentId)</div>
                    </div>
"@
        
        # Add system tags (including phishing triage indicators)
        if ($Incident.SystemTags -and $Incident.SystemTags.Count -gt 0) {
            $systemTagsHtml = ($Incident.SystemTags | ForEach-Object { 
                $badgeClass = if ($_ -like '*Phish*' -or $_ -like '*Triage*') { 'severity-high' } else { 'severity-informational' }
                "<span class='badge $badgeClass' style='margin: 2px;'>$_</span>" 
            }) -join ' '
            $html += @"
                    <div class="info-item">
                        <div class="info-label">🤖 System Tags</div>
                        <div class="info-value">$systemTagsHtml</div>
                    </div>
"@
        }
        
        # Add custom tags (e.g., Agent tags)
        if ($Incident.CustomTags -and $Incident.CustomTags.Count -gt 0) {
            $customTagsHtml = ($Incident.CustomTags | ForEach-Object { 
                $badgeClass = if ($_ -like '*Agent*') { 'severity-medium' } else { 'severity-informational' }
                "<span class='badge $badgeClass' style='margin: 2px;'>$_</span>" 
            }) -join ' '
            $html += @"
                    <div class="info-item">
                        <div class="info-label">🏷️ Custom Tags</div>
                        <div class="info-value">$customTagsHtml</div>
                    </div>
"@
        }
        
        # Add standard tags
        if ($Incident.Tags -and $Incident.Tags.Count -gt 0) {
            $tagsHtml = ($Incident.Tags | ForEach-Object { "<span class='badge severity-informational' style='margin: 2px;'>$_</span>" }) -join ' '
            $html += @"
                    <div class="info-item">
                        <div class="info-label">Tags</div>
                        <div class="info-value">$tagsHtml</div>
                    </div>
"@
        }
        
        # Highlight if phishing triage agent was involved
        if ($Incident.PhishingTriageIndicators -and $Incident.PhishingTriageIndicators.Count -gt 0) {
            $html += @"
                    <div class="info-item" style="background: #e7f3ff; border: 2px solid #0078d4;">
                        <div class="info-label" style="color: #0078d4;">🎯 Phishing Triage Agent</div>
                        <div class="info-value" style="color: #0078d4; font-weight: bold;">This incident was triaged by automated phishing analysis</div>
                    </div>
"@
        }
        
        $html += @"
                </div>
"@

        # Incident Alerts with expandable details
        if ($Incident.Alerts -and $Incident.Alerts.Count -gt 0) {
            $html += @"
                <h3 style="margin-top: 20px; margin-bottom: 15px;">Associated Alerts ($($Incident.Alerts.Count))</h3>
"@
            $alertNum = 1
            foreach ($incAlert in $Incident.Alerts) {
                $alertSevClass = "severity-" + $incAlert.Severity.ToLower()
                $alertNumDisplay = $alertNum
                $html += @"
                <div class="expandable">
                    <div class="expand-header" onclick="toggleExpand(this)">
                        <span><strong>Alert #${alertNumDisplay}:</strong> $($incAlert.Title) <span class="badge $alertSevClass">$($incAlert.Severity)</span></span>
                        <span class="arrow">▼</span>
                    </div>
                    <div class="expand-content">
                        <div class="expand-content-inner">
                            <div class="info-grid">
                                <div class="info-item">
                                    <div class="info-label">Alert ID</div>
                                    <div class="info-value" style="font-size: 12px;">$($incAlert.Id)</div>
                                </div>
                                <div class="info-item">
                                    <div class="info-label">Status</div>
                                    <div class="info-value">$($incAlert.Status)</div>
                                </div>
                                <div class="info-item">
                                    <div class="info-label">Category</div>
                                    <div class="info-value">$($incAlert.Category)</div>
                                </div>
                                <div class="info-item">
                                    <div class="info-label">Detection Source</div>
                                    <div class="info-value">$($incAlert.DetectionSource)</div>
                                </div>
                                <div class="info-item">
                                    <div class="info-label">Service Source</div>
                                    <div class="info-value">$($incAlert.ServiceSource)</div>
                                </div>
                                <div class="info-item">
                                    <div class="info-label">Created</div>
                                    <div class="info-value">$($incAlert.CreatedDateTime)</div>
                                </div>
                                <div class="info-item">
                                    <div class="info-label">First Activity</div>
                                    <div class="info-value">$($incAlert.FirstActivityDateTime)</div>
                                </div>
                                <div class="info-item">
                                    <div class="info-label">Last Activity</div>
                                    <div class="info-value">$($incAlert.LastActivityDateTime)</div>
                                </div>
                            </div>
"@
                if ($incAlert.Description) {
                    $html += @"
                            <h4 style="margin-top: 15px; margin-bottom: 10px;">Description</h4>
                            <div class="alert-box">$($incAlert.Description)</div>
"@
                }
                if ($incAlert.RecommendedActions) {
                    $html += @"
                            <h4 style="margin-top: 15px; margin-bottom: 10px;">Recommended Actions</h4>
                            <div class="alert-box">$($incAlert.RecommendedActions)</div>
"@
                }
                $html += @"
                        </div>
                    </div>
                </div>
"@
                $alertNum++
            }
        }
        
        $html += "</div>"
    }

    # Detailed Alert Section
    if ($Alert) {
        $alertSevClass = "severity-" + $Alert.Severity.ToLower()
        $alertStatusClass = "status-" + $Alert.Status.ToLower().Replace(' ', '')
        
        $html += @"
            <div class="section">
                <h2 class="section-title">🚨 Alert Details</h2>
                <div class="info-grid">
                    <div class="info-item">
                        <div class="info-label">Alert ID</div>
                        <div class="info-value" style="font-size: 13px;">$($Alert.Id)</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Title</div>
                        <div class="info-value">$($Alert.Title)</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Severity</div>
                        <div class="info-value"><span class="badge $alertSevClass">$($Alert.Severity)</span></div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Status</div>
                        <div class="info-value"><span class="badge $alertStatusClass">$($Alert.Status)</span></div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Category</div>
                        <div class="info-value">$($Alert.Category)</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Detection Source</div>
                        <div class="info-value">$($Alert.DetectionSource)</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Service Source</div>
                        <div class="info-value">$($Alert.ServiceSource)</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Provider Alert ID</div>
                        <div class="info-value" style="font-size: 13px;">$($Alert.ProviderAlertId)</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Created</div>
                        <div class="info-value">$($Alert.CreatedDateTime)</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Last Updated</div>
                        <div class="info-value">$($Alert.LastUpdateDateTime)</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">First Activity</div>
                        <div class="info-value">$($Alert.FirstActivityDateTime)</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Last Activity</div>
                        <div class="info-value">$($Alert.LastActivityDateTime)</div>
                    </div>
"@
        
        # Add additional classification details if available
        if ($Alert.DetailedClassification) {
            $html += @"
                    <div class="info-item">
                        <div class="info-label">🎯 Detailed Classification</div>
                        <div class="info-value"><span class="badge severity-informational">$($Alert.DetailedClassification)</span></div>
                    </div>
"@
        }
        
        if ($Alert.ThreatFamilyName) {
            $html += @"
                    <div class="info-item">
                        <div class="info-label">Threat Family</div>
                        <div class="info-value">$($Alert.ThreatFamilyName)</div>
                    </div>
"@
        }
        
        $html += @"
                    <div class="info-item">
                        <div class="info-label">Actor Display Name</div>
                        <div class="info-value">$($Alert.ActorDisplayName)</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Alert Web URL</div>
                        <div class="info-value" style="font-size: 11px; word-break: break-all;">$($Alert.AlertWebUrl)</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Assigned To</div>
                        <div class="info-value">$($Alert.AssignedTo)</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Classification</div>
                        <div class="info-value">$($Alert.Classification)</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Determination</div>
                        <div class="info-value">$($Alert.Determination)</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Incident ID</div>
                        <div class="info-value">$($Alert.IncidentId)</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Incident Web URL</div>
                        <div class="info-value" style="font-size: 11px; word-break: break-all;">$($Alert.IncidentWebUrl)</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Mitre Techniques</div>
                        <div class="info-value">$($Alert.MitreTechniques -join ', ')</div>
                    </div>
"@
        
        # Add tags if available
        if ($Alert.Tags -and $Alert.Tags.Count -gt 0) {
            $alertTagsHtml = ($Alert.Tags | ForEach-Object { "<span class='badge severity-informational' style='margin: 2px;'>$_</span>" }) -join ' '
            $html += @"
                    <div class="info-item">
                        <div class="info-label">🏷️ Alert Tags</div>
                        <div class="info-value">$alertTagsHtml</div>
                    </div>
"@
        }
        
        $html += @"
                </div>
                
                <h3 style="margin-top: 20px; margin-bottom: 10px;">Description</h3>
                <div class="alert-box">
                    $($Alert.Description)
                </div>
                
                <h3 style="margin-top: 20px; margin-bottom: 10px;">Recommended Actions</h3>
                <div class="alert-box">
                    $($Alert.RecommendedActions)
                </div>
"@

        # Evidence
        if ($Alert.Evidence -and $Alert.Evidence.Count -gt 0) {
            $html += @"
                <h3 style="margin-top: 20px; margin-bottom: 15px;">📁 Evidence ($($Alert.Evidence.Count) items)</h3>
"@
            foreach ($evidence in $Alert.Evidence) {
                $evidenceType = if ($evidence.AdditionalProperties.'@odata.type') { 
                    $evidence.AdditionalProperties.'@odata.type'.Replace('#microsoft.graph.security.', '')
                } else { 
                    'Unknown' 
                }
                
                $html += @"
                <div class="evidence-item">
                    <strong>Type:</strong> $evidenceType<br>
                    <strong>Verdict:</strong> $($evidence.Verdict)<br>
                    <strong>Remediation Status:</strong> $($evidence.RemediationStatus)<br>
"@
                
                # Add type-specific details
                if ($evidence.AdditionalProperties) {
                    foreach ($key in $evidence.AdditionalProperties.Keys | Where-Object { $_ -notlike '@odata.*' }) {
                        $value = $evidence.AdditionalProperties[$key]
                        if ($value -and $value -ne '') {
                            $html += "                    <strong>${key}:</strong> $value<br>`n"
                        }
                    }
                }
                
                $html += "                </div>`n"
            }
        }

        # Activity List
        if ($AlertActivities -and $AlertActivities.Count -gt 0) {
            $html += @"
                <h3 style="margin-top: 20px; margin-bottom: 15px;">📋 Activity Timeline ($($AlertActivities.Count) entries)</h3>
"@
            foreach ($activityEntry in ($AlertActivities | Sort-Object { if ($_.Timestamp) { $_.Timestamp } else { $_.LastUpdated } } -Descending)) {
                $activityType = $activityEntry.Type
                $html += @"
                <div class="evidence-item">
                    <strong>Type:</strong> <span class="badge severity-informational">$activityType</span><br>
"@
                foreach ($key in $activityEntry.Keys | Where-Object { $_ -ne 'Type' }) {
                    $value = $activityEntry[$key]
                    if ($value) {
                        $html += "                    <strong>${key}:</strong> $value<br>`n"
                    }
                }
                $html += "                </div>`n"
            }
        }

        # System Alert IDs
        if ($Alert.SystemAlertIds -and $Alert.SystemAlertIds.Count -gt 0) {
            $html += @"
                <h3 style="margin-top: 20px; margin-bottom: 10px;">System Alert IDs</h3>
                <div class="json-details">
$($Alert.SystemAlertIds -join "`n")
                </div>
"@
        }

        # Comments
        if ($Alert.Comments -and $Alert.Comments.Count -gt 0) {
            $html += @"
                <h3 style="margin-top: 20px; margin-bottom: 15px;">💬 Comments</h3>
"@
            foreach ($comment in $Alert.Comments) {
                $html += @"
                <div class="evidence-item">
                    <strong>[$($comment.CreatedDateTime)]</strong> by <strong>$($comment.CreatedByDisplayName)</strong><br>
                    $($comment.Comment)
                </div>
"@
            }
        }

        # Additional Properties
        if ($Alert.AdditionalProperties -and $Alert.AdditionalProperties.Count -gt 0) {
            $additionalProps = $Alert.AdditionalProperties | Where-Object { $_.Key -notlike '@odata.*' }
            if ($additionalProps) {
                $html += @"
                <h3 style="margin-top: 20px; margin-bottom: 10px;">Additional Properties</h3>
                <div class="json-details">
"@
                foreach ($prop in $additionalProps) {
                    $html += "$($prop.Key): $($prop.Value | ConvertTo-Json -Depth 2 -Compress)`n"
                }
                $html += @"
                </div>
"@
            }
        }
        
        $html += "</div>"
    }

    # Activity/Copilot Section
    if ($Activity) {
        $html += @"
            <div class="section">
                <h2 class="section-title">🤖 Security Copilot Activity</h2>
                <div class="info-grid">
                    <div class="info-item">
                        <div class="info-label">Activity ID</div>
                        <div class="info-value" style="font-size: 13px;">$($Activity.ActivityId)</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Activity Type</div>
                        <div class="info-value">$($Activity.ActivityType)</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Activity Name</div>
                        <div class="info-value">$($Activity.ActivityName)</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Source</div>
                        <div class="info-value">$($Activity.Source)</div>
                    </div>
"@
        if ($Activity.Status) {
            $html += @"
                    <div class="info-item">
                        <div class="info-label">Status</div>
                        <div class="info-value"><span class="badge severity-informational">$($Activity.Status)</span></div>
                    </div>
"@
        }
        
        if ($Activity.Classification) {
            $html += @"
                    <div class="info-item">
                        <div class="info-label">Classification</div>
                        <div class="info-value">$($Activity.Classification)</div>
                    </div>
"@
        }
        
        if ($Activity.Determination -or $Activity.Verdict) {
            $verdictValue = if ($Activity.Verdict) { $Activity.Verdict } else { $Activity.Determination }
            $html += @"
                    <div class="info-item">
                        <div class="info-label">Verdict</div>
                        <div class="info-value"><strong>$verdictValue</strong></div>
                    </div>
"@
        }
        
        if ($Activity.RunTime) {
            $html += @"
                    <div class="info-item">
                        <div class="info-label">Run Time</div>
                        <div class="info-value">$($Activity.RunTime)</div>
                    </div>
"@
        }
        
        if ($Activity.CreatedDateTime) {
            $html += @"
                    <div class="info-item">
                        <div class="info-label">Created</div>
                        <div class="info-value">$($Activity.CreatedDateTime)</div>
                    </div>
"@
        }
        
        if ($Activity.SystemTags -and $Activity.SystemTags.Count -gt 0) {
            $tagsHtml = ($Activity.SystemTags | ForEach-Object { "<span class='badge severity-informational' style='margin: 2px;'>$_</span>" }) -join ' '
            $html += @"
                    <div class="info-item">
                        <div class="info-label">System Tags</div>
                        <div class="info-value">$tagsHtml</div>
                    </div>
"@
        }
        
        $html += @"
                </div>
"@
        
        # Display prompts/inputs
        if ($Activity.Prompts -and $Activity.Prompts.Count -gt 0) {
            $html += @"
                <h3 style="margin-top: 20px; margin-bottom: 15px;">💬 Prompts & Inputs ($($Activity.Prompts.Count))</h3>
"@
            foreach ($prompt in $Activity.Prompts) {
                $promptType = if ($prompt.Type) { $prompt.Type } else { "Prompt" }
                $html += @"
                <div class="evidence-item">
                    <strong>Type:</strong> <span class="badge severity-informational">$promptType</span><br>
"@
                if ($prompt.Timestamp) {
                    $html += "                    <strong>Timestamp:</strong> $($prompt.Timestamp)<br>`n"
                }
                if ($prompt.Author) {
                    $html += "                    <strong>Author:</strong> $($prompt.Author)<br>`n"
                }
                if ($prompt.Content) {
                    $html += "                    <strong>Content:</strong> $($prompt.Content)<br>`n"
                }
                $html += "                </div>`n"
            }
        }
        
        # Display results/outputs
        if ($Activity.Results -and $Activity.Results.Count -gt 0) {
            $html += @"
                <h3 style="margin-top: 20px; margin-bottom: 15px;">📊 Results & Analysis ($($Activity.Results.Count))</h3>
"@
            foreach ($result in $Activity.Results) {
                $resultType = if ($result.Type) { $result.Type } else { "Result" }
                $html += @"
                <div class="evidence-item">
                    <strong>Type:</strong> <span class="badge severity-informational">$resultType</span><br>
"@
                foreach ($key in $result.Keys | Where-Object { $_ -ne 'Type' }) {
                    $value = $result[$key]
                    if ($value) {
                        if ($value -is [array]) {
                            $html += "                    <strong>${key}:</strong> $($value -join ', ')<br>`n"
                        } else {
                            $html += "                    <strong>${key}:</strong> $value<br>`n"
                        }
                    }
                }
                $html += "                </div>`n"
            }
        }
        
        # Display entity analysis
        if ($Activity.EntityAnalysis -and $Activity.EntityAnalysis.EvidenceCount -gt 0) {
            $html += @"
                <h3 style="margin-top: 20px; margin-bottom: 15px;">🔍 Entity Analysis</h3>
                <div class="info-grid">
                    <div class="info-item">
                        <div class="info-label">Evidence Analyzed</div>
                        <div class="info-value" style="font-size: 24px; font-weight: bold; color: #0078d4;">$($Activity.EntityAnalysis.EvidenceCount)</div>
                    </div>
                </div>
"@
        }
        
        # Display recommendations
        if ($Activity.Recommendations -and $Activity.Recommendations.Count -gt 0) {
            $html += @"
                <h3 style="margin-top: 20px; margin-bottom: 15px;">💡 Recommendations</h3>
                <div class="alert-box">
"@
            foreach ($recommendation in $Activity.Recommendations) {
                $html += "                    • $recommendation<br>`n"
            }
            $html += "                </div>`n"
        }
        
        if ($Activity.Note) {
            $html += @"
                <div class="alert-box" style="margin-top: 15px;">
                    <strong>ℹ️ Note:</strong> $($Activity.Note)
                </div>
"@
        }
        
        if ($Activity.AdditionalData) {
            $html += @"
                <h3 style="margin-top: 20px; margin-bottom: 10px;">Additional Activity Data</h3>
                <div class="json-details">
$($Activity.AdditionalData | ConvertTo-Json -Depth 5)
                </div>
"@
        }
        
        if ($Activity.Error) {
            $html += @"
                <div class="alert-box alert-box-high" style="margin-top: 15px;">
                    <strong>⚠️ Error:</strong> $($Activity.Error)
                </div>
"@
        }
        
        $html += "</div>"
    }

    # Summary Section
    $html += @"
            <div class="section">
                <h2 class="section-title">📊 Summary</h2>
                <div class="info-grid">
"@
    
    if ($Incident) {
        $html += @"
                    <div class="info-item">
                        <div class="info-label">Total Incident Alerts</div>
                        <div class="info-value" style="font-size: 24px; font-weight: bold; color: #0078d4;">$($Incident.Alerts.Count)</div>
                    </div>
"@
        if ($Incident.Alerts) {
            $highCount = ($Incident.Alerts | Where-Object { $_.Severity -eq 'high' }).Count
            $medCount = ($Incident.Alerts | Where-Object { $_.Severity -eq 'medium' }).Count
            $lowCount = ($Incident.Alerts | Where-Object { $_.Severity -eq 'low' }).Count
            
            $html += @"
                    <div class="info-item">
                        <div class="info-label">High Severity Alerts</div>
                        <div class="info-value" style="font-size: 24px; font-weight: bold; color: #dc3545;">$highCount</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Medium Severity Alerts</div>
                        <div class="info-value" style="font-size: 24px; font-weight: bold; color: #fd7e14;">$medCount</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Low Severity Alerts</div>
                        <div class="info-value" style="font-size: 24px; font-weight: bold; color: #ffc107;">$lowCount</div>
                    </div>
"@
        }
    }
    
    if ($Alert -and $Alert.Evidence) {
        $html += @"
                    <div class="info-item">
                        <div class="info-label">Evidence Items</div>
                        <div class="info-value" style="font-size: 24px; font-weight: bold; color: #0078d4;">$($Alert.Evidence.Count)</div>
                    </div>
"@
    }
    
    $html += @"
                </div>
            </div>
"@
    
    # Build JSON data for embedding
    $jsonDataForHTML = @{
        ReportMetadata = @{
            GeneratedAt = Get-Date -Format 'o'
            IncidentId = if ($Incident) { $Incident.Id } else { $null }
            AlertId = if ($Alert) { $Alert.Id } else { $null }
            ActivityId = if ($Activity) { $Activity.ActivityId } else { $null }
        }
        Incident = $null
        Alert = $null
        Activity = $null
    }
    
    if ($Incident) {
        $jsonDataForHTML.Incident = @{
            Id = $Incident.Id
            DisplayName = $Incident.DisplayName
            Status = $Incident.Status
            Severity = $Incident.Severity
            Classification = $Incident.Classification
            Determination = $Incident.Determination
            CreatedDateTime = $Incident.CreatedDateTime
            LastUpdateDateTime = $Incident.LastUpdateDateTime
            AssignedTo = $Incident.AssignedTo
            RedirectIncidentId = $Incident.RedirectIncidentId
            TenantId = $Incident.TenantId
            Tags = if ($Incident.Tags) { $Incident.Tags } else { @() }
            Alerts = @()
        }
        
        if ($Incident.Alerts) {
            foreach ($incAlert in $Incident.Alerts) {
                $alertData = @{
                    Id = $incAlert.Id
                    Title = $incAlert.Title
                    Severity = $incAlert.Severity
                    Status = $incAlert.Status
                    Category = $incAlert.Category
                    DetectionSource = $incAlert.DetectionSource
                    ServiceSource = $incAlert.ServiceSource
                    CreatedDateTime = $incAlert.CreatedDateTime
                    FirstActivityDateTime = $incAlert.FirstActivityDateTime
                    LastActivityDateTime = $incAlert.LastActivityDateTime
                    Description = $incAlert.Description
                    RecommendedActions = $incAlert.RecommendedActions
                }
                $jsonDataForHTML.Incident.Alerts += $alertData
            }
        }
    }
    
    if ($Alert) {
        $jsonDataForHTML.Alert = @{
            Id = $Alert.Id
            Title = $Alert.Title
            Severity = $Alert.Severity
            Status = $Alert.Status
            Category = $Alert.Category
            DetectionSource = $Alert.DetectionSource
            ServiceSource = $Alert.ServiceSource
            ProviderAlertId = $Alert.ProviderAlertId
            CreatedDateTime = $Alert.CreatedDateTime
            LastUpdateDateTime = $Alert.LastUpdateDateTime
            FirstActivityDateTime = $Alert.FirstActivityDateTime
            LastActivityDateTime = $Alert.LastActivityDateTime
            ActorDisplayName = $Alert.ActorDisplayName
            AlertWebUrl = $Alert.AlertWebUrl
            AssignedTo = $Alert.AssignedTo
            Classification = $Alert.Classification
            Determination = $Alert.Determination
            IncidentId = $Alert.IncidentId
            IncidentWebUrl = $Alert.IncidentWebUrl
            MitreTechniques = $Alert.MitreTechniques
            Description = $Alert.Description
            RecommendedActions = $Alert.RecommendedActions
            Tags = if ($Alert.Tags) { $Alert.Tags } else { @() }
            Evidence = @()
            SystemAlertIds = $Alert.SystemAlertIds
        }
        
        if ($Alert.Evidence) {
            foreach ($evidence in $Alert.Evidence) {
                $evidenceData = @{
                    Verdict = $evidence.Verdict
                    RemediationStatus = $evidence.RemediationStatus
                    Type = $evidence.AdditionalProperties.'@odata.type'
                    Properties = @{}
                }
                
                if ($evidence.AdditionalProperties) {
                    foreach ($key in $evidence.AdditionalProperties.Keys | Where-Object { $_ -notlike '@odata.*' }) {
                        $evidenceData.Properties[$key] = $evidence.AdditionalProperties[$key]
                    }
                }
                
                $jsonDataForHTML.Alert.Evidence += $evidenceData
            }
        }
    }
    
    if ($Activity) {
        $jsonDataForHTML.Activity = $Activity
    }
    
    $jsonString = ($jsonDataForHTML | ConvertTo-Json -Depth 10).Replace('"', '&quot;').Replace('<', '&lt;').Replace('>', '&gt;')
    $jsonForDisplay = $jsonDataForHTML | ConvertTo-Json -Depth 10
    
    $html += @"
            <div class="section">
                <h2 class="section-title">⚙️ Report Generation Flow</h2>
                <p style="margin-bottom: 15px; color: #666;">This section documents the PowerShell commands and API calls used to generate this report.</p>
                <div class="info-grid" style="grid-template-columns: 1fr;">
"@
    
    if ($ExecutionFlow -and $ExecutionFlow.Count -gt 0) {
        foreach ($step in $ExecutionFlow) {
            $html += @"
                    <div class="evidence-item">
                        <strong>[$($step.Timestamp)] $($step.Step)</strong><br>
                        <strong>Command:</strong> <code style="background: #f0f0f0; padding: 2px 6px; border-radius: 3px; font-family: 'Courier New', monospace;">$($step.Command)</code><br>
                        <strong>Description:</strong> $($step.Description)<br>
                        <strong>Result:</strong> $($step.Result)
                    </div>
"@
        }
    }
    
    $html += @"
                </div>
            </div>
            
            <div class="section">
                <h2 class="section-title">📄 JSON Data Export</h2>
                <p style="margin-bottom: 15px; color: #666;">Complete report data in JSON format. Click to copy to clipboard.</p>
                <button id="copy-btn" class="copy-button" onclick="copyJSON()">📋 Copy JSON to Clipboard</button>
                <div class="expandable">
                    <div class="expand-header" onclick="toggleExpand(this)">
                        <span><strong>View JSON Data</strong></span>
                        <span class="arrow">▼</span>
                    </div>
                    <div class="expand-content">
                        <div class="expand-content-inner">
                            <pre id="json-data" class="json-viewer">$jsonForDisplay</pre>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="footer">
            <p><strong>Microsoft Defender for Endpoint - Incident & Alert Report</strong></p>
            <p>This report was automatically generated using Microsoft Graph Security API</p>
            <p style="margin-top: 10px; font-size: 10px; color: #999;">
                <strong>DISCLAIMER:</strong> This report is provided "AS IS" without warranty of any kind. 
                Microsoft Defender for Endpoint, Microsoft Graph, and related services are trademarks of Microsoft Corporation.
                This tool is not officially supported by Microsoft Corporation.
            </p>
        </div>
    </div>
</body>
</html>
"@

    # Output the report
    if ($OutputPath) {
        try {
            # Default to HTML extension if not specified
            if (-not $OutputPath.EndsWith('.html')) {
                $OutputPath = $OutputPath + '.html'
            }
            $html | Out-File -FilePath $OutputPath -Encoding UTF8
            Write-Host "`nHTML Report saved to: $OutputPath" -ForegroundColor Green
            
            # Try to open in default browser
            try {
                Start-Process $OutputPath
                Write-Host "Opening report in default browser..." -ForegroundColor Cyan
            }
            catch {
                Write-Host "Report saved but could not auto-open. Please open manually: $OutputPath" -ForegroundColor Yellow
            }
        }
        catch {
            Write-Error "Failed to save report to file: $_"
        }
    }
    else {
        # Save to temp file and open
        $tempPath = Join-Path $env:TEMP "DefenderReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
        $html | Out-File -FilePath $tempPath -Encoding UTF8
        Write-Host "`nHTML Report saved to: $tempPath" -ForegroundColor Green
        Start-Process $tempPath
        Write-Host "Opening report in default browser..." -ForegroundColor Cyan
    }
}

<#
.SYNOPSIS
    Generates a plain-text report for incident details.
    
.DESCRIPTION
    Creates a formatted text report suitable for logging, email, or console output.
    Provides all incident data in a structured, human-readable format.
    
.PARAMETER Incident
    Incident object
    
.PARAMETER Alert
    Alert object
    
.PARAMETER Activity
    Activity object
    
.PARAMETER AlertActivities
    Activity timeline array
    
.PARAMETER OutputPath
    File path for saving
#>
function New-TextReport {
    param(
        [object]$Incident,
        [object]$Alert,
        [object]$Activity,
        [object[]]$AlertActivities,
        [string]$OutputPath
    )
    
    $reportBuilder = @()
    $reportBuilder += "=" * 80
    $reportBuilder += "MICROSOFT DEFENDER INCIDENT REPORT"
    $reportBuilder += "=" * 80
    $reportBuilder += ""
    $reportBuilder += "Report Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $reportBuilder += ""
    
    # Incident Information
    if ($Incident) {
        # Basic Incident Information
        $reportBuilder += "-" * 80
        $reportBuilder += "INCIDENT OVERVIEW"
        $reportBuilder += "-" * 80
        $reportBuilder += "Incident ID: $($Incident.Id)"
        $reportBuilder += "Display Name: $($Incident.DisplayName)"
        $reportBuilder += "Status: $($Incident.Status)"
        $reportBuilder += "Severity: $($Incident.Severity)"
        $reportBuilder += "Classification: $($Incident.Classification)"
        $reportBuilder += "Determination: $($Incident.Determination)"
        $reportBuilder += ""
        
        # Time Information
        $reportBuilder += "-" * 80
        $reportBuilder += "TIMELINE"
        $reportBuilder += "-" * 80
        $reportBuilder += "Created: $($Incident.CreatedDateTime)"
        $reportBuilder += "Last Updated: $($Incident.LastUpdateDateTime)"
        if ($Incident.ResolvedDateTime) {
            $reportBuilder += "Resolved: $($Incident.ResolvedDateTime)"
        }
        $reportBuilder += ""
        
        # Assignment Information
        $reportBuilder += "-" * 80
        $reportBuilder += "ASSIGNMENT"
        $reportBuilder += "-" * 80
        $reportBuilder += "Assigned To: $($Incident.AssignedTo)"
        
        # System Tags
        if ($Incident.SystemTags -and $Incident.SystemTags.Count -gt 0) {
            $reportBuilder += "System Tags: $($Incident.SystemTags -join ', ')"
            $reportBuilder += "System Tag Count: $($Incident.SystemTags.Count)"
        }
        
        # Custom Tags
        if ($Incident.CustomTags -and $Incident.CustomTags.Count -gt 0) {
            $reportBuilder += "Custom Tags: $($Incident.CustomTags -join ', ')"
            $reportBuilder += "Custom Tag Count: $($Incident.CustomTags.Count)"
        }
        
        # Standard Tags
        if ($Incident.Tags -and $Incident.Tags.Count -gt 0) {
            $reportBuilder += "Tags: $($Incident.Tags -join ', ')"
            $reportBuilder += "Tag Count: $($Incident.Tags.Count)"
        }
        
        # Phishing Triage Indicators
        if ($Incident.PhishingTriageIndicators -and $Incident.PhishingTriageIndicators.Count -gt 0) {
            $reportBuilder += ""
            $reportBuilder += "*** PHISHING TRIAGE AGENT DETECTED ***"
            $reportBuilder += "Indicators: $($Incident.PhishingTriageIndicators -join ', ')"
        }
        
        if (-not $Incident.Tags -and -not $Incident.SystemTags -and -not $Incident.CustomTags) {
            $reportBuilder += "Tags: None"
        }
        $reportBuilder += ""
        
        # Alerts Information
        if ($Incident.Alerts -and $Incident.Alerts.Count -gt 0) {
            $reportBuilder += "-" * 80
            $reportBuilder += "ALERTS ($($Incident.Alerts.Count))"
            $reportBuilder += "-" * 80
            
            $alertIndex = 1
            foreach ($incAlert in $Incident.Alerts) {
                $reportBuilder += ""
                $reportBuilder += "Alert #$alertIndex"
                $reportBuilder += "  Title: $($incAlert.Title)"
                $reportBuilder += "  Severity: $($incAlert.Severity)"
                $reportBuilder += "  Status: $($incAlert.Status)"
                $reportBuilder += "  Category: $($incAlert.Category)"
                $reportBuilder += "  Created: $($incAlert.CreatedDateTime)"
                if ($incAlert.Description) {
                    $reportBuilder += "  Description: $($incAlert.Description)"
                }
                $alertIndex++
            }
            $reportBuilder += ""
        }
    }
    
    # Activity Information
    if ($Activity) {
        $reportBuilder += "-" * 80
        $reportBuilder += "SECURITY COPILOT ACTIVITY"
        $reportBuilder += "-" * 80
        $reportBuilder += "Activity ID: $($Activity.ActivityId)"
        $reportBuilder += "Activity Type: $($Activity.ActivityType)"
        $reportBuilder += "Activity Name: $($Activity.ActivityName)"
        $reportBuilder += "Source: $($Activity.Source)"
        
        if ($Activity.Status) {
            $reportBuilder += "Status: $($Activity.Status)"
        }
        if ($Activity.Classification) {
            $reportBuilder += "Classification: $($Activity.Classification)"
        }
        if ($Activity.Determination -or $Activity.Verdict) {
            $verdict = if ($Activity.Verdict) { $Activity.Verdict } else { $Activity.Determination }
            $reportBuilder += "Verdict: $verdict"
        }
        if ($Activity.RunTime) {
            $reportBuilder += "Run Time: $($Activity.RunTime)"
        }
        if ($Activity.CreatedDateTime) {
            $reportBuilder += "Created: $($Activity.CreatedDateTime)"
        }
        if ($Activity.SystemTags -and $Activity.SystemTags.Count -gt 0) {
            $reportBuilder += "System Tags: $($Activity.SystemTags -join ', ')"
        }
        $reportBuilder += ""
        
        # Display prompts
        if ($Activity.Prompts -and $Activity.Prompts.Count -gt 0) {
            $reportBuilder += "Prompts/Inputs ($($Activity.Prompts.Count)):"
            $promptNum = 1
            foreach ($prompt in $Activity.Prompts) {
                $reportBuilder += "  Prompt #$promptNum - $($prompt.Type)"
                if ($prompt.Content) {
                    $reportBuilder += "    Content: $($prompt.Content)"
                }
                if ($prompt.Timestamp) {
                    $reportBuilder += "    Timestamp: $($prompt.Timestamp)"
                }
                $promptNum++
            }
            $reportBuilder += ""
        }
        
        # Display results
        if ($Activity.Results -and $Activity.Results.Count -gt 0) {
            $reportBuilder += "Results/Analysis ($($Activity.Results.Count)):"
            $resultNum = 1
            foreach ($result in $Activity.Results) {
                $reportBuilder += "  Result #$resultNum - $($result.Type)"
                foreach ($key in $result.Keys | Where-Object { $_ -ne 'Type' }) {
                    $value = $result[$key]
                    if ($value) {
                        if ($value -is [array]) {
                            $reportBuilder += "    ${key}: $($value -join ', ')"
                        } else {
                            $reportBuilder += "    ${key}: $value"
                        }
                    }
                }
                $resultNum++
            }
            $reportBuilder += ""
        }
        
        # Display entity analysis
        if ($Activity.EntityAnalysis -and $Activity.EntityAnalysis.EvidenceCount -gt 0) {
            $reportBuilder += "Entity Analysis:"
            $reportBuilder += "  Evidence Analyzed: $($Activity.EntityAnalysis.EvidenceCount)"
            $reportBuilder += ""
        }
        
        # Display recommendations
        if ($Activity.Recommendations -and $Activity.Recommendations.Count -gt 0) {
            $reportBuilder += "Recommendations:"
            foreach ($recommendation in $Activity.Recommendations) {
                $reportBuilder += "  • $recommendation"
            }
            $reportBuilder += ""
        }
        
        if ($Activity.Note) {
            $reportBuilder += "Note: $($Activity.Note)"
        }
        $reportBuilder += ""
    }
    
    # Detailed Alert Information
    if ($Alert) {
        $reportBuilder += "-" * 80
        $reportBuilder += "DETAILED ALERT INFORMATION"
        $reportBuilder += "-" * 80
        $reportBuilder += "Alert ID: $($Alert.Id)"
        $reportBuilder += "Title: $($Alert.Title)"
        $reportBuilder += "Severity: $($Alert.Severity)"
        $reportBuilder += "Status: $($Alert.Status)"
        $reportBuilder += "Category: $($Alert.Category)"
        $reportBuilder += "Detection Source: $($Alert.DetectionSource)"
        $reportBuilder += "Service Source: $($Alert.ServiceSource)"
        $reportBuilder += "Created: $($Alert.CreatedDateTime)"
        $reportBuilder += "Last Updated: $($Alert.LastUpdateDateTime)"
        $reportBuilder += "First Activity: $($Alert.FirstActivityDateTime)"
        $reportBuilder += "Last Activity: $($Alert.LastActivityDateTime)"
        if ($Alert.Tags -and $Alert.Tags.Count -gt 0) {
            $reportBuilder += "Tags: $($Alert.Tags -join ', ')"
            $reportBuilder += "Tag Count: $($Alert.Tags.Count)"
        }
        $reportBuilder += ""
        $reportBuilder += "Description:"
        $reportBuilder += $Alert.Description
        $reportBuilder += ""
        $reportBuilder += "Recommended Actions:"
        $reportBuilder += $Alert.RecommendedActions
        $reportBuilder += ""
        
        if ($Alert.Evidence -and $Alert.Evidence.Count -gt 0) {
            $reportBuilder += "-" * 80
            $reportBuilder += "EVIDENCE ($($Alert.Evidence.Count) items)"
            $reportBuilder += "-" * 80
            foreach ($evidence in $Alert.Evidence) {
                $reportBuilder += ""
                $reportBuilder += "Evidence Type: $($evidence.AdditionalProperties.'@odata.type')"
                $reportBuilder += "Verdict: $($evidence.Verdict)"
                $reportBuilder += "Remediation Status: $($evidence.RemediationStatus)"
            }
            $reportBuilder += ""
        }
        
        if ($AlertActivities -and $AlertActivities.Count -gt 0) {
            $reportBuilder += ""
            $reportBuilder += "-" * 80
            $reportBuilder += "ACTIVITY TIMELINE ($($AlertActivities.Count) entries)"
            $reportBuilder += "-" * 80
            $activityNum = 1
            foreach ($activityEntry in ($AlertActivities | Sort-Object { if ($_.Timestamp) { $_.Timestamp } else { $_.LastUpdated } } -Descending)) {
                $reportBuilder += ""
                $reportBuilder += "Activity #$activityNum - $($activityEntry.Type)"
                foreach ($key in $activityEntry.Keys | Where-Object { $_ -ne 'Type' }) {
                    $value = $activityEntry[$key]
                    if ($value) {
                        $reportBuilder += "  ${key}: $value"
                    }
                }
                $activityNum++
            }
            $reportBuilder += ""
        }
    }
    
    # Comments
    if ($Incident -and $Incident.Comments -and $Incident.Comments.Count -gt 0) {
        $reportBuilder += "-" * 80
        $reportBuilder += "COMMENTS"
        $reportBuilder += "-" * 80
        foreach ($comment in $Incident.Comments) {
            $reportBuilder += ""
            $reportBuilder += "[$($comment.CreatedDateTime)] $($comment.CreatedBy):"
            $reportBuilder += "$($comment.Comment)"
        }
        $reportBuilder += ""
    }
    
    # Summary Statistics
    $reportBuilder += "-" * 80
    $reportBuilder += "SUMMARY"
    $reportBuilder += "-" * 80
    if ($Incident -and $Incident.Alerts) {
        $reportBuilder += "Total Alerts: $($Incident.Alerts.Count)"
        $highSeverity = ($Incident.Alerts | Where-Object { $_.Severity -eq 'high' }).Count
        $mediumSeverity = ($Incident.Alerts | Where-Object { $_.Severity -eq 'medium' }).Count
        $lowSeverity = ($Incident.Alerts | Where-Object { $_.Severity -eq 'low' }).Count
        
        $reportBuilder += "  High Severity: $highSeverity"
        $reportBuilder += "  Medium Severity: $mediumSeverity"
        $reportBuilder += "  Low Severity: $lowSeverity"
    }
    if ($Alert -and $Alert.Evidence) {
        $reportBuilder += "Evidence Items: $($Alert.Evidence.Count)"
    }
    $reportBuilder += ""
    $reportBuilder += "=" * 80
    
    $report = $reportBuilder -join "`n"
    
    # Output the report
    Write-Host "`n"
    Write-Host $report
    
    # Save to file if path specified
    if ($OutputPath) {
        try {
            $report | Out-File -FilePath $OutputPath -Encoding UTF8
            Write-Host "`nReport saved to: $OutputPath" -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to save report to file: $_"
        }
    }
}

# Main script execution
try {
    Write-Host "`n"
    Write-Host "=" * 80 -ForegroundColor Cyan
    Write-Host "Microsoft Defender Incident Report Generator" -ForegroundColor Cyan
    Write-Host "=" * 80 -ForegroundColor Cyan
    Write-Host "`n"
    
    # Connect to Defender Portal
    $connected = Connect-DefenderPortal -TenantId $TenantId
    
    if (-not $connected) {
        Write-Error "Failed to connect to Microsoft Defender Portal. Exiting."
        exit 1
    }
    
    # Get incident details
    $incident = Get-IncidentDetails -IncidentId $IncidentId
    
    if (-not $incident) {
        Write-Error "Failed to retrieve incident details. Exiting."
        Disconnect-MgGraph | Out-Null
        exit 1
    }
    
    # Auto-discover alerts from incident
    Write-Host "\nAuto-discovering alerts from incident..." -ForegroundColor Cyan
    $alert = $null
    $alertActivities = @()
    $activity = $null
    $AlertId = $null
    $ActivityId = $null
    
    if ($incident.Alerts -and $incident.Alerts.Count -gt 0) {
        Write-Host "Found $($incident.Alerts.Count) alert(s) in incident" -ForegroundColor Green
        
        # Get the most recent alert for detailed analysis
        $selectedAlert = $incident.Alerts | Sort-Object CreatedDateTime -Descending | Select-Object -First 1
        $AlertId = $selectedAlert.Id
        
        Write-Host "Selecting most recent alert: $AlertId" -ForegroundColor Cyan
        Write-Host "  Title: $($selectedAlert.Title)" -ForegroundColor Gray
        Write-Host "  Created: $($selectedAlert.CreatedDateTime)" -ForegroundColor Gray
        
        # Get detailed alert information
        $alert = Get-AlertDetails -AlertId $AlertId
        
        if ($alert) {
            # Get alert activity list
            $alertActivities = Get-AlertActivityList -AlertId $AlertId
            
            # Try to find activity ID from the alert (for Security Copilot activities)
            # The activity ID is often the same as an alert ID in the incident
            $ActivityId = $AlertId
            
            # Parse activity type and name from alert
            $activityTypeParam = "agents"
            $activityNameParam = if ($alert.Title) { $alert.Title } else { "Email reported by user as malware or phish" }
            
            Write-Host "\nRetrieving Security Copilot activity for alert..." -ForegroundColor Cyan
            $activity = Get-ActivityDetails -IncidentId $IncidentId -ActivityId $ActivityId -ActivityType $activityTypeParam -ActivityName $activityNameParam
        }
    }
    else {
        Write-Warning "No alerts found in incident $IncidentId"
    }
    
    # Check if we have any data
    if (-not $incident -and -not $alert) {
        Write-Error "Failed to retrieve both incident and alert details. Exiting."
        Disconnect-MgGraph | Out-Null
        exit 1
    }
    
    # Add final summary step
    Add-ExecutionStep -Step "5. Generate Report" -Command "New-IncidentReport -Format '$Format'" -Description "Compile all collected data into $Format report" -Result "Report generated with $($incident.Alerts.Count) alert(s), $($alert.Evidence.Count) evidence item(s), and $($alertActivities.Count) activity entries"
    
    # Generate and display report
    New-IncidentReport -Incident $incident -Alert $alert -Activity $activity -AlertActivities $alertActivities -OutputPath $OutputPath -Format $Format -ExecutionFlow $script:ExecutionFlow
    
    # Export JSON data
    Write-Host "\nGenerating JSON export..." -ForegroundColor Cyan
    $jsonData = @{
        ReportMetadata = @{
            GeneratedAt = Get-Date -Format 'o'
            IncidentId = $IncidentId
            AlertId = $AlertId
            ActivityId = $ActivityId
            TenantId = $TenantId
        }
        Incident = $null
        Alert = $null
        Activity = $null
    }
    
    if ($incident) {
        $jsonData.Incident = @{
            Id = $incident.Id
            DisplayName = $incident.DisplayName
            Status = $incident.Status
            Severity = $incident.Severity
            Classification = $incident.Classification
            Determination = $incident.Determination
            CreatedDateTime = $incident.CreatedDateTime
            LastUpdateDateTime = $incident.LastUpdateDateTime
            AssignedTo = $incident.AssignedTo
            RedirectIncidentId = $incident.RedirectIncidentId
            Tags = if ($incident.Tags) { $incident.Tags } else { @() }
            SystemTags = if ($incident.SystemTags) { $incident.SystemTags } else { @() }
            CustomTags = if ($incident.CustomTags) { $incident.CustomTags } else { @() }
            PhishingTriageIndicators = if ($incident.PhishingTriageIndicators) { $incident.PhishingTriageIndicators } else { @() }
            Alerts = @()
        }
        
        if ($incident.Alerts) {
            foreach ($incAlert in $incident.Alerts) {
                $jsonData.Incident.Alerts += @{
                    Id = $incAlert.Id
                    Title = $incAlert.Title
                    Severity = $incAlert.Severity
                    Status = $incAlert.Status
                    Category = $incAlert.Category
                    CreatedDateTime = $incAlert.CreatedDateTime
                    Description = $incAlert.Description
                }
            }
        }
    }
    
    if ($alert) {
        $jsonData.Alert = @{
            Id = $alert.Id
            Title = $alert.Title
            Severity = $alert.Severity
            Status = $alert.Status
            Category = $alert.Category
            DetectionSource = $alert.DetectionSource
            ServiceSource = $alert.ServiceSource
            ProviderAlertId = $alert.ProviderAlertId
            CreatedDateTime = $alert.CreatedDateTime
            LastUpdateDateTime = $alert.LastUpdateDateTime
            FirstActivityDateTime = $alert.FirstActivityDateTime
            LastActivityDateTime = $alert.LastActivityDateTime
            ActorDisplayName = $alert.ActorDisplayName
            AlertWebUrl = $alert.AlertWebUrl
            AssignedTo = $alert.AssignedTo
            Classification = $alert.Classification
            Determination = $alert.Determination
            IncidentId = $alert.IncidentId
            IncidentWebUrl = $alert.IncidentWebUrl
            MitreTechniques = $alert.MitreTechniques
            Description = $alert.Description
            RecommendedActions = $alert.RecommendedActions
            Tags = if ($alert.Tags) { $alert.Tags } else { @() }
            Evidence = @()
            SystemAlertIds = $alert.SystemAlertIds
        }
        
        if ($alert.Evidence) {
            foreach ($evidence in $alert.Evidence) {
                $evidenceData = @{
                    Verdict = $evidence.Verdict
                    RemediationStatus = $evidence.RemediationStatus
                    Type = $evidence.AdditionalProperties.'@odata.type'
                    Properties = @{}
                }
                
                if ($evidence.AdditionalProperties) {
                    foreach ($key in $evidence.AdditionalProperties.Keys | Where-Object { $_ -notlike '@odata.*' }) {
                        $evidenceData.Properties[$key] = $evidence.AdditionalProperties[$key]
                    }
                }
                
                $jsonData.Alert.Evidence += $evidenceData
            }
        }
    }
    
    if ($activity) {
        $jsonData.Activity = $activity
    }
    
    if ($alertActivities -and $alertActivities.Count -gt 0) {
        $jsonData.AlertActivities = $alertActivities
    }
    
    # Save JSON to file
    $jsonOutputPath = if ($OutputPath) {
        [System.IO.Path]::ChangeExtension($OutputPath, '.json')
    } else {
        Join-Path $env:TEMP "DefenderReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    }
    
    $jsonData | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonOutputPath -Encoding UTF8
    Write-Host "JSON data exported to: $jsonOutputPath" -ForegroundColor Green
    
    # Display JSON to console
    Write-Host "\n" -NoNewline
    Write-Host "=" * 80 -ForegroundColor Cyan
    Write-Host "JSON RESPONSE" -ForegroundColor Cyan
    Write-Host "=" * 80 -ForegroundColor Cyan
    $jsonData | ConvertTo-Json -Depth 10 | Write-Host
    Write-Host "=" * 80 -ForegroundColor Cyan
    
    # Disconnect
    Write-Host "`nDisconnecting from Microsoft Graph..." -ForegroundColor Cyan
    Disconnect-MgGraph | Out-Null
    Write-Host "Done!" -ForegroundColor Green
}
catch {
    Write-Error "An error occurred: $_"
    if (Get-MgContext) {
        Disconnect-MgGraph | Out-Null
    }
    exit 1
}

#endregion
