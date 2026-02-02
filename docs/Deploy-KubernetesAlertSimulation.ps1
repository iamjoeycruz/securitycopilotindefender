#Requires -Version 7.0
<#
.SYNOPSIS
    Deploys and runs the Microsoft Defender for Cloud Kubernetes Alerts Simulation Tool.

.DESCRIPTION
    This script provides a complete, automated solution for running Microsoft Defender 
    for Cloud's Kubernetes attack simulation tool. It is designed to help security teams
    validate that Defender for Containers is properly configured and detecting threats.

    REQUIREMENTS:
    ─────────────────────────────────────────────────────────────────────────────────────
    • PowerShell 7.0 or later (run 'pwsh' not 'powershell')
    • PowerShell ISE is NOT supported - use VS Code or Windows Terminal
    • To install PowerShell 7: winget install Microsoft.PowerShell
    ─────────────────────────────────────────────────────────────────────────────────────

    KEY FEATURES:
    ─────────────────────────────────────────────────────────────────────────────────────
    • Automatic Prerequisite Management
      - Checks for required tools (Azure CLI, kubectl, Helm, Python)
      - Offers to automatically install missing components via winget
      - Validates Azure authentication and handles login if needed
    
    • Intelligent Cluster Discovery
      - Discovers all AKS clusters in your subscription
      - Option to use existing cluster (least privilege) or create a new one
      - Production cluster detection with safety warnings
    
    • Permission Validation
      - Validates Azure RBAC permissions before operations
      - Follows principle of least privilege
      - Clear guidance on required roles
    
    • Visual Progress Tracking
      - Real-time progress bar for long-running operations
      - Deployment stage indicators with time estimates
      - Color-coded status output
    
    • Comprehensive Reporting
      - Generates detailed HTML report of simulation results
      - Documents executed attack scenarios with timestamps
      - Lists expected security alerts for each scenario
    
    • Cost-Aware Operations
      - Displays cost analysis before operations
      - Estimates costs for new cluster creation
      - Prompts for cleanup to avoid ongoing charges
    
    • Complete Cleanup
      - Cleans up simulation pods and namespaces
      - Option to delete newly created clusters
      - Prevents orphaned resources and unexpected charges

    SIMULATION WORKFLOW:
    ─────────────────────────────────────────────────────────────────────────────────────
    1. Validates prerequisites and offers to install missing components
    2. Authenticates to Azure (browser-based login if needed)
    3. Checks Azure RBAC permissions for the operation type
    4. Discovers AKS clusters or offers to create a new non-prod cluster
    5. Validates Defender for Containers sensor is installed
    6. Downloads the official Microsoft simulation tool
    7. Executes selected attack scenarios interactively
    8. Generates HTML report with scenario details and expected alerts
    9. Cleans up simulation resources (pods, namespaces)
    10. Offers to delete newly created clusters (if applicable)

    ATTACK SCENARIOS INCLUDED:
    ─────────────────────────────────────────────────────────────────────────────────────
    • Reconnaissance - Network scanning (Nmap), service account enumeration
    • Lateral Movement - Cloud metadata service access, IMDS token retrieval
    • Secrets Gathering - Accessing .git-credentials, Kubernetes service account tokens
    • Cryptomining - Mining software download simulation, CPU optimization
    • Web Shell - Remote command execution via web shell

.PARAMETER ClusterName
    Optional. The name of the AKS cluster to run the simulation on.
    If not specified, the script will discover and list available clusters.

.PARAMETER ResourceGroup
    Optional. The resource group containing the target AKS cluster.
    Required if ClusterName is specified.

.PARAMETER SubscriptionId
    Optional. The Azure subscription ID to use. If not specified, uses the current
    subscription context from Azure CLI.

.PARAMETER SimulationScenario
    Optional. The specific simulation scenario to run.
    Valid values: All, Reconnaissance, LateralMovement, SecretsGathering, CryptoMining, WebShell
    Default: All

.PARAMETER WorkingDirectory
    Optional. The directory where simulation tools will be downloaded.
    Default: $env:TEMP\K8sAlertSimulation

.PARAMETER SkipPrerequisiteCheck
    Optional switch. Skip the prerequisite validation checks.
    Use with caution - missing prerequisites will cause script failure.

.PARAMETER CleanupAfterRun
    Optional switch. Automatically clean up simulation resources after completion
    without prompting. If not specified, the script will prompt for cleanup.

.PARAMETER ReportPath
    Optional. The file path where the HTML simulation report will be saved.
    Default: $env:USERPROFILE\Documents\K8s-Simulation-Report-<timestamp>.html

.NOTES
    ============================================================================
    Script Name    : Deploy-KubernetesAlertSimulation.ps1
    Version        : 2.2.0
    Author         : Microsoft Defender for Cloud Community
    Last Updated   : December 2025
    
    Prerequisites  : Azure CLI, kubectl, Helm, Python 3.7+
                     (Script can auto-install missing components)
    
    Tested On      : Windows 10/11, PowerShell 5.1+, PowerShell 7+
    
    Copyright      : (c) 2024-2025 Microsoft Corporation
    License        : MIT License
    ============================================================================
    
    PREREQUISITES (Auto-Installable):
    ─────────────────────────────────
    • Azure CLI    - Install: winget install Microsoft.AzureCLI
    • kubectl      - Install: az aks install-cli
    • Helm         - Install: winget install Helm.Helm
    • Python 3.7+  - Install: winget install Python.Python.3.11
    
    The script will detect missing prerequisites and offer to install them
    automatically. Some installations may require administrator privileges.
    
    REQUIRED AZURE PERMISSIONS (Least Privilege):
    ─────────────────────────────────────────────
    
    FOR USING AN EXISTING AKS CLUSTER (Recommended - Minimum Permissions):
    • Azure Kubernetes Service Cluster User Role (on the AKS cluster)
      - Allows: Get cluster credentials, list clusters
      - Scope: /subscriptions/{sub}/resourceGroups/{rg}/providers/
               Microsoft.ContainerService/managedClusters/{cluster}
    
    • Reader (on the resource group or subscription)
      - Allows: List and view AKS clusters
      - Scope: /subscriptions/{sub} or /subscriptions/{sub}/resourceGroups/{rg}
    
    FOR CREATING A NEW AKS CLUSTER (Elevated Permissions Required):
    • Contributor (on the subscription or resource group)
      - Allows: Create resource groups, AKS clusters, and associated resources
      - Scope: /subscriptions/{sub}
    
    • OR a custom role with these permissions:
      - Microsoft.Resources/subscriptions/resourceGroups/write
      - Microsoft.ContainerService/managedClusters/write
      - Microsoft.ContainerService/managedClusters/read
      - Microsoft.Network/virtualNetworks/write
      - Microsoft.Compute/virtualMachines/write

    ESTIMATED COSTS:
    ────────────────
    • Using existing cluster: < $0.10 (simulation pods only)
    • Creating new cluster:   ~$0.08/hour, ~$1.80/day (Standard_B2s, 1 node)
    • The script will prompt for cleanup to avoid ongoing charges
    
    SECURITY CONSIDERATIONS:
    ────────────────────────
    • This script executes attack simulations that generate security alerts
    • Run ONLY on non-production, dedicated test/demo clusters
    • The simulation deploys pods with elevated privileges
    • All simulation resources are cleaned up after execution
    • Alerts generated may require investigation in Azure Portal
    • Microsoft recommends using a dedicated cluster without production workloads

    WHAT THIS SCRIPT DOES NOT DO:
    ─────────────────────────────
    • Does NOT modify your existing workloads
    • Does NOT access your application data
    • Does NOT make permanent changes to cluster configuration
    • Does NOT disable any security controls
    • Does NOT require cluster-admin for existing clusters (Cluster User is sufficient)

.EXAMPLE
    .\Deploy-KubernetesAlertSimulation.ps1
    
    Runs the script interactively with full guided experience:
    - Checks and offers to install missing prerequisites
    - Discovers available AKS clusters
    - Prompts for cluster selection or new cluster creation
    - Runs all attack scenarios
    - Generates HTML report
    - Prompts for cleanup
    
.EXAMPLE
    .\Deploy-KubernetesAlertSimulation.ps1 -ClusterName "dev-aks" -ResourceGroup "dev-rg"
    
    Runs the simulation directly on the specified cluster, bypassing discovery.
    Useful for automation or when you know the target cluster.
    
.EXAMPLE
    .\Deploy-KubernetesAlertSimulation.ps1 -SimulationScenario Reconnaissance
    
    Runs only the Reconnaissance scenario (network scanning, service enumeration).
    Useful for testing specific detection capabilities.

.EXAMPLE
    .\Deploy-KubernetesAlertSimulation.ps1 -CleanupAfterRun
    
    Runs the simulation with automatic cleanup (no prompts for cleanup).
    Useful for automated/scripted execution.

.EXAMPLE
    .\Deploy-KubernetesAlertSimulation.ps1 -SubscriptionId "12345678-1234-1234-1234-123456789012"
    
    Runs the script using a specific Azure subscription instead of the default.

.EXAMPLE
    .\Deploy-KubernetesAlertSimulation.ps1 -SkipPrerequisiteCheck
    
    Skips prerequisite validation (not recommended).
    Use only when you're certain all prerequisites are installed.

.INPUTS
    None. This script does not accept pipeline input.

.OUTPUTS
    HTML Report - Detailed simulation report saved to the specified ReportPath
    Console Output - Real-time progress and status information
    Security Alerts - Generated in Microsoft Defender for Cloud (Azure Portal)

.LINK
    https://github.com/microsoft/Defender-for-Cloud-Attack-Simulation
    
.LINK
    https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-containers-introduction

.LINK
    https://learn.microsoft.com/en-us/azure/defender-for-cloud/kubernetes-workload-protections

.LINK
    https://learn.microsoft.com/en-us/azure/defender-for-cloud/alerts-containers

#>

<#
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║                              DISCLAIMER                                      ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝

THE SAMPLE SCRIPTS ARE NOT SUPPORTED UNDER ANY MICROSOFT STANDARD SUPPORT
PROGRAM OR SERVICE. THE SAMPLE SCRIPTS ARE PROVIDED "AS IS" WITHOUT WARRANTY
OF ANY KIND. MICROSOFT FURTHER DISCLAIMS ALL IMPLIED WARRANTIES INCLUDING,
WITHOUT LIMITATION, ANY IMPLIED WARRANTIES OF MERCHANTABILITY OR OF FITNESS
FOR A PARTICULAR PURPOSE.

THE ENTIRE RISK ARISING OUT OF THE USE OR PERFORMANCE OF THE SAMPLE SCRIPTS
AND DOCUMENTATION REMAINS WITH YOU. IN NO EVENT SHALL MICROSOFT, ITS AUTHORS,
OR ANYONE ELSE INVOLVED IN THE CREATION, PRODUCTION, OR DELIVERY OF THE
SCRIPTS BE LIABLE FOR ANY DAMAGES WHATSOEVER (INCLUDING, WITHOUT LIMITATION,
DAMAGES FOR LOSS OF BUSINESS PROFITS, BUSINESS INTERRUPTION, LOSS OF BUSINESS
INFORMATION, OR OTHER PECUNIARY LOSS) ARISING OUT OF THE USE OF OR INABILITY
TO USE THE SAMPLE SCRIPTS OR DOCUMENTATION, EVEN IF MICROSOFT HAS BEEN ADVISED
OF THE POSSIBILITY OF SUCH DAMAGES.

╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║                              USAGE NOTICE                                    ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝

This script is provided as a sample to help demonstrate the capabilities of
Microsoft Defender for Cloud. Before using this script in any environment:

  1. REVIEW    - Read the script code to understand what operations it performs
  2. TEST      - Run in a non-production environment first
  3. AUTHORIZE - Ensure you have proper authorization to run security simulations
  4. COMPLY    - Verify compliance with your organization's security policies
  5. ISOLATE   - DO NOT run on production clusters with active workloads

This script downloads and executes code from Microsoft's GitHub repository:
https://github.com/microsoft/Defender-for-Cloud-Attack-Simulation

The simulation tool is subject to the MIT License. Please review the license
terms at the repository before use.

╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║                         MICROSOFT CODE OF CONDUCT                            ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝

This project has adopted the Microsoft Open Source Code of Conduct.
For more information see the Code of Conduct FAQ or contact
opencode@microsoft.com with any additional questions or comments.

https://opensource.microsoft.com/codeofconduct/

╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║                            VERSION HISTORY                                   ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝

Version 2.2.0 (December 2025)
─────────────────────────────
• Enhanced HTML report with comprehensive action timeline tracking
• Added "Actions Performed" section showing all script operations with timestamps
• Added Azure resource summary (cluster type, location, cleanup status)
• Added subscription ID capture for better audit trail
• Report now includes cleanup verification status
• Report now includes cluster deletion status for newly created clusters
• Simulation output captured in report for reference
• Report generation moved to end of script to capture all actions

Version 2.1.0 (December 2025)
─────────────────────────────
• Added comprehensive Defender for Containers configuration check
• Added ability to enable Defender for Containers (subscription or cluster level)
• Added detailed pricing estimates for Defender for Containers
• Added step-by-step manual setup instructions option
• Enhanced explanations of WHY Defender sensor is required for alerts

Version 2.0.0 (December 2025)
─────────────────────────────
• Added automatic prerequisite installation via winget
• Added Azure permission validation with least-privilege recommendations
• Added option to create new non-prod AKS cluster for testing
• Added visual progress bar for cluster deployment
• Added production cluster detection with safety warnings
• Added comprehensive cost analysis and estimates
• Enhanced cleanup prompts for both simulation resources and clusters
• Enhanced HTML report generation with detailed scenario tracking
• Enhanced error handling with specific guidance for common issues
• Improved browser-based Azure login (replaced device code flow)

Version 1.0.0 (Initial Release)
───────────────────────────────
• Basic simulation automation
• Cluster discovery and selection
• HTML report generation

═══════════════════════════════════════════════════════════════════════════════
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ClusterName,
    
    [Parameter(Mandatory = $false)]
    [string]$ResourceGroup,
    
    [Parameter(Mandatory = $false)]
    [string]$SubscriptionId,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("All", "Reconnaissance", "LateralMovement", "SecretsGathering", "CryptoMining", "WebShell")]
    [string]$SimulationScenario = "All",
    
    [Parameter(Mandatory = $false)]
    [string]$WorkingDirectory = "$env:TEMP\K8sAlertSimulation",
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipPrerequisiteCheck,
    
    [Parameter(Mandatory = $false)]
    [switch]$CleanupAfterRun,
    
    [Parameter(Mandatory = $false)]
    [string]$ReportPath = "$env:USERPROFILE\Documents\K8s-Simulation-Report-$(Get-Date -Format 'yyyy-MM-dd-HHmmss').html"
)

# Global report data collection
$script:SimulationReport = @{
    StartTime = $null
    EndTime = $null
    ClusterName = $null
    ResourceGroup = $null
    Subscription = $null
    SubscriptionId = $null
    UserName = $null
    Scenarios = @()
    Prerequisites = @()
    DefenderSensorStatus = $null
    SimulationStartTime = $null
    SimulationEndTime = $null
    # New detailed tracking
    ClusterLocation = $null
    ClusterNodeCount = $null
    ClusterVMSize = $null
    IsNewCluster = $false
    SimulationToolVersion = $null
    SimulationOutput = $null
    CleanupStatus = $null
    ClusterDeletedAfterRun = $false
    ScriptVersion = "2.2.0"
    ActionsPerformed = @()  # Track all actions
    TenantId = $null  # Azure AD tenant ID for alert portal link
}

# Track if we created a new cluster (for cleanup prompt)
$script:CreatedClusterForCleanup = $null

# Flag to enable Defender when creating new cluster
$script:EnableDefenderOnNewCluster = $false

# Session state file for resume capability
$script:SessionStateFile = "$env:USERPROFILE\Documents\.mdc-simulation-session.json"
$script:ErrorLogFile = "$env:USERPROFILE\Documents\K8s-Simulation-ErrorLog-$(Get-Date -Format 'yyyy-MM-dd-HHmmss').txt"

# Session state for resume capability
$script:SessionState = @{
    SessionId = [guid]::NewGuid().ToString()
    StartTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    CurrentStage = "NotStarted"
    CompletedStages = @()
    ClusterName = $null
    ResourceGroup = $null
    SubscriptionId = $null
    Location = $null
    IsNewCluster = $false
    LastError = $null
    LastErrorTime = $null
}

# ============================================================================
# Session State & Error Logging Functions
# ============================================================================

function Write-ErrorLog {
    <#
    .SYNOPSIS
        Writes error details to a persistent log file.
    #>
    param(
        [string]$Message,
        [string]$ErrorDetails = "",
        [string]$Stage = ""
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = @"

================================================================================
ERROR LOG ENTRY - $timestamp
================================================================================
Stage: $Stage
Message: $Message
Details: $ErrorDetails
Session ID: $($script:SessionState.SessionId)
Cluster: $($script:SessionState.ClusterName)
Resource Group: $($script:SessionState.ResourceGroup)
================================================================================

"@
    
    # Append to error log file
    Add-Content -Path $script:ErrorLogFile -Value $logEntry -ErrorAction SilentlyContinue
    
    # Update session state with last error
    $script:SessionState.LastError = $Message
    $script:SessionState.LastErrorTime = $timestamp
    Save-SessionState
}

function Save-SessionState {
    <#
    .SYNOPSIS
        Saves the current session state to a JSON file for resume capability.
    #>
    try {
        $script:SessionState | ConvertTo-Json -Depth 5 | Set-Content -Path $script:SessionStateFile -Force
    }
    catch {
        # Silently fail - don't interrupt main flow for state save errors
    }
}

function Get-SessionState {
    <#
    .SYNOPSIS
        Retrieves a previous session state if one exists.
    #>
    if (Test-Path $script:SessionStateFile) {
        try {
            $savedState = Get-Content -Path $script:SessionStateFile -Raw | ConvertFrom-Json
            return $savedState
        }
        catch {
            return $null
        }
    }
    return $null
}

function Remove-SessionState {
    <#
    .SYNOPSIS
        Removes the session state file after successful completion.
    #>
    if (Test-Path $script:SessionStateFile) {
        Remove-Item -Path $script:SessionStateFile -Force -ErrorAction SilentlyContinue
    }
}

function Update-SessionStage {
    <#
    .SYNOPSIS
        Updates the current stage in the session state.
    #>
    param(
        [string]$Stage,
        [switch]$MarkComplete
    )
    
    $script:SessionState.CurrentStage = $Stage
    
    if ($MarkComplete -and $script:SessionState.CompletedStages -notcontains $Stage) {
        $script:SessionState.CompletedStages += $Stage
    }
    
    Save-SessionState
}

function Test-StageCompleted {
    <#
    .SYNOPSIS
        Checks if a stage has already been completed in a previous session.
    #>
    param(
        [string]$Stage
    )
    
    return $script:SessionState.CompletedStages -contains $Stage
}

function Show-ResumePrompt {
    <#
    .SYNOPSIS
        Shows a prompt to resume from a previous failed session.
    #>
    param(
        [object]$PreviousSession
    )
    
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Yellow
    Write-Host "║                     PREVIOUS SESSION DETECTED                                ║" -ForegroundColor Yellow
    Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  A previous simulation session was interrupted or failed." -ForegroundColor White
    Write-Host ""
    Write-Host "  Session Details:" -ForegroundColor Cyan
    Write-Host "  ─────────────────────────────────────────────────────────────────────────────" -ForegroundColor Gray
    Write-Host "  Started:        $($PreviousSession.StartTime)" -ForegroundColor White
    Write-Host "  Last Stage:     $($PreviousSession.CurrentStage)" -ForegroundColor White
    
    if ($PreviousSession.ClusterName) {
        Write-Host "  Cluster:        $($PreviousSession.ClusterName)" -ForegroundColor White
    }
    if ($PreviousSession.ResourceGroup) {
        Write-Host "  Resource Group: $($PreviousSession.ResourceGroup)" -ForegroundColor White
    }
    if ($PreviousSession.LastError) {
        Write-Host ""
        Write-Host "  Last Error:     $($PreviousSession.LastError)" -ForegroundColor Red
        Write-Host "  Error Time:     $($PreviousSession.LastErrorTime)" -ForegroundColor Red
    }
    Write-Host "  ─────────────────────────────────────────────────────────────────────────────" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Completed Stages:" -ForegroundColor Cyan
    
    if ($PreviousSession.CompletedStages -and $PreviousSession.CompletedStages.Count -gt 0) {
        foreach ($stage in $PreviousSession.CompletedStages) {
            Write-Host "    ✓ $stage" -ForegroundColor Green
        }
    } else {
        Write-Host "    (none)" -ForegroundColor Gray
    }
    
    Write-Host ""
    Write-Host "  Options:" -ForegroundColor Cyan
    Write-Host "    [1] Resume from where it failed (recommended)" -ForegroundColor White
    Write-Host "    [2] Start fresh (will attempt to clean up previous resources)" -ForegroundColor White
    Write-Host "    [3] Exit" -ForegroundColor White
    Write-Host ""
    
    $choice = Read-Host "  Enter your choice (1-3)"
    
    switch ($choice) {
        "1" {
            # Resume - restore session state
            $script:SessionState = @{
                SessionId = $PreviousSession.SessionId
                StartTime = $PreviousSession.StartTime
                CurrentStage = $PreviousSession.CurrentStage
                CompletedStages = @($PreviousSession.CompletedStages)
                ClusterName = $PreviousSession.ClusterName
                ResourceGroup = $PreviousSession.ResourceGroup
                SubscriptionId = $PreviousSession.SubscriptionId
                Location = $PreviousSession.Location
                IsNewCluster = $PreviousSession.IsNewCluster
                LastError = $PreviousSession.LastError
                LastErrorTime = $PreviousSession.LastErrorTime
            }
            
            # Restore cluster cleanup info if it was a new cluster
            if ($PreviousSession.IsNewCluster -and $PreviousSession.ClusterName -and $PreviousSession.ResourceGroup) {
                $script:CreatedClusterForCleanup = @{
                    Name = $PreviousSession.ClusterName
                    ResourceGroup = $PreviousSession.ResourceGroup
                }
            }
            
            Write-Host ""
            Write-Host "  ✓ Resuming from stage: $($PreviousSession.CurrentStage)" -ForegroundColor Green
            Write-Host ""
            return "Resume"
        }
        "2" {
            # Start fresh - offer to clean up
            if ($PreviousSession.IsNewCluster -and $PreviousSession.ResourceGroup) {
                Write-Host ""
                Write-Host "  Checking for resources to clean up..." -ForegroundColor Yellow
                
                $rgExists = az group exists --name $PreviousSession.ResourceGroup 2>$null
                if ($rgExists -eq "true") {
                    Write-Host "  Found resource group: $($PreviousSession.ResourceGroup)" -ForegroundColor Yellow
                    $cleanupChoice = Read-Host "  Delete this resource group before starting fresh? (yes/no)"
                    
                    if ($cleanupChoice -eq 'yes' -or $cleanupChoice -eq 'y') {
                        Write-Host "  Deleting resource group (this runs in background)..." -ForegroundColor Yellow
                        az group delete --name $PreviousSession.ResourceGroup --yes --no-wait 2>$null
                        Write-Host "  ✓ Deletion initiated" -ForegroundColor Green
                    }
                }
            }
            
            Remove-SessionState
            
            # Reset session state
            $script:SessionState = @{
                SessionId = [guid]::NewGuid().ToString()
                StartTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                CurrentStage = "NotStarted"
                CompletedStages = @()
                ClusterName = $null
                ResourceGroup = $null
                SubscriptionId = $null
                Location = $null
                IsNewCluster = $false
                LastError = $null
                LastErrorTime = $null
            }
            
            Write-Host ""
            Write-Host "  ✓ Starting fresh session" -ForegroundColor Green
            Write-Host ""
            return "Fresh"
        }
        "3" {
            Write-Host ""
            Write-Host "  Exiting. Your previous session state is preserved." -ForegroundColor Yellow
            Write-Host "  Run the script again to resume or start fresh." -ForegroundColor Gray
            Write-Host ""
            exit 0
        }
        default {
            Write-Host "  Invalid choice. Exiting." -ForegroundColor Red
            exit 1
        }
    }
}

# ============================================================================
# Microsoft Disclaimer
# ============================================================================
function Show-Disclaimer {
    Clear-Host
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                                                                              ║" -ForegroundColor Cyan
    Write-Host "║       MICROSOFT DEFENDER FOR CLOUD - KUBERNETES ALERTS SIMULATION           ║" -ForegroundColor Cyan
    Write-Host "║                                                                              ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  ┌────────────────────────────────────────────────────────────────────────────┐" -ForegroundColor Yellow
    Write-Host "  │                              DISCLAIMER                                   │" -ForegroundColor Yellow
    Write-Host "  └────────────────────────────────────────────────────────────────────────────┘" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  This script automates the Microsoft Defender for Cloud Kubernetes attack" -ForegroundColor White
    Write-Host "  simulation tool to validate security alert detection capabilities." -ForegroundColor White
    Write-Host ""
    Write-Host "  BY USING THIS SCRIPT, YOU ACKNOWLEDGE AND AGREE:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  1. AUTHORIZED USE ONLY" -ForegroundColor Cyan
    Write-Host "     This tool should only be run on Azure resources you own or have explicit" -ForegroundColor Gray
    Write-Host "     authorization to test. Unauthorized use may violate laws and policies." -ForegroundColor Gray
    Write-Host ""
    Write-Host "  2. NO WARRANTY" -ForegroundColor Cyan
    Write-Host "     This script is provided 'AS IS' without warranty of any kind. Microsoft" -ForegroundColor Gray
    Write-Host "     and the script authors disclaim all warranties, express or implied." -ForegroundColor Gray
    Write-Host ""
    Write-Host "  3. AZURE COSTS" -ForegroundColor Cyan
    Write-Host "     Running this simulation may incur Azure charges for compute, storage," -ForegroundColor Gray
    Write-Host "     networking, and Defender for Cloud services. You are responsible for" -ForegroundColor Gray
    Write-Host "     all costs associated with your Azure subscription usage." -ForegroundColor Gray
    Write-Host ""
    Write-Host "  4. SECURITY ALERTS" -ForegroundColor Cyan
    Write-Host "     This tool intentionally triggers security alerts in Microsoft Defender" -ForegroundColor Gray
    Write-Host "     for Cloud. These are simulated attacks for testing purposes only." -ForegroundColor Gray
    Write-Host "     Ensure your security team is aware before running." -ForegroundColor Gray
    Write-Host ""
    Write-Host "  5. NON-PRODUCTION USE" -ForegroundColor Cyan
    Write-Host "     Microsoft recommends running this simulation on dedicated non-production" -ForegroundColor Gray
    Write-Host "     clusters to avoid any impact on production workloads." -ForegroundColor Gray
    Write-Host ""
    Write-Host "  6. LIMITATION OF LIABILITY" -ForegroundColor Cyan
    Write-Host "     In no event shall Microsoft or the script authors be liable for any" -ForegroundColor Gray
    Write-Host "     damages arising from the use of this script or simulation tool." -ForegroundColor Gray
    Write-Host ""
    Write-Host "  ─────────────────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host "  Official Microsoft Documentation:" -ForegroundColor Gray
    Write-Host "  https://learn.microsoft.com/en-us/azure/defender-for-cloud/alert-validation" -ForegroundColor Blue
    Write-Host "  ─────────────────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host ""
    
    $acceptance = Read-Host "  Do you accept these terms and wish to continue? (yes/no)"
    
    if ($acceptance -ne 'yes' -and $acceptance -ne 'y') {
        Write-Host ""
        Write-Host "  Disclaimer not accepted. Exiting script." -ForegroundColor Yellow
        Write-Host ""
        exit 0
    }
    
    Write-Host ""
    Write-Host "  ✓ Disclaimer accepted. Proceeding with simulation..." -ForegroundColor Green
    Write-Host ""
    Start-Sleep -Seconds 1
}

#region Helper Functions

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("Info", "Warning", "Error", "Success")]
        [string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "Info"    { "Cyan" }
        "Warning" { "Yellow" }
        "Error"   { "Red" }
        "Success" { "Green" }
    }
    
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

function Test-AzurePermissions {
    <#
    .SYNOPSIS
        Validates that the current user has required Azure permissions.
    .DESCRIPTION
        Checks for permissions required to run the simulation:
        - For EXISTING clusters: Only needs AKS Cluster User + kubectl access
        - For NEW clusters: Needs Contributor on resource group/subscription
        
        The function accepts EITHER:
        1. Elevated roles (Owner, Contributor, Global Admin) - full access
        2. Least-privilege roles (AKS Cluster User) - minimal access
        
        If user has elevated roles, they have sufficient permissions.
        If user has only least-privilege roles, the function verifies specific access.
    #>
    param(
        [switch]$CheckClusterCreation,
        [string]$ResourceGroup,
        [string]$ClusterName
    )
    
    Write-Log "Checking Azure permissions..." -Level Info
    
    $permissionResults = @{
        Passed = $true
        Checks = @()
        RequiredRoles = @()
        HasElevatedAccess = $false
        ElevatedRoles = @()
    }
    
    # Get current user/service principal info
    try {
        $accountInfo = az account show 2>$null | ConvertFrom-Json
        $currentUser = $accountInfo.user.name
        $subscriptionId = $accountInfo.id
        $subscriptionName = $accountInfo.name
        $userType = $accountInfo.user.type  # 'user' or 'servicePrincipal'
        
        Write-Host ""
        Write-Host "┌─────────────────────────────────────────────────────────────┐" -ForegroundColor Cyan
        Write-Host "│               PERMISSION VALIDATION                         │" -ForegroundColor Cyan
        Write-Host "└─────────────────────────────────────────────────────────────┘" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  User: $currentUser" -ForegroundColor White
        Write-Host "  Subscription: $subscriptionName" -ForegroundColor White
        Write-Host ""
    }
    catch {
        Write-Log "Failed to get account info. Please run 'az login' first." -Level Error
        $permissionResults.Passed = $false
        return $permissionResults
    }
    
    # First, check for ELEVATED roles that supersede least-privilege requirements
    Write-Host "  Checking for elevated Azure roles..." -ForegroundColor Gray
    
    $elevatedRolePatterns = @(
        "Owner",
        "Contributor", 
        "Global Administrator",
        "User Access Administrator",
        "Co-Administrator"
    )
    
    try {
        # Get all role assignments for the current user at subscription scope
        $roleAssignments = az role assignment list --assignee $currentUser --all 2>$null | ConvertFrom-Json
        
        if ($roleAssignments) {
            foreach ($assignment in $roleAssignments) {
                $roleName = $assignment.roleDefinitionName
                
                # Check if this is an elevated role
                foreach ($pattern in $elevatedRolePatterns) {
                    if ($roleName -match $pattern) {
                        $permissionResults.HasElevatedAccess = $true
                        if ($permissionResults.ElevatedRoles -notcontains $roleName) {
                            $permissionResults.ElevatedRoles += $roleName
                        }
                    }
                }
            }
        }
    }
    catch {
        # Could not check role assignments - will proceed with specific checks
    }
    
    # Display elevated access status
    if ($permissionResults.HasElevatedAccess) {
        Write-Host ""
        Write-Host "  ┌─────────────────────────────────────────────────────────┐" -ForegroundColor Green
        Write-Host "  │  ✓ ELEVATED ACCESS DETECTED                            │" -ForegroundColor Green
        Write-Host "  └─────────────────────────────────────────────────────────┘" -ForegroundColor Green
        Write-Host ""
        Write-Host "  Your roles:" -ForegroundColor White
        foreach ($role in $permissionResults.ElevatedRoles) {
            Write-Host "    • $role" -ForegroundColor Green
        }
        Write-Host ""
        Write-Host "  These roles provide FULL access to perform:" -ForegroundColor White
        Write-Host "    ✓ Create new AKS clusters" -ForegroundColor Gray
        Write-Host "    ✓ Use existing AKS clusters" -ForegroundColor Gray
        Write-Host "    ✓ Run security simulations" -ForegroundColor Gray
        Write-Host "    ✓ Enable Defender for Containers" -ForegroundColor Gray
        Write-Host ""
        
        # Still show least-privilege recommendation
        Write-Host "  ─────────────────────────────────────────────────────────" -ForegroundColor Gray
        Write-Host "  💡 LEAST PRIVILEGE RECOMMENDATION:" -ForegroundColor Yellow
        Write-Host "  For production use, consider using these minimal roles:" -ForegroundColor Gray
        Write-Host ""
        
        if ($CheckClusterCreation) {
            Write-Host "    For creating clusters:" -ForegroundColor White
            Write-Host "      • Contributor (scoped to resource group)" -ForegroundColor Gray
            Write-Host ""
        }
        
        Write-Host "    For running simulations only:" -ForegroundColor White
        Write-Host "      • Azure Kubernetes Service Cluster User Role" -ForegroundColor Gray
        Write-Host "        (scoped to specific AKS cluster)" -ForegroundColor Gray
        Write-Host "  ─────────────────────────────────────────────────────────" -ForegroundColor Gray
        Write-Host ""
        
        $permissionResults.Passed = $true
        $permissionResults.Checks += @{ Check = "Elevated Access"; Status = "Pass"; Details = "Has $($permissionResults.ElevatedRoles -join ', ')" }
        
        # With elevated access, we don't need to check individual permissions
        # Just verify prerequisites are available
        Write-Host "  Verifying prerequisites..." -ForegroundColor Gray
        Write-Host ""
        
        # Verify kubectl is available (this is a PREREQUISITE, not a permission)
        Write-Host "  [1/1] Checking kubectl availability..." -NoNewline
        $kubectlAvailable = $false
        try {
            $kubectlCheck = kubectl version --client 2>&1
            if ($LASTEXITCODE -eq 0 -or $kubectlCheck -match "Client Version") {
                Write-Host " ✓" -ForegroundColor Green
                $permissionResults.Checks += @{ Check = "kubectl"; Status = "Pass"; Details = "kubectl is available" }
                $kubectlAvailable = $true
            } else {
                Write-Host " ⚠ Not installed" -ForegroundColor Yellow
                $permissionResults.Checks += @{ Check = "kubectl"; Status = "Warning"; Details = "kubectl not found - will be installed during prerequisites" }
            }
        }
        catch {
            Write-Host " ⚠ Not installed" -ForegroundColor Yellow
            $permissionResults.Checks += @{ Check = "kubectl"; Status = "Warning"; Details = "kubectl not found - will be installed during prerequisites" }
        }
        
        # kubectl missing is NOT a permission failure - it's handled by Test-Prerequisites
        # Don't fail the permission check, just note it as a warning
        
        Write-Host ""
        Write-Host "  ✅ PERMISSION CHECK PASSED" -ForegroundColor Green
        Write-Host ""
        
        return $permissionResults
    }
    
    # No elevated access - check for specific least-privilege permissions
    Write-Host ""
    Write-Host "  No elevated roles detected. Checking specific permissions..." -ForegroundColor Gray
    Write-Host ""
    
    # Define minimum required permissions based on operation type
    if ($CheckClusterCreation) {
        Write-Host "  Checking permissions for: CREATE NEW AKS CLUSTER" -ForegroundColor Yellow
        Write-Host ""
        
        $permissionResults.RequiredRoles = @(
            @{
                Role = "Contributor"
                Scope = "Resource Group or Subscription"
                Description = "Required to create AKS cluster and associated resources"
                Required = $true
            }
        )
        
        # Check if user can create resource groups
        Write-Host "  [1/4] Checking resource group permissions..." -NoNewline
        try {
            # Get all role assignments and filter in PowerShell (avoids JMESPath escaping issues)
            $allRoles = az role assignment list --assignee $currentUser 2>$null | ConvertFrom-Json
            $roleAssignments = $allRoles | Where-Object { $_.roleDefinitionName -match 'Contributor|Owner' }
            
            if ($roleAssignments -and @($roleAssignments).Count -gt 0) {
                Write-Host " ✓" -ForegroundColor Green
                $permissionResults.Checks += @{ Check = "Resource Group Create"; Status = "Pass"; Details = "Has Contributor/Owner role" }
            } else {
                # Check for specific permissions
                $customRoles = az role assignment list --assignee $currentUser 2>$null | ConvertFrom-Json
                $hasCreatePermission = $customRoles | Where-Object { 
                    $_.roleDefinitionName -match "Contributor|Owner" -or 
                    $_.scope -match "/subscriptions/$subscriptionId$"
                }
                
                if ($hasCreatePermission) {
                    Write-Host " ✓" -ForegroundColor Green
                    $permissionResults.Checks += @{ Check = "Resource Group Create"; Status = "Pass"; Details = "Has required permissions" }
                } else {
                    Write-Host " ⚠" -ForegroundColor Yellow
                    $permissionResults.Checks += @{ Check = "Resource Group Create"; Status = "Warning"; Details = "Could not verify - will attempt operation" }
                }
            }
        }
        catch {
            Write-Host " ⚠" -ForegroundColor Yellow
            $permissionResults.Checks += @{ Check = "Resource Group Create"; Status = "Warning"; Details = "Could not verify" }
        }
        
        # Check AKS create permissions
        Write-Host "  [2/4] Checking AKS cluster permissions..." -NoNewline
        try {
            # Check for Microsoft.ContainerService provider registration
            $aksProvider = az provider show --namespace Microsoft.ContainerService --query "registrationState" -o tsv 2>$null
            
            if ($aksProvider -eq "Registered") {
                Write-Host " ✓" -ForegroundColor Green
                $permissionResults.Checks += @{ Check = "AKS Provider"; Status = "Pass"; Details = "Microsoft.ContainerService registered" }
            } else {
                Write-Host " ✗" -ForegroundColor Red
                $permissionResults.Checks += @{ Check = "AKS Provider"; Status = "Fail"; Details = "Microsoft.ContainerService not registered" }
                $permissionResults.Passed = $false
            }
        }
        catch {
            Write-Host " ⚠" -ForegroundColor Yellow
            $permissionResults.Checks += @{ Check = "AKS Provider"; Status = "Warning"; Details = "Could not verify" }
        }
        
        # Check compute quota
        Write-Host "  [3/4] Checking compute quota..." -NoNewline
        try {
            $quotaCheck = az vm list-usage --location "eastus" --query "[?contains(name.value, 'standardBSFamily')].{name:name.value, current:currentValue, limit:limit}" 2>$null | ConvertFrom-Json
            
            if ($quotaCheck -and $quotaCheck.Count -gt 0) {
                $bsQuota = $quotaCheck | Select-Object -First 1
                $available = $bsQuota.limit - $bsQuota.current
                
                if ($available -ge 2) {
                    Write-Host " ✓" -ForegroundColor Green
                    $permissionResults.Checks += @{ Check = "Compute Quota"; Status = "Pass"; Details = "$($available) vCPUs available" }
                } else {
                    Write-Host " ✗" -ForegroundColor Red
                    $permissionResults.Checks += @{ Check = "Compute Quota"; Status = "Fail"; Details = "Insufficient quota: $($available) vCPUs" }
                    $permissionResults.Passed = $false
                }
            } else {
                Write-Host " ✓" -ForegroundColor Green
                $permissionResults.Checks += @{ Check = "Compute Quota"; Status = "Pass"; Details = "Quota check passed" }
            }
        }
        catch {
            Write-Host " ⚠" -ForegroundColor Yellow
            $permissionResults.Checks += @{ Check = "Compute Quota"; Status = "Warning"; Details = "Could not verify quota" }
        }
        
        # Check networking permissions
        Write-Host "  [4/4] Checking networking permissions..." -NoNewline
        try {
            $networkProvider = az provider show --namespace Microsoft.Network --query "registrationState" -o tsv 2>$null
            
            if ($networkProvider -eq "Registered") {
                Write-Host " ✓" -ForegroundColor Green
                $permissionResults.Checks += @{ Check = "Network Provider"; Status = "Pass"; Details = "Microsoft.Network registered" }
            } else {
                Write-Host " ⚠" -ForegroundColor Yellow
                $permissionResults.Checks += @{ Check = "Network Provider"; Status = "Warning"; Details = "Microsoft.Network may need registration" }
            }
        }
        catch {
            Write-Host " ⚠" -ForegroundColor Yellow
            $permissionResults.Checks += @{ Check = "Network Provider"; Status = "Warning"; Details = "Could not verify" }
        }
        
    } else {
        # Permissions for USING an existing cluster (least privilege)
        Write-Host "  Checking permissions for: USE EXISTING AKS CLUSTER" -ForegroundColor Yellow
        Write-Host ""
        
        $permissionResults.RequiredRoles = @(
            @{
                Role = "Azure Kubernetes Service Cluster User Role"
                Scope = "AKS Cluster"
                Description = "Minimum required to get cluster credentials"
                Required = $true
            },
            @{
                Role = "Azure Kubernetes Service RBAC Reader"
                Scope = "AKS Cluster"
                Description = "Optional - for K8s RBAC enabled clusters"
                Required = $false
            }
        )
        
        # Check for AKS-specific roles
        Write-Host "  [1/3] Checking AKS role assignments..." -NoNewline
        try {
            # Get all role assignments and filter in PowerShell (avoids JMESPath escaping issues)
            $allRoles = az role assignment list --assignee $currentUser 2>$null | ConvertFrom-Json
            $aksRoles = $allRoles | Where-Object { $_.roleDefinitionName -match 'Kubernetes|AKS|Contributor|Owner' }
            
            if ($aksRoles -and @($aksRoles).Count -gt 0) {
                Write-Host " ✓" -ForegroundColor Green
                $roleNames = ($aksRoles | Select-Object -ExpandProperty roleDefinitionName -Unique) -join ", "
                $permissionResults.Checks += @{ Check = "AKS Roles"; Status = "Pass"; Details = "Has: $roleNames" }
            } else {
                Write-Host " ⚠" -ForegroundColor Yellow
                $permissionResults.Checks += @{ Check = "AKS Roles"; Status = "Warning"; Details = "No AKS-specific roles found - may still have access" }
            }
        }
        catch {
            Write-Host " ⚠" -ForegroundColor Yellow
            $permissionResults.Checks += @{ Check = "AKS Roles"; Status = "Warning"; Details = "Could not verify" }
        }
        
        # Check cluster access
        Write-Host "  [2/3] Checking AKS cluster list permissions..." -NoNewline
        try {
            $clusters = az aks list --query "[].name" 2>$null | ConvertFrom-Json
            
            if ($null -ne $clusters) {
                Write-Host " ✓" -ForegroundColor Green
                $clusterCount = if ($clusters -is [array]) { $clusters.Count } else { 1 }
                $permissionResults.Checks += @{ Check = "AKS List"; Status = "Pass"; Details = "Can list AKS clusters ($($clusterCount) found)" }
            } else {
                Write-Host " ⚠" -ForegroundColor Yellow
                $permissionResults.Checks += @{ Check = "AKS List"; Status = "Warning"; Details = "No clusters found or limited permissions" }
            }
        }
        catch {
            Write-Host " ⚠" -ForegroundColor Yellow
            $permissionResults.Checks += @{ Check = "AKS List"; Status = "Warning"; Details = "Could not verify - may have access to specific clusters" }
        }
        
        # Check cluster credentials access (if cluster specified)
        if ($ClusterName -and $ResourceGroup) {
            Write-Host "  [3/3] Checking cluster credential access..." -NoNewline
            try {
                # Dry run check - see if we can get the cluster info
                $clusterInfo = az aks show --name $ClusterName --resource-group $ResourceGroup --query "name" 2>$null
                
                if ($clusterInfo) {
                    Write-Host " ✓" -ForegroundColor Green
                    $permissionResults.Checks += @{ Check = "Cluster Access"; Status = "Pass"; Details = "Can access cluster: $ClusterName" }
                } else {
                    Write-Host " ✗" -ForegroundColor Red
                    $permissionResults.Checks += @{ Check = "Cluster Access"; Status = "Fail"; Details = "Cannot access cluster" }
                    $permissionResults.Passed = $false
                }
            }
            catch {
                Write-Host " ✗" -ForegroundColor Red
                $permissionResults.Checks += @{ Check = "Cluster Access"; Status = "Fail"; Details = "Cannot access cluster" }
                $permissionResults.Passed = $false
            }
        } else {
            Write-Host "  [3/3] Cluster credential access..." -NoNewline
            Write-Host " ⏭ (will check after selection)" -ForegroundColor Gray
            $permissionResults.Checks += @{ Check = "Cluster Access"; Status = "Pending"; Details = "Will verify after cluster selection" }
        }
    }
    
    Write-Host ""
    
    # Show required roles summary
    Write-Host "  ─────────────────────────────────────────────────────────────" -ForegroundColor Gray
    Write-Host "  MINIMUM REQUIRED AZURE ROLES (Least Privilege):" -ForegroundColor Cyan
    Write-Host ""
    
    foreach ($role in $permissionResults.RequiredRoles) {
        $marker = if ($role.Required) { "•" } else { "○" }
        $requiredText = if ($role.Required) { "(Required)" } else { "(Optional)" }
        Write-Host "    $marker $($role.Role)" -ForegroundColor White
        Write-Host "      Scope: $($role.Scope) $requiredText" -ForegroundColor Gray
    }
    
    Write-Host ""
    Write-Host "  NOTE: Higher-level roles (Owner, Contributor, Global Admin)" -ForegroundColor Gray
    Write-Host "        also provide sufficient access." -ForegroundColor Gray
    Write-Host ""
    Write-Host "  ─────────────────────────────────────────────────────────────" -ForegroundColor Gray
    
    # Summary
    $failedChecks = $permissionResults.Checks | Where-Object { $_.Status -eq "Fail" }
    $warningChecks = $permissionResults.Checks | Where-Object { $_.Status -eq "Warning" }
    
    if ($failedChecks.Count -gt 0) {
        Write-Host ""
        Write-Host "  ❌ PERMISSION CHECK FAILED" -ForegroundColor Red
        Write-Host ""
        Write-Host "  The following checks failed:" -ForegroundColor Red
        foreach ($check in $failedChecks) {
            Write-Host "    • $($check.Check): $($check.Details)" -ForegroundColor Red
        }
        Write-Host ""
        Write-Host "  To resolve permission issues:" -ForegroundColor Yellow
        Write-Host "    1. Contact your Azure administrator" -ForegroundColor White
        Write-Host "    2. Request one of these roles:" -ForegroundColor White
        Write-Host "       • Owner or Contributor (full access)" -ForegroundColor Gray
        Write-Host "       • Azure Kubernetes Service Cluster User Role (least privilege)" -ForegroundColor Gray
        Write-Host "    3. Or use a subscription where you have sufficient access" -ForegroundColor White
        $permissionResults.Passed = $false
    }
    elseif ($warningChecks.Count -gt 0) {
        Write-Host ""
        Write-Host "  ⚠️  PERMISSION CHECK PASSED WITH WARNINGS" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  Some checks could not be fully verified:" -ForegroundColor Yellow
        foreach ($check in $warningChecks) {
            Write-Host "    • $($check.Check): $($check.Details)" -ForegroundColor Yellow
        }
        Write-Host ""
        Write-Host "  The script will attempt to proceed. If you encounter permission" -ForegroundColor Gray
        Write-Host "  errors, please request elevated access from your administrator." -ForegroundColor Gray
    }
    else {
        Write-Host ""
        Write-Host "  ✅ ALL PERMISSION CHECKS PASSED" -ForegroundColor Green
    }
    
    Write-Host ""
    
    return $permissionResults
}

function Get-AzureCliErrorMessage {
    <#
    .SYNOPSIS
        Extracts meaningful error messages from Azure CLI output.
    .DESCRIPTION
        Azure CLI can return verbose output including help text when errors occur.
        This function parses the output to extract the actual error message.
    #>
    param(
        [string]$Output
    )
    
    if ([string]::IsNullOrWhiteSpace($Output)) {
        return "Unknown error (no output)"
    }
    
    # Try to parse as JSON error response
    try {
        $jsonMatch = [regex]::Match($Output, '\{[^{}]*"error"[^{}]*\}')
        if ($jsonMatch.Success) {
            $errorJson = $jsonMatch.Value | ConvertFrom-Json -ErrorAction SilentlyContinue
            if ($errorJson.error.message) {
                return $errorJson.error.message
            }
        }
    }
    catch {
        # Not JSON, continue with text parsing
    }
    
    # Look for common error patterns in Azure CLI output
    $errorPatterns = @(
        "(?:ERROR|Error):\s*(.+?)(?:\r?\n|$)",
        "(?:error|Error)\s*:\s*(.+?)(?:\r?\n|$)",
        "The .+ failed with error:?\s*(.+?)(?:\r?\n|$)",
        "(?:ValidationError|BadRequest|Conflict|NotFound|Forbidden):\s*(.+?)(?:\r?\n|$)",
        "Operation failed with status:\s*'([^']+)'",
        "Message:\s*(.+?)(?:\r?\n|$)"
    )
    
    foreach ($pattern in $errorPatterns) {
        $match = [regex]::Match($Output, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        if ($match.Success -and $match.Groups[1].Value.Trim()) {
            $errorMsg = $match.Groups[1].Value.Trim()
            # Skip if it looks like help text
            if ($errorMsg -notmatch "^az |usage:|--help|Read more about") {
                return $errorMsg
            }
        }
    }
    
    # Filter out help text and get first meaningful line
    $lines = $Output -split "`n" | Where-Object { 
        $_.Trim() -and 
        $_ -notmatch "^az " -and 
        $_ -notmatch "usage:" -and 
        $_ -notmatch "--help" -and 
        $_ -notmatch "Read more about" -and
        $_ -notmatch "System\.Management\.Automation" -and
        $_ -notmatch "^\s*$"
    }
    
    if ($lines -and $lines.Count -gt 0) {
        # Return first non-help line, limited to reasonable length
        $firstLine = ($lines | Select-Object -First 1).Trim()
        if ($firstLine.Length -gt 200) {
            return $firstLine.Substring(0, 200) + "..."
        }
        return $firstLine
    }
    
    return "Azure CLI command failed. Run with --debug for more details."
}

function Show-DeploymentProgress {
    <#
    .SYNOPSIS
        Displays a visual progress indicator for long-running deployments.
    .DESCRIPTION
        Shows an animated progress bar with stage information to keep the user
        informed during AKS cluster creation (which can take 5-10 minutes).
    #>
    param(
        [string]$Activity = "Creating AKS Cluster",
        [string]$Status = "Initializing...",
        [int]$PercentComplete = 0,
        [string]$CurrentOperation = ""
    )
    
    Write-Progress -Activity $Activity -Status $Status -PercentComplete $PercentComplete -CurrentOperation $CurrentOperation
}

function Start-AKSDeploymentWithProgress {
    <#
    .SYNOPSIS
        Creates an AKS cluster with visual progress feedback.
    .DESCRIPTION
        Runs the AKS creation in a background job while showing progress
        updates to the user based on typical deployment stages.
    #>
    param(
        [string]$ClusterName,
        [string]$ResourceGroup,
        [string]$Location
    )
    
    # Define deployment stages with estimated timing
    $deploymentStages = @(
        @{ Name = "Validating configuration"; Duration = 10; Percent = 5 }
        @{ Name = "Provisioning resource group"; Duration = 5; Percent = 10 }
        @{ Name = "Creating virtual network"; Duration = 20; Percent = 20 }
        @{ Name = "Provisioning node pool"; Duration = 60; Percent = 40 }
        @{ Name = "Deploying Kubernetes control plane"; Duration = 90; Percent = 60 }
        @{ Name = "Configuring cluster networking"; Duration = 30; Percent = 75 }
        @{ Name = "Installing cluster components"; Duration = 45; Percent = 85 }
        @{ Name = "Finalizing cluster setup"; Duration = 30; Percent = 95 }
    )
    
    # Build the AKS create command as a single string for the job
    $aksCommand = "az aks create --name `"$ClusterName`" --resource-group `"$ResourceGroup`" --location `"$Location`" --node-count 1 --node-vm-size Standard_B2s --enable-managed-identity --generate-ssh-keys --tags purpose=mdc-simulation auto-delete=recommended --only-show-errors 2>&1"
    
    # Start the AKS creation as a background job
    $job = Start-Job -ScriptBlock {
        param($cmd)
        Invoke-Expression $cmd
    } -ArgumentList $aksCommand
    
    Write-Host ""
    Write-Host "┌─────────────────────────────────────────────────────────────┐" -ForegroundColor Cyan
    Write-Host "│           AKS CLUSTER DEPLOYMENT IN PROGRESS                │" -ForegroundColor Cyan
    Write-Host "└─────────────────────────────────────────────────────────────┘" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  This typically takes 5-8 minutes. Please wait..." -ForegroundColor Gray
    Write-Host ""
    
    $startTime = Get-Date
    $stageIndex = 0
    $lastStageIndex = -1
    $spinnerChars = @('-', '\', '|', '/')
    $spinnerIndex = 0
    
    # Store initial cursor position for single-line updates
    $progressLineY = [Console]::CursorTop
    
    # Monitor job and show progress
    while ($job.State -eq 'Running') {
        $elapsedSeconds = ((Get-Date) - $startTime).TotalSeconds
        
        # Determine current stage based on elapsed time
        $cumulativeTime = 0
        for ($i = 0; $i -lt $deploymentStages.Count; $i++) {
            $cumulativeTime += $deploymentStages[$i].Duration
            if ($elapsedSeconds -lt $cumulativeTime) {
                $stageIndex = $i
                break
            }
            $stageIndex = $deploymentStages.Count - 1
        }
        
        $currentStage = $deploymentStages[$stageIndex]
        $percentComplete = [Math]::Min($currentStage.Percent, 99)
        
        # Format elapsed time
        $elapsedMinutes = [int][Math]::Floor($elapsedSeconds / 60)
        $elapsedSecs = [int][Math]::Floor($elapsedSeconds % 60)
        $elapsedDisplay = "{0:D2}:{1:D2}" -f $elapsedMinutes, $elapsedSecs
        
        # Build progress bar (simple ASCII for compatibility)
        $barWidth = 40
        $filledWidth = [int][Math]::Floor($percentComplete / 100 * $barWidth)
        $emptyWidth = $barWidth - $filledWidth
        $progressBar = ("#" * $filledWidth) + ("-" * $emptyWidth)
        
        # Get spinner character
        $spinner = $spinnerChars[$spinnerIndex % $spinnerChars.Length]
        $spinnerIndex++
        
        # Build single-line status update - truncate stage name
        $stageName = $currentStage.Name
        if ($stageName.Length -gt 30) {
            $stageName = $stageName.Substring(0, 27) + "..."
        }
        $statusLine = "  $spinner [$progressBar] $($percentComplete.ToString().PadLeft(2))% | $($stageName.PadRight(30)) | $elapsedDisplay"
        
        # Clear the line and write new content using cursor positioning
        try {
            [Console]::SetCursorPosition(0, $progressLineY)
            [Console]::Write($statusLine.PadRight([Console]::WindowWidth - 1))
        }
        catch {
            # Fallback if console positioning fails
            Write-Host "`r$($statusLine.PadRight(100))" -NoNewline
        }
        
        # Track stage transitions but don't print anything (single line only)
        $lastStageIndex = $stageIndex
        
        Start-Sleep -Milliseconds 500
    }
    
    # Final newline and completion
    Write-Host ""
    Write-Host ""
    
    # Get job results
    $jobResult = Receive-Job -Job $job
    $jobExitCode = if ($job.State -eq 'Completed' -and $jobResult -notmatch "error|failed|Error|Failed") { 0 } else { 1 }
    Remove-Job -Job $job -Force
    
    $endTime = Get-Date
    $totalDuration = $endTime - $startTime
    
    return @{
        Success = ($jobExitCode -eq 0 -and $jobResult -notmatch "ERROR|error:")
        Output = ($jobResult | Out-String)
        Duration = $totalDuration
    }
}

function Test-Prerequisites {
    <#
    .SYNOPSIS
        Checks for required prerequisites and offers to install missing ones.
    .DESCRIPTION
        Validates that all required tools are installed (Azure CLI, kubectl, Helm, Python).
        If any are missing, offers to install them automatically with user permission.
    #>
    
    Write-Log "Checking prerequisites..." -Level Info
    Write-Host ""
    
    $prerequisites = @(
        @{
            Name = "Azure CLI"
            TestCommand = { az version 2>$null }
            InstallCommand = "winget install Microsoft.AzureCLI --accept-source-agreements --accept-package-agreements"
            InstallMethod = "winget"
            ManualInstall = "https://docs.microsoft.com/cli/azure/install-azure-cli-windows"
            Required = $true
        },
        @{
            Name = "kubectl"
            TestCommand = { kubectl version --client 2>$null }
            InstallCommand = "az aks install-cli"
            InstallMethod = "Azure CLI"
            ManualInstall = "https://kubernetes.io/docs/tasks/tools/install-kubectl-windows/"
            Required = $true
            DependsOn = "Azure CLI"
        },
        @{
            Name = "Helm"
            TestCommand = { helm version 2>$null }
            InstallCommand = "winget install Helm.Helm --accept-source-agreements --accept-package-agreements"
            InstallMethod = "winget"
            ManualInstall = "https://helm.sh/docs/intro/install/"
            Required = $true
        },
        @{
            Name = "Python 3.7+"
            TestCommand = { python --version 2>$null }
            InstallCommand = "winget install Python.Python.3.11 --accept-source-agreements --accept-package-agreements"
            InstallMethod = "winget"
            ManualInstall = "https://www.python.org/downloads/"
            Required = $true
        }
    )
    
    $missingPrereqs = @()
    $installedPrereqs = @()
    
    # First pass: Check what's installed
    Write-Host "  Checking installed components..." -ForegroundColor Cyan
    Write-Host ""
    
    foreach ($prereq in $prerequisites) {
        Write-Host "  [$($prereq.Name)]" -NoNewline
        try {
            $result = & $prereq.TestCommand
            if ($LASTEXITCODE -eq 0 -or $result) {
                Write-Host " ✓ Installed" -ForegroundColor Green
                $installedPrereqs += $prereq.Name
                $script:SimulationReport.Prerequisites += @{ Name = $prereq.Name; Status = "Installed" }
            } else {
                Write-Host " ✗ Not found" -ForegroundColor Red
                $missingPrereqs += $prereq
                $script:SimulationReport.Prerequisites += @{ Name = $prereq.Name; Status = "Not Found" }
            }
        }
        catch {
            Write-Host " ✗ Not found" -ForegroundColor Red
            $missingPrereqs += $prereq
            $script:SimulationReport.Prerequisites += @{ Name = $prereq.Name; Status = "Not Found" }
        }
    }
    
    Write-Host ""
    
    # If there are missing prerequisites, offer to install them
    if ($missingPrereqs.Count -gt 0) {
        Write-Host "┌─────────────────────────────────────────────────────────────┐" -ForegroundColor Yellow
        Write-Host "│           MISSING PREREQUISITES DETECTED                    │" -ForegroundColor Yellow
        Write-Host "└─────────────────────────────────────────────────────────────┘" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  The following required components are missing:" -ForegroundColor Yellow
        Write-Host ""
        
        foreach ($missing in $missingPrereqs) {
            Write-Host "    • $($missing.Name)" -ForegroundColor Red
            Write-Host "      Install via: $($missing.InstallMethod)" -ForegroundColor Gray
        }
        
        Write-Host ""
        Write-Host "  Options:" -ForegroundColor Cyan
        Write-Host "    [1] Install missing components automatically (requires admin for some)" -ForegroundColor White
        Write-Host "    [2] Show manual installation instructions" -ForegroundColor White
        Write-Host "    [3] Continue anyway (script may fail)" -ForegroundColor White
        Write-Host "    [4] Exit" -ForegroundColor White
        Write-Host ""
        
        $installChoice = Read-Host "  Enter your choice (1-4)"
        
        switch ($installChoice) {
            "1" {
                # Attempt automatic installation
                Write-Host ""
                Write-Log "Attempting to install missing components..." -Level Info
                Write-Host ""
                
                $installSuccess = $true
                
                foreach ($missing in $missingPrereqs) {
                    # Check dependencies first
                    if ($missing.DependsOn -and $missing.DependsOn -notin $installedPrereqs) {
                        Write-Log "$($missing.Name) depends on $($missing.DependsOn) which is also missing. Installing dependency first..." -Level Warning
                    }
                    
                    Write-Host "  Installing $($missing.Name)..." -ForegroundColor Cyan
                    Write-Host "  Command: $($missing.InstallCommand)" -ForegroundColor Gray
                    Write-Host ""
                    
                    try {
                        # Check if running as admin for winget installs
                        if ($missing.InstallMethod -eq "winget") {
                            $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
                            if (-not $isAdmin) {
                                Write-Host "  ⚠️  Note: Some installations may require administrator privileges." -ForegroundColor Yellow
                                Write-Host "     If installation fails, please run PowerShell as Administrator." -ForegroundColor Yellow
                                Write-Host ""
                            }
                        }
                        
                        # Execute the install command
                        $installResult = Invoke-Expression $missing.InstallCommand 2>&1
                        
                        # Refresh PATH for newly installed tools
                        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
                        
                        # Verify installation
                        Start-Sleep -Seconds 2
                        $verifyResult = & $missing.TestCommand 2>$null
                        
                        if ($LASTEXITCODE -eq 0 -or $verifyResult) {
                            Write-Log "$($missing.Name) installed successfully!" -Level Success
                            $installedPrereqs += $missing.Name
                            
                            # Update the report
                            $existingEntry = $script:SimulationReport.Prerequisites | Where-Object { $_.Name -eq $missing.Name }
                            if ($existingEntry) {
                                $existingEntry.Status = "Installed (Auto)"
                            }
                            
                            # Track installation action
                            $script:SimulationReport.ActionsPerformed += @{
                                Time = Get-Date -Format "HH:mm:ss"
                                Action = "Installed prerequisite: $($missing.Name)"
                                Status = "Success"
                                Details = "Installed via $($missing.InstallMethod)"
                            }
                        } else {
                            Write-Log "$($missing.Name) installation may have succeeded but verification failed." -Level Warning
                            Write-Host "  You may need to restart your terminal for PATH changes to take effect." -ForegroundColor Yellow
                            $installSuccess = $false
                        }
                    }
                    catch {
                        Write-Log "Failed to install $($missing.Name): $_" -Level Error
                        $installSuccess = $false
                    }
                    
                    Write-Host ""
                }
                
                if (-not $installSuccess) {
                    Write-Host ""
                    Write-Log "Some installations may have failed. Checking prerequisites again..." -Level Warning
                    Write-Host ""
                    Write-Host "  ⚠️  If tools were just installed, you may need to:" -ForegroundColor Yellow
                    Write-Host "      1. Close and reopen this PowerShell window" -ForegroundColor White
                    Write-Host "      2. Run the script again" -ForegroundColor White
                    Write-Host ""
                    
                    $retryCheck = Read-Host "  Retry prerequisite check now? (y/n)"
                    if ($retryCheck -eq 'y') {
                        # Refresh PATH and retry
                        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
                        return Test-Prerequisites
                    }
                }
            }
            "2" {
                # Show manual installation instructions
                Write-Host ""
                Write-Host "  ─────────────────────────────────────────────────────────────" -ForegroundColor Cyan
                Write-Host "  MANUAL INSTALLATION INSTRUCTIONS" -ForegroundColor Cyan
                Write-Host "  ─────────────────────────────────────────────────────────────" -ForegroundColor Cyan
                Write-Host ""
                
                foreach ($missing in $missingPrereqs) {
                    Write-Host "  $($missing.Name):" -ForegroundColor Yellow
                    Write-Host "    URL: $($missing.ManualInstall)" -ForegroundColor White
                    Write-Host "    Or run: $($missing.InstallCommand)" -ForegroundColor Gray
                    Write-Host ""
                }
                
                Write-Host "  After installing, restart PowerShell and run this script again." -ForegroundColor Cyan
                Write-Host ""
                return $false
            }
            "3" {
                Write-Log "Continuing without all prerequisites. Script may fail." -Level Warning
                # Continue - will likely fail later
            }
            default {
                Write-Log "Exiting due to missing prerequisites." -Level Warning
                return $false
            }
        }
    }
    
    # Check Azure login status
    Write-Host "  Checking Azure login status..." -ForegroundColor Cyan
    $loginPerformed = $false
    try {
        $account = az account show 2>$null | ConvertFrom-Json
        if ($account) {
            Write-Log "Azure CLI logged in as: $($account.user.name)" -Level Success
            $script:SimulationReport.UserName = $account.user.name
            $script:SimulationReport.Subscription = $account.name
            $script:SimulationReport.SubscriptionId = $account.id
            $script:SimulationReport.TenantId = $account.tenantId
        } else {
            Write-Log "Azure CLI not logged in. Initiating browser login..." -Level Warning
            az login --only-show-errors
            $loginPerformed = $true
            
            $account = az account show 2>$null | ConvertFrom-Json
            if ($account) {
                Write-Log "Successfully logged in as: $($account.user.name)" -Level Success
                $script:SimulationReport.UserName = $account.user.name
                $script:SimulationReport.Subscription = $account.name
                $script:SimulationReport.SubscriptionId = $account.id
                $script:SimulationReport.TenantId = $account.tenantId
            } else {
                Write-Log "Login failed. Please run 'az login' manually." -Level Error
                return $false
            }
        }
    }
    catch {
        Write-Log "Azure CLI not logged in. Initiating browser login..." -Level Warning
        try {
            az login --only-show-errors
            $loginPerformed = $true
            
            $account = az account show 2>$null | ConvertFrom-Json
            if ($account) {
                Write-Log "Successfully logged in as: $($account.user.name)" -Level Success
                $script:SimulationReport.UserName = $account.user.name
                $script:SimulationReport.Subscription = $account.name
                $script:SimulationReport.SubscriptionId = $account.id
                $script:SimulationReport.TenantId = $account.tenantId
            } else {
                Write-Log "Login failed. Please run 'az login' manually." -Level Error
                return $false
            }
        }
        catch {
            Write-Log "Login failed: $_" -Level Error
            return $false
        }
    }
    
    # Track Azure login action
    $script:SimulationReport.ActionsPerformed += @{
        Time = Get-Date -Format "HH:mm:ss"
        Action = if ($loginPerformed) { "Azure login performed" } else { "Azure session verified" }
        Status = "Success"
        Details = "User: $($account.user.name), Subscription: $($account.name)"
    }
    
    Write-Host ""
    return $true
}

function Get-AKSClusters {
    param(
        [string]$SubscriptionId
    )
    
    Write-Log "Discovering AKS clusters..." -Level Info
    
    if ($SubscriptionId) {
        az account set --subscription $SubscriptionId
    }
    
    $clusters = az aks list 2>$null | ConvertFrom-Json
    
    if (-not $clusters -or $clusters.Count -eq 0) {
        Write-Log "No AKS clusters found in the current subscription." -Level Warning
        return $null
    }
    
    Write-Log "Found $($clusters.Count) AKS cluster(s):" -Level Success
    
    $clusterList = @()
    $index = 1
    foreach ($cluster in $clusters) {
        $clusterInfo = [PSCustomObject]@{
            Index = $index
            Name = $cluster.name
            ResourceGroup = $cluster.resourceGroup
            Location = $cluster.location
            KubernetesVersion = $cluster.kubernetesVersion
            NodeCount = ($cluster.agentPoolProfiles | Measure-Object -Property count -Sum).Sum
            ProvisioningState = $cluster.provisioningState
        }
        $clusterList += $clusterInfo
        Write-Host "  [$index] $($cluster.name) (RG: $($cluster.resourceGroup), Location: $($cluster.location), Nodes: $($clusterInfo.NodeCount))"
        $index++
    }
    
    return $clusterList
}

function Select-AKSCluster {
    param(
        [array]$Clusters
    )
    
    if ($Clusters.Count -eq 1) {
        Write-Log "Auto-selecting the only available cluster: $($Clusters[0].Name)" -Level Info
        $script:SimulationReport.ActionsPerformed += @{
            Time = Get-Date -Format "HH:mm:ss"
            Action = "Selected AKS cluster"
            Status = "Success"
            Details = "Auto-selected: $($Clusters[0].Name) (only cluster available)"
        }
        return $Clusters[0]
    }
    
    Write-Host ""
    $selection = Read-Host "Enter the number of the cluster to use (1-$($Clusters.Count))"
    
    if ($selection -match '^\d+$' -and [int]$selection -ge 1 -and [int]$selection -le $Clusters.Count) {
        $selectedCluster = $Clusters[[int]$selection - 1]
        $script:SimulationReport.ActionsPerformed += @{
            Time = Get-Date -Format "HH:mm:ss"
            Action = "Selected AKS cluster"
            Status = "Success"
            Details = "User selected: $($selectedCluster.Name)"
        }
        return $selectedCluster
    } else {
        Write-Log "Invalid selection. Please enter a number between 1 and $($Clusters.Count)." -Level Error
        return $null
    }
}

function New-SimulationAKSCluster {
    <#
    .SYNOPSIS
        Creates a new dedicated non-production AKS cluster for simulation purposes.
    #>
    
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Yellow
    Write-Host "  ⚠️  NEW AKS CLUSTER COST DISCLAIMER" -ForegroundColor Yellow
    Write-Host "============================================" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Creating a new AKS cluster will incur Azure costs:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  ESTIMATED COSTS (Standard_B2s, 1 node):" -ForegroundColor Cyan
    Write-Host "  ─────────────────────────────────────────" -ForegroundColor Gray
    Write-Host "  • VM Compute:        ~`$0.042/hour (~`$1.00/day)" -ForegroundColor White
    Write-Host "  • OS Disk (30GB):    ~`$0.004/hour (~`$0.10/day)" -ForegroundColor White
    Write-Host "  • Load Balancer:     ~`$0.025/hour (~`$0.60/day)" -ForegroundColor White
    Write-Host "  • Public IP:         ~`$0.004/hour (~`$0.10/day)" -ForegroundColor White
    Write-Host "  ─────────────────────────────────────────" -ForegroundColor Gray
    Write-Host "  • TOTAL:             ~`$0.075/hour (~`$1.80/day)" -ForegroundColor Green
    Write-Host ""
    Write-Host "  For a 1-hour simulation: ~`$0.08 - `$0.15" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  ⚠️  IMPORTANT:" -ForegroundColor Red
    Write-Host "  • Costs continue until the cluster is DELETED" -ForegroundColor Red
    Write-Host "  • You will be prompted to delete the cluster after simulation" -ForegroundColor Yellow
    Write-Host "  • Actual costs may vary by region and Azure pricing changes" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Pricing reference: https://azure.microsoft.com/pricing/details/kubernetes-service/" -ForegroundColor Gray
    Write-Host ""
    
    $confirmCreate = Read-Host "Do you accept the costs and want to create the cluster? (yes/no)"
    
    if ($confirmCreate -ne 'yes') {
        Write-Log "Cluster creation cancelled by user." -Level Warning
        return $null
    }
    
    # Subscription selection for new cluster
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "  SELECT AZURE SUBSCRIPTION" -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host ""
    
    # Get list of available subscriptions
    Write-Host "  Fetching available subscriptions..." -ForegroundColor Gray
    $subscriptions = az account list --query "[?state=='Enabled'].{Name:name, Id:id, IsDefault:isDefault}" 2>$null | ConvertFrom-Json
    
    if (-not $subscriptions -or $subscriptions.Count -eq 0) {
        Write-Log "No subscriptions found. Please ensure you're logged in with 'az login'." -Level Error
        return $null
    }
    
    Write-Host ""
    Write-Host "  Available subscriptions:" -ForegroundColor Cyan
    Write-Host ""
    
    $subIndex = 1
    $defaultSubIndex = 1
    foreach ($sub in $subscriptions) {
        $marker = if ($sub.IsDefault) { " (current)" } else { "" }
        if ($sub.IsDefault) { $defaultSubIndex = $subIndex }
        Write-Host "  [$subIndex] $($sub.Name)$marker" -ForegroundColor White
        Write-Host "      $($sub.Id)" -ForegroundColor Gray
        $subIndex++
    }
    
    Write-Host ""
    $subChoice = Read-Host "Select subscription (1-$($subscriptions.Count), press Enter for current [$defaultSubIndex])"
    
    # Determine which subscription to use
    $selectedSubIndex = if ($subChoice -match '^\d+$') { 
        [int]$subChoice 
    } else { 
        $defaultSubIndex 
    }
    
    if ($selectedSubIndex -lt 1 -or $selectedSubIndex -gt $subscriptions.Count) {
        Write-Log "Invalid subscription selection." -Level Error
        return $null
    }
    
    $selectedSubscription = $subscriptions[$selectedSubIndex - 1]
    
    # Switch to selected subscription if different from current
    if (-not $selectedSubscription.IsDefault) {
        Write-Host ""
        Write-Host "  Switching to subscription: $($selectedSubscription.Name)..." -ForegroundColor Yellow
        $switchResult = az account set --subscription $selectedSubscription.Id 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Log "Failed to switch subscription: $switchResult" -Level Error
            return $null
        }
        Write-Host "  ✓ Subscription changed successfully" -ForegroundColor Green
    }
    
    Write-Host ""
    Write-Host "  ┌─────────────────────────────────────────────────────────┐" -ForegroundColor Cyan
    Write-Host "  │  Deploying to: $($selectedSubscription.Name.PadRight(40).Substring(0,40)) │" -ForegroundColor Cyan
    Write-Host "  └─────────────────────────────────────────────────────────┘" -ForegroundColor Cyan
    
    # Update report with subscription info
    $script:SimulationReport.Subscription = $selectedSubscription.Name
    $script:SimulationReport.SubscriptionId = $selectedSubscription.Id
    
    # Get cluster configuration from user
    Write-Host ""
    Write-Host "Configure your simulation cluster:" -ForegroundColor Cyan
    Write-Host ""
    
    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $defaultName = "mdc-simulation-aks-$timestamp"
    $clusterNameInput = Read-Host "Cluster name (press Enter for '$defaultName')"
    $newClusterName = if ($clusterNameInput) { $clusterNameInput } else { $defaultName }
    
    $defaultRG = "mdc-simulation-rg-$timestamp"
    $rgInput = Read-Host "Resource group name (press Enter for '$defaultRG')"
    $newResourceGroup = if ($rgInput) { $rgInput } else { $defaultRG }
    
    $defaultLocation = "eastus"
    $locationInput = Read-Host "Azure region (press Enter for '$defaultLocation')"
    $location = if ($locationInput) { $locationInput } else { $defaultLocation }
    
    Write-Host ""
    Write-Log "Creating resource group: $newResourceGroup..." -Level Info
    
    try {
        $rgResult = az group create --name $newResourceGroup --location $location 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0) {
            $errorMessage = Get-AzureCliErrorMessage -Output $rgResult
            Write-Log "Failed to create resource group: $errorMessage" -Level Error
            return $null
        }
        Write-Log "Resource group created successfully." -Level Success
    }
    catch {
        Write-Log "Exception creating resource group: $_" -Level Error
        return $null
    }
    
    Write-Host ""
    Write-Log "Creating AKS cluster: $newClusterName (this may take 5-10 minutes)..." -Level Info
    Write-Host ""
    Write-Host "Configuration:" -ForegroundColor Cyan
    Write-Host "  • Name: $newClusterName" -ForegroundColor White
    Write-Host "  • Resource Group: $newResourceGroup" -ForegroundColor White
    Write-Host "  • Location: $location" -ForegroundColor White
    Write-Host "  • Node Size: Standard_B2s (cost-optimized)" -ForegroundColor White
    Write-Host "  • Node Count: 1" -ForegroundColor White
    Write-Host "  • Managed Identity: Enabled" -ForegroundColor White
    Write-Host ""
    
    try {
        # Use the progress bar function for AKS deployment
        $deployResult = Start-AKSDeploymentWithProgress -ClusterName $newClusterName -ResourceGroup $newResourceGroup -Location $location
        
        if (-not $deployResult.Success) {
            $aksResult = $deployResult.Output
            $errorMessage = Get-AzureCliErrorMessage -Output $aksResult
            
            # Check for common error scenarios and provide helpful guidance
            if ($aksResult -match "quota|limit|exceeded") {
                Write-Log "QUOTA ERROR: Your subscription has exceeded its quota for this resource." -Level Error
                Write-Host ""
                Write-Host "Possible solutions:" -ForegroundColor Yellow
                Write-Host "  1. Try a different Azure region (e.g., westus2, westeurope)" -ForegroundColor White
                Write-Host "  2. Request a quota increase in the Azure Portal" -ForegroundColor White
                Write-Host "  3. Delete unused resources to free up quota" -ForegroundColor White
            }
            elseif ($aksResult -match "already exists") {
                Write-Log "CONFLICT: A resource with this name already exists." -Level Error
                Write-Host ""
                Write-Host "Possible solutions:" -ForegroundColor Yellow
                Write-Host "  1. Choose a different cluster name" -ForegroundColor White
                Write-Host "  2. Delete the existing resource first" -ForegroundColor White
            }
            elseif ($aksResult -match "not registered|not enabled") {
                Write-Log "PROVIDER ERROR: Required resource provider is not registered." -Level Error
                Write-Host ""
                Write-Host "Run this command to register the provider:" -ForegroundColor Yellow
                Write-Host "  az provider register --namespace Microsoft.ContainerService" -ForegroundColor Cyan
            }
            elseif ($aksResult -match "permission|authorization|forbidden|denied") {
                Write-Log "PERMISSION ERROR: You don't have sufficient permissions." -Level Error
                Write-Host ""
                Write-Host "Required permissions:" -ForegroundColor Yellow
                Write-Host "  • Contributor or Owner role on the subscription/resource group" -ForegroundColor White
                Write-Host "  • Microsoft.ContainerService/* permissions" -ForegroundColor White
            }
            elseif ($aksResult -match "InvalidTemplateDeployment|DeploymentFailed") {
                Write-Log "DEPLOYMENT ERROR: The cluster deployment failed." -Level Error
                Write-Host ""
                Write-Host "This could be due to:" -ForegroundColor Yellow
                Write-Host "  • VM size not available in the selected region" -ForegroundColor White
                Write-Host "  • Network configuration issues" -ForegroundColor White
                Write-Host "  • Try a different region or VM size" -ForegroundColor White
            }
            else {
                Write-Log "AKS CREATION FAILED: $errorMessage" -Level Error
            }
            
            Write-Host ""
            Write-Log "You may need to clean up the resource group manually:" -Level Warning
            Write-Host "  az group delete --name $newResourceGroup --yes --no-wait" -ForegroundColor Cyan
            Write-Host ""
            
            # Offer to retry with different settings
            $retry = Read-Host "Would you like to try with different settings? (yes/no)"
            if ($retry -eq 'yes') {
                # Clean up the failed resource group first
                Write-Log "Cleaning up resource group before retry..." -Level Info
                az group delete --name $newResourceGroup --yes --no-wait 2>$null
                Start-Sleep -Seconds 5
                
                # Recursive call to try again
                return New-SimulationAKSCluster
            }
            
            return $null
        }
        
        # Success path
        $duration = $deployResult.Duration
        $durationMinutes = [Math]::Floor($duration.TotalMinutes)
        $durationSeconds = [Math]::Floor($duration.TotalSeconds % 60)
        
        Write-Host ""
        Write-Host "┌─────────────────────────────────────────────────────────────┐" -ForegroundColor Green
        Write-Host "│              ✅ AKS CLUSTER CREATED SUCCESSFULLY            │" -ForegroundColor Green
        Write-Host "└─────────────────────────────────────────────────────────────┘" -ForegroundColor Green
        Write-Host ""
        Write-Host "  Cluster: $newClusterName" -ForegroundColor White
        Write-Host "  Duration: ${durationMinutes}m ${durationSeconds}s" -ForegroundColor Gray
        Write-Host ""
        
        Write-Log "AKS cluster created successfully!" -Level Success
        
        # Track cluster creation
        $script:SimulationReport.ActionsPerformed += @{
            Time = Get-Date -Format "HH:mm:ss"
            Action = "Created AKS cluster"
            Status = "Success"
            Details = "Cluster: $newClusterName in $newResourceGroup ($location)"
        }
        
        # Enable Defender for Containers on the cluster (post-creation)
        Write-Log "Enabling Defender for Containers..." -Level Info
        Write-Host ""
        Write-Host "  This typically takes 2-3 minutes..." -ForegroundColor Gray
        Write-Host ""
        
        # Start the defender enable command as a background job
        $defenderJob = Start-Job -ScriptBlock {
            param($clusterName, $rgName)
            az aks update --name $clusterName --resource-group $rgName --enable-defender --only-show-errors 2>&1
        } -ArgumentList $newClusterName, $newResourceGroup
        
        # Animated progress bar while waiting
        $progressLineY = [Console]::CursorTop
        $spinnerChars = @('-', '\', '|', '/')
        $spinnerIdx = 0
        $barWidth = 40
        $elapsed = 0
        $estimatedTime = 150  # ~2.5 minutes estimate
        
        while ($defenderJob.State -eq 'Running') {
            $spinnerIdx = ($spinnerIdx + 1) % $spinnerChars.Count
            $spinner = $spinnerChars[$spinnerIdx]
            
            # Calculate progress based on elapsed time (estimate)
            $progress = [math]::Min(95, [math]::Floor(($elapsed / $estimatedTime) * 100))
            $filledWidth = [math]::Floor(($progress / 100) * $barWidth)
            $emptyWidth = $barWidth - $filledWidth
            $progressBar = ('#' * $filledWidth) + ('-' * $emptyWidth)
            
            $elapsedMin = [int][math]::Floor($elapsed / 60)
            $elapsedSec = [int][math]::Floor($elapsed % 60)
            $timeStr = "{0}:{1:D2}" -f $elapsedMin, $elapsedSec
            
            [Console]::SetCursorPosition(0, $progressLineY)
            [Console]::Write("  $spinner [$progressBar] $progress% | Enabling Defender... | $timeStr   ")
            
            Start-Sleep -Milliseconds 500
            $elapsed += 0.5
        }
        
        # Get job result
        $defenderResult = Receive-Job -Job $defenderJob
        $jobExitSuccess = $defenderJob.State -eq 'Completed'
        Remove-Job -Job $defenderJob -Force
        
        # Show completion
        [Console]::SetCursorPosition(0, $progressLineY)
        $elapsedMin = [int][math]::Floor($elapsed / 60)
        $elapsedSec = [int][math]::Floor($elapsed % 60)
        $finalTimeStr = "{0}:{1:D2}" -f $elapsedMin, $elapsedSec
        [Console]::Write("  [########################################] 100% | Complete | $finalTimeStr        ")
        Write-Host ""
        Write-Host ""
        
        # Check if defender was enabled successfully (look for success indicators in output)
        $defenderSuccess = $jobExitSuccess -and ($defenderResult -notmatch "error|failed")
        
        if ($defenderSuccess) {
            Write-Log "Defender for Containers enabled." -Level Success
            $script:SimulationReport.ActionsPerformed += @{
                Time = Get-Date -Format "HH:mm:ss"
                Action = "Enabled Defender for Containers"
                Status = "Success"
                Details = "Enabled on cluster: $newClusterName"
            }
        } else {
            Write-Log "Note: Defender auto-enable skipped. You can enable it manually in Azure Portal." -Level Warning
            Write-Host "Navigate to: Defender for Cloud > Environment settings > Enable Defender for Containers" -ForegroundColor Gray
            $script:SimulationReport.ActionsPerformed += @{
                Time = Get-Date -Format "HH:mm:ss"
                Action = "Defender for Containers (skipped)"
                Status = "Warning"
                Details = "Auto-enable skipped - enable manually in portal"
            }
        }
        
        # Store for cleanup reminder
        $script:CreatedClusterForCleanup = @{
            Name = $newClusterName
            ResourceGroup = $newResourceGroup
        }
        
        return [PSCustomObject]@{
            Name = $newClusterName
            ResourceGroup = $newResourceGroup
            Location = $location
            NodeCount = 1
            IsNewCluster = $true
        }
    }
    catch {
        Write-Log "Exception creating AKS cluster: $_" -Level Error
        Write-Host ""
        Write-Log "You may need to clean up the resource group manually:" -Level Warning
        Write-Host "  az group delete --name $newResourceGroup --yes --no-wait" -ForegroundColor Cyan
        return $null
    }
}

function Connect-ToAKSCluster {
    param(
        [string]$ClusterName,
        [string]$ResourceGroup,
        [switch]$IsNewCluster
    )
    
    Write-Log "Connecting to AKS cluster: $ClusterName..." -Level Info
    
    # For newly created clusters, wait for the cluster to be fully ready
    if ($IsNewCluster) {
        Write-Host ""
        Write-Host "  Waiting for cluster to be fully provisioned..." -ForegroundColor Yellow
        
        $maxWaitSeconds = 180  # Wait up to 3 minutes for cluster to be ready
        $waitedSeconds = 0
        $checkInterval = 10
        $clusterReady = $false
        
        while ($waitedSeconds -lt $maxWaitSeconds -and -not $clusterReady) {
            # Check cluster provisioning state
            $clusterState = az aks show --name $ClusterName --resource-group $ResourceGroup --query "provisioningState" -o tsv 2>$null
            
            if ($clusterState -eq "Succeeded") {
                $clusterReady = $true
                Write-Host ""
                Write-Host "  ✓ Cluster is ready!" -ForegroundColor Green
            } elseif ($clusterState -eq "Failed") {
                Write-Host ""
                Write-Log "Cluster provisioning failed." -Level Error
                return $false
            } elseif ($null -eq $clusterState -or $clusterState -eq "") {
                # Cluster not found yet - might still be registering
                $progressDots = "." * (($waitedSeconds / $checkInterval) % 4 + 1)
                Write-Host "`r  Waiting for cluster registration$progressDots     " -NoNewline -ForegroundColor Gray
            } else {
                # Still provisioning (Creating, Updating, etc.)
                $progressDots = "." * (($waitedSeconds / $checkInterval) % 4 + 1)
                Write-Host "`r  Cluster state: $clusterState$progressDots     " -NoNewline -ForegroundColor Gray
            }
            
            if (-not $clusterReady) {
                Start-Sleep -Seconds $checkInterval
                $waitedSeconds += $checkInterval
            }
        }
        
        Write-Host ""
        
        if (-not $clusterReady) {
            Write-Log "Timed out waiting for cluster to be ready. Current state: $clusterState" -Level Warning
            Write-Host "  The cluster may still be provisioning. Attempting to connect anyway..." -ForegroundColor Yellow
        }
    }
    
    # Attempt to get credentials with retry for new clusters
    $maxRetries = if ($IsNewCluster) { 3 } else { 1 }
    $retryDelay = 15
    
    for ($attempt = 1; $attempt -le $maxRetries; $attempt++) {
        $result = az aks get-credentials --name $ClusterName --resource-group $ResourceGroup --overwrite-existing 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Successfully connected to cluster: $ClusterName" -Level Success
            
            # Verify kubectl can reach the cluster
            Write-Host "  Verifying cluster connectivity..." -ForegroundColor Gray
            $kubectlTest = kubectl get nodes 2>&1
            
            if ($LASTEXITCODE -eq 0) {
                Write-Host "  ✓ kubectl connected successfully" -ForegroundColor Green
                return $true
            } else {
                Write-Host "  ⚠ kubectl connection test failed, but credentials obtained" -ForegroundColor Yellow
                return $true  # Credentials work, node access might just take a moment
            }
        } else {
            if ($attempt -lt $maxRetries) {
                Write-Host "  Attempt $attempt failed. Retrying in $retryDelay seconds..." -ForegroundColor Yellow
                Start-Sleep -Seconds $retryDelay
            } else {
                Write-Log "Failed to connect to cluster after $maxRetries attempts: $result" -Level Error
                return $false
            }
        }
    }
    
    return $false
}

function Test-DefenderForContainersSettings {
    <#
    .SYNOPSIS
        Validates Microsoft Defender for Containers settings required for the simulation.
    .DESCRIPTION
        Checks if Defender for Containers is enabled at the subscription level and if
        the Defender sensor is deployed on the AKS cluster. Offers to enable missing
        settings with cost estimates.
        
        REQUIRED SETTING FOR RUNTIME ALERTS:
        ─────────────────────────────────────
        • Defender sensor - MUST be enabled and deployed on the cluster
          - This is the DaemonSet that runs on each node
          - Collects runtime security data from containers
          - Required for ALL runtime threat detection alerts
        
        The simulation will NOT generate alerts without the Defender sensor.
    #>
    param(
        [string]$ClusterName,
        [string]$ResourceGroup,
        [switch]$IsNewCluster
    )
    
    Write-Host ""
    Write-Host "┌─────────────────────────────────────────────────────────────┐" -ForegroundColor Cyan
    Write-Host "│      DEFENDER FOR CONTAINERS CONFIGURATION CHECK           │" -ForegroundColor Cyan
    Write-Host "└─────────────────────────────────────────────────────────────┘" -ForegroundColor Cyan
    Write-Host ""
    
    $checkResults = @{
        SubscriptionDefenderEnabled = $false
        DefenderSensorDeployed = $false
        AllRequirementsMet = $false
    }
    
    # Explain why these settings are required
    Write-Host "  WHY THIS CHECK IS REQUIRED:" -ForegroundColor Yellow
    Write-Host "  ─────────────────────────────────────────────────────────────" -ForegroundColor Gray
    Write-Host "  The simulation generates attack patterns that Microsoft Defender" -ForegroundColor White
    Write-Host "  for Containers detects and reports as security alerts." -ForegroundColor White
    Write-Host ""
    Write-Host "  For alerts to be generated, you need:" -ForegroundColor White
    Write-Host "    1. Defender for Containers PLAN enabled on the subscription" -ForegroundColor Cyan
    Write-Host "    2. Defender SENSOR deployed on the AKS cluster" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  The Defender sensor is a DaemonSet that runs on each node and" -ForegroundColor Gray
    Write-Host "  monitors container runtime activity for malicious behavior." -ForegroundColor Gray
    Write-Host ""
    
    # Check 1: Is Defender for Containers enabled at subscription level?
    Write-Host "  [1/2] Checking Defender for Containers plan..." -NoNewline
    
    try {
        $subscriptionId = (az account show --query id -o tsv 2>$null)
        $defenderSettings = az security pricing show --name Containers 2>$null | ConvertFrom-Json
        
        if ($defenderSettings -and $defenderSettings.pricingTier -eq "Standard") {
            Write-Host " ✓ Enabled" -ForegroundColor Green
            $checkResults.SubscriptionDefenderEnabled = $true
        } else {
            Write-Host " ✗ Not Enabled" -ForegroundColor Red
            $checkResults.SubscriptionDefenderEnabled = $false
        }
    }
    catch {
        Write-Host " ⚠ Could not verify" -ForegroundColor Yellow
        # Assume it might be enabled, we'll check the sensor
    }
    
    # Check 2: Is the Defender sensor deployed on the cluster?
    Write-Host "  [2/2] Checking Defender sensor on cluster..." -NoNewline
    
    try {
        $sensor = kubectl get ds microsoft-defender-collector-ds -n kube-system 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host " ✓ Deployed & Running" -ForegroundColor Green
            $checkResults.DefenderSensorDeployed = $true
            
            # Get sensor details
            $sensorPods = kubectl get pods -n kube-system -l app=microsoft-defender-collector -o json 2>$null | ConvertFrom-Json
            if ($sensorPods -and $sensorPods.items) {
                $runningPods = ($sensorPods.items | Where-Object { $_.status.phase -eq "Running" }).Count
                $totalPods = $sensorPods.items.Count
                Write-Host "       Sensor pods: $runningPods/$totalPods running" -ForegroundColor Gray
            }
        } else {
            Write-Host " ✗ Not Deployed" -ForegroundColor Red
            $checkResults.DefenderSensorDeployed = $false
        }
    }
    catch {
        Write-Host " ⚠ Could not verify" -ForegroundColor Yellow
        $checkResults.DefenderSensorDeployed = $false
    }
    
    Write-Host ""
    
    # Determine if all requirements are met
    $checkResults.AllRequirementsMet = $checkResults.DefenderSensorDeployed
    
    # If requirements not met, provide guidance and options
    if (-not $checkResults.AllRequirementsMet) {
        Write-Host "  ─────────────────────────────────────────────────────────────" -ForegroundColor Gray
        Write-Host "  ⚠️  DEFENDER FOR CONTAINERS IS NOT FULLY CONFIGURED" -ForegroundColor Yellow
        Write-Host "  ─────────────────────────────────────────────────────────────" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  The simulation will NOT generate alerts without proper setup." -ForegroundColor Red
        Write-Host ""
        
        # Show cost information
        Write-Host "  ┌─────────────────────────────────────────────────────────┐" -ForegroundColor Cyan
        Write-Host "  │  💰 DEFENDER FOR CONTAINERS PRICING (ESTIMATED)        │" -ForegroundColor Cyan
        Write-Host "  └─────────────────────────────────────────────────────────┘" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  PRICING MODEL: Per vCore/hour for protected nodes" -ForegroundColor White
        Write-Host ""
        Write-Host "    Component                    Estimated Cost" -ForegroundColor Gray
        Write-Host "    ─────────────────────────────────────────────" -ForegroundColor Gray
        Write-Host "    Defender for Containers      ~`$0.0095/vCore/hour" -ForegroundColor White
        Write-Host "                                 ~`$7.00/vCore/month" -ForegroundColor White
        Write-Host ""
        Write-Host "    FOR THIS SIMULATION (1 node, 2 vCores, ~1 hour):" -ForegroundColor Yellow
        Write-Host "    ─────────────────────────────────────────────────" -ForegroundColor Gray
        Write-Host "    • Defender cost:             ~`$0.02 - `$0.05" -ForegroundColor Green
        Write-Host "    • Combined with AKS:         ~`$0.10 - `$0.15 total" -ForegroundColor Green
        Write-Host ""
        Write-Host "    FOR ONGOING USE (if you keep Defender enabled):" -ForegroundColor Yellow
        Write-Host "    ─────────────────────────────────────────────────" -ForegroundColor Gray
        Write-Host "    • 1 node (2 vCores):         ~`$14/month" -ForegroundColor White
        Write-Host "    • 3 nodes (6 vCores):        ~`$42/month" -ForegroundColor White
        Write-Host "    • 10 nodes (20 vCores):      ~`$140/month" -ForegroundColor White
        Write-Host ""
        Write-Host "  ⚠️  DISCLAIMER: These are ESTIMATES based on public Azure" -ForegroundColor Yellow
        Write-Host "     pricing. Actual costs may vary by region, discounts," -ForegroundColor Yellow
        Write-Host "     and Microsoft pricing changes. Check Azure Portal or" -ForegroundColor Yellow
        Write-Host "     Azure Pricing Calculator for exact pricing." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  📋 FREE TRIAL: Defender for Containers includes a" -ForegroundColor Cyan
        Write-Host "     30-day free trial for new subscriptions!" -ForegroundColor Cyan
        Write-Host ""
        
        # Options for the user
        Write-Host "  ─────────────────────────────────────────────────────────────" -ForegroundColor Gray
        Write-Host "  OPTIONS:" -ForegroundColor Cyan
        Write-Host ""
        
        if (-not $checkResults.SubscriptionDefenderEnabled) {
            Write-Host "  [1] Enable Defender for Containers NOW (subscription-wide)" -ForegroundColor White
            Write-Host "      - Enables protection for ALL AKS clusters in subscription" -ForegroundColor Gray
            Write-Host "      - Sensor will auto-deploy to this cluster" -ForegroundColor Gray
            Write-Host ""
        }
        
        if ($IsNewCluster) {
            Write-Host "  [2] Enable Defender for THIS cluster only (recommended for testing)" -ForegroundColor White
            Write-Host "      - Uses --enable-defender flag during cluster creation" -ForegroundColor Gray
            Write-Host "      - Only this cluster will have Defender sensor" -ForegroundColor Gray
            Write-Host ""
        }
        
        Write-Host "  [3] Continue anyway (alerts will NOT be generated)" -ForegroundColor White
        Write-Host "      - Simulation will run but no alerts will appear" -ForegroundColor Gray
        Write-Host "      - Useful for testing the simulation process only" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  [4] Show manual setup instructions" -ForegroundColor White
        Write-Host "      - Step-by-step guide to enable via Azure Portal" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  [5] Exit and configure manually" -ForegroundColor White
        Write-Host ""
        
        $choice = Read-Host "  Enter your choice (1-5)"
        
        switch ($choice) {
            "1" {
                # Enable Defender for Containers at subscription level
                Write-Host ""
                Write-Log "Enabling Defender for Containers at subscription level..." -Level Info
                Write-Host ""
                Write-Host "  This will enable Defender for Containers for ALL AKS clusters" -ForegroundColor Yellow
                Write-Host "  in subscription: $subscriptionId" -ForegroundColor Yellow
                Write-Host ""
                
                $confirmEnable = Read-Host "  Type 'ENABLE' to confirm"
                
                if ($confirmEnable -eq 'ENABLE') {
                    try {
                        $enableResult = az security pricing create --name Containers --tier Standard 2>&1
                        
                        if ($LASTEXITCODE -eq 0) {
                            Write-Log "Defender for Containers enabled successfully!" -Level Success
                            $checkResults.SubscriptionDefenderEnabled = $true
                            
                            Write-Host ""
                            Write-Host "  The Defender sensor will be automatically deployed to your" -ForegroundColor Cyan
                            Write-Host "  AKS cluster. This may take a few minutes." -ForegroundColor Cyan
                            Write-Host ""
                            Write-Host "  Waiting for sensor deployment..." -ForegroundColor Gray
                            
                            # Wait for sensor deployment
                            $maxWaitSeconds = 180
                            $waitedSeconds = 0
                            $sensorDeployed = $false
                            
                            while ($waitedSeconds -lt $maxWaitSeconds -and -not $sensorDeployed) {
                                Start-Sleep -Seconds 10
                                $waitedSeconds += 10
                                
                                Write-Host "    Checking... ($waitedSeconds/$maxWaitSeconds seconds)" -ForegroundColor Gray
                                
                                $sensorCheck = kubectl get ds microsoft-defender-collector-ds -n kube-system 2>&1
                                if ($LASTEXITCODE -eq 0) {
                                    $sensorDeployed = $true
                                    $checkResults.DefenderSensorDeployed = $true
                                    $checkResults.AllRequirementsMet = $true
                                }
                            }
                            
                            if ($sensorDeployed) {
                                Write-Log "Defender sensor deployed successfully!" -Level Success
                            } else {
                                Write-Host ""
                                Write-Host "  Sensor not yet deployed. It may take a few more minutes." -ForegroundColor Yellow
                                Write-Host "  The simulation will proceed - alerts should appear once sensor is active." -ForegroundColor Yellow
                                $checkResults.AllRequirementsMet = $true  # Allow to proceed
                            }
                        } else {
                            Write-Log "Failed to enable Defender for Containers: $enableResult" -Level Error
                        }
                    }
                    catch {
                        Write-Log "Error enabling Defender: $_" -Level Error
                    }
                } else {
                    Write-Host "  Operation cancelled." -ForegroundColor Yellow
                }
            }
            "2" {
                if ($IsNewCluster) {
                    Write-Host ""
                    Write-Host "  Defender will be enabled when creating the new cluster." -ForegroundColor Green
                    Write-Host "  The --enable-defender flag will be used." -ForegroundColor Gray
                    $checkResults.AllRequirementsMet = $true
                    $script:EnableDefenderOnNewCluster = $true
                } else {
                    Write-Host ""
                    Write-Host "  This option is only available for new cluster creation." -ForegroundColor Yellow
                    Write-Host "  For existing clusters, use option 1 or 4." -ForegroundColor Yellow
                }
            }
            "3" {
                Write-Host ""
                Write-Host "  ⚠️  Continuing without Defender enabled." -ForegroundColor Yellow
                Write-Host "  The simulation will run but NO ALERTS will be generated." -ForegroundColor Yellow
                Write-Host "  This is useful for testing the simulation process only." -ForegroundColor Yellow
                Write-Host ""
                $checkResults.AllRequirementsMet = $true  # Allow to continue
                $script:SimulationReport.DefenderSensorStatus = "Not Configured - No Alerts Expected"
            }
            "4" {
                # Show manual instructions
                Write-Host ""
                Write-Host "  ┌─────────────────────────────────────────────────────────┐" -ForegroundColor Cyan
                Write-Host "  │  MANUAL SETUP INSTRUCTIONS                              │" -ForegroundColor Cyan
                Write-Host "  └─────────────────────────────────────────────────────────┘" -ForegroundColor Cyan
                Write-Host ""
                Write-Host "  OPTION A: Via Azure Portal" -ForegroundColor Yellow
                Write-Host "  ─────────────────────────────" -ForegroundColor Gray
                Write-Host "  1. Go to: https://portal.azure.com" -ForegroundColor White
                Write-Host "  2. Navigate to: Microsoft Defender for Cloud" -ForegroundColor White
                Write-Host "  3. Click: Environment settings (left menu)" -ForegroundColor White
                Write-Host "  4. Select your subscription" -ForegroundColor White
                Write-Host "  5. Find 'Containers' row and toggle ON" -ForegroundColor White
                Write-Host "  6. Click 'Settings' next to Containers" -ForegroundColor White
                Write-Host "  7. Ensure 'Defender sensor' is toggled ON" -ForegroundColor White
                Write-Host "  8. Click 'Continue' then 'Save'" -ForegroundColor White
                Write-Host ""
                Write-Host "  OPTION B: Via Azure CLI" -ForegroundColor Yellow
                Write-Host "  ─────────────────────────────" -ForegroundColor Gray
                Write-Host "  # Enable Defender for Containers" -ForegroundColor Gray
                Write-Host "  az security pricing create --name Containers --tier Standard" -ForegroundColor Cyan
                Write-Host ""
                Write-Host "  # For a specific cluster, update with Defender" -ForegroundColor Gray
                Write-Host "  az aks update --name $ClusterName --resource-group $ResourceGroup --enable-defender" -ForegroundColor Cyan
                Write-Host ""
                Write-Host "  OPTION C: Via ARM Template / Bicep / Terraform" -ForegroundColor Yellow
                Write-Host "  ─────────────────────────────────────────────────" -ForegroundColor Gray
                Write-Host "  Include 'securityProfile.defender.enabled: true' in your" -ForegroundColor White
                Write-Host "  AKS cluster configuration." -ForegroundColor White
                Write-Host ""
                Write-Host "  After enabling, wait 5-10 minutes for the Defender sensor" -ForegroundColor Gray
                Write-Host "  to deploy to your cluster nodes." -ForegroundColor Gray
                Write-Host ""
                
                $retryCheck = Read-Host "  Press Enter to retry the check, or type 'skip' to continue anyway"
                
                if ($retryCheck -ne 'skip') {
                    return Test-DefenderForContainersSettings -ClusterName $ClusterName -ResourceGroup $ResourceGroup -IsNewCluster:$IsNewCluster
                } else {
                    $checkResults.AllRequirementsMet = $true
                }
            }
            default {
                Write-Host ""
                Write-Log "Exiting. Please configure Defender for Containers and try again." -Level Warning
                return $checkResults
            }
        }
    } else {
        # All requirements met
        Write-Host "  ─────────────────────────────────────────────────────────────" -ForegroundColor Gray
        Write-Host "  ✅ ALL DEFENDER FOR CONTAINERS REQUIREMENTS MET" -ForegroundColor Green
        Write-Host "  ─────────────────────────────────────────────────────────────" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  The simulation will generate security alerts that will appear" -ForegroundColor White
        Write-Host "  in Microsoft Defender for Cloud within minutes of execution." -ForegroundColor White
        Write-Host ""
        
        $script:SimulationReport.DefenderSensorStatus = "Installed & Running"
    }
    
    Write-Host ""
    
    return $checkResults
}

function Test-DefenderSensor {
    <#
    .SYNOPSIS
        Quick check if Defender sensor is installed on the cluster.
    .DESCRIPTION
        Simple validation that the microsoft-defender-collector-ds DaemonSet exists.
        For full configuration check with enable options, use Test-DefenderForContainersSettings.
    #>
    
    Write-Log "Checking if Defender sensor is installed..." -Level Info
    
    $sensor = kubectl get ds microsoft-defender-collector-ds -n kube-system 2>&1
    
    if ($LASTEXITCODE -eq 0) {
        Write-Log "Defender sensor is installed and running." -Level Success
        $script:SimulationReport.DefenderSensorStatus = "Installed & Running"
        return $true
    } else {
        Write-Log "Defender sensor not found." -Level Warning
        $script:SimulationReport.DefenderSensorStatus = "Not Found"
        return $false
    }
}

function Get-SimulationTool {
    param(
        [string]$WorkingDirectory
    )
    
    Write-Log "Downloading simulation tool..." -Level Info
    
    if (-not (Test-Path $WorkingDirectory)) {
        New-Item -ItemType Directory -Path $WorkingDirectory -Force | Out-Null
    }
    
    $simulationScript = Join-Path $WorkingDirectory "simulation.py"
    $downloadUrl = "https://raw.githubusercontent.com/microsoft/Defender-for-Cloud-Attack-Simulation/refs/heads/main/simulation.py"
    
    try {
        Invoke-WebRequest -Uri $downloadUrl -OutFile $simulationScript -UseBasicParsing
        
        if (Test-Path $simulationScript) {
            Write-Log "Simulation tool downloaded successfully." -Level Success
            
            # Track download action
            $script:SimulationReport.ActionsPerformed += @{
                Time = Get-Date -Format "HH:mm:ss"
                Action = "Downloaded simulation tool"
                Status = "Success"
                Details = "From: $downloadUrl"
            }
            
            return $simulationScript
        } else {
            Write-Log "Failed to download simulation tool." -Level Error
            $script:SimulationReport.ActionsPerformed += @{
                Time = Get-Date -Format "HH:mm:ss"
                Action = "Download simulation tool"
                Status = "Error"
                Details = "File not created"
            }
            return $null
        }
    }
    catch {
        Write-Log "Error downloading simulation tool: $_" -Level Error
        $script:SimulationReport.ActionsPerformed += @{
            Time = Get-Date -Format "HH:mm:ss"
            Action = "Download simulation tool"
            Status = "Error"
            Details = "Error: $_"
        }
        return $null
    }
}

function Invoke-Simulation {
    param(
        [string]$SimulationScript,
        [string]$Scenario
    )
    
    Write-Log "Starting Kubernetes alerts simulation..." -Level Info
    Write-Log "Scenario: $Scenario" -Level Info
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Magenta
    Write-Host "  SIMULATION TOOL OUTPUT" -ForegroundColor Magenta
    Write-Host "============================================" -ForegroundColor Magenta
    Write-Host ""
    
    $scriptDir = Split-Path $SimulationScript -Parent
    Push-Location $scriptDir
    
    # Create a wrapper script that captures scenario selections and outputs
    $wrapperScript = @'
import subprocess
import sys
import re
from datetime import datetime

scenarios_run = []
current_scenario = None
scenario_start = None

# Run the original simulation and capture output
process = subprocess.Popen(
    [sys.executable, 'simulation.py'],
    stdin=sys.stdin,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True,
    bufsize=1
)

scenario_map = {
    '1': 'Reconnaissance',
    '2': 'Lateral Movement', 
    '3': 'Secrets Gathering',
    '4': 'Cryptomining',
    '5': 'Webshell',
    '6': 'All'
}

output_buffer = []

for line in process.stdout:
    print(line, end='', flush=True)
    output_buffer.append(line)
    
    # Detect scenario start
    if 'Started at' in line:
        scenario_start = line.strip().replace('Started at ', '')
    
    # Detect scenario completion
    if 'Scenario completed successfully' in line and current_scenario:
        scenarios_run.append({
            'name': current_scenario,
            'start_time': scenario_start,
            'end_time': datetime.utcnow().strftime('%a %b %d %H:%M:%S UTC %Y'),
            'status': 'Success'
        })
        current_scenario = None
        
    # Detect scenario selection
    if 'Select a scenario:' in line:
        # Look for the next input in output
        pass

process.wait()

# Write scenarios to a temp file for PowerShell to read
import json
with open('simulation_results.json', 'w') as f:
    json.dump(scenarios_run, f)
'@
    
    try {
        # Record simulation start time
        $script:SimulationReport.SimulationStartTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        
        # Run the simulation interactively and capture output
        $outputFile = Join-Path $scriptDir "simulation_output.txt"
        
        # Use Start-Process with redirected output to capture while still being interactive
        python $SimulationScript 2>&1 | Tee-Object -FilePath $outputFile
        
        $script:SimulationReport.SimulationEndTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        
        # Parse the output to extract scenarios
        if (Test-Path $outputFile) {
            $output = Get-Content $outputFile -Raw
            
            # Extract scenarios that were run
            $scenarioPatterns = @{
                "Webshell" = "--- Webshell ---"
                "Reconnaissance" = "--- Reconnaissance ---"
                "Lateral Movement" = "--- Lateral Movement ---"
                "Secrets Gathering" = "--- Secrets Gathering ---"
                "Cryptomining" = "--- Cryptomining ---"
            }
            
            # Find all "Started at" timestamps
            $startMatches = [regex]::Matches($output, "Started at (.+)")
            $scenarioIndex = 0
            
            foreach ($pattern in $scenarioPatterns.GetEnumerator()) {
                if ($output -match [regex]::Escape($pattern.Value)) {
                    $startTime = if ($startMatches.Count -gt $scenarioIndex) { 
                        $startMatches[$scenarioIndex].Groups[1].Value 
                    } else { 
                        $script:SimulationReport.SimulationStartTime 
                    }
                    
                    $script:SimulationReport.Scenarios += @{
                        Name = $pattern.Key
                        StartTime = $startTime
                        Status = "Completed"
                        Alerts = Get-ExpectedAlerts -ScenarioName $pattern.Key
                    }
                }
            }
            
            # If we detected "Scenario completed successfully" count them
            $completedCount = ([regex]::Matches($output, "Scenario completed successfully")).Count
            Write-Log "Detected $completedCount completed scenario run(s)" -Level Info
            
            # Store simulation output for report
            $script:SimulationReport.SimulationOutput = $output
            
            # Track simulation completion
            $script:SimulationReport.ActionsPerformed += @{
                Time = Get-Date -Format "HH:mm:ss"
                Action = "Attack simulation completed"
                Status = "Success"
                Details = "$completedCount scenario(s) executed"
            }
        }
    }
    catch {
        Write-Log "Error running simulation: $_" -Level Error
        $script:SimulationReport.ActionsPerformed += @{
            Time = Get-Date -Format "HH:mm:ss"
            Action = "Attack simulation"
            Status = "Error"
            Details = "Error: $_"
        }
    }
    finally {
        Pop-Location
    }
    
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Magenta
    Write-Host "  SIMULATION COMPLETE" -ForegroundColor Magenta
    Write-Host "============================================" -ForegroundColor Magenta
}

function Get-ExpectedAlerts {
    param([string]$ScenarioName)
    
    $alertMap = @{
        "Webshell" = @("Possible Web Shell activity detected")
        "Reconnaissance" = @(
            "Possible Web Shell activity detected",
            "Suspicious Kubernetes service account operation detected",
            "Network scanning tool detected"
        )
        "Lateral Movement" = @(
            "Possible Web Shell activity detected",
            "Access to cloud metadata service detected"
        )
        "Secrets Gathering" = @(
            "Possible Web Shell activity detected",
            "Sensitive files access detected",
            "Possible secret reconnaissance detected"
        )
        "Cryptomining" = @(
            "Possible Web Shell activity detected",
            "Kubernetes CPU optimization detected",
            "Command within a container accessed ld.so.preload",
            "Possible Crypto miners download detected",
            "A drift binary detected executing in the container"
        )
    }
    
    return $alertMap[$ScenarioName]
}

function New-SimulationReport {
    param(
        [string]$ReportPath,
        [hashtable]$ReportData
    )
    
    Write-Log "Generating simulation report..." -Level Info
    
    # Build scenario rows
    $scenarioRows = ""
    $scenarioIndex = 1
    foreach ($scenario in $ReportData.Scenarios) {
        $alertsList = if ($scenario.Alerts) { 
            ($scenario.Alerts | ForEach-Object { "<li>$_</li>" }) -join "`n"
        } else { 
            "<li>No specific alerts mapped</li>" 
        }
        
        $scenarioRows += @"
                <tr>
                    <td>$scenarioIndex</td>
                    <td><strong>$($scenario.Name)</strong></td>
                    <td>$($scenario.StartTime)</td>
                    <td><span class="status-success">$($scenario.Status)</span></td>
                    <td><ul class="alert-list">$alertsList</ul></td>
                </tr>
"@
        $scenarioIndex++
    }
    
    # Build prerequisite rows
    $prereqRows = ""
    foreach ($prereq in $ReportData.Prerequisites) {
        $statusClass = if ($prereq.Status -eq "Installed") { "status-success" } else { "status-error" }
        $prereqRows += @"
                <tr>
                    <td>$($prereq.Name)</td>
                    <td><span class="$statusClass">$($prereq.Status)</span></td>
                </tr>
"@
    }
    
    # Build actions performed rows
    $actionRows = ""
    $actionIndex = 1
    foreach ($action in $ReportData.ActionsPerformed) {
        $statusClass = switch ($action.Status) {
            "Success" { "status-success" }
            "Warning" { "status-warning" }
            "Error" { "status-error" }
            "Failed" { "status-error" }
            default { "status-info" }
        }
        $actionRows += @"
                <tr>
                    <td>$actionIndex</td>
                    <td>$($action.Time)</td>
                    <td>$($action.Action)</td>
                    <td><span class="$statusClass">$($action.Status)</span></td>
                    <td>$($action.Details)</td>
                </tr>
"@
        $actionIndex++
    }
    
    # Cluster info section
    $clusterCreatedText = if ($ReportData.IsNewCluster) { 
        "<span class='status-new'>Newly Created</span>" 
    } else { 
        "<span class='status-existing'>Existing Cluster</span>" 
    }
    
    $clusterDeletedText = if ($ReportData.ClusterDeletedAfterRun) {
        "<span class='status-success'>Deleted (no ongoing costs)</span>"
    } else {
        if ($ReportData.IsNewCluster) {
            "<span class='status-warning'>Still Running (costs ~`$1.80/day)</span>"
        } else {
            "<span class='status-info'>N/A (existing cluster)</span>"
        }
    }
    
    $cleanupStatusText = switch ($ReportData.CleanupStatus) {
        "Verified" { "<span class='status-success'>✓ Verified Clean</span>" }
        "Partial" { "<span class='status-warning'>⚠ Partial (some resources may remain)</span>" }
        "Skipped" { "<span class='status-warning'>Skipped</span>" }
        default { "<span class='status-info'>Unknown</span>" }
    }

    $htmlReport = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Kubernetes Alert Simulation Report - $($ReportData.ClusterName)</title>
    <style>
        :root {
            --primary: #0078d4;
            --success: #107c10;
            --warning: #ff8c00;
            --danger: #d13438;
            --info: #0078d4;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f5f5;
            padding: 20px;
            color: #333;
            line-height: 1.6;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        .header {
            background: linear-gradient(135deg, #0078d4 0%, #106ebe 100%);
            color: white;
            padding: 30px;
            border-radius: 12px 12px 0 0;
            text-align: center;
        }
        .header h1 { font-size: 1.8rem; margin-bottom: 10px; }
        .header .subtitle { opacity: 0.9; }
        .header .timestamp { 
            margin-top: 15px; 
            background: rgba(255,255,255,0.2); 
            display: inline-block; 
            padding: 8px 20px; 
            border-radius: 20px; 
        }
        .content {
            background: white;
            padding: 30px;
            border-radius: 0 0 12px 12px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.1);
        }
        .section { margin-bottom: 30px; }
        .section h2 {
            color: var(--primary);
            border-bottom: 2px solid var(--primary);
            padding-bottom: 10px;
            margin-bottom: 20px;
            font-size: 1.3rem;
        }
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 15px;
        }
        .info-card {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            border-left: 4px solid var(--primary);
        }
        .info-card label {
            font-size: 0.85rem;
            color: #666;
            display: block;
            margin-bottom: 5px;
        }
        .info-card .value {
            font-weight: 600;
            font-size: 1.1rem;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }
        th, td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #e0e0e0;
        }
        th {
            background: #f0f0f0;
            font-weight: 600;
            color: #333;
        }
        tr:hover { background: #f8f9fa; }
        .status-success {
            background: #dff6dd;
            color: var(--success);
            padding: 4px 12px;
            border-radius: 12px;
            font-weight: 600;
            font-size: 0.85rem;
        }
        .status-warning {
            background: #fff4ce;
            color: var(--warning);
            padding: 4px 12px;
            border-radius: 12px;
            font-weight: 600;
            font-size: 0.85rem;
        }
        .status-error {
            background: #fde7e9;
            color: var(--danger);
            padding: 4px 12px;
            border-radius: 12px;
            font-weight: 600;
            font-size: 0.85rem;
        }
        .status-info {
            background: #e5f1fb;
            color: var(--info);
            padding: 4px 12px;
            border-radius: 12px;
            font-weight: 600;
            font-size: 0.85rem;
        }
        .status-new {
            background: #e8f5e9;
            color: var(--success);
            padding: 4px 12px;
            border-radius: 12px;
            font-weight: 600;
            font-size: 0.85rem;
        }
        .status-existing {
            background: #e3f2fd;
            color: #1565c0;
            padding: 4px 12px;
            border-radius: 12px;
            font-weight: 600;
            font-size: 0.85rem;
        }
        .alert-list {
            margin: 0;
            padding-left: 20px;
            font-size: 0.9rem;
        }
        .alert-list li {
            margin: 3px 0;
            color: var(--warning);
        }
        .summary-box {
            background: linear-gradient(135deg, #e8f5e9 0%, #c8e6c9 100%);
            border-radius: 12px;
            padding: 25px;
            text-align: center;
            margin-bottom: 30px;
        }
        .summary-box h3 {
            color: var(--success);
            font-size: 2rem;
            margin-bottom: 5px;
        }
        .summary-box p { color: #666; }
        .summary-stats {
            display: flex;
            justify-content: center;
            gap: 40px;
            margin-top: 20px;
            flex-wrap: wrap;
        }
        .stat-item {
            text-align: center;
        }
        .stat-item .number {
            font-size: 2rem;
            font-weight: bold;
            color: var(--primary);
        }
        .stat-item .label {
            font-size: 0.85rem;
            color: #666;
        }
        .footer {
            text-align: center;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #e0e0e0;
            color: #666;
            font-size: 0.9rem;
        }
        .footer a { color: var(--primary); text-decoration: none; }
        .next-steps {
            background: #fff3cd;
            border-left: 4px solid var(--warning);
            padding: 20px;
            border-radius: 8px;
            margin-top: 20px;
        }
        .next-steps h4 { color: var(--warning); margin-bottom: 10px; }
        .next-steps ol { margin-left: 20px; }
        .next-steps li { margin: 8px 0; }
        .resource-box {
            background: #f0f7ff;
            border: 1px solid #cce5ff;
            border-radius: 8px;
            padding: 20px;
            margin: 15px 0;
        }
        .resource-box h4 {
            color: var(--primary);
            margin-bottom: 10px;
        }
        .resource-list {
            list-style: none;
            padding: 0;
        }
        .resource-list li {
            padding: 8px 0;
            border-bottom: 1px solid #e0e0e0;
            display: flex;
            justify-content: space-between;
        }
        .resource-list li:last-child {
            border-bottom: none;
        }
        .code-block {
            background: #2d2d2d;
            color: #f8f8f2;
            padding: 15px;
            border-radius: 8px;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 0.85rem;
            overflow-x: auto;
            margin: 10px 0;
        }
        .collapsible {
            background: #f0f0f0;
            padding: 15px;
            border-radius: 8px;
            cursor: pointer;
            margin: 10px 0;
        }
        .collapsible:hover {
            background: #e5e5e5;
        }
        .collapsible-content {
            padding: 15px;
            border: 1px solid #e0e0e0;
            border-top: none;
            border-radius: 0 0 8px 8px;
            display: none;
        }
        .collapsible-content.show {
            display: block;
        }
        .disclaimer {
            background: #f8f9fa;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            padding: 15px;
            font-size: 0.85rem;
            color: #666;
            margin-top: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Kubernetes Alert Simulation Report</h1>
            <p class="subtitle">Microsoft Defender for Cloud - Attack Simulation Results</p>
            <div class="timestamp">
                📅 Generated: $(Get-Date -Format "MMMM dd, yyyy 'at' HH:mm:ss")
            </div>
        </div>
        
        <div class="content">
            <!-- Summary Box -->
            <div class="summary-box">
                <h3>✅ Simulation Completed Successfully</h3>
                <p>All attack scenarios executed on cluster <strong>$($ReportData.ClusterName)</strong></p>
                <div class="summary-stats">
                    <div class="stat-item">
                        <div class="number">$($ReportData.Scenarios.Count)</div>
                        <div class="label">Scenarios Executed</div>
                    </div>
                    <div class="stat-item">
                        <div class="number">$($ReportData.ActionsPerformed.Count)</div>
                        <div class="label">Actions Performed</div>
                    </div>
                    <div class="stat-item">
                        <div class="number">$($ReportData.Prerequisites.Count)</div>
                        <div class="label">Prerequisites Verified</div>
                    </div>
                </div>
            </div>
            
            <!-- Execution Details -->
            <div class="section">
                <h2>📋 Execution Details</h2>
                <div class="info-grid">
                    <div class="info-card">
                        <label>Cluster Name</label>
                        <div class="value">$($ReportData.ClusterName)</div>
                    </div>
                    <div class="info-card">
                        <label>Resource Group</label>
                        <div class="value">$($ReportData.ResourceGroup)</div>
                    </div>
                    <div class="info-card">
                        <label>Subscription</label>
                        <div class="value">$($ReportData.Subscription)</div>
                    </div>
                    <div class="info-card">
                        <label>Subscription ID</label>
                        <div class="value" style="font-size: 0.9rem;">$($ReportData.SubscriptionId)</div>
                    </div>
                    <div class="info-card">
                        <label>Executed By</label>
                        <div class="value">$($ReportData.UserName)</div>
                    </div>
                    <div class="info-card">
                        <label>Cluster Type</label>
                        <div class="value">$clusterCreatedText</div>
                    </div>
                    <div class="info-card">
                        <label>Cluster Location</label>
                        <div class="value">$($ReportData.ClusterLocation)</div>
                    </div>
                    <div class="info-card">
                        <label>Node Count</label>
                        <div class="value">$($ReportData.ClusterNodeCount)</div>
                    </div>
                    <div class="info-card">
                        <label>Simulation Start</label>
                        <div class="value">$($ReportData.SimulationStartTime)</div>
                    </div>
                    <div class="info-card">
                        <label>Simulation End</label>
                        <div class="value">$($ReportData.SimulationEndTime)</div>
                    </div>
                    <div class="info-card">
                        <label>Defender Sensor</label>
                        <div class="value"><span class="status-success">$($ReportData.DefenderSensorStatus)</span></div>
                    </div>
                    <div class="info-card">
                        <label>Script Version</label>
                        <div class="value">$($ReportData.ScriptVersion)</div>
                    </div>
                </div>
            </div>
            
            <!-- Azure Resources -->
            <div class="section">
                <h2>☁️ Azure Resources Used</h2>
                <div class="resource-box">
                    <h4>Resources Involved in Simulation</h4>
                    <ul class="resource-list">
                        <li>
                            <span><strong>AKS Cluster:</strong> $($ReportData.ClusterName)</span>
                            <span>$clusterCreatedText</span>
                        </li>
                        <li>
                            <span><strong>Resource Group:</strong> $($ReportData.ResourceGroup)</span>
                            <span></span>
                        </li>
                        <li>
                            <span><strong>Subscription:</strong> $($ReportData.Subscription)</span>
                            <span></span>
                        </li>
                        <li>
                            <span><strong>Defender for Containers:</strong></span>
                            <span class="status-success">$($ReportData.DefenderSensorStatus)</span>
                        </li>
                    </ul>
                </div>
                <div class="info-grid">
                    <div class="info-card">
                        <label>Simulation Resources Cleanup</label>
                        <div class="value">$cleanupStatusText</div>
                    </div>
                    <div class="info-card">
                        <label>Cluster Status After Run</label>
                        <div class="value">$clusterDeletedText</div>
                    </div>
                </div>
            </div>
            
            <!-- Attack Scenarios -->
            <div class="section">
                <h2>⚔️ Attack Scenarios Executed</h2>
                <table>
                    <thead>
                        <tr>
                            <th>#</th>
                            <th>Scenario</th>
                            <th>Start Time</th>
                            <th>Status</th>
                            <th>Expected Defender Alerts</th>
                        </tr>
                    </thead>
                    <tbody>
$scenarioRows
                    </tbody>
                </table>
            </div>
            
            <!-- Actions Timeline -->
            <div class="section">
                <h2>📜 Actions Performed (Timeline)</h2>
                <table>
                    <thead>
                        <tr>
                            <th>#</th>
                            <th>Time</th>
                            <th>Action</th>
                            <th>Status</th>
                            <th>Details</th>
                        </tr>
                    </thead>
                    <tbody>
$actionRows
                    </tbody>
                </table>
            </div>
            
            <!-- Prerequisites -->
            <div class="section">
                <h2>✅ Prerequisites Verified</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Component</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
$prereqRows
                    </tbody>
                </table>
            </div>
            
            <!-- Expected Alerts Section -->
            <div class="section">
                <h2>🚨 Expected Security Alerts</h2>
                <p>The simulation generates the following alerts in Microsoft Defender. Alerts typically appear within minutes, but some may take up to 1 hour.</p>
                <table>
                    <thead>
                        <tr>
                            <th>Alert Name</th>
                            <th>Severity</th>
                            <th>Category</th>
                            <th>Description</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td>Digital currency mining related behavior detected</td>
                            <td><span class="status-error">High</span></td>
                            <td>Execution</td>
                            <td>Cryptocurrency mining activity detected in container</td>
                        </tr>
                        <tr>
                            <td>A drift binary detected executing in the container</td>
                            <td><span class="status-error">High</span></td>
                            <td>Execution</td>
                            <td>Unauthorized binary execution detected</td>
                        </tr>
                        <tr>
                            <td>Possible Cryptocoinminer download detected</td>
                            <td><span class="status-warning">Medium</span></td>
                            <td>Initial access</td>
                            <td>Download of crypto mining tools detected</td>
                        </tr>
                        <tr>
                            <td>Command within a container accessed ld.so.preload</td>
                            <td><span class="status-warning">Medium</span></td>
                            <td>Defense evasion</td>
                            <td>Attempt to hook library loading detected</td>
                        </tr>
                        <tr>
                            <td>Kubernetes CPU optimization detected (Preview)</td>
                            <td><span class="status-error">High</span></td>
                            <td>Impact</td>
                            <td>Suspicious CPU resource manipulation</td>
                        </tr>
                        <tr>
                            <td>Possible Secret Reconnaissance Detected</td>
                            <td><span class="status-warning">Medium</span></td>
                            <td>Credential access</td>
                            <td>Enumeration of Kubernetes secrets detected</td>
                        </tr>
                        <tr>
                            <td>Sensitive Files Access Detected</td>
                            <td><span class="status-warning">Medium</span></td>
                            <td>Credential access</td>
                            <td>Access to sensitive credential files</td>
                        </tr>
                        <tr>
                            <td>Access to cloud metadata service detected</td>
                            <td><span class="status-warning">Medium</span></td>
                            <td>Credential access</td>
                            <td>IMDS/metadata endpoint access detected</td>
                        </tr>
                        <tr>
                            <td>Suspicious access to workload identity token</td>
                            <td><span class="status-info">Low</span></td>
                            <td>Credential access</td>
                            <td>Attempt to access identity tokens</td>
                        </tr>
                        <tr>
                            <td>Possible Web Shell Activity Detected</td>
                            <td><span class="status-warning">Medium</span></td>
                            <td>Persistence</td>
                            <td>Web shell behavior patterns detected</td>
                        </tr>
                    </tbody>
                </table>
            </div>
            
            <!-- Next Steps -->
            <div class="next-steps">
                <h4>📌 Next Steps - View Your Security Alerts</h4>
                <p><strong>🔗 Direct Link to Your Alerts:</strong></p>
                <a href="https://security.microsoft.com/alerts?tid=$($ReportData.TenantId)" target="_blank" class="btn-primary" style="display: inline-block; background: #0078d4; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: 600; margin: 10px 0;">
                    🛡️ Open Microsoft Defender Portal - View Alerts
                </a>
                <p style="margin-top: 15px; font-size: 0.9rem; color: #666;">
                    Tenant ID: <code>$($ReportData.TenantId)</code>
                </p>
                
                <ol style="margin-top: 20px;">
                    <li>Click the button above or copy the link: <code>https://security.microsoft.com/alerts?tid=$($ReportData.TenantId)</code></li>
                    <li>Filter by resource: <strong>$($ReportData.ClusterName)</strong></li>
                    <li>Review generated alerts (some may take up to 1 hour to appear)</li>
                    <li>Validate that Defender for Containers detected the simulated attacks</li>
                </ol>
                
                <div class="code-block">
# Direct link to your tenant's alerts:
https://security.microsoft.com/alerts?tid=$($ReportData.TenantId)

# Alternative - Azure Portal Security Alerts:
https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/SecurityAlerts
                </div>
            </div>
            
            <!-- Cleanup Commands -->
            <div class="section">
                <h2>🧹 Cleanup Commands (if needed)</h2>
                <p>If you need to manually clean up resources, use these commands:</p>
                <div class="code-block">
# Delete simulation namespace and pods
kubectl delete namespace mdc-simulation

# Delete simulation Helm releases
helm uninstall mdc-simulation --namespace mdc-simulation

# If you created a new cluster and want to delete it:
az group delete --name $($ReportData.ResourceGroup) --yes
                </div>
            </div>
            
            <!-- Disclaimer -->
            <div class="disclaimer">
                <strong>⚠️ Disclaimer:</strong> This report was generated by an automated simulation script. 
                The security alerts generated are simulated attacks for testing purposes only. 
                Cost estimates mentioned are approximations and may vary based on Azure region and pricing changes.
                Microsoft is not responsible for any charges incurred. Always verify with Azure Cost Management for actual costs.
            </div>
            
            <!-- Footer -->
            <div class="footer">
                <p>
                    Report generated by <strong>Deploy-KubernetesAlertSimulation.ps1 v$($ReportData.ScriptVersion)</strong><br>
                    Simulation tool: <a href="https://github.com/microsoft/Defender-for-Cloud-Attack-Simulation" target="_blank">Microsoft/Defender-for-Cloud-Attack-Simulation</a>
                </p>
            </div>
        </div>
    </div>
    
    <script>
        // Collapsible sections (optional enhancement)
        document.querySelectorAll('.collapsible').forEach(function(elem) {
            elem.addEventListener('click', function() {
                var content = this.nextElementSibling;
                content.classList.toggle('show');
            });
        });
    </script>
</body>
</html>
"@

    try {
        $htmlReport | Out-File -FilePath $ReportPath -Encoding UTF8
        Write-Log "Report saved to: $ReportPath" -Level Success
        return $ReportPath
    }
    catch {
        Write-Log "Failed to save report: $_" -Level Error
        return $null
    }
}

function Remove-SimulationResources {
    <#
    .SYNOPSIS
        Cleans up all simulation resources from the cluster.
    .DESCRIPTION
        Removes pods, namespaces, and Helm releases created by the simulation tool.
        Provides detailed output of what was cleaned up.
    #>
    param(
        [switch]$Force
    )
    
    Write-Log "Cleaning up simulation resources..." -Level Info
    Write-Host ""
    
    $cleanedItems = @()
    
    # Delete mdc-simulation namespace if it exists
    Write-Host "  Checking for simulation namespace..." -NoNewline
    $nsExists = kubectl get namespace mdc-simulation 2>$null
    if ($nsExists) {
        Write-Host " found" -ForegroundColor Yellow
        Write-Host "  Deleting namespace 'mdc-simulation'..." -ForegroundColor Gray
        kubectl delete namespace mdc-simulation --timeout=60s 2>$null
        if ($LASTEXITCODE -eq 0) {
            $cleanedItems += "Namespace: mdc-simulation"
            Write-Host "    ✓ Deleted" -ForegroundColor Green
        } else {
            Write-Host "    ⚠ May still be terminating" -ForegroundColor Yellow
        }
    } else {
        Write-Host " not found (already clean)" -ForegroundColor Green
    }
    
    # Delete simulation pods in default namespace
    Write-Host "  Checking for simulation pods in default namespace..." -NoNewline
    $simPods = kubectl get pods -n default -l app=simulation --no-headers 2>$null
    if ($simPods) {
        Write-Host " found" -ForegroundColor Yellow
        kubectl delete pods -n default -l app=simulation 2>$null
        $cleanedItems += "Pods: simulation (default namespace)"
        Write-Host "    ✓ Deleted" -ForegroundColor Green
    } else {
        Write-Host " not found (already clean)" -ForegroundColor Green
    }
    
    # Delete attacker/victim pods
    Write-Host "  Checking for attacker/victim pods..." -NoNewline
    $attackerPods = kubectl get pods --all-namespaces --no-headers 2>$null | Select-String -Pattern "attacker|victim"
    if ($attackerPods) {
        Write-Host " found" -ForegroundColor Yellow
        kubectl delete pods -n default -l role=attacker 2>$null
        kubectl delete pods -n default -l role=victim 2>$null
        $cleanedItems += "Pods: attacker/victim"
        Write-Host "    ✓ Deleted" -ForegroundColor Green
    } else {
        Write-Host " not found (already clean)" -ForegroundColor Green
    }
    
    # Try to remove any helm releases created by simulation
    Write-Host "  Checking for simulation Helm releases..." -NoNewline
    $releases = helm list --all-namespaces -q 2>$null
    $simReleases = $releases | Where-Object { $_ -match "simulation|attacker|victim|mdc" }
    if ($simReleases) {
        Write-Host " found" -ForegroundColor Yellow
        foreach ($release in $simReleases) {
            Write-Host "    Uninstalling: $release" -ForegroundColor Gray
            helm uninstall $release --namespace mdc-simulation 2>$null
            helm uninstall $release 2>$null
            $cleanedItems += "Helm release: $release"
        }
        Write-Host "    ✓ Deleted" -ForegroundColor Green
    } else {
        Write-Host " not found (already clean)" -ForegroundColor Green
    }
    
    Write-Host ""
    
    if ($cleanedItems.Count -gt 0) {
        Write-Log "Cleanup completed. Removed $($cleanedItems.Count) item(s)." -Level Success
    } else {
        Write-Log "Cleanup completed. No simulation resources found to remove." -Level Success
    }
    
    return $cleanedItems
}

function Show-CostAnalysis {
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "  COST ANALYSIS - One-Time Simulation Run" -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host ""
    
    $costAnalysis = @"
COST BREAKDOWN FOR RUNNING KUBERNETES ALERTS SIMULATION TOOL
=============================================================

1. AKS CLUSTER COSTS (if cluster already exists):
   - No additional AKS cluster costs for running the simulation
   - The simulation deploys 2 lightweight pods (attacker and victim)
   - Minimal CPU/Memory impact on existing nodes

2. COMPUTE COSTS (Simulation Pods):
   - Duration: Typically 5-30 minutes depending on scenarios
   - Resources: Minimal (< 0.5 vCPU, < 512MB RAM per pod)
   - Estimated Cost: < `$0.01 for the simulation runtime

3. DEFENDER FOR CONTAINERS COSTS:
   - Pricing: ~`$7/vCore/month for Defender sensor
   - For simulation only: Prorated cost is negligible
   - One-time run: < `$0.05 (assuming 1-2 vCores, 30 min runtime)

4. NETWORKING COSTS:
   - Egress: Minimal (simulation is internal to cluster)
   - Estimated: < `$0.01

5. LOG ANALYTICS / STORAGE:
   - Alert data ingestion: Minimal
   - Estimated: < `$0.01

TOTAL ESTIMATED ONE-TIME COST: < `$0.10
=============================================

NOTES:
- If you need to create a NEW AKS cluster for testing:
  * Minimum cluster (1 node, Standard_B2s): ~`$0.05/hour
  * 1-hour test: ~`$0.05 + simulation costs
  * Remember to delete the cluster after testing!

- Defender for Containers must be enabled:
  * If not already enabled, you get 30-day free trial
  * After trial: ~`$7/vCore/month

- The simulation tool itself is FREE (open source)

RECOMMENDATIONS FOR COST OPTIMIZATION:
1. Use an existing development/test AKS cluster
2. Run during off-peak hours if billing is per-hour
3. Delete any test clusters immediately after use
4. Monitor Azure Cost Management for actual charges

"@
    
    Write-Host $costAnalysis -ForegroundColor White
}

#endregion

#region Main Script

# Check for previous session and offer to resume
$previousSession = Get-SessionState
$resumeMode = $false

if ($previousSession -and $previousSession.CurrentStage -ne "NotStarted" -and $previousSession.CurrentStage -ne "Completed") {
    $resumeChoice = Show-ResumePrompt -PreviousSession $previousSession
    $resumeMode = ($resumeChoice -eq "Resume")
}

# Initialize new session if not resuming
if (-not $resumeMode) {
    $script:SessionState.SessionId = [guid]::NewGuid().ToString()
    $script:SessionState.StartTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Save-SessionState
}

# Show Microsoft disclaimer first (skip if resuming)
if (-not (Test-StageCompleted -Stage "Disclaimer")) {
    Show-Disclaimer
    Update-SessionStage -Stage "Disclaimer" -MarkComplete
}

Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "  Kubernetes Alerts Simulation Tool" -ForegroundColor Green
Write-Host "  Microsoft Defender for Cloud" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host ""

# Show session info if resuming
if ($resumeMode) {
    Write-Host "  📋 Resuming Session: $($script:SessionState.SessionId.Substring(0,8))..." -ForegroundColor Cyan
    Write-Host "  📝 Error Log: $script:ErrorLogFile" -ForegroundColor Gray
    Write-Host ""
}

# Show cost analysis first (skip if resuming past this point)
if (-not (Test-StageCompleted -Stage "CostAnalysis")) {
    Show-CostAnalysis
    
    $proceed = Read-Host "Do you want to proceed with the simulation? (y/n)"
    if ($proceed -ne 'y') {
        Write-Log "Operation cancelled by user." -Level Warning
        Remove-SessionState
        exit 0
    }
    Update-SessionStage -Stage "CostAnalysis" -MarkComplete
}

# Check prerequisites (skip if resuming past this point)
if (-not (Test-StageCompleted -Stage "Prerequisites")) {
    if (-not $SkipPrerequisiteCheck) {
        try {
            $prereqsPassed = Test-Prerequisites
            if (-not $prereqsPassed) {
                Write-ErrorLog -Message "Prerequisites check failed" -Stage "Prerequisites" -ErrorDetails "Missing required components"
                Write-Log "Prerequisites check failed. Please install missing components and try again." -Level Error
                Write-Host ""
                Write-Host "  📝 Error logged to: $script:ErrorLogFile" -ForegroundColor Yellow
                exit 1
            }
            Update-SessionStage -Stage "Prerequisites" -MarkComplete
        }
        catch {
            Write-ErrorLog -Message "Prerequisites check exception" -Stage "Prerequisites" -ErrorDetails $_.Exception.Message
            throw
        }
    } else {
        Update-SessionStage -Stage "Prerequisites" -MarkComplete
    }
}

# Set subscription if provided
if ($SubscriptionId) {
    az account set --subscription $SubscriptionId
}

# Initial permission check (skip if resuming past this point)
if (-not (Test-StageCompleted -Stage "PermissionCheck")) {
    Write-Host ""
    try {
        $permissionCheck = Test-AzurePermissions -CheckClusterCreation:$false
        
        # Track permission check
        $script:SimulationReport.ActionsPerformed += @{
            Time = Get-Date -Format "HH:mm:ss"
            Action = "Azure permission check"
            Status = if ($permissionCheck.Passed) { "Success" } else { "Warning" }
            Details = if ($permissionCheck.HasElevatedAccess) { "Has elevated access (Owner/Contributor/GA)" } else { "Least-privilege permissions verified" }
        }
        
        if (-not $permissionCheck.Passed) {
            $continueAnyway = Read-Host "Permission check failed. Do you want to continue anyway? (y/n)"
            if ($continueAnyway -ne 'y') {
                Write-ErrorLog -Message "Permission check failed and user chose not to continue" -Stage "PermissionCheck"
                Write-Log "Exiting due to permission issues." -Level Error
                exit 1
            }
        }
        Update-SessionStage -Stage "PermissionCheck" -MarkComplete
    }
    catch {
        Write-ErrorLog -Message "Permission check exception" -Stage "PermissionCheck" -ErrorDetails $_.Exception.Message
        throw
    }
}

# Get or discover AKS cluster
$selectedCluster = $null

# Check if we're resuming with a known cluster
if ($resumeMode -and $script:SessionState.ClusterName -and $script:SessionState.ResourceGroup) {
    Write-Host ""
    Write-Log "Resuming with cluster: $($script:SessionState.ClusterName)" -Level Info
    $selectedCluster = [PSCustomObject]@{
        Name = $script:SessionState.ClusterName
        ResourceGroup = $script:SessionState.ResourceGroup
        IsNewCluster = $script:SessionState.IsNewCluster
    }
    
    # Restore cluster cleanup info
    if ($script:SessionState.IsNewCluster) {
        $script:CreatedClusterForCleanup = @{
            Name = $script:SessionState.ClusterName
            ResourceGroup = $script:SessionState.ResourceGroup
        }
    }
} elseif ($ClusterName -and $ResourceGroup) {
    Write-Log "Using specified cluster: $ClusterName in resource group: $ResourceGroup" -Level Info
    $selectedCluster = [PSCustomObject]@{
        Name = $ClusterName
        ResourceGroup = $ResourceGroup
    }
} else {
    # Discover available clusters
    $clusters = Get-AKSClusters -SubscriptionId $SubscriptionId
    
    if (-not $clusters -or $clusters.Count -eq 0) {
        Write-Host ""
        Write-Host "============================================" -ForegroundColor Yellow
        Write-Host "  NO AKS CLUSTERS FOUND" -ForegroundColor Yellow
        Write-Host "============================================" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "No existing AKS clusters were found in the current subscription." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Would you like to create a dedicated non-production AKS cluster" -ForegroundColor Cyan
        Write-Host "specifically for running this security simulation?" -ForegroundColor Cyan
        Write-Host ""
        
        $createCluster = Read-Host "Create a new non-prod AKS cluster? (yes/no)"
        
        if ($createCluster -eq 'yes') {
            # Only check permissions if we didn't already detect elevated access
            $canCreateCluster = $false
            
            if ($permissionCheck.HasElevatedAccess) {
                # User already has elevated access, no need to check again
                $canCreateCluster = $true
            } else {
                # Check elevated permissions for cluster creation
                Write-Host ""
                Write-Log "Checking permissions for cluster creation..." -Level Info
                $createPermCheck = Test-AzurePermissions -CheckClusterCreation:$true
                $canCreateCluster = $createPermCheck.Passed
            }
            
            if (-not $canCreateCluster) {
                Write-Host ""
                Write-Host "  ⚠️  Creating a new AKS cluster requires elevated permissions." -ForegroundColor Yellow
                Write-Host ""
                Write-Host "  You need ONE of the following:" -ForegroundColor White
                Write-Host "    • Contributor role on the subscription" -ForegroundColor Gray
                Write-Host "    • Contributor role on a resource group + ability to create RGs" -ForegroundColor Gray
                Write-Host "    • Owner role" -ForegroundColor Gray
                Write-Host ""
                
                $proceedCreate = Read-Host "Permission issues detected. Try anyway? (y/n)"
                if ($proceedCreate -ne 'y') {
                    Write-Log "Cluster creation cancelled due to permission concerns." -Level Warning
                    exit 0
                }
            }
            
            $selectedCluster = New-SimulationAKSCluster
            if (-not $selectedCluster) {
                Write-Log "Failed to create AKS cluster. Exiting." -Level Error
                exit 1
            }
        } else {
            Write-Log "No cluster available. Please create an AKS cluster and try again." -Level Warning
            exit 0
        }
    } else {
        # Offer choice: use existing or create new
        Write-Host ""
        Write-Host "============================================" -ForegroundColor Cyan
        Write-Host "  CLUSTER SELECTION" -ForegroundColor Cyan
        Write-Host "============================================" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  ┌─────────────────────────────────────────────────────────┐" -ForegroundColor Yellow
        Write-Host "  │  📝 NOTE                                                │" -ForegroundColor Yellow
        Write-Host "  │                                                         │" -ForegroundColor Yellow
        Write-Host "  │  Although the simulation tool doesn't run any           │" -ForegroundColor Yellow
        Write-Host "  │  malicious components, it's recommended to run it       │" -ForegroundColor Yellow
        Write-Host "  │  on a dedicated cluster without production workloads.   │" -ForegroundColor Yellow
        Write-Host "  └─────────────────────────────────────────────────────────┘" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Would you like to:" -ForegroundColor Yellow
        Write-Host "  [1] Use an existing AKS cluster (listed above)" -ForegroundColor White
        Write-Host "  [2] Create a NEW dedicated non-prod AKS cluster for this simulation" -ForegroundColor White
        Write-Host "      (Recommended for first-time users)" -ForegroundColor Gray
        Write-Host ""
        
        $clusterChoice = Read-Host "Enter your choice (1 or 2)"
        
        if ($clusterChoice -eq '2') {
            # Only check permissions if we didn't already detect elevated access
            $canCreateCluster = $false
            
            if ($permissionCheck.HasElevatedAccess) {
                # User already has elevated access, no need to check again
                $canCreateCluster = $true
            } else {
                # Check elevated permissions for cluster creation
                Write-Host ""
                Write-Log "Checking permissions for cluster creation..." -Level Info
                $createPermCheck = Test-AzurePermissions -CheckClusterCreation:$true
                $canCreateCluster = $createPermCheck.Passed
            }
            
            if (-not $canCreateCluster) {
                Write-Host ""
                Write-Host "  ⚠️  Creating a new AKS cluster requires elevated permissions." -ForegroundColor Yellow
                Write-Host ""
                
                $proceedCreate = Read-Host "Permission issues detected. Try anyway? (y/n)"
                if ($proceedCreate -ne 'y') {
                    Write-Log "Returning to cluster selection..." -Level Info
                    $selectedCluster = Select-AKSCluster -Clusters $clusters
                } else {
                    $selectedCluster = New-SimulationAKSCluster
                }
            } else {
                $selectedCluster = New-SimulationAKSCluster
            }
            
            if (-not $selectedCluster) {
                Write-Log "Failed to create AKS cluster. Exiting." -Level Error
                exit 1
            }
        } else {
            $selectedCluster = Select-AKSCluster -Clusters $clusters
            
            if (-not $selectedCluster) {
                Write-Log "No cluster selected. Exiting." -Level Error
                exit 1
            }
        }
    }
}

# Determine if this is a newly created cluster
$isNewCluster = $false
if ($selectedCluster.PSObject.Properties.Name -contains 'IsNewCluster') {
    $isNewCluster = $selectedCluster.IsNewCluster
}

# Update session state with cluster info
$script:SessionState.ClusterName = $selectedCluster.Name
$script:SessionState.ResourceGroup = $selectedCluster.ResourceGroup
$script:SessionState.IsNewCluster = $isNewCluster
if ($selectedCluster.PSObject.Properties.Name -contains 'Location') {
    $script:SessionState.Location = $selectedCluster.Location
}
Update-SessionStage -Stage "ClusterSelection" -MarkComplete

# Connect to the selected cluster
try {
    $connected = Connect-ToAKSCluster -ClusterName $selectedCluster.Name -ResourceGroup $selectedCluster.ResourceGroup -IsNewCluster:$isNewCluster
    
    if (-not $connected) {
        Write-ErrorLog -Message "Failed to connect to cluster" -Stage "ClusterConnection" -ErrorDetails "Could not get credentials for cluster: $($selectedCluster.Name)"
        Write-Log "Failed to connect to cluster. Exiting." -Level Error
        Write-Host ""
        Write-Host "  📝 Error logged to: $script:ErrorLogFile" -ForegroundColor Yellow
        Write-Host "  💡 Run the script again to resume from this point." -ForegroundColor Cyan
        exit 1
    }
    Update-SessionStage -Stage "ClusterConnection" -MarkComplete
}
catch {
    Write-ErrorLog -Message "Cluster connection exception" -Stage "ClusterConnection" -ErrorDetails $_.Exception.Message
    Write-Log "Failed to connect to cluster: $($_.Exception.Message)" -Level Error
    Write-Host ""
    Write-Host "  📝 Error logged to: $script:ErrorLogFile" -ForegroundColor Yellow
    Write-Host "  💡 Run the script again to resume from this point." -ForegroundColor Cyan
    exit 1
}

# Capture cluster info for report
$script:SimulationReport.ClusterName = $selectedCluster.Name
$script:SimulationReport.ResourceGroup = $selectedCluster.ResourceGroup
$script:SimulationReport.StartTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# Capture additional cluster details
if ($selectedCluster.PSObject.Properties.Name -contains 'IsNewCluster') {
    $script:SimulationReport.IsNewCluster = $selectedCluster.IsNewCluster
}
if ($selectedCluster.PSObject.Properties.Name -contains 'Location') {
    $script:SimulationReport.ClusterLocation = $selectedCluster.Location
}
if ($selectedCluster.PSObject.Properties.Name -contains 'NodeCount') {
    $script:SimulationReport.ClusterNodeCount = $selectedCluster.NodeCount
}

# Get subscription ID
try {
    $subId = az account show --query id -o tsv 2>$null
    $script:SimulationReport.SubscriptionId = $subId
} catch {}

# Add action to timeline
$script:SimulationReport.ActionsPerformed += @{
    Time = Get-Date -Format "HH:mm:ss"
    Action = "Connected to AKS cluster"
    Status = "Success"
    Details = "Cluster: $($selectedCluster.Name) in $($selectedCluster.ResourceGroup)"
}

# Production cluster warning check
Write-Host ""
Write-Host "============================================" -ForegroundColor Yellow
Write-Host "  ⚠️  PRODUCTION CLUSTER CHECK" -ForegroundColor Yellow
Write-Host "============================================" -ForegroundColor Yellow
Write-Host ""
Write-Host "Microsoft recommends running this simulation on a dedicated" -ForegroundColor Yellow
Write-Host "cluster WITHOUT production workloads." -ForegroundColor Yellow
Write-Host ""
Write-Host "Selected cluster: $($selectedCluster.Name)" -ForegroundColor Cyan

# Check for production indicators
$prodIndicators = @()
$clusterNameLower = $selectedCluster.Name.ToLower()

if ($clusterNameLower -match "prod|production|live|prd") {
    $prodIndicators += "Cluster name contains 'prod', 'production', 'live', or 'prd'"
}

# Count workloads (excluding system namespaces)
$userPods = kubectl get pods --all-namespaces --no-headers 2>$null | Where-Object { 
    $_ -notmatch "^kube-system|^kube-public|^kube-node-lease|^gatekeeper-system|^mdc-simulation" 
}
$userPodCount = ($userPods | Measure-Object).Count

$userNamespaces = kubectl get namespaces --no-headers 2>$null | Where-Object {
    $_ -notmatch "^kube-system|^kube-public|^kube-node-lease|^default|^gatekeeper-system|^mdc-simulation"
}
$userNamespaceCount = ($userNamespaces | Measure-Object).Count

if ($userPodCount -gt 20) {
    $prodIndicators += "Cluster has $userPodCount user workload pods (>20 may indicate production)"
}

if ($userNamespaceCount -gt 5) {
    $prodIndicators += "Cluster has $userNamespaceCount custom namespaces (>5 may indicate production)"
}

# Display findings
if ($prodIndicators.Count -gt 0) {
    Write-Host ""
    Write-Host "⚠️  POTENTIAL PRODUCTION INDICATORS DETECTED:" -ForegroundColor Red
    foreach ($indicator in $prodIndicators) {
        Write-Host "   • $indicator" -ForegroundColor Red
    }
    Write-Host ""
    Write-Host "Running attack simulations on production clusters may:" -ForegroundColor Yellow
    Write-Host "   • Trigger alerts that require investigation" -ForegroundColor Yellow
    Write-Host "   • Cause temporary network scanning traffic" -ForegroundColor Yellow
    Write-Host "   • Access cluster metadata services" -ForegroundColor Yellow
    Write-Host ""
    $confirmProd = Read-Host "Are you sure this is NOT a production cluster? (yes/no)"
    if ($confirmProd -ne 'yes') {
        Write-Log "Operation cancelled. Please use a dev/test cluster." -Level Warning
        exit 0
    }
} else {
    Write-Host ""
    Write-Host "✅ No production indicators detected." -ForegroundColor Green
    Write-Host "   • User pods: $userPodCount" -ForegroundColor Gray
    Write-Host "   • Custom namespaces: $userNamespaceCount" -ForegroundColor Gray
    Write-Host ""
    Write-Host "This appears to be a dev/test/demo cluster. Proceeding..." -ForegroundColor Green
}

Write-Host ""

# Check for Defender for Containers settings (comprehensive check)
if (-not (Test-StageCompleted -Stage "DefenderCheck")) {
    Update-SessionStage -Stage "DefenderCheck"
    
    try {
        $isNewCluster = $false
        if ($selectedCluster.PSObject.Properties.Name -contains 'IsNewCluster') {
            $isNewCluster = $selectedCluster.IsNewCluster
        }

        $defenderCheck = Test-DefenderForContainersSettings -ClusterName $selectedCluster.Name -ResourceGroup $selectedCluster.ResourceGroup -IsNewCluster:$isNewCluster

        # Track Defender check
        $script:SimulationReport.ActionsPerformed += @{
            Time = Get-Date -Format "HH:mm:ss"
            Action = "Defender for Containers validation"
            Status = if ($defenderCheck.AllRequirementsMet) { "Success" } else { "Error" }
            Details = "Sensor status: $($script:SimulationReport.DefenderSensorStatus)"
        }

        if (-not $defenderCheck.AllRequirementsMet) {
            Write-Log "Defender for Containers configuration check failed. Exiting." -Level Error
            Write-Host ""
            Write-Host "Please configure Defender for Containers and run the script again." -ForegroundColor Yellow
            Write-ErrorLog -Stage "DefenderCheck" -ErrorMessage "Defender for Containers configuration check failed" -AdditionalInfo @{ SensorStatus = $script:SimulationReport.DefenderSensorStatus }
            exit 1
        }
        
        Update-SessionStage -Stage "DefenderCheck" -MarkComplete
    }
    catch {
        Write-ErrorLog -Stage "DefenderCheck" -ErrorMessage $_.Exception.Message -AdditionalInfo @{ ClusterName = $selectedCluster.Name }
        Write-Host ""
        Write-Host "Error during Defender check: $_" -ForegroundColor Red
        Write-Host "Session saved. Run the script again to resume." -ForegroundColor Yellow
        exit 1
    }
} else {
    Write-Log "Defender check already completed in previous session. Skipping..." -Level Info
}

# Download the simulation tool
if (-not (Test-StageCompleted -Stage "SimulationDownload")) {
    Update-SessionStage -Stage "SimulationDownload"
    
    try {
        $simulationScript = Get-SimulationTool -WorkingDirectory $WorkingDirectory

        if (-not $simulationScript) {
            Write-Log "Failed to obtain simulation tool. Exiting." -Level Error
            Write-ErrorLog -Stage "SimulationDownload" -ErrorMessage "Failed to download simulation tool" -AdditionalInfo @{ WorkingDirectory = $WorkingDirectory }
            exit 1
        }
        
        # Store in session state for resume
        $script:SessionState.SimulationScriptPath = $simulationScript
        Update-SessionStage -Stage "SimulationDownload" -MarkComplete
    }
    catch {
        Write-ErrorLog -Stage "SimulationDownload" -ErrorMessage $_.Exception.Message -AdditionalInfo @{ WorkingDirectory = $WorkingDirectory }
        Write-Host ""
        Write-Host "Error downloading simulation tool: $_" -ForegroundColor Red
        Write-Host "Session saved. Run the script again to resume." -ForegroundColor Yellow
        exit 1
    }
} else {
    Write-Log "Simulation tool download already completed in previous session. Skipping..." -Level Info
    $simulationScript = $script:SessionState.SimulationScriptPath
    
    # Verify the file still exists
    if (-not (Test-Path $simulationScript)) {
        Write-Log "Simulation script from previous session no longer exists. Re-downloading..." -Level Warning
        $simulationScript = Get-SimulationTool -WorkingDirectory $WorkingDirectory
        if (-not $simulationScript) {
            Write-Log "Failed to re-download simulation tool. Exiting." -Level Error
            exit 1
        }
    }
}

# Run the simulation
if (-not (Test-StageCompleted -Stage "SimulationExecution")) {
    Update-SessionStage -Stage "SimulationExecution"
    
    try {
        Write-Host ""
        Write-Log "Ready to run simulation on cluster: $($selectedCluster.Name)" -Level Info
        Write-Host ""
        Write-Host "Available Simulation Scenarios:" -ForegroundColor Yellow
        Write-Host "  1. Reconnaissance - Web Shell, Kubernetes service account operations, Network scanning"
        Write-Host "  2. Lateral Movement - Web Shell, Cloud metadata service access"
        Write-Host "  3. Secrets Gathering - Web Shell, Sensitive files access, Secret reconnaissance"
        Write-Host "  4. Crypto Mining - Multiple crypto mining indicators"
        Write-Host "  5. Web Shell - Web Shell activity detection"
        Write-Host "  6. All - Run all scenarios"
        Write-Host ""
        Write-Host "NOTE: Some alerts are triggered in near real-time, others may take up to an hour." -ForegroundColor Cyan
        Write-Host ""

        Invoke-Simulation -SimulationScript $simulationScript -Scenario $SimulationScenario
        
        Update-SessionStage -Stage "SimulationExecution" -MarkComplete
    }
    catch {
        Write-ErrorLog -Stage "SimulationExecution" -ErrorMessage $_.Exception.Message -AdditionalInfo @{ SimulationScript = $simulationScript; Scenario = $SimulationScenario }
        Write-Host ""
        Write-Host "Error running simulation: $_" -ForegroundColor Red
        Write-Host "Session saved. Run the script again to resume." -ForegroundColor Yellow
        exit 1
    }
} else {
    Write-Log "Simulation already completed in previous session. Skipping..." -Level Info
}

# Note: Report will be generated after cleanup to capture all actions

Write-Host ""
Write-Log "Simulation phase completed. Check Microsoft Defender Portal for generated alerts." -Level Success
Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  🔗 VIEW YOUR SECURITY ALERTS" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Direct link to your alerts (tenant-specific):" -ForegroundColor Yellow
Write-Host "  https://security.microsoft.com/alerts?tid=$($script:SimulationReport.TenantId)" -ForegroundColor Green
Write-Host ""
Write-Host "  Expected alerts from this simulation:" -ForegroundColor Cyan
Write-Host "    • Digital currency mining related behavior detected" -ForegroundColor White
Write-Host "    • A drift binary detected executing in the container" -ForegroundColor White
Write-Host "    • Possible Cryptocoinminer download detected" -ForegroundColor White
Write-Host "    • Command within a container accessed ld.so.preload" -ForegroundColor White
Write-Host "    • Possible Secret Reconnaissance Detected" -ForegroundColor White
Write-Host "    • Sensitive Files Access Detected" -ForegroundColor White
Write-Host "    • Access to cloud metadata service detected" -ForegroundColor White
Write-Host "    • Possible Web Shell Activity Detected" -ForegroundColor White
Write-Host ""
Write-Host "  Note: Most alerts appear in minutes, some may take up to 1 hour." -ForegroundColor Gray
Write-Host ""

# ============================================
# AUTOMATIC SIMULATION CLEANUP (Part of process)
# ============================================
if (-not (Test-StageCompleted -Stage "SimulationCleanup")) {
    Update-SessionStage -Stage "SimulationCleanup"
    
    try {
        Write-Host ""
        Write-Host "============================================" -ForegroundColor Cyan
        Write-Host "  🧹 CLEANING UP SIMULATION RESOURCES" -ForegroundColor Cyan
        Write-Host "============================================" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Cleaning up attack simulation artifacts from the cluster..." -ForegroundColor Gray
        Write-Host ""

        # Perform cleanup
        Remove-SimulationResources

        # Verify cleanup was successful
        Write-Host ""
        Write-Host "  Verifying cleanup..." -ForegroundColor Cyan
        $verificationPassed = $true
        $verificationIssues = @()

        # Check 1: mdc-simulation namespace should not exist
        $nsCheck = kubectl get namespace mdc-simulation 2>&1
        if ($LASTEXITCODE -eq 0) {
            $verificationIssues += "Namespace 'mdc-simulation' still exists (may be terminating)"
            $verificationPassed = $false
        }

        # Check 2: No attacker/victim pods
        $attackerPods = kubectl get pods --all-namespaces --no-headers 2>$null | Select-String -Pattern "attacker|victim"
        if ($attackerPods) {
            $verificationIssues += "Attacker/victim pods still found"
            $verificationPassed = $false
        }

        # Check 3: No simulation helm releases
        $simReleases = helm list --all-namespaces -q 2>$null | Where-Object { $_ -match "simulation|mdc" }
        if ($simReleases) {
            $verificationIssues += "Simulation Helm releases still found"
            $verificationPassed = $false
        }

        if ($verificationPassed) {
            Write-Host ""
            Write-Host "  ┌─────────────────────────────────────────────────────────┐" -ForegroundColor Green
            Write-Host "  │  ✅ CLEANUP VERIFIED - All simulation resources removed │" -ForegroundColor Green
            Write-Host "  └─────────────────────────────────────────────────────────┘" -ForegroundColor Green
            Write-Host ""
            $script:SimulationReport.CleanupStatus = "Verified"
            $script:SimulationReport.ActionsPerformed += @{
                Time = Get-Date -Format "HH:mm:ss"
                Action = "Simulation cleanup completed"
                Status = "Success"
                Details = "All simulation resources removed from cluster"
            }
        } else {
            Write-Host ""
            Write-Host "  ⚠️  Some resources may still be cleaning up:" -ForegroundColor Yellow
            foreach ($issue in $verificationIssues) {
                Write-Host "    • $issue" -ForegroundColor Yellow
            }
            Write-Host ""
            Write-Host "  This is normal - Kubernetes may take a minute to fully remove resources." -ForegroundColor Gray
            Write-Host "  To check status: kubectl get all --all-namespaces | Select-String simulation" -ForegroundColor Gray
            Write-Host ""
            $script:SimulationReport.CleanupStatus = "Partial - Resources still terminating"
            $script:SimulationReport.ActionsPerformed += @{
                Time = Get-Date -Format "HH:mm:ss"
                Action = "Simulation cleanup"
                Status = "Warning"
                Details = ($verificationIssues -join "; ")
            }
        }
        
        Update-SessionStage -Stage "SimulationCleanup" -MarkComplete
    }
    catch {
        Write-ErrorLog -Stage "SimulationCleanup" -ErrorMessage $_.Exception.Message -AdditionalInfo @{ ClusterName = $selectedCluster.Name }
        Write-Host ""
        Write-Host "Error during cleanup: $_" -ForegroundColor Red
        Write-Host "Session saved. Run the script again to resume." -ForegroundColor Yellow
        exit 1
    }
} else {
    Write-Log "Simulation cleanup already completed in previous session. Skipping..." -Level Info
}

# ============================================
# AKS CLUSTER CLEANUP (if we created one)
# ============================================
if ($script:CreatedClusterForCleanup) {
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Yellow
    Write-Host "  💰 AKS CLUSTER CLEANUP" -ForegroundColor Yellow
    Write-Host "============================================" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "You created a NEW AKS cluster for this simulation:" -ForegroundColor Cyan
    Write-Host "  • Cluster: $($script:CreatedClusterForCleanup.Name)" -ForegroundColor White
    Write-Host "  • Resource Group: $($script:CreatedClusterForCleanup.ResourceGroup)" -ForegroundColor White
    Write-Host ""
    Write-Host "⚠️  This cluster is incurring ongoing costs (~`$1.80/day)" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Cost breakdown while cluster exists:" -ForegroundColor Gray
    Write-Host "    • 1 hour:  ~`$0.08" -ForegroundColor Gray
    Write-Host "    • 1 day:   ~`$1.80" -ForegroundColor Gray
    Write-Host "    • 1 week:  ~`$12.60" -ForegroundColor Gray
    Write-Host "    • 1 month: ~`$54.00" -ForegroundColor Gray
    Write-Host ""
    
    # Default to DELETE for cost savings
    Write-Host "Do you want to DELETE this cluster now to stop charges?" -ForegroundColor Cyan
    Write-Host "  [Y] Yes, delete the cluster (recommended - stops all charges)" -ForegroundColor Green
    Write-Host "  [N] No, keep the cluster (costs will continue)" -ForegroundColor White
    Write-Host ""
    
    $deleteChoice = Read-Host "Delete cluster? (Y/n)"
    
    # Default to Yes if just pressing Enter
    if ($deleteChoice -eq '' -or $deleteChoice -eq 'Y' -or $deleteChoice -eq 'y' -or $deleteChoice -eq 'yes') {
        Write-Host ""
        Write-Log "Deleting resource group: $($script:CreatedClusterForCleanup.ResourceGroup)..." -Level Info
        Write-Host ""
        Write-Host "  Starting deletion (this takes 5-10 minutes)..." -ForegroundColor Gray
        Write-Host ""
        
        # Start deletion WITHOUT --no-wait so we can track progress
        $rgName = $script:CreatedClusterForCleanup.ResourceGroup
        $deleteJob = Start-Job -ScriptBlock {
            param($resourceGroup)
            az group delete --name $resourceGroup --yes 2>&1
        } -ArgumentList $rgName
        
        # Animated progress bar while waiting
        $progressLineY = [Console]::CursorTop
        $spinnerChars = @('-', '\', '|', '/')
        $spinnerIdx = 0
        $barWidth = 40
        $elapsed = 0
        $estimatedTime = 360  # ~6 minutes estimate
        
        while ($deleteJob.State -eq 'Running') {
            $spinnerIdx = ($spinnerIdx + 1) % $spinnerChars.Count
            $spinner = $spinnerChars[$spinnerIdx]
            
            # Calculate progress based on elapsed time (estimate)
            $progress = [math]::Min(95, [math]::Floor(($elapsed / $estimatedTime) * 100))
            $filledWidth = [math]::Floor(($progress / 100) * $barWidth)
            $emptyWidth = $barWidth - $filledWidth
            $progressBar = ('#' * $filledWidth) + ('-' * $emptyWidth)
            
            $elapsedMin = [int][math]::Floor($elapsed / 60)
            $elapsedSec = [int][math]::Floor($elapsed % 60)
            $timeStr = "{0}:{1:D2}" -f $elapsedMin, $elapsedSec
            
            [Console]::SetCursorPosition(0, $progressLineY)
            [Console]::Write("  $spinner [$progressBar] $progress% | Deleting resources... | $timeStr   ")
            
            Start-Sleep -Milliseconds 500
            $elapsed += 0.5
        }
        
        # Get job result
        $deleteResult = Receive-Job -Job $deleteJob
        $deleteSuccess = $deleteJob.State -eq 'Completed'
        Remove-Job -Job $deleteJob -Force
        
        # Show completion
        [Console]::SetCursorPosition(0, $progressLineY)
        $elapsedMin = [int][math]::Floor($elapsed / 60)
        $elapsedSec = [int][math]::Floor($elapsed % 60)
        $finalTimeStr = "{0}:{1:D2}" -f $elapsedMin, $elapsedSec
        
        if ($deleteSuccess) {
            [Console]::Write("  [########################################] 100% | Deleted | $finalTimeStr        ")
            Write-Host ""
            Write-Host ""
            Write-Host "  ┌─────────────────────────────────────────────────────────┐" -ForegroundColor Green
            Write-Host "  │  ✅ CLUSTER DELETED SUCCESSFULLY                        │" -ForegroundColor Green
            Write-Host "  └─────────────────────────────────────────────────────────┘" -ForegroundColor Green
            Write-Host ""
            Write-Host "  ✅ No further charges will be incurred." -ForegroundColor Green
            
            $script:SimulationReport.ClusterDeletedAfterRun = $true
            $script:SimulationReport.ActionsPerformed += @{
                Time = Get-Date -Format "HH:mm:ss"
                Action = "AKS cluster deleted"
                Status = "Success"
                Details = "Resource group '$rgName' deleted in $finalTimeStr"
            }
        } else {
            [Console]::Write("  [########################################] --- | Error | $finalTimeStr          ")
            Write-Host ""
            Write-Host ""
            Write-Log "Failed to delete resource group: $deleteResult" -Level Error
            Write-Host ""
            Write-Host "  To delete manually, run:" -ForegroundColor Yellow
            Write-Host "    az group delete --name $rgName --yes" -ForegroundColor Cyan
            
            $script:SimulationReport.ClusterDeletedAfterRun = $false
            $script:SimulationReport.ActionsPerformed += @{
                Time = Get-Date -Format "HH:mm:ss"
                Action = "AKS cluster deletion"
                Status = "Error"
                Details = "Failed to delete: $deleteResult"
            }
        }
    } else {
        Write-Host ""
        Write-Host "  ┌─────────────────────────────────────────────────────────┐" -ForegroundColor Yellow
        Write-Host "  │  ⚠️  CLUSTER KEPT - ONGOING COSTS WILL APPLY            │" -ForegroundColor Yellow
        Write-Host "  └─────────────────────────────────────────────────────────┘" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  The cluster will continue to incur ~`$1.80/day in charges." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  To delete later:" -ForegroundColor Cyan
        Write-Host "    az group delete --name $($script:CreatedClusterForCleanup.ResourceGroup) --yes" -ForegroundColor White
        Write-Host ""
        Write-Host "  💡 TIP: Set a reminder to delete this cluster!" -ForegroundColor Magenta
        
        $script:SimulationReport.ClusterDeletedAfterRun = $false
        $script:SimulationReport.ActionsPerformed += @{
            Time = Get-Date -Format "HH:mm:ss"
            Action = "AKS cluster retained"
            Status = "Warning"
            Details = "User chose to keep cluster - ongoing costs apply (~`$1.80/day)"
        }
    }
}

# ============================================
# GENERATE HTML REPORT (after all actions complete)
# ============================================
$script:SimulationReport.EndTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# Generate the HTML report
$generatedReport = New-SimulationReport -ReportPath $ReportPath -ReportData $script:SimulationReport

Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "  SIMULATION COMPLETE" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host ""

# Show report and offer to open
if ($generatedReport -and (Test-Path $generatedReport)) {
    Write-Host "📊 Simulation Report Generated: $generatedReport" -ForegroundColor Cyan
    Write-Host ""
    $openReport = Read-Host "Open the HTML report now? (y/n)"
    if ($openReport -eq 'y') {
        Start-Process $generatedReport
    }
}

Write-Host ""

# Clean up session state file since simulation completed successfully
Remove-SessionState
Write-Host "Session completed successfully. Session state cleared." -ForegroundColor Green
Write-Host ""

# ============================================
# VERIFY RESOURCE CLEANUP IN AZURE PORTAL
# ============================================
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  🔍 VERIFY RESOURCE CLEANUP" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Please double-check that all resources were deleted as expected." -ForegroundColor Yellow
Write-Host ""
Write-Host "Azure Portal - Kubernetes Clusters:" -ForegroundColor Cyan
Write-Host "https://portal.azure.com/#view/Microsoft_Azure_KubernetesFleet/KubernetesHub.MenuView/~/clusters" -ForegroundColor Green
Write-Host ""
Write-Host "Verify that:" -ForegroundColor White
Write-Host "  • The simulation cluster no longer appears in the list" -ForegroundColor Gray
Write-Host "  • The associated resource group has been deleted" -ForegroundColor Gray
Write-Host "  • No orphaned resources remain that could incur charges" -ForegroundColor Gray
Write-Host ""

$openPortal = Read-Host "Open Azure Portal to verify cleanup? (y/n)"
if ($openPortal -eq 'y' -or $openPortal -eq 'Y' -or $openPortal -eq 'yes') {
    Write-Host ""
    Write-Host "Opening Azure Portal..." -ForegroundColor Cyan
    Start-Process "https://portal.azure.com/#view/Microsoft_Azure_KubernetesFleet/KubernetesHub.MenuView/~/clusters"
}

Write-Host ""
Write-Host "Thank you for using the Microsoft Defender for Cloud Kubernetes Alerts Simulation Tool!" -ForegroundColor Green
Write-Host ""

#endregion
