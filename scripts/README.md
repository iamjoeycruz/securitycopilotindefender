# Scripts

> **⚠️ DISCLAIMER:** All scripts in this directory are provided "AS IS" without warranty of any kind. They are for educational and experimental purposes only and are NOT officially supported by Microsoft. Always review scripts before running them. Test in non-production environments first. See the [repository disclaimer](../README.md#-disclaimer) for full details.

## Available Scripts

| Script | Description | Modifies Resources? |
|--------|-------------|---------------------|
| [`Deploy-KubernetesAlertSimulation.ps1`](Deploy-KubernetesAlertSimulation.ps1) | Runs Defender for Cloud K8s attack simulations | Yes — creates test pods on AKS |
| [`Get-DefenderIncidentReport.ps1`](Get-DefenderIncidentReport.ps1) | Generates HTML reports for Defender incidents via Microsoft Graph | No — read-only |
| [`Investigate-PhishingTriageAgentTagRemoval.ps1`](Investigate-PhishingTriageAgentTagRemoval.ps1) | Diagnoses Phishing Triage Agent tag stripping | No — read-only |

---

## Investigate-PhishingTriageAgentTagRemoval.ps1

Diagnoses whether the Security Copilot Phishing Triage Agent (or other services like Defender XDR alert correlation) is stripping tags/labels from Microsoft Sentinel incidents. Produces a comprehensive HTML report with findings, KQL evidence, impacted incidents, and remediation steps.

**This script is read-only — it does NOT modify any resources in your environment.**

### Prerequisites

| Requirement | Details |
|-------------|---------|
| **PowerShell** | 7.0 or later (`pwsh`). Check with `$PSVersionTable.PSVersion` |
| **Azure Modules** | `Az.Accounts`, `Az.SecurityInsights`, `Az.Monitor`, `Az.OperationalInsights` |
| **Azure Permissions** | **Microsoft Sentinel Reader** (or higher) on the target workspace |
| **Network** | Access to `management.azure.com` and `api.loganalytics.io` |

#### Install modules (one-time)

```powershell
Install-Module Az.Accounts, Az.SecurityInsights, Az.Monitor, Az.OperationalInsights -Scope CurrentUser -Force
```

### How to Run

#### Option A: Interactive mode (recommended for first-time users)

Just run the script with no parameters — it walks you through everything:

```powershell
.\Investigate-PhishingTriageAgentTagRemoval.ps1
```

The wizard will:
1. Check that required modules are installed
2. Authenticate to Azure (or reuse an existing session)
3. List your subscriptions and ask you to pick one
4. List Sentinel-enabled workspaces and ask you to pick one
5. Show tags currently in use and ask which ones you expect to be present
6. Ask how many days back to scan (default: 7)
7. Run the diagnostic (usually takes 30–90 seconds)
8. Generate and save an HTML report

#### Option B: Parameterized mode (for automation or repeat runs)

Pass all required values on the command line to skip the interactive prompts:

```powershell
.\Investigate-PhishingTriageAgentTagRemoval.ps1 `
    -SubscriptionId "your-subscription-id" `
    -ResourceGroupName "your-resource-group" `
    -WorkspaceName "your-workspace-name" `
    -ExpectedTags "AutoEscalate","Tier2-Review","VIP-Customer"
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `-SubscriptionId` | No* | Azure subscription ID containing your Sentinel workspace |
| `-ResourceGroupName` | No* | Resource group containing the workspace |
| `-WorkspaceName` | No* | Name of the Log Analytics workspace with Sentinel enabled |
| `-ExpectedTags` | No | Array of tag names your automation depends on |

\* Required only if you want to skip the interactive prompts.

### What to Expect

```
[1/6] Checking prerequisites          — verifies Az modules are installed
[2/6] Connecting to Azure              — authenticates (or reuses session)
[3/6] Finding Sentinel workspaces      — auto-discovers workspace
[4/6] Gathering tag info               — asks scan window and expected tags
[5/6] Running diagnostics              — REST API scan + KQL queries
  [5a] Azure Activity Log ...          — checks for agent identity writes
  [5b] Sentinel incident scan ...      — scans incidents for missing tags
  [5c] KQL deep-dive ...               — runs 4 analytic queries
[6/6] Generating report                — saves HTML report
```

### Output

The script saves an HTML report to your current directory:

```
PhishingTriageAgent_Report_YYYYMMDD_HHMMSS.html
```

The report includes:
- **Executive Summary** — verdict, key stats, impacted incidents table
- **Who Is Removing Tags?** — table of actors/services that stripped tags, with counts
- **Incidents With Tags Stripped** — clickable table of affected incidents
- **KQL Evidence** — copy-pastable KQL queries you can run directly in Sentinel
- **Remediation Steps** — 5 recommended actions with links to deployment scripts

Open the report in any browser:

```powershell
Start-Process ".\PhishingTriageAgent_Report_*.html"
```

### Troubleshooting

| Issue | Solution |
|-------|----------|
| `Module not found` | Run `Install-Module Az.Accounts -Scope CurrentUser -Force` |
| `Get-AzAccessToken` returns error | Run `Connect-AzAccount` to re-authenticate |
| Script hangs on large workspace | Normal — large workspaces (10K+ incidents) take longer. Use `-DaysBack 3` to narrow the scan window |
| `WARNING: Unable to acquire token for tenant` | Safe to ignore — these are tenants your account can't access automatically |
| All stats show 0 | Check that the workspace has Sentinel enabled and incidents exist in the scan window |

---

## Deploy-KubernetesAlertSimulation.ps1

See the [main README](../README.md#kubernetes-alert-simulation) and the [Complete Walkthrough Guide](../docs/Kubernetes-Alert-Simulation-Guide.md) for detailed instructions.

```powershell
.\Deploy-KubernetesAlertSimulation.ps1
```

---

## Get-DefenderIncidentReport.ps1

Generates HTML reports for Defender incidents via Microsoft Graph.

```powershell
# Get help
Get-Help .\Get-DefenderIncidentReport.ps1 -Detailed

# Run for a specific incident
.\Get-DefenderIncidentReport.ps1 -IncidentId 256968
```

**Requirements:** `Microsoft.Graph.Security`, `Microsoft.Graph.Authentication` modules and `SecurityIncident.Read.All` + `SecurityAlert.Read.All` permissions.
