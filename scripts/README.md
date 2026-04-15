# Scripts

> **⚠️ DISCLAIMER:** All scripts in this directory are provided "AS IS" without warranty of any kind. They are for educational and experimental purposes only and are NOT officially supported by Microsoft. Always review scripts before running them. Test in non-production environments first. See the [repository disclaimer](../README.md#-disclaimer) for full details.

## Available Scripts

| Script | Description | Modifies Resources? |
|--------|-------------|---------------------|
| [`Diagnose-And-Remediate-PhishingTriageAgentTags.ps1`](Diagnose-And-Remediate-PhishingTriageAgentTags.ps1) | Diagnoses & remediates Phishing Triage Agent tag stripping | Optional — use `-DiagnosticOnly` for read-only |
| [`Deploy-KubernetesAlertSimulation.ps1`](Deploy-KubernetesAlertSimulation.ps1) | Runs Defender for Cloud K8s attack simulations | Yes — creates test pods on AKS |
| [`Get-DefenderIncidentReport.ps1`](Get-DefenderIncidentReport.ps1) | Generates HTML reports for Defender incidents via Microsoft Graph | No — read-only |

---

## Diagnose-And-Remediate-PhishingTriageAgentTags.ps1

Diagnoses whether the Security Copilot Phishing Triage Agent is stripping tags/labels from Microsoft Sentinel incidents, and optionally **restores the missing tags**. Uses KQL-first server-side queries for scale — handles workspaces with thousands of incidents efficiently. Produces a comprehensive HTML report with findings, KQL evidence, and remediation results.

### Modes

| Mode | Flag | What it does |
|------|------|-------------|
| **Diagnostic only** | `-DiagnosticOnly` | Read-only scan. Generates a report showing impacted incidents and what needs fixing. No resources are modified. |
| **Diagnose + Remediate** | *(default)* | Scans for impacted incidents, shows findings, then asks for explicit admin approval (two gates) before restoring missing tags. |

### Prerequisites

| Requirement | Details |
|-------------|---------|
| **PowerShell** | 7.0 or later (`pwsh`). Check with `$PSVersionTable.PSVersion` |
| **Azure Modules** | `Az.Accounts` |
| **Azure Permissions** | **Microsoft Sentinel Reader** for diagnostic-only, **Microsoft Sentinel Contributor** for remediation |
| **Network** | Access to `management.azure.com` |

#### Install modules (one-time)

```powershell
Install-Module Az.Accounts -Scope CurrentUser -Force
```

### How to Run

#### Option A: Diagnostic only (recommended first run)

```powershell
.\Diagnose-And-Remediate-PhishingTriageAgentTags.ps1 -DiagnosticOnly
```

#### Option B: Interactive mode with remediation

```powershell
.\Diagnose-And-Remediate-PhishingTriageAgentTags.ps1
```

The wizard will:
1. Check that required modules are installed
2. Authenticate to Azure (or reuse an existing session)
3. List your subscriptions and ask you to pick one
4. List Sentinel-enabled workspaces and ask you to pick one
5. Show tags currently in use and ask which ones you expect to be present
6. Ask how many days back to scan (default: 7)
7. Run KQL-first diagnostics (usually takes 30–90 seconds)
8. Show findings and ask for approval (Gate 1: Y/N, Gate 2: type "I ACCEPT")
9. Restore missing tags and generate HTML report with audit trail

#### Option C: Parameterized mode (for automation or repeat runs)

```powershell
.\Diagnose-And-Remediate-PhishingTriageAgentTags.ps1 `
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
| `-DiagnosticOnly` | No | Run in read-only mode (no remediation) |
| `-DaysBack` | No | Number of days to scan (default: 7) |
| `-IncidentIds` | No | Scope to specific incident IDs |

\* Required only if you want to skip the interactive prompts.

### What to Expect

```
[1/6] Checking prerequisites          — verifies Az.Accounts is installed
[2/6] Connecting to Azure              — authenticates (or reuses session)
[3/6] Finding Sentinel workspaces      — auto-discovers workspace
[4/6] Gathering tag info               — asks scan window and expected tags
[5/6] Running diagnostics              — KQL-first scan
  [5a] Azure Activity Log ...          — checks for agent identity writes
  [5b] KQL incident statistics ...     — scans phishing incidents via KQL
  [5c] KQL deep-dive ...               — tag history & actor identification
[6/6] Generating report                — saves HTML report + optional remediation
```

### Output

The script saves an HTML report to your current directory:

```
PhishingTriageAgent_DiagnoseRemediate_YYYYMMDD_HHMMSS.html
```

The report includes:
- **Executive Summary** — verdict, key stats, impacted incidents
- **Who Is Removing Tags?** — actors/services that stripped tags, with counts
- **Tag History Per Incident** — KQL-identified incidents where agent removed tags
- **KQL Evidence** — copy-pastable KQL queries you can run directly in Sentinel Logs
- **Remediation Results** — what was fixed (if remediation was run)

Open the report in any browser:

```powershell
Start-Process ".\PhishingTriageAgent_DiagnoseRemediate_*.html"
```

### Troubleshooting

| Issue | Solution |
|-------|----------|
| `Module not found` | Run `Install-Module Az.Accounts -Scope CurrentUser -Force` |
| `Get-AzAccessToken` returns error | Run `Connect-AzAccount` to re-authenticate |
| Script hangs on large workspace | Normal for very large workspaces. Use `-DaysBack 3` to narrow the scan window |
| `WARNING: Unable to acquire token for tenant` | Safe to ignore — these are tenants your account can't access automatically |
| All stats show 0 | Check that the workspace has Sentinel enabled and phishing incidents exist in the scan window |

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
