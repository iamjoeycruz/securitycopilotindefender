# Scripts

> **⚠️ DISCLAIMER:** All scripts in this directory are provided "AS IS" without warranty of any kind. They are for educational and experimental purposes only and are NOT officially supported by Microsoft. Always review scripts before running them. Test in non-production environments first. See the [repository disclaimer](../README.md#-disclaimer) for full details.

## Available Scripts

| Script | Description | Modifies Resources? |
|--------|-------------|---------------------|
| [`Diagnose-And-Remediate-PhishingTriageAgentTags.ps1`](Diagnose-And-Remediate-PhishingTriageAgentTags.ps1) | Diagnoses & remediates Phishing Triage Agent tag stripping | Optional — use `-DiagnosticOnly` for read-only |
| [`Deploy-KubernetesAlertSimulation.ps1`](Deploy-KubernetesAlertSimulation.ps1) | Runs Defender for Cloud K8s attack simulations | Yes — creates test pods on AKS |
| [`Get-DefenderIncidentReport.ps1`](Get-DefenderIncidentReport.ps1) | Generates HTML reports for Defender incidents via Microsoft Graph; auto-discovers phishing triage agent incidents | No — read-only |

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

Retrieves incident and alert data from Microsoft Defender XDR using the Microsoft Graph Security API and generates a comprehensive, interactive HTML report. Designed to surface **Security Copilot Phishing Triage Agent** activity — including automated classifications, verdicts, and evidence analysis — in a single, shareable document.

### What It Does

1. **Connects to Microsoft Graph** — authenticates with `SecurityIncident.Read.All` and `SecurityAlert.Read.All` scopes (installs the Graph modules automatically if missing)
2. **Finds the incident** — either by a specific Incident ID you provide, or by **automatically discovering the most recent phishing triage agent incident** (matching "Email reported by user as malware or phish" display names, then falling back to system/custom tag checks for `Phish`, `Triage`, or `Agent` tags)
3. **Retrieves incident details** — pulls incident metadata, associated alerts, system tags, custom tags, and phishing triage indicators from both v1.0 and beta Graph endpoints
4. **Retrieves alert details** — fetches the most recent alert's full evidence chain (mailbox, analyzed message, IP, user, mail cluster evidence), MITRE ATT&CK techniques, classification, determination, and detection source
5. **Collects alert activity timeline** — gathers status changes, classifications, investigation state, and analyst comments
6. **Retrieves Security Copilot activity data** — attempts to pull automated triage results including verdict, confidence level, and entity analysis from Copilot/investigation APIs
7. **Generates an interactive HTML report** — produces a styled, expandable report with:
   - Incident overview with severity, status, and tags
   - Phishing Triage Agent detection banner (when agent involvement is found)
   - Full alert details with evidence items
   - Activity timeline
   - Security Copilot activity section (classification results, prompts, entity analysis)
   - Summary statistics
   - Report generation flow (documenting every API call made)
   - Embedded JSON data with copy-to-clipboard
8. **Exports JSON** — saves a separate `.json` file with all collected data for integration with other tools

### Sample Report

An anonymized sample report is included: [`sample-report.html`](sample-report.html). Download and open it in a browser to see what the output looks like.
<img width="3205" height="1438" alt="image" src="https://github.com/user-attachments/assets/ddaf7607-69c6-4a15-bf27-edf8be0e3077" />

### How to Run

#### Option A: Auto-discover most recent phishing triage incident (no ID needed)

```powershell
.\Get-DefenderIncidentReport.ps1
```

The script will search the 50 most recent incidents for one matching phishing triage agent patterns and generate a report automatically.

#### Option B: Specific incident ID

```powershell
.\Get-DefenderIncidentReport.ps1 -IncidentId 256968
```

#### Option C: Specific tenant and output path

```powershell
.\Get-DefenderIncidentReport.ps1 -IncidentId 256968 -TenantId "your-tenant-id" -OutputPath "C:\Reports\my_report" -Format HTML
```

### Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `-IncidentId` | No | The incident ID to retrieve. If omitted, auto-discovers the most recent phishing triage incident |
| `-TenantId` | No | Azure AD Tenant ID (GUID). If omitted, uses automatic tenant detection |
| `-OutputPath` | No | Full path for the report (without extension). If omitted, saves to temp directory and opens in browser |
| `-Format` | No | `HTML` (default) or `Text` |

### Prerequisites

| Requirement | Details |
|-------------|---------|
| **PowerShell** | 7.0 or later (`pwsh`) |
| **Graph Modules** | `Microsoft.Graph.Security`, `Microsoft.Graph.Authentication` (auto-installed if missing) |
| **Permissions** | `SecurityIncident.Read.All`, `SecurityAlert.Read.All` |
| **Network** | Access to `graph.microsoft.com` |

### What to Expect

```
[Auth]        Connect to Microsoft Graph (browser sign-in on first run)
[Discovery]   Auto-find phishing triage incident (if no ID provided)
[Incident]    Retrieve incident + tags + phishing triage indicators
[Alert]       Retrieve most recent alert + evidence + classification
[Activities]  Retrieve alert activity timeline
[Copilot]     Retrieve Security Copilot activity data (if available)
[Report]      Generate HTML report + JSON export → opens in browser
```

### Output

The script saves two files:

```
DefenderReport_YYYYMMDD_HHMMSS.html   — Interactive HTML report
DefenderReport_YYYYMMDD_HHMMSS.json   — Machine-readable JSON export
```

The HTML report includes:
- **Incident Overview** — ID, display name, severity, status, classification, determination, tags
- **Phishing Triage Agent Banner** — highlighted when system/custom tags indicate agent involvement (e.g., "Credential Phish", "Agent")
- **Alert Details** — full alert metadata, MITRE techniques, detection/service source
- **Evidence** — mailbox, analyzed message, IP, user, and mail cluster evidence with verdicts
- **Activity Timeline** — status changes, classifications, investigation state
- **Security Copilot Activity** — automated triage results, prompts, verdicts, entity analysis
- **Summary Statistics** — alert counts by severity, evidence item counts
- **Report Generation Flow** — every PowerShell command and Graph API call documented with timestamps
- **JSON Data Export** — embedded JSON with copy-to-clipboard button

### Troubleshooting

| Issue | Solution |
|-------|----------|
| `Module not found` | The script auto-installs Graph modules; if that fails, run `Install-Module Microsoft.Graph.Security -Scope CurrentUser -Force` manually |
| Auth window hidden | WAM (Web Account Manager) may open the browser behind other windows — check your taskbar |
| `User canceled authentication` | The browser auth prompt was closed. Re-run the script and complete sign-in |
| `No recent phishing triage incidents found` | No incidents matching "Email reported by user as malware or phish" exist in the last 50 incidents. Provide an `-IncidentId` manually |
| `Authentication needed` | Your Graph session expired. The script will re-authenticate on next run |
| `Security Copilot API not available` | Normal if Copilot isn't enabled. The report will still include incident/alert data |
