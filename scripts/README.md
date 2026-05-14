# Scripts

> **⚠️ DISCLAIMER:** All scripts in this directory are provided "AS IS" without warranty of any kind. They are for educational and experimental purposes only and are NOT officially supported by Microsoft. Always review scripts before running them. Test in non-production environments first. See the [repository disclaimer](../README.md#-disclaimer) for full details.

## Available Scripts

| Script | Description | Modifies Resources? |
|--------|-------------|---------------------|
| [`Diagnose-And-Remediate-PhishingTriageAgentTags.ps1`](Diagnose-And-Remediate-PhishingTriageAgentTags.ps1) | Diagnoses & remediates Phishing Triage Agent tag stripping | Optional — use `-DiagnosticOnly` for read-only |
| [`Deploy-KubernetesAlertSimulation.ps1`](Deploy-KubernetesAlertSimulation.ps1) | Runs Defender for Cloud K8s attack simulations | Yes — creates test pods on AKS |
| [`Get-DefenderIncidentReport.ps1`](Get-DefenderIncidentReport.ps1) | Generates HTML reports for Defender incidents via Microsoft Graph; auto-discovers phishing triage agent incidents | No — read-only |
| [`Get-PTAReport.ps1`](Get-PTAReport.ps1) | Bulk Phishing Triage Agent gap analysis across all user-reported phishing incidents in the last N days; produces MTTT/MTTR metrics, inferred failure root cause, and an interactive HTML dashboard | No — read-only |

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

### Consuming Phishing Triage Agent output in a SIEM

This script calls the Microsoft Graph Security API (`/security/incidents` and
`/security/alerts_v2`, v1.0 + beta) to pull everything the Phishing Triage Agent
(PTA) writes back to an incident. The agent's internal reasoning and workflow
are intentionally not exposed, but its **decision artifacts are standard
incident/alert fields** — which means any SIEM that already ingests Defender XDR
data is already receiving PTA output. You just need to key your rules on the
right fields.

**What PTA emits (and what this script extracts):**

- `classification` — agent verdict (e.g. `TruePositive`, `FalsePositive`)
- `determination` — threat category (e.g. `Phishing`, `NotMalicious`)
- `status` — auto-resolved vs. still active
- `systemTags` / `customTags` (beta endpoint only) — agent-applied labels;
  detect PTA involvement by matching patterns like `Phish`, `Triage`, or `Agent`
- `assignedTo` — the agent identity when it owns the incident
- `comments` — short rationale the agent writes back to the incident
- `lastUpdateDateTime` — timestamp of the agent's action
- `recommendedActions` and per-entity `evidence[].verdict` / `remediationStatus`

**How a SIEM consumes the same data:**

1. **Pull model** — the SIEM polls the Graph Security incidents/alerts REST API
   (the path this script uses). Most common integration; carries all fields above.
2. **Push model** — the Defender XDR Streaming API ships Advanced Hunting tables
   (`AlertInfo`, `AlertEvidence`, `EmailEvents`, `UrlClickEvents`) to an Event
   Hub or storage account; agent-driven classification and status changes
   appear there as alert updates.
3. **Via Microsoft Sentinel** — the Defender XDR connector forwards incidents
   (including tags, classification, determination) and the SIEM ingests from
   Sentinel.
4. **Event-driven** — a webhook / Logic App on incident update can push a
   slimmed payload (incident ID, classification, determination, systemTags,
   comment) to a SIEM HTTP collector when you want a dedicated "PTA verdict"
   event rather than a full incident record.

**Recommended detection predicate** (mirrors `Get-IncidentDetails` in this
script):

```
displayName contains "Email reported by user as malware or phish"
  OR any systemTag matches /Phish|Triage/i
  OR any customTag matches /Agent|Phish|Triage/i
```

Then surface `classification` + `determination` + the matching tag as the agent
verdict. Key correlation/dedupe on `incidentId` + `lastUpdateDateTime`.

---

## Get-PTAReport.ps1

Bulk **Phishing Triage Agent (PTA) gap-analysis report** across every user-reported phishing
incident in the last *N* days. Produces an interactive HTML dashboard plus a CSV export,
with MTTT/MTTR timing metrics, per-incident PTA verdicts, and an **inferred root cause**
for any incident the agent failed to process.

Unlike [`Get-DefenderIncidentReport.ps1`](Get-DefenderIncidentReport.ps1) (single incident,
deep evidence), this script is **cross-incident** — it answers “how is the agent doing
overall?” and “which submissions slipped through?”

See [`sample-pta-report.html`](sample-pta-report.html) for a fully anonymized example output.

### What the report includes

- **Stat tiles**: total submissions, addressed-by-PTA %, resolved (FP) %, true positives, not-processed, failed, MTTT, MTTR
- **Daily activity chart** (Chart.js): FP / TP / Missed / Failed counts per day
- **Submission Outcomes table**: every submission grouped by what happened to it (addressed FP/TP, failed, ZAPed, deleted, not-junk, no incident, etc.)
- **Not Processed table**: incidents the agent never touched
- **Failed table** with an **Inferred Root Cause** column. Categories (priority order):
  1. `Reported email unavailable for analysis` — highest confidence; stub-only `analyzedMessageEvidence` pattern (no MIME body, no URLs/attachments, sentinel sender IP)
  2. `Preempted by other automation` — another playbook modified the incident after PTA was assigned
  3. `Agent error (see comments)` — a comment contains failure / permission / error language
  4. `Agent did not complete` — alert stuck in `inProgress` or `new` beyond expected SLA
  5. `Insufficient signal` — very sparse evidence
  6. `Investigation Required` — no signals could be inferred; open the incident's Tasks panel in the Defender portal for the Copilot message
- **Clickable portal links** for every incident and reporting user

### How it works

1. **Authenticate** via `Microsoft.Graph.Authentication` (WAM on Windows). Requests only
   `SecurityIncident.Read.All` + `SecurityAlert.Read.All` by default; `ThreatSubmission.Read.All`
   is added only when `-FetchSubmissions` is used (avoids an MSAL incremental-consent re-prompt).
2. **Page through `/security/incidents`** (v1.0) filtered on title “Email reported by user…”,
   stopping when the oldest result crosses the `-Days` window. Console shows live page progress.
3. **Pre-fetch beta details** in batches via `/beta/$batch` for every matched incident + its
   first alert, so the per-incident analysis loop avoids N+1 round-trips.
4. **Classify each incident** by examining system tags, custom tags, alert classification,
   evidence shape, and incident age. Produces a `PTAStatus` of `Processed`, `Missed`, or `Failed`
   and (for failures) a short `RootCause` plus a longer `FailureReason` with the diagnostic evidence.
5. **Compute metrics**: MTTT (incident-created → phishing alert resolved) and MTTR
   (incident-created → incident resolved). Reports median, average, min, max.
6. **Render** an HTML dashboard with Chart.js and an Excel-friendly CSV. The HTML opens in your
   default browser automatically.

### Prerequisites

| Requirement | Details |
|-------------|---------|
| **PowerShell** | 7.0 or later (`pwsh`). Check with `$PSVersionTable.PSVersion` |
| **Graph Modules** | `Microsoft.Graph.Authentication`, `Microsoft.Graph.Security` |
| **Graph Permissions** | `SecurityIncident.Read.All`, `SecurityAlert.Read.All` (delegated). `ThreatSubmission.Read.All` only with `-FetchSubmissions` |
| **Defender role** | Read-only role that grants visibility into user-reported phishing incidents (e.g., Security Reader) |
| **Network** | Access to `graph.microsoft.com` |

#### Install modules (one-time)

```powershell
Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.Security -Scope CurrentUser -Force
```

### How to Run

#### Option A: Default (last 30 days, full report)

```powershell
.\Get-PTAReport.ps1
```

#### Option B: Custom window

```powershell
.\Get-PTAReport.ps1 -Days 14
```

#### Option C: Failures only (fast, focused triage view)

```powershell
.\Get-PTAReport.ps1 -Days 30 -FailuresOnly
```

Only emits incidents where `PTAStatus = Failed`. The HTML title, file name, and console
banner are tagged with `(Failures Only)`. Exits early with a friendly message if there are
no failures in the window.

#### Option D: Pin a tenant / output folder

```powershell
.\Get-PTAReport.ps1 -Days 30 -TenantId "<tenant-guid>" -OutputPath "C:\Reports"
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `-Days` | No | Look-back window in days. Default: `30` |
| `-FailuresOnly` | No | Restrict the report to incidents PTA failed to process |
| `-TenantId` | No | Azure AD tenant GUID for multi-tenant accounts |
| `-OutputPath` | No | Output directory. Default: `Desktop\Performance Dashboard Analysis` |
| `-FetchSubmissions` | No | Also call `/security/threatSubmission/emailThreats` for stronger user-submission correlation |
| `-SubmissionsCsv` | No | Path to a pre-exported submissions CSV (skips the live Graph call) |

### What gets written

- `PTAReport_<timestamp>.html` — interactive dashboard, opens automatically
- `PTAReport_<timestamp>.csv` — row per incident with `PTAStatus`, `RootCause`, `FailureReason`, classification, timing
- `PTAReport_Failures_<timestamp>.{html,csv}` — when `-FailuresOnly` is used

### Notes & gotchas

- The `/security/incidents` endpoint does not support server-side filtering on title, so the
  script pages through all incidents in the window and filters client-side. Large tenants
  with thousands of daily incidents will take several minutes.
- Microsoft Graph throttling (HTTP 429) is handled with exponential backoff. If a single
  incident's beta detail call is throttled repeatedly, the script may pause for up to a
  few minutes per affected incident.
- The `Inferred Root Cause` column is **heuristic**. Graph does not expose the agent's
  failure reason directly; always validate against the Tasks panel in the Defender portal.
- The HTML report includes a prominent disclaimer banner reminding viewers that numbers
  may not be accurate or complete.


