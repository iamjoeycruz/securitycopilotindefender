# Security Copilot in Defender — Tools & Remediation

> **🚨 NOT OFFICIAL MICROSOFT DOCUMENTATION**
>
> This repository is an **unofficial, community-driven** collection of scripts and templates created for **educational and experimental purposes only**. It is **not** affiliated with, endorsed by, or representative of Microsoft in any official capacity.
>
> **For official Microsoft documentation, visit: [https://learn.microsoft.com](https://learn.microsoft.com)**
>
> - [Microsoft Sentinel Documentation](https://learn.microsoft.com/en-us/azure/sentinel/)
> - [Microsoft Defender XDR Documentation](https://learn.microsoft.com/en-us/defender-xdr/)
> - [Security Copilot Documentation](https://learn.microsoft.com/en-us/security-copilot/)
>
> Nothing in this repository should be interpreted as official guidance, best practices, or supported solutions from Microsoft. See the [full Disclaimer](#-disclaimer) below.

Unofficial PowerShell scripts, ARM templates, and playbooks to help security administrators simulate threats, diagnose issues, and remediate known problems in Microsoft Defender and Microsoft Sentinel environments.

---

## 🚀 Getting Started

### Prerequisites

| Requirement | Details |
|-------------|---------|
| **PowerShell 7+** | [Install PowerShell](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell). Check with `$PSVersionTable.PSVersion` |
| **Azure PowerShell Modules** | See individual script requirements below |
| **Azure Permissions** | At minimum **Sentinel Reader** (diagnostic) or **Sentinel Contributor** (remediation) |
| **Git** | To clone this repo |

### Step 1: Clone the Repository

```powershell
git clone https://github.com/iamjoeycruz/securitycopilotindefender.git
cd securitycopilotindefender
```

### Step 2: Install Azure PowerShell Modules

```powershell
# For the diagnostic + remediation script
Install-Module Az.Accounts -Scope CurrentUser -Force

# For the automation rule deployment script (only needs Az.Accounts)
Install-Module Az.Accounts -Scope CurrentUser -Force
```

### Step 3: Authenticate to Azure

```powershell
Connect-AzAccount
```

> If your Sentinel workspace is in a specific tenant, use: `Connect-AzAccount -TenantId "your-tenant-id"`

### Step 4: Run the Tool You Need

| Goal | Command |
|------|---------|
| **Diagnose & remediate** stripped tags | `.\scripts\Diagnose-And-Remediate-PhishingTriageAgentTags.ps1` |
| **Diagnose only** (read-only report) | `.\scripts\Diagnose-And-Remediate-PhishingTriageAgentTags.ps1 -DiagnosticOnly` |
| **Prevent future** stripping (Automation Rule) | `.\remediation\Deploy-TagProtectionAutomationRule.ps1` |

All scripts support **interactive mode** (no parameters — walks you through everything) and **parameterized mode** (pass all values for automation). See the individual sections below for detailed instructions.

---

## 📂 Repository Structure

```
├── scripts/                         # PowerShell diagnostic & simulation scripts
│   ├── Diagnose-And-Remediate-PhishingTriageAgentTags.ps1  # ⭐ Diagnose + fix
│   ├── Deploy-KubernetesAlertSimulation.ps1
│   └── Get-DefenderIncidentReport.ps1
│
├── remediation/                     # Preventive fixes (forward-looking)
│   └── Deploy-TagProtectionAutomationRule.ps1  # Automation rule (free)
│
├── samples/                         # Anonymized sample report outputs
│   ├── sample-diagnostic-report.html
│   └── sample-deployment-report.html
│
├── demos/                           # Demo content & guidebooks
│   └── human-operated-ransomware-guidebook.txt
│
├── docs/                            # Documentation & walkthrough guides
│   └── Kubernetes-Alert-Simulation-Guide.md
│
├── LICENSE                          # MIT License
└── README.md                        # This file
```

---

## 🛡️ Scripts

### Kubernetes Alert Simulation

Automates Microsoft Defender for Cloud's Kubernetes attack simulation to validate threat detection on AKS clusters.

| | |
|---|---|
| **Script** | [`scripts/Deploy-KubernetesAlertSimulation.ps1`](scripts/Deploy-KubernetesAlertSimulation.ps1) |
| **Documentation** | 📖 [Complete Walkthrough Guide](docs/Kubernetes-Alert-Simulation-Guide.md) |
| **Version** | 2.2.0 |
| **Requirements** | PowerShell 7.0+, Azure CLI, kubectl, Helm, Python 3.7+ |

```powershell
.\scripts\Deploy-KubernetesAlertSimulation.ps1
```

<details>
<summary>Attack Scenarios</summary>

| Scenario | Description | Key Alerts Generated |
|----------|-------------|---------------------|
| Reconnaissance | Network scanning, service enumeration | Network scanning tool detected |
| Lateral Movement | IMDS access, token retrieval | Access to cloud metadata service detected |
| Secrets Gathering | Credential file access | Sensitive files access detected |
| Crypto Mining | Mining software simulation | Digital currency mining behavior detected |
| Web Shell | Remote command execution | Possible Web Shell activity detected |

</details>

> ⚠️ Run **only** on non-production clusters.

---

### Defender Incident Report

Retrieves incident data from Microsoft Defender for Endpoint via Microsoft Graph and generates comprehensive HTML reports with alerts, evidence, and timelines.

| | |
|---|---|
| **Script** | [`scripts/Get-DefenderIncidentReport.ps1`](scripts/Get-DefenderIncidentReport.ps1) |
| **Version** | 2.0.0 |
| **Requirements** | Microsoft.Graph.Security, Microsoft.Graph.Authentication modules |
| **Permissions** | SecurityIncident.Read.All, SecurityAlert.Read.All |

```powershell
.\scripts\Get-DefenderIncidentReport.ps1 -IncidentId 256968
```

---

### Phishing Triage Agent — Tag Diagnose & Remediate

Diagnoses whether the Security Copilot Phishing Triage Agent is stripping tags from Sentinel incidents, and optionally **restores the missing tags**. Uses KQL-first queries for scale (handles thousands of incidents). Generates an HTML report with findings, KQL evidence, and remediation results.

| | |
|---|---|
| **Script** | [`scripts/Diagnose-And-Remediate-PhishingTriageAgentTags.ps1`](scripts/Diagnose-And-Remediate-PhishingTriageAgentTags.ps1) |
| **Detailed Instructions** | 📖 **[scripts/README.md](scripts/README.md#diagnose-and-remediate-phishingtriageagenttagsps1)** |
| **Type** | Diagnostic + optional remediation (use `-DiagnosticOnly` for read-only mode) |
| **Requirements** | Az.Accounts |
| **Output** | `PhishingTriageAgent_DiagnoseRemediate_YYYYMMDD_HHMMSS.html` |

```powershell
# Diagnostic only — read-only report, no changes
.\scripts\Diagnose-And-Remediate-PhishingTriageAgentTags.ps1 -DiagnosticOnly

# Full diagnose + remediate (interactive approval gates)
.\scripts\Diagnose-And-Remediate-PhishingTriageAgentTags.ps1

# Parameterized mode
.\scripts\Diagnose-And-Remediate-PhishingTriageAgentTags.ps1 `
    -SubscriptionId "xxxx" -ResourceGroupName "rg" `
    -WorkspaceName "ws" -ExpectedTags "AutoRemediate","PhishingReview"
```

---

## 🔧 Remediation — Protect Sentinel Incident Tags

A bug in code is causing the Phishing Triage Agent to overwrite incident tags when it updates Sentinel incidents, breaking tag-based automation. The agent writes its own tags without preserving existing labels, so any customer-applied tags are stripped.

### Two-step approach

| Step | Tool | What it does |
|------|------|-------------|
| **1. Fix existing incidents** | [`Diagnose-And-Remediate-PhishingTriageAgentTags.ps1`](scripts/Diagnose-And-Remediate-PhishingTriageAgentTags.ps1) | Scans your Sentinel workspace via KQL, identifies incidents where the agent stripped tags, and restores them. Run with `-DiagnosticOnly` first to review the report before remediating. |
| **2. Prevent future stripping** | [`Deploy-TagProtectionAutomationRule.ps1`](remediation/Deploy-TagProtectionAutomationRule.ps1) | Deploys a free Sentinel automation rule that re-applies your critical tags whenever an incident is updated. |

### Automation Rule (Prevent Future Issues)

The simplest, free, Sentinel-native approach. Deploys an automation rule that re-applies your specified critical tags whenever an incident is updated.

| | |
|---|---|
| **Script** | [`remediation/Deploy-TagProtectionAutomationRule.ps1`](remediation/Deploy-TagProtectionAutomationRule.ps1) |
| **Detailed Instructions** | 📖 **[remediation/README.md](remediation/README.md)** |
| **Type** | Sentinel Automation Rule (native, no extra resources) |
| **Cost** | **Free** — automation rules have no per-execution cost |
| **Protects** | Specific tags you configure (e.g., `AutoEscalate`, `Tier2-Review`) |
| **Output** | `TagProtection_DeployReport_YYYYMMDD_HHMMSS.html` |

```powershell
# Interactive mode — walks you through everything
.\remediation\Deploy-TagProtectionAutomationRule.ps1

# Or pass parameters directly
.\remediation\Deploy-TagProtectionAutomationRule.ps1 `
    -SubscriptionId "xxxx" -ResourceGroupName "rg" `
    -WorkspaceName "ws" -TagsToProtect "AutoEscalate","Tier2-Review"
```

> **Note:** Automation rules can only add **static, predefined tags**. If your tags change frequently, use the diagnostic + remediation script to restore missing tags on demand.

---

## 📊 Sample Reports

Want to see what the reports look like before running anything? Check the [`samples/`](samples/) directory for anonymized HTML report examples:

- [**Diagnostic Report Sample**](samples/sample-diagnostic-report.html) — shows findings when tag stripping is detected
- [**Deployment Report Sample**](samples/sample-deployment-report.html) — shows the output after deploying tag protection rules

---

## ⚠️ Disclaimer

> **This repository is NOT official Microsoft documentation, guidance, or tooling.**
>
> For official product documentation, always refer to **[https://learn.microsoft.com](https://learn.microsoft.com)**.

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                              DISCLAIMER                                    ║
╚══════════════════════════════════════════════════════════════════════════════╝

THIS REPOSITORY AND ALL OF ITS CONTENTS — INCLUDING SCRIPTS, TEMPLATES,
PLAYBOOKS, DOCUMENTATION, AND SAMPLE REPORTS — ARE PROVIDED FOR EDUCATIONAL
AND EXPERIMENTAL PURPOSES ONLY.

THIS IS NOT OFFICIAL MICROSOFT DOCUMENTATION. THIS IS NOT AN OFFICIAL
MICROSOFT PRODUCT, SERVICE, OR TOOL. NOTHING IN THIS REPOSITORY REPRESENTS
OFFICIAL MICROSOFT GUIDANCE, BEST PRACTICES, OR SUPPORTED SOLUTIONS.

FOR OFFICIAL DOCUMENTATION, VISIT: https://learn.microsoft.com

THE SAMPLE SCRIPTS, TEMPLATES, AND PLAYBOOKS IN THIS REPOSITORY ARE NOT
SUPPORTED UNDER ANY MICROSOFT STANDARD SUPPORT PROGRAM OR SERVICE. THEY ARE
PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED. MICROSOFT
FURTHER DISCLAIMS ALL IMPLIED WARRANTIES INCLUDING, WITHOUT LIMITATION, ANY
IMPLIED WARRANTIES OF MERCHANTABILITY OR OF FITNESS FOR A PARTICULAR PURPOSE.

THE ENTIRE RISK ARISING OUT OF THE USE OR PERFORMANCE OF THE SAMPLE SCRIPTS,
TEMPLATES, AND DOCUMENTATION REMAINS WITH YOU. IN NO EVENT SHALL MICROSOFT,
ITS AUTHORS, OR ANYONE ELSE INVOLVED IN THE CREATION, PRODUCTION, OR DELIVERY
OF THE SCRIPTS BE LIABLE FOR ANY DAMAGES WHATSOEVER (INCLUDING, WITHOUT
LIMITATION, DAMAGES FOR LOSS OF BUSINESS PROFITS, BUSINESS INTERRUPTION, LOSS
OF BUSINESS INFORMATION, OR OTHER PECUNIARY LOSS) ARISING OUT OF THE USE OF
OR INABILITY TO USE THE SAMPLE SCRIPTS, TEMPLATES, OR DOCUMENTATION, EVEN IF
MICROSOFT HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.
```

### Before Using Anything in This Repository

1. **UNDERSTAND** — This is **not** official Microsoft documentation or tooling. For official guidance, visit [learn.microsoft.com](https://learn.microsoft.com)
2. **REVIEW** — Read the script/template code and documentation to understand what it does
3. **TEST** — Always run in a **non-production environment** first
4. **AUTHORIZE** — Ensure you have proper authorization and permissions
5. **COMPLY** — Verify compliance with your organization's security policies
6. **UNDERSTAND COSTS** — Some deployments create billable Azure resources (see individual READMEs)
7. **ISOLATE** — Do NOT run simulation scripts on production systems with active workloads

These are **unofficial community tools** provided for **educational and experimental purposes only**. They are **not** Microsoft products, services, or official guidance in any way, shape, or form.

---

## 📚 Additional Resources

- [Microsoft Defender for Containers Documentation](https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-containers-introduction)
- [Microsoft Sentinel Documentation](https://learn.microsoft.com/en-us/azure/sentinel/)
- [Security Copilot Documentation](https://learn.microsoft.com/en-us/security-copilot/)
- [Official Defender Attack Simulation Repository](https://github.com/microsoft/Defender-for-Cloud-Attack-Simulation)
- [Container Security Alerts Reference](https://learn.microsoft.com/en-us/azure/defender-for-cloud/alerts-containers)

---

## 📜 License

This project is provided under the [MIT License](LICENSE) with additional disclaimers. See [LICENSE](LICENSE) for details.
