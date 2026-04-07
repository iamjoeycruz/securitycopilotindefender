# Security Copilot in Defender — Tools & Remediation

> **⚠️ IMPORTANT:** All scripts and templates in this repository are provided **"AS IS"** for **educational and experimental purposes only**. They are **not officially supported by Microsoft**. See [Disclaimer](#-disclaimer) below.

Unofficial PowerShell scripts, ARM templates, and playbooks to help security administrators simulate threats, diagnose issues, and remediate known problems in Microsoft Defender and Microsoft Sentinel environments.

---

## 📂 Repository Structure

```
├── scripts/                         # PowerShell diagnostic & simulation scripts
│   ├── Deploy-KubernetesAlertSimulation.ps1
│   ├── Get-DefenderIncidentReport.ps1
│   └── Investigate-PhishingTriageAgentTagRemoval.ps1
│
├── remediation/                     # Deployable fixes
│   ├── Deploy-TagProtectionAutomationRule.ps1  # ⭐ Recommended (free)
│   └── restore-sentinel-incident-tags/
│       ├── azuredeploy.json         # One-click Deploy to Azure (Logic App)
│       └── README.md                # Deployment guide
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

### Phishing Triage Agent — Tag Removal Diagnostic

Investigates whether the Security Copilot Phishing Triage Agent (or other services) are stripping tags from Sentinel incidents. Generates an HTML report with findings, KQL evidence, and remediation steps.

| | |
|---|---|
| **Script** | [`scripts/Investigate-PhishingTriageAgentTagRemoval.ps1`](scripts/Investigate-PhishingTriageAgentTagRemoval.ps1) |
| **Type** | Read-only diagnostic (does NOT modify any resources) |
| **Requirements** | Az.Accounts, Az.SecurityInsights, Az.Monitor, Az.OperationalInsights |

```powershell
# Interactive mode — walks you through everything
.\scripts\Investigate-PhishingTriageAgentTagRemoval.ps1

# Or pass parameters directly
.\scripts\Investigate-PhishingTriageAgentTagRemoval.ps1 `
    -SubscriptionId "xxxx" -ResourceGroupName "rg" `
    -WorkspaceName "ws" -ExpectedTags "AutoRemediate","PhishingReview"
```

---

## 🔧 Remediation — Protect Sentinel Incident Tags

The Phishing Triage Agent and Defender XDR alert correlation can strip tags/labels from Sentinel incidents, breaking tag-based automation. This happens because Sentinel's PUT API uses **full-replace semantics** — if the update payload omits the `labels` field, all existing tags are deleted.

Choose the approach that fits your needs:

### Option 1: Automation Rule ⭐ Recommended

The simplest, free, Sentinel-native approach. Deploys an automation rule that re-applies your specified critical tags whenever an incident is updated.

| | |
|---|---|
| **Script** | [`remediation/Deploy-TagProtectionAutomationRule.ps1`](remediation/Deploy-TagProtectionAutomationRule.ps1) |
| **Type** | Sentinel Automation Rule (native, no extra resources) |
| **Cost** | **Free** — automation rules have no per-execution cost |
| **Protects** | Specific tags you configure (e.g., `AutoEscalate`, `Tier2-Review`) |
| **Limitation** | Only re-applies preconfigured tags, not dynamic; fires on severity changes |

```powershell
# Interactive mode — walks you through everything
.\remediation\Deploy-TagProtectionAutomationRule.ps1

# Or pass parameters directly
.\remediation\Deploy-TagProtectionAutomationRule.ps1 `
    -SubscriptionId "xxxx" -ResourceGroupName "rg" `
    -WorkspaceName "ws" -TagsToProtect "AutoEscalate","Tier2-Review"
```

### Option 2: Logic App Playbook (Dynamic)

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fiamjoeycruz%2Fsecuritycopilotindefender%2Fmain%2Fremediation%2Frestore-sentinel-incident-tags%2Fazuredeploy.json)

A Logic App that dynamically restores **any** tag that was stripped — it reads previous tags from the Activity Log and merges them back.

| | |
|---|---|
| **Template** | [`remediation/restore-sentinel-incident-tags/azuredeploy.json`](remediation/restore-sentinel-incident-tags/azuredeploy.json) |
| **Documentation** | 📖 **[Full Deployment Guide](remediation/restore-sentinel-incident-tags/README.md)** |
| **Cost** | < $1/month (Logic App Consumption tier) |
| **Protects** | **Any** tag dynamically (GET → merge → PUT pattern) |
| **Limitation** | Requires Logic App + Managed Identity + RBAC setup |

### Which should I choose?

| Criteria | Automation Rule | Logic App |
|----------|:-:|:-:|
| I know exactly which tags to protect | ✅ | ✅ |
| Tags change frequently / I can't predict them | ❌ | ✅ |
| I want zero cost | ✅ | ❌ |
| I want zero extra Azure resources | ✅ | ❌ |
| I need dynamic tag restoration from Activity Log | ❌ | ✅ |

---

## ⚠️ Disclaimer

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                              DISCLAIMER                                    ║
╚══════════════════════════════════════════════════════════════════════════════╝

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

1. **REVIEW** — Read the script/template code and documentation to understand what it does
2. **TEST** — Always run in a **non-production environment** first
3. **AUTHORIZE** — Ensure you have proper authorization and permissions
4. **COMPLY** — Verify compliance with your organization's security policies
5. **UNDERSTAND COSTS** — Some deployments create billable Azure resources (see individual READMEs)
6. **ISOLATE** — Do NOT run simulation scripts on production systems with active workloads

These are **unofficial community tools** provided for **educational and experimental purposes only**. They are **not** Microsoft products.

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
