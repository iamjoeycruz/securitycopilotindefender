# Scripts

> **⚠️ DISCLAIMER:** All scripts in this directory are provided "AS IS" without warranty of any kind. They are for educational and experimental purposes only and are NOT officially supported by Microsoft. Always review scripts before running them. Test in non-production environments first. See the [repository disclaimer](../README.md#-disclaimer) for full details.

## Available Scripts

| Script | Description | Modifies Resources? |
|--------|-------------|---------------------|
| [`Deploy-KubernetesAlertSimulation.ps1`](Deploy-KubernetesAlertSimulation.ps1) | Runs Defender for Cloud K8s attack simulations | Yes — creates test pods on AKS |
| [`Get-DefenderIncidentReport.ps1`](Get-DefenderIncidentReport.ps1) | Generates HTML reports for Defender incidents via Microsoft Graph | No — read-only |
| [`Investigate-PhishingTriageAgentTagRemoval.ps1`](Investigate-PhishingTriageAgentTagRemoval.ps1) | Diagnoses Phishing Triage Agent tag stripping | No — read-only |

## Usage

See the [main README](../README.md) for quick-start commands, or run any script with `-?` for help:

```powershell
Get-Help .\Deploy-KubernetesAlertSimulation.ps1 -Detailed
Get-Help .\Get-DefenderIncidentReport.ps1 -Detailed
Get-Help .\Investigate-PhishingTriageAgentTagRemoval.ps1 -Detailed
```
