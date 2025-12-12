# Security Copilot in Defender - Testing Scripts

Unofficial PowerShell scripts to help administrators test Security Copilot scenarios in Microsoft Defender.

## 🛡️ Scripts

This repository contains the following PowerShell scripts:

### Kubernetes Alert Simulation Script

Deploy-KubernetesAlertSimulation.ps1 - Automates Microsoft Defender for Cloud's Kubernetes attack simulation to validate threat detection on AKS clusters.

| | |
|---|---|
| **Purpose** | Validate that Microsoft Defender for Containers is properly configured and detecting threats |
| **Documentation** | 📖 **[Complete Walkthrough Guide](docs/Kubernetes-Alert-Simulation-Guide.md)** |
| **Version** | 2.2.0 (December 2025) |
| **Requirements** | PowerShell 7.0+, Azure CLI, kubectl, Helm, Python 3.7+ |

#### Quick Start

```powershell
# Run interactively (recommended for first-time users)
.\Deploy-KubernetesAlertSimulation.ps1

# Run on a specific cluster
.\Deploy-KubernetesAlertSimulation.ps1 -ClusterName "my-cluster" -ResourceGroup "my-rg"

# Run all scenarios with automatic cleanup
.\Deploy-KubernetesAlertSimulation.ps1 -SimulationScenario All -CleanupAfterRun
```

#### Key Features

- ✅ **Automatic prerequisite installation** via winget
- ✅ **Azure permission validation** with least-privilege recommendations
- ✅ **Option to create a new non-prod AKS cluster** for testing
- ✅ **Visual progress bar** for cluster deployment
- ✅ **Production cluster detection** with safety warnings
- ✅ **Comprehensive cost analysis** and estimates
- ✅ **Detailed HTML report generation** with expected alerts
- ✅ **Complete cleanup** of simulation resources

#### Attack Scenarios

| Scenario | Description | Key Alerts Generated |
|----------|-------------|---------------------|
| Reconnaissance | Network scanning, service enumeration | Network scanning tool detected |
| Lateral Movement | IMDS access, token retrieval | Access to cloud metadata service detected |
| Secrets Gathering | Credential file access | Sensitive files access detected |
| Crypto Mining | Mining software simulation | Digital currency mining behavior detected |
| Web Shell | Remote command execution | Possible Web Shell activity detected |

> ⚠️ **Important**: Run only on non-production clusters. See the [complete guide](docs/Kubernetes-Alert-Simulation-Guide.md) for detailed instructions and safety considerations.

---

## ⚠️ Disclaimer

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                              DISCLAIMER                                       ║
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
```

### Before Using These Scripts

1. **REVIEW** - Read the script code and documentation to understand what operations it performs
2. **TEST** - Run in a non-production environment first
3. **AUTHORIZE** - Ensure you have proper authorization to run security simulations
4. **COMPLY** - Verify compliance with your organization's security policies
5. **ISOLATE** - DO NOT run on production systems with active workloads

These are unofficial scripts provided for testing and educational purposes only.

---

## 📚 Additional Resources

- [Microsoft Defender for Containers Documentation](https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-containers-introduction)
- [Official Attack Simulation Tool Repository](https://github.com/microsoft/Defender-for-Cloud-Attack-Simulation)
- [Container Security Alerts Reference](https://learn.microsoft.com/en-us/azure/defender-for-cloud/alerts-containers)

---

## 📜 License

This project is provided under the MIT License. See [LICENSE](LICENSE) for details.
