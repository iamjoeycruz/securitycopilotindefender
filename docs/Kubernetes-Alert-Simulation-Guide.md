# Microsoft Defender for Cloud - Kubernetes Alert Simulation Guide

> **Complete walkthrough for running security alert simulations on AKS clusters**

This guide provides step-by-step instructions for using the [`Deploy-KubernetesAlertSimulation.ps1`](https://github.com/iamjoeycruz/securitycopilotindefender/blob/main/docs/Deploy-KubernetesAlertSimulation.ps1) script to validate that Microsoft Defender for Containers is properly configured and detecting threats in your Azure Kubernetes Service (AKS) environment.

---

## 📋 Table of Contents

- [Overview](#overview)
- [What This Script Does](#what-this-script-does)
- [Prerequisites](#prerequisites)
- [Important Disclaimer](#important-disclaimer)
- [Step-by-Step Walkthrough](#step-by-step-walkthrough)
- [Attack Scenarios Explained](#attack-scenarios-explained)
- [Understanding the Output](#understanding-the-output)
- [Viewing Security Alerts](#viewing-security-alerts)
- [Cost Considerations](#cost-considerations)
- [Troubleshooting](#troubleshooting)
- [Frequently Asked Questions](#frequently-asked-questions)

---

## Overview

The **Kubernetes Alert Simulation Script** automates the process of running Microsoft's official [Defender for Cloud Attack Simulation tool](https://github.com/microsoft/Defender-for-Cloud-Attack-Simulation) on your AKS clusters. It handles everything from prerequisite installation to cleanup, making it easy to validate your security posture.

### Why Use This Script?

- ✅ **Validate Defender Configuration** - Ensure Defender for Containers is properly detecting threats
- ✅ **Security Testing** - Test your security team's response to real-world attack patterns
- ✅ **Demo & Training** - Demonstrate Defender capabilities to stakeholders
- ✅ **Compliance Validation** - Verify security controls are working as expected

---

## What This Script Does

### The Complete Workflow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         SIMULATION WORKFLOW                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  1. PREREQUISITES CHECK                                                     │
│     └── Validates Azure CLI, kubectl, Helm, Python                          │
│     └── Offers to auto-install missing components                           │
│                                                                             │
│  2. AZURE AUTHENTICATION                                                    │
│     └── Checks Azure login status                                           │
│     └── Browser-based login if needed                                       │
│                                                                             │
│  3. PERMISSION VALIDATION                                                   │
│     └── Validates Azure RBAC permissions                                    │
│     └── Checks for least-privilege access                                   │
│                                                                             │
│  4. CLUSTER SELECTION                                                       │
│     └── Discovers existing AKS clusters                                     │
│     └── Option to create a new non-prod cluster                             │
│                                                                             │
│  5. DEFENDER CONFIGURATION                                                  │
│     └── Validates Defender for Containers is enabled                        │
│     └── Checks Defender sensor deployment                                   │
│     └── Offers to enable if missing                                         │
│                                                                             │
│  6. SIMULATION EXECUTION                                                    │
│     └── Downloads official Microsoft simulation tool                        │
│     └── Runs selected attack scenarios                                      │
│     └── Captures output for reporting                                       │
│                                                                             │
│  7. REPORT GENERATION                                                       │
│     └── Creates detailed HTML report                                        │
│     └── Lists expected security alerts                                      │
│     └── Documents all actions performed                                     │
│                                                                             │
│  8. CLEANUP                                                                 │
│     └── Removes simulation pods and namespaces                              │
│     └── Prompts to delete newly created clusters                            │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### What the Script Does NOT Do

- ❌ Does NOT modify your existing workloads
- ❌ Does NOT access your application data
- ❌ Does NOT make permanent changes to cluster configuration
- ❌ Does NOT disable any security controls
- ❌ Does NOT require cluster-admin for existing clusters

---

## Prerequisites

### Required Tools

| Tool | Version | Auto-Install | Purpose |
|------|---------|--------------|---------|
| **PowerShell** | 7.0+ | ❌ Manual | Script execution |
| **Azure CLI** | Latest | ✅ winget | Azure authentication & management |
| **kubectl** | Latest | ✅ az aks install-cli | Kubernetes cluster access |
| **Helm** | Latest | ✅ winget | Simulation tool deployment |
| **Python** | 3.7+ | ✅ winget | Simulation tool execution |

> **Note**: The script will detect missing prerequisites and offer to install them automatically using `winget`.

### Required Azure Permissions

#### For Using an Existing AKS Cluster (Minimum Permissions)

| Role | Scope | Purpose |
|------|-------|---------|
| **Azure Kubernetes Service Cluster User Role** | AKS Cluster | Get cluster credentials |
| **Reader** | Resource Group or Subscription | List and view clusters |

#### For Creating a New AKS Cluster (Elevated Permissions)

| Role | Scope | Purpose |
|------|-------|---------|
| **Contributor** | Subscription or Resource Group | Create all required resources |

---

## Important Disclaimer

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

### Before You Begin

1. **REVIEW** - Read this documentation and the script code to understand what operations it performs
2. **TEST** - Run in a non-production environment first
3. **AUTHORIZE** - Ensure you have proper authorization to run security simulations
4. **COMPLY** - Verify compliance with your organization's security policies
5. **ISOLATE** - DO NOT run on production clusters with active workloads

---

## Step-by-Step Walkthrough

### Step 1: Launch the Script

Open PowerShell 7 (not Windows PowerShell 5.1) and run:

```powershell
# Navigate to the script location
cd C:\Path\To\Script

# Run the script
.\Deploy-KubernetesAlertSimulation.ps1
```

### Step 2: Accept the Disclaimer
<img width="975" height="1118" alt="image" src="https://github.com/user-attachments/assets/54250edf-c9d4-4aa1-8f22-86a00c604d34" />


The script will display a disclaimer. Read it carefully and type `yes` to continue.

### Step 3: Prerequisites Check

The script checks for required tools:

```
Checking installed components...

  [Azure CLI] ✓ Installed
  [kubectl] ✓ Installed
  [Helm] ✓ Installed
  [Python 3.7+] ✓ Installed
```

If any tools are missing, you'll see options to:
1. Install missing components automatically
2. Show manual installation instructions
3. Continue anyway (not recommended)
4. Exit

### Step 4: Azure Authentication

The script verifies your Azure login:

```
Checking Azure login status...
[Success] Azure CLI logged in as: user@contoso.com
```

If not logged in, a browser window will open for Azure authentication.

### Step 5: Permission Validation

<img width="975" height="581" alt="image" src="https://github.com/user-attachments/assets/b9aa93c3-067d-4c02-81b7-547048458fcd" />


The script validates your Azure permissions:

```
┌─────────────────────────────────────────────────────────────────┐
│               PERMISSION VALIDATION                              │
└─────────────────────────────────────────────────────────────────┘

  User: user@contoso.com
  Subscription: Contoso - Demo Subscription

  ✅ ELEVATED ACCESS DETECTED
  
  Your roles:
    • Contributor

  ✅ PERMISSION CHECK PASSED
```

### Step 6: Cluster Selection


The script discovers available AKS clusters:

```
[Info] Discovering AKS clusters...
[Success] Found 3 AKS cluster(s):
  [1] dev-cluster (RG: dev-rg, Location: eastus, Nodes: 2)
  [2] test-cluster (RG: test-rg, Location: westus2, Nodes: 1)
  [3] mdc-simulation-aks-20251211-172941 (RG: mdc-simulation-rg-20251211-172941, Location: eastus, Nodes: 1)

═══════════════════════════════════════════════════════════════════
  CLUSTER SELECTION
═══════════════════════════════════════════════════════════════════

Would you like to:
  [1] Use an existing AKS cluster (listed above)
  [2] Create a NEW dedicated non-prod AKS cluster for this simulation
      (Recommended for first-time users)

Enter your choice (1 or 2):
```

**Option 1**: Use an existing cluster - Best for clusters you've already set up for testing

**Option 2**: Create a new cluster - Recommended for first-time users or when you want a clean environment

### Step 7: Cost Acknowledgment (New Cluster Only)

<img width="975" height="531" alt="image" src="https://github.com/user-attachments/assets/12888c70-da40-4e85-bd3a-00550c28c694" />


If creating a new cluster, you'll see cost estimates:

```
Creating a new AKS cluster will incur Azure costs:

  ESTIMATED COSTS (Standard_B2s, 1 node):
  ─────────────────────────────────────────
  • VM Compute:        ~$0.042/hour (~$1.00/day)
  • OS Disk (30GB):    ~$0.004/hour (~$0.10/day)
  • Load Balancer:     ~$0.025/hour (~$0.60/day)
  • Public IP:         ~$0.004/hour (~$0.10/day)
  ─────────────────────────────────────────
  • TOTAL:             ~$0.075/hour (~$1.80/day)

  For a 1-hour simulation: ~$0.08 - $0.15

Do you accept the costs and want to create the cluster? (yes/no):
```

### Step 8: Cluster Deployment Progress

<img width="975" height="850" alt="image" src="https://github.com/user-attachments/assets/a3a9e8d8-882e-420e-9cb8-9d25690c2069" />


The script shows a real-time progress bar during cluster creation:

```
┌─────────────────────────────────────────────────────────────┐
│           AKS CLUSTER DEPLOYMENT IN PROGRESS                │
└─────────────────────────────────────────────────────────────┘

  This typically takes 5-8 minutes. Please wait...

  / [########################################----] 90% | Finalizing cluster setup | 04:52

┌─────────────────────────────────────────────────────────────┐
│              ✅ AKS CLUSTER CREATED SUCCESSFULLY            │
└─────────────────────────────────────────────────────────────┘

  Cluster: mdc-simulation-aks-20251211-175325
  Duration: 4m 53s
```

### Step 9: Defender for Containers Enablement

After cluster creation, Defender for Containers is automatically enabled:

```
[Info] Enabling Defender for Containers...

  This typically takes 2-3 minutes...

  [########################################] 100% | Complete | 2:11

[Success] Defender for Containers enabled.
```

### Step 10: Scenario Selection

<img width="975" height="793" alt="image" src="https://github.com/user-attachments/assets/bf16f406-06ba-4a4f-97da-014c55789e70" />


Choose which attack scenarios to run:

```
Ready to run simulation on cluster: mdc-simulation-aks-20251211-175325

Available Simulation Scenarios:
  1. Reconnaissance - Web Shell, Kubernetes service account operations, Network scanning
  2. Lateral Movement - Web Shell, Cloud metadata service access
  3. Secrets Gathering - Web Shell, Sensitive files access, Secret reconnaissance
  4. Crypto Mining - Multiple crypto mining indicators
  5. Web Shell - Web Shell activity detection
  6. All - Run all scenarios

NOTE: Some alerts are triggered in near real-time, others may take up to an hour.

═══════════════════════════════════════════════════════════════════
  SIMULATION TOOL OUTPUT
═══════════════════════════════════════════════════════════════════

+++ Defender for Cloud Attack Simulation +++

This simulation creates two pods - attacker and victim
The attacker pod will execute the chosen scenario on the victim

Select a scenario:
```

### Step 11: Simulation Execution

<img width="975" height="776" alt="image" src="https://github.com/user-attachments/assets/64d2e916-2489-4193-9f6e-dd18208625eb" />


The simulation runs and shows real-time output:

```
Select a scenario: Started at Fri Dec 12 02:01:43 UTC 2025

--- Webshell ---
Sending payload request to the victim pod

--- Reconnaissance ---
Checking read permissions for other pods via SelfSubjectAccessReview API request
Results:  "allowed":false

Searching for endpoints listening on port 443 via Nmap:
Starting Nmap 7.93 ( https://nmap.org )
Host is up (0.0020s latency).
PORT    STATE SERVICE
443/tcp open  https

--- Lateral Movement ---
Sending request to IMDS to retrieve cloud identity token
Azure token: eyJ0eXAiOiJKV1Qi...

--- Secrets Gathering ---
Searching for sensitive files
Found .git-credential at /home/user/.git-credentials: https://user:pass@somegit.com
Found Kubernetes service account in /var/run/secrets/kubernetes.io/serviceaccount/token

--- Cryptomining ---
Optimizing host for mining
Downloading and running Xmrig crypto miner

--- Simulation completed ---
Scenario completed successfully.
```

### Step 12: HTML Report Generation

<img width="975" height="504" alt="image" src="https://github.com/user-attachments/assets/017e5264-a048-4b1a-b301-abd2b4290ab3" />


The script generates a comprehensive HTML report:

```
[Info] Generating simulation report...
[Success] Report saved to: C:\Users\user\Documents\K8s-Simulation-Report-2025-12-11-181000.html
```

The report includes:
- Execution summary with scenario count
- Cluster and subscription details
- Timeline of all actions performed
- Expected security alerts
- Links to view alerts in Defender portal
- Cleanup commands

### Step 13: Cleanup

The script prompts for cleanup:

```
═══════════════════════════════════════════════════════════════════
  CLEANUP
═══════════════════════════════════════════════════════════════════

Would you like to clean up simulation resources? (yes/no): yes

[Info] Cleaning up simulation namespace...
[Success] Simulation resources cleaned up.

You created a new cluster for this simulation:
  Cluster: mdc-simulation-aks-20251211-175325
  Resource Group: mdc-simulation-rg-20251211-175325

⚠️  COST WARNING: This cluster will continue to incur charges (~$1.80/day)

Would you like to DELETE this cluster now? (yes/no): yes

[Info] Deleting AKS cluster (this runs in background)...
[Success] Cluster deletion initiated.
```

---

## Attack Scenarios Explained

### 1. Reconnaissance
Simulates an attacker gathering information about the cluster environment:
- **Kubernetes API enumeration** - Checking permissions via SelfSubjectAccessReview
- **Network scanning** - Using Nmap to discover services
- **Service account operations** - Accessing Kubernetes service accounts

**Expected Alerts:**
- Suspicious Kubernetes service account operation detected
- Network scanning tool detected

### 2. Lateral Movement
Simulates an attacker moving from container to cloud:
- **IMDS access** - Accessing Azure Instance Metadata Service
- **Token retrieval** - Obtaining cloud identity tokens

**Expected Alerts:**
- Access to cloud metadata service detected
- Suspicious access to workload identity token

### 3. Secrets Gathering
Simulates credential theft activities:
- **File system enumeration** - Searching for credential files
- **Git credentials** - Accessing .git-credentials
- **Kubernetes secrets** - Reading service account tokens

**Expected Alerts:**
- Sensitive files access detected
- Possible secret reconnaissance detected

### 4. Crypto Mining
Simulates cryptocurrency mining activity:
- **CPU optimization** - Modifying system for mining
- **Miner download** - Downloading crypto mining software
- **ld.so.preload access** - Hooking library loading

**Expected Alerts:**
- Digital currency mining related behavior detected
- Kubernetes CPU optimization detected
- Possible Cryptocoinminer download detected
- Command within a container accessed ld.so.preload

### 5. Web Shell
Simulates web shell deployment:
- **Remote command execution** - Executing commands via HTTP
- **Persistence** - Maintaining access through web interface

**Expected Alerts:**
- Possible Web Shell activity detected
- A drift binary detected executing in the container

---

## Understanding the Output

### Console Output Colors

| Color | Meaning |
|-------|---------|
| 🟢 Green | Success / Completed |
| 🔵 Cyan | Information / Status |
| 🟡 Yellow | Warning / Attention needed |
| 🔴 Red | Error / Failed |
| ⚫ Gray | Details / Additional info |

### HTML Report Sections

1. **Summary Box** - Quick overview of scenarios executed
2. **Execution Details** - Cluster, subscription, and user information
3. **Azure Resources** - Resources used and their cleanup status
4. **Attack Scenarios** - Detailed list of scenarios with expected alerts
5. **Actions Timeline** - Complete audit trail of script actions
6. **Expected Alerts** - Full list of security alerts to look for
7. **Next Steps** - Links to view alerts in Defender portal
8. **Cleanup Commands** - Manual cleanup commands if needed

---

## Viewing Security Alerts

After the simulation completes, view generated alerts in:

### Microsoft Defender Portal (Recommended)
```
https://security.microsoft.com/alerts
```

### Azure Portal
```
https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/SecurityAlerts
```

### Alert Timeline

| Alert Type | Expected Time |
|------------|---------------|
| Web Shell activity | 1-5 minutes |
| Crypto mining detection | 5-15 minutes |
| Secrets access | 5-15 minutes |
| Network scanning | 15-30 minutes |
| Lateral movement | 30-60 minutes |

> **Note**: Some alerts may take up to 1 hour to appear depending on Defender processing.

---

## Cost Considerations

### Using an Existing Cluster
| Item | Estimated Cost |
|------|----------------|
| Simulation pods only | < $0.10 |

### Creating a New Cluster
| Component | Per Hour | Per Day |
|-----------|----------|---------|
| VM Compute (Standard_B2s) | ~$0.042 | ~$1.00 |
| OS Disk (30GB) | ~$0.004 | ~$0.10 |
| Load Balancer | ~$0.025 | ~$0.60 |
| Public IP | ~$0.004 | ~$0.10 |
| **Total** | **~$0.075** | **~$1.80** |

### Defender for Containers
| Metric | Estimated Cost |
|--------|----------------|
| Per vCore/hour | ~$0.0095 |
| Per vCore/month | ~$7.00 |
| For 1-hour simulation (2 vCores) | ~$0.02 - $0.05 |

> **Important**: Delete your cluster after simulation to stop incurring charges!

---

## Troubleshooting

### Common Issues

#### "PowerShell version not supported"
```
Solution: Install PowerShell 7+
  winget install Microsoft.PowerShell
  
Then run the script using 'pwsh' instead of 'powershell'
```

#### "Permission denied" errors
```
Solution: Verify you have required Azure roles:
  - For existing clusters: Azure Kubernetes Service Cluster User Role
  - For new clusters: Contributor on subscription/resource group
```

#### "Defender sensor not found"
```
Solution: Enable Defender for Containers:
  az security pricing create --name Containers --tier Standard
  az aks update --name <cluster> --resource-group <rg> --enable-defender
```

#### "Quota exceeded" when creating cluster
```
Solution: Try a different Azure region or request quota increase:
  - Change location to westus2, westeurope, etc.
  - Request quota increase in Azure Portal
```

#### Alerts not appearing
```
Possible causes:
  1. Defender sensor not fully deployed (wait 10-15 minutes)
  2. Defender for Containers not enabled
  3. Alert processing delay (some alerts take up to 1 hour)
  
Check sensor status:
  kubectl get ds microsoft-defender-collector-ds -n kube-system
```

---

## Frequently Asked Questions

### Q: Is this safe to run on production clusters?
**A**: No. Microsoft recommends running this simulation only on dedicated non-production clusters. The simulation deploys pods with elevated privileges and generates security alerts.

### Q: Will this affect my existing workloads?
**A**: The simulation runs in an isolated namespace (`mdc-simulation`). It does not interact with your existing workloads, but you should still use a non-production cluster.

### Q: How do I know if Defender detected the attacks?
**A**: Check the Microsoft Defender portal for alerts. The HTML report includes a list of expected alerts and direct links to the portal.

### Q: Can I automate this script?
**A**: Yes, use parameters for non-interactive execution:
```powershell
.\Deploy-KubernetesAlertSimulation.ps1 `
    -ClusterName "my-cluster" `
    -ResourceGroup "my-rg" `
    -SimulationScenario "All" `
    -CleanupAfterRun
```

### Q: What if the script fails midway?
**A**: The script has session state recovery. If it fails, run it again and choose "Resume from where it failed" when prompted.

### Q: How do I clean up manually?
**A**: Run these commands:
```bash
# Delete simulation namespace
kubectl delete namespace mdc-simulation

# Delete Helm releases
helm uninstall mdc-simulation -n mdc-simulation

# Delete entire resource group (if you created a new cluster)
az group delete --name <resource-group-name> --yes
```

---

## Additional Resources

- [Microsoft Defender for Containers Documentation](https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-containers-introduction)
- [Kubernetes Workload Protections](https://learn.microsoft.com/en-us/azure/defender-for-cloud/kubernetes-workload-protections)
- [Container Security Alerts Reference](https://learn.microsoft.com/en-us/azure/defender-for-cloud/alerts-containers)
- [Official Attack Simulation Tool](https://github.com/microsoft/Defender-for-Cloud-Attack-Simulation)

---

*This guide accompanies the Deploy-KubernetesAlertSimulation.ps1 script v2.2.0 (December 2025)*
