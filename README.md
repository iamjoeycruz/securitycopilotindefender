# Security Copilot in Defender - Testing Scripts

Unofficial PowerShell scripts to help administrators test Security Copilot scenarios in Microsoft Defender.

## Scripts

This repository contains the following PowerShell scripts:

### Test-SecurityCopilotConnection.ps1
Tests the connection to Security Copilot and verifies basic functionality within the Microsoft Defender environment.

**Usage:**
```powershell
.\Test-SecurityCopilotConnection.ps1
```

### Get-SecurityCopilotCapabilities.ps1
Retrieves and displays the Security Copilot capabilities available in your tenant.

**Usage:**
```powershell
.\Get-SecurityCopilotCapabilities.ps1
```

### Invoke-SecurityCopilotQuery.ps1
Executes a sample query against Security Copilot for testing purposes.

**Usage:**
```powershell
.\Invoke-SecurityCopilotQuery.ps1 -Query "Show me recent security incidents"
```

## Prerequisites

- PowerShell 5.1 or later
- Azure PowerShell modules (Az.Accounts)
- Microsoft Graph PowerShell SDK (Microsoft.Graph.Authentication)
- Appropriate permissions in your Microsoft 365 tenant

## Installation

1. Clone this repository
2. Install required modules:
```powershell
Install-Module -Name Az.Accounts -Scope CurrentUser
Install-Module -Name Microsoft.Graph.Authentication -Scope CurrentUser
```

3. Authenticate to Azure:
```powershell
Connect-AzAccount
```

## Disclaimer

**THE SAMPLE SCRIPTS ARE NOT SUPPORTED UNDER ANY MICROSOFT STANDARD SUPPORT PROGRAM OR SERVICE. THE SAMPLE SCRIPTS ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND. MICROSOFT FURTHER DISCLAIMS ALL IMPLIED WARRANTIES INCLUDING, WITHOUT LIMITATION, ANY IMPLIED WARRANTIES OF MERCHANTABILITY OR OF FITNESS FOR A PARTICULAR PURPOSE. THE ENTIRE RISK ARISING OUT OF THE USE OR SAMPLE SCRIPTS.**

These are unofficial scripts provided for testing and educational purposes only.
