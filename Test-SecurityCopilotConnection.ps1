<#
.SYNOPSIS
    Test connection to Security Copilot in Microsoft Defender.

.DESCRIPTION
    This script helps administrators test their connection to Security Copilot
    and verify basic functionality within Microsoft Defender environment.

.DISCLAIMER
    THE SAMPLE SCRIPTS ARE NOT SUPPORTED UNDER ANY MICROSOFT STANDARD SUPPORT
    PROGRAM OR SERVICE. THE SAMPLE SCRIPTS ARE PROVIDED "AS IS" WITHOUT WARRANTY
    OF ANY KIND. MICROSOFT FURTHER DISCLAIMS ALL IMPLIED WARRANTIES INCLUDING,
    WITHOUT LIMITATION, ANY IMPLIED WARRANTIES OF MERCHANTABILITY OR OF FITNESS
    FOR A PARTICULAR PURPOSE. THE ENTIRE RISK ARISING OUT OF THE USE OR SAMPLE SCRIPTS.

.EXAMPLE
    .\Test-SecurityCopilotConnection.ps1
    Tests the connection to Security Copilot.

.NOTES
    This is an unofficial script to help administrators test scenarios.
#>

[CmdletBinding()]
param()

Write-Host "Testing Security Copilot Connection..." -ForegroundColor Cyan

try {
    # Check if required modules are available
    Write-Host "Checking for required modules..." -ForegroundColor Yellow
    
    $requiredModules = @(
        "Az.Accounts",
        "Microsoft.Graph.Authentication"
    )
    
    foreach ($module in $requiredModules) {
        if (Get-Module -ListAvailable -Name $module) {
            Write-Host "  [OK] Module '$module' is available" -ForegroundColor Green
        } else {
            Write-Host "  [WARNING] Module '$module' is not installed" -ForegroundColor Red
            Write-Host "  Install with: Install-Module -Name $module" -ForegroundColor Yellow
        }
    }
    
    # Test Azure connection
    Write-Host "`nTesting Azure authentication..." -ForegroundColor Yellow
    $azContext = Get-AzContext -ErrorAction SilentlyContinue
    
    if ($azContext) {
        Write-Host "  [OK] Connected to Azure as: $($azContext.Account.Id)" -ForegroundColor Green
        Write-Host "  Subscription: $($azContext.Subscription.Name)" -ForegroundColor Green
    } else {
        Write-Host "  [INFO] Not connected to Azure. Run 'Connect-AzAccount' to authenticate." -ForegroundColor Yellow
    }
    
    Write-Host "`nConnection test completed." -ForegroundColor Cyan
}
catch {
    Write-Host "Error during connection test: $_" -ForegroundColor Red
}
