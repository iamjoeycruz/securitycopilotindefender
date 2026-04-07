# Restore Sentinel Incident Tags — Logic App Playbook

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fiamjoeycruz%2Fsecuritycopilotindefender%2Fmain%2Fremediation%2Frestore-sentinel-incident-tags%2Fazuredeploy.json)

## Problem

The **Security Copilot Phishing Triage Agent** (and other services like **Microsoft Defender XDR alert correlation**) can unintentionally remove tags/labels from Sentinel incidents. This breaks any downstream automation that depends on those tags.

### Root Cause

The Sentinel `Incidents – Create Or Update` REST API uses **PUT (full-replace) semantics**. When any service updates an incident, the entire incident object is replaced. If the `labels` array is omitted or empty in the PUT body, **all existing labels are deleted**.

This is **by-design API behavior**, not a bug in the agent. The agent simply doesn't preserve fields it didn't set.

## Solution

This playbook deploys a **Logic App** that automatically restores required tags within seconds of removal. It runs on every incident update and is completely self-healing.

### How It Works

```
Trigger:  Sentinel Automation Rule fires on "Incident Updated"
              ↓
Step 1:   GET /incidents/{id} — read the full incident with current labels
              ↓
Step 2:   Compare current labels against your required tags list
              ↓
Step 3:   IF any required tags are missing:
            → Merge: current labels ∪ missing tags
            → PUT /incidents/{id} with etag — writes the full label set back
            → Log: "Restored [missing tags]"
          ELSE:
            → Log: "Tags intact, no action needed"
```

### What Gets Deployed

| Resource | Type | Purpose | Cost |
|----------|------|---------|------|
| `Restore-SentinelIncidentTags` | Logic App (Consumption) | Checks and restores tags on each incident update | ~$0.000025/action; typically < $1/month |
| `azuresentinel-Restore-*` | API Connection | Connects Logic App to Sentinel trigger webhook | Free |

- Uses **System Managed Identity** — no credentials to manage
- **etag** header prevents race conditions between concurrent updates
- Runs only when tags are actually missing (no-op if tags are intact)

## Deployment

### Option 1: Deploy to Azure Button (Recommended)

Click the button above, or use this link:

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fiamjoeycruz%2Fsecuritycopilotindefender%2Fmain%2Fremediation%2Frestore-sentinel-incident-tags%2Fazuredeploy.json)

Fill in:
- **Resource Group**: Same resource group as your Sentinel workspace
- **Playbook Name**: `Restore-SentinelIncidentTags` (default)
- **Required Tags**: Comma-separated list of tags to protect (e.g., `AutoRemediate,PhishingReview`)

### Option 2: Azure CLI

```bash
az deployment group create \
  --resource-group <your-sentinel-rg> \
  --template-file azuredeploy.json \
  --parameters RequiredTags="AutoRemediate,PhishingReview"
```

### Option 3: PowerShell

```powershell
New-AzResourceGroupDeployment `
  -ResourceGroupName "<your-sentinel-rg>" `
  -TemplateFile "azuredeploy.json" `
  -RequiredTags "AutoRemediate,PhishingReview"
```

## Post-Deployment Steps (Required)

After the ARM template deploys, complete these 3 manual steps:

### 1. Authorize the API Connection

1. Go to **Azure Portal → Resource Groups → \<your-rg\>**
2. Open the **API Connection** resource (`azuresentinel-Restore-SentinelIncidentTags`)
3. Click **Edit API connection** in the left menu
4. Click **Authorize** and sign in
5. Click **Save**

### 2. Grant Sentinel Responder Role

The Logic App's managed identity needs permission to read and write incidents.

1. Go to **Azure Portal → Log Analytics Workspaces → \<your-workspace\>**
2. Click **Access control (IAM)** → **Add role assignment**
3. Role: **Microsoft Sentinel Responder**
4. Members: Select **Managed Identity** → **Logic App** → `Restore-SentinelIncidentTags`
5. Click **Review + assign**

Or via CLI:
```bash
# Get the managed identity principal ID from deployment outputs
az role assignment create \
  --assignee <managed-identity-object-id> \
  --role "Microsoft Sentinel Responder" \
  --scope "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.OperationalInsights/workspaces/<workspace>"
```

### 3. Create Sentinel Automation Rule

1. Go to **Microsoft Sentinel → Automation**
2. Click **Create → Automation rule**
3. Configure:
   - **Name**: `Auto-Restore Tags on Incident Update`
   - **Trigger**: When incident is updated
   - **Conditions**: Incident provider → Contains → `Microsoft 365 Defender` (or leave blank for all incidents)
   - **Actions**: Run playbook → `Restore-SentinelIncidentTags`
   - **Order**: `100` (runs after other rules)
4. Click **Apply**

## Verify It Works

1. Open any incident in Sentinel
2. Manually remove one of your required tags
3. Wait ~30 seconds and refresh the page
4. The tag should reappear automatically
5. Check the Logic App **Run History** to confirm it fired

## Diagnostic Script

If you need to investigate whether tag removal is happening in your environment **before** deploying this fix, use the companion diagnostic script:

```powershell
# Zero-config — walks you through everything interactively
.\Investigate-PhishingTriageAgentTagRemoval.ps1
```

The diagnostic script:
- Scans your Sentinel incidents for missing tags (read-only)
- Runs KQL queries to identify which actors are stripping tags
- Generates an HTML report with findings and remediation steps
- **Does NOT modify any resources**

## Removal

To remove the playbook and all associated resources:

1. Delete the **Automation Rule** in Sentinel → Automation
2. Delete the **Logic App** in the Azure Portal
3. Delete the **API Connection** (`azuresentinel-Restore-*`)
4. The RBAC role assignment is automatically cleaned up when the managed identity is deleted

## ⚠️ Disclaimer

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                              DISCLAIMER                                     ║
╚══════════════════════════════════════════════════════════════════════════════╝

THE SAMPLE SCRIPTS AND TEMPLATES ARE NOT SUPPORTED UNDER ANY MICROSOFT
STANDARD SUPPORT PROGRAM OR SERVICE. THEY ARE PROVIDED "AS IS" WITHOUT
WARRANTY OF ANY KIND. MICROSOFT FURTHER DISCLAIMS ALL IMPLIED WARRANTIES
INCLUDING, WITHOUT LIMITATION, ANY IMPLIED WARRANTIES OF MERCHANTABILITY
OR OF FITNESS FOR A PARTICULAR PURPOSE.

THE ENTIRE RISK ARISING OUT OF THE USE OR PERFORMANCE OF THE SAMPLE SCRIPTS,
TEMPLATES, AND DOCUMENTATION REMAINS WITH YOU. IN NO EVENT SHALL MICROSOFT,
ITS AUTHORS, OR ANYONE ELSE INVOLVED IN THE CREATION, PRODUCTION, OR DELIVERY
OF THE SCRIPTS BE LIABLE FOR ANY DAMAGES WHATSOEVER (INCLUDING, WITHOUT
LIMITATION, DAMAGES FOR LOSS OF BUSINESS PROFITS, BUSINESS INTERRUPTION,
LOSS OF BUSINESS INFORMATION, OR OTHER PECUNIARY LOSS) ARISING OUT OF THE
USE OF OR INABILITY TO USE THE SAMPLE SCRIPTS, TEMPLATES, OR DOCUMENTATION,
EVEN IF MICROSOFT HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.
```

### Before Deploying

1. **REVIEW** — Read the ARM template and Logic App definition to understand what resources will be created
2. **TEST** — Deploy in a non-production environment first
3. **AUTHORIZE** — Ensure you have Contributor permissions on the resource group
4. **COST** — The Logic App uses Consumption pricing (~$0.000025/action, typically < $1/month)
5. **MONITOR** — Check the Logic App Run History after deployment to ensure it's working correctly

This is an unofficial tool provided for educational and experimental purposes only.
