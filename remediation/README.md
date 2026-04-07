# Remediation — Protect Sentinel Incident Tags

> **⚠️ DISCLAIMER:** All scripts and templates in this directory are provided **"AS IS"** for **educational and experimental purposes only**. They are **not officially supported by Microsoft**. See the [full disclaimer](#%EF%B8%8F-disclaimer) below.

## The Problem

The **Security Copilot Phishing Triage Agent**, **Microsoft Defender XDR alert correlation**, and other services can unintentionally **remove tags/labels** from Microsoft Sentinel incidents. This breaks downstream automation that depends on those tags (e.g., auto-escalation, SOAR playbook triggers, assignment rules).

### Root Cause

The Sentinel [`Incidents – Create Or Update`](https://learn.microsoft.com/en-us/rest/api/securityinsights/incidents/create-or-update) REST API uses **PUT (full-replace) semantics**. When any service updates an incident, the **entire** incident object is replaced. If the `labels` array is omitted or empty in the PUT body, **all existing labels are deleted**.

This is **by-design API behavior**, not a bug in any agent. The updating service simply doesn't preserve fields it didn't set.

### Who is affected?

Any organization that:
- Uses **incident tags** to trigger automation rules, playbooks, or SOAR workflows
- Has the **Phishing Triage Agent** or **Defender XDR alert correlation** enabled
- Relies on tags for incident classification, routing, or SLA tracking

---

## Remediation Options

### ⭐ Option 1: Automation Rule (Recommended)

**The simplest, free, Sentinel-native approach.** Deploys an automation rule that re-applies your specified critical tags whenever an incident is updated.

| | |
|---|---|
| **Script** | [`Deploy-TagProtectionAutomationRule.ps1`](Deploy-TagProtectionAutomationRule.ps1) |
| **Cost** | **Free** — automation rules have no per-execution cost |
| **Complexity** | Low — single PowerShell script, no extra Azure resources |
| **What it protects** | Specific tags you configure in advance |
| **Requirements** | PowerShell 7+, `Az.Accounts` module, Sentinel Contributor role |

#### How It Works

```
You run the script → it asks which tags to protect
                         ↓
Creates Automation Rule 1 (Update trigger):
  When incident severity changes → add your tags back
                         ↓
Creates Automation Rule 2 (Create trigger):
  When new incident is created → stamp your tags on it
```

The "Add tags" action is **idempotent** — if the tag already exists, nothing happens. If it was stripped, it gets re-added.

#### Quick Start

```powershell
# Interactive mode — walks you through everything
.\Deploy-TagProtectionAutomationRule.ps1

# Or pass parameters directly
.\Deploy-TagProtectionAutomationRule.ps1 `
    -SubscriptionId "your-sub-id" `
    -ResourceGroupName "your-rg" `
    -WorkspaceName "your-workspace" `
    -TagsToProtect "AutoEscalate","Tier2-Review","VIP-Customer"
```

#### What the Script Does (Step by Step)

1. **Authenticates** to Azure (reuses existing session or prompts login)
2. **Discovers** your subscriptions and Sentinel-enabled workspaces
3. **Scans** recent incidents to show you which tags are currently in use
4. **Asks** which tags you want to protect
5. **Deploys** two automation rules via the Sentinel REST API:
   - **Update rule** — fires when incident severity changes (catches most agent updates)
   - **Create rule** — fires when any new incident is created
6. **Verifies** deployment and shows a summary

#### Limitations

- **Static tags only** — you must know in advance which tags to protect. If your tags change frequently, use Option 2 instead.
- **Severity-change trigger** — the update rule fires when incident severity changes. If an update doesn't change severity, that specific update won't trigger the rule. In practice, the Phishing Triage Agent typically does change severity, so this covers most cases.
- **Doesn't restore historical tags** — only protects going forward from when the rule is deployed.

#### Removal

To remove the automation rules:
1. Go to **Microsoft Sentinel → Automation**
2. Find and delete **"Protect Critical Incident Tags"** and **"Protect Critical Incident Tags (New Incidents)"**

---

### Option 2: Logic App Playbook (Dynamic)

**A more robust approach that dynamically restores _any_ tag**, not just preconfigured ones. It reads previous tags from the Azure Activity Log and merges them back.

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fiamjoeycruz%2Fsecuritycopilotindefender%2Fmain%2Fremediation%2Frestore-sentinel-incident-tags%2Fazuredeploy.json)

| | |
|---|---|
| **Template** | [`restore-sentinel-incident-tags/azuredeploy.json`](restore-sentinel-incident-tags/azuredeploy.json) |
| **Documentation** | 📖 **[Full Deployment Guide](restore-sentinel-incident-tags/README.md)** |
| **Cost** | ~$0.000025/action; typically < $1/month |
| **Complexity** | Medium — Logic App + Managed Identity + RBAC + Automation Rule |
| **What it protects** | **Any** tag dynamically (GET → merge → PUT pattern) |
| **Requirements** | Contributor role on the resource group |

#### How It Works

```
Sentinel Automation Rule fires on "Incident Updated"
         ↓
Logic App:
  1. GET /incidents/{id} — read current labels
  2. Compare against required tags list
  3. IF any tags missing → merge and PUT back with etag
  4. Log result
```

#### When to Use This Instead

- Your automation tags change frequently and you can't predict them all
- You need **any** tag restored, not just a known set
- You want Activity Log–based tag discovery (restores tags you didn't even know about)

#### Deployment

See the **[Full Deployment Guide](restore-sentinel-incident-tags/README.md)** for step-by-step instructions including post-deployment RBAC and automation rule setup.

---

## Which Option Should I Choose?

| Scenario | Recommended |
|----------|:-----------:|
| I know which tags my automation uses | ⭐ **Automation Rule** |
| I want the simplest, fastest fix | ⭐ **Automation Rule** |
| I want zero cost | ⭐ **Automation Rule** |
| My tags change often or I can't predict them | **Logic App** |
| I need dynamic tag restoration from Activity Log | **Logic App** |
| I want defense in depth (both!) | **Both** |

> **Tip:** You can deploy **both** options together. The automation rule handles the known tags immediately (free, no latency), and the Logic App catches anything else as a safety net.

---

## Diagnosing the Problem First

Not sure if tag removal is actually happening in your environment? Run the diagnostic script **before** deploying any fix:

```powershell
# Zero-config — walks you through everything interactively
.\scripts\Investigate-PhishingTriageAgentTagRemoval.ps1
```

The diagnostic script:
- ✅ Scans your Sentinel incidents for missing tags (read-only)
- ✅ Runs KQL queries to identify which actors are stripping tags
- ✅ Generates an HTML report with findings, evidence, and remediation steps
- ✅ **Does NOT modify any resources**

---

## ⚠️ Disclaimer

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                              DISCLAIMER                                    ║
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

1. **REVIEW** — Read the script/template code to understand what it does
2. **TEST** — Always deploy in a **non-production environment** first
3. **AUTHORIZE** — Ensure you have proper permissions (Sentinel Contributor for automation rules, Contributor for Logic App)
4. **COMPLY** — Verify compliance with your organization's security and change management policies
5. **MONITOR** — After deployment, verify the rules/playbooks are working as expected

These are **unofficial community tools** provided for **educational and experimental purposes only**. They are **not** Microsoft products.
