# Remediation — Protect Sentinel Incident Tags

> **⚠️ DISCLAIMER:** All scripts and templates in this directory are provided **"AS IS"** for **educational and experimental purposes only**. They are **not officially supported by Microsoft**. See the [full disclaimer](#%EF%B8%8F-disclaimer) below.

## The Problem

The **Security Copilot Phishing Triage Agent**, **Microsoft Defender XDR alert correlation**, and other services can unintentionally **remove tags/labels** from Microsoft Sentinel incidents. This breaks downstream automation that depends on those tags (e.g., auto-escalation, SOAR playbook triggers, assignment rules).

### Root Cause

There was a bug that was overwriting the tags.

### Who may be impacted?

Any organization that:
- Uses **incident tags** to trigger automation rules, playbooks, or SOAR workflows
- Has the **Phishing Triage Agent** or **Defender XDR alert correlation** enabled
- Relies on tags for incident classification, routing, or SLA tracking

---

## Supported Remediation Script

The only supported remediation script is **[`Diagnose-And-Remediate-PhishingTriageAgentTags.ps1`](../scripts/Diagnose-And-Remediate-PhishingTriageAgentTags.ps1)**, located in the [`scripts/`](../scripts/) directory.

Use it to scan your workspace, identify impacted incidents, and restore missing tags:

```powershell
# Diagnostic only (read-only report) — run this first
..\scripts\Diagnose-And-Remediate-PhishingTriageAgentTags.ps1 -DiagnosticOnly

# Full diagnose + remediate (interactive approval gates)
..\scripts\Diagnose-And-Remediate-PhishingTriageAgentTags.ps1
```

📖 **[Full instructions and prerequisites](../scripts/README.md#diagnose-and-remediate-phishingtriageagenttagsps1)** | 📄 **[View the script](../scripts/Diagnose-And-Remediate-PhishingTriageAgentTags.ps1)**

The script:
- ✅ Uses KQL-first server-side queries (scales to thousands of incidents)
- ✅ Identifies which actors/services are stripping tags
- ✅ Generates an HTML report with findings, KQL evidence, and remediation results
- ✅ Restores only agent-removed tags (not all historical tags)
- ✅ Two-gate admin approval before any changes
- ✅ Full property round-trip on PUT with etag concurrency protection
- 📊 **[See a sample report](../samples/sample-diagnostic-report.html)**

> **Note:** The `Deploy-TagProtectionAutomationRule.ps1` script in this directory is **deprecated and no longer supported**. Use the diagnose & remediate script above instead.

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
3. **AUTHORIZE** — Ensure you have proper permissions (Sentinel Contributor for automation rules)
4. **COMPLY** — Verify compliance with your organization's security and change management policies
5. **MONITOR** — After deployment, verify the rules are working as expected

These are **unofficial community tools** provided for **educational and experimental purposes only**. They are **not** Microsoft products.
