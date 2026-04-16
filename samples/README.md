# Sample Reports

> **Note:** These are anonymized sample outputs generated from a test environment. All subscription IDs, workspace names, email addresses, and other identifying information have been replaced with placeholder values.

## Available Samples

| Sample | Source Script | Description |
|--------|---------------|-------------|
| [`sample-diagnostic-report.html`](sample-diagnostic-report.html) | `scripts/Diagnose-And-Remediate-PhishingTriageAgentTags.ps1` | Shows what the diagnostic report looks like when tag stripping is detected — includes executive summary, impacted incidents, KQL evidence, and remediation steps |

## How to View

Download the HTML file and open it in any browser, or use GitHub's raw file view:

```
# Clone the repo and open locally
git clone https://github.com/iamjoeycruz/securitycopilotindefender.git
start samples/sample-diagnostic-report.html
```

## What These Reports Show

### Diagnostic Report
- **Verdict** — whether tag stripping is confirmed, suspected, or not detected
- **Executive Summary** — key stats (total incidents scanned, phishing-related, tags missing)
- **Who Is Removing Tags** — table of actors/services responsible, with removal rates
- **Incidents With Tags Stripped** — list of affected incidents with before/after tag counts
- **KQL Evidence** — copy-pastable KQL queries for your own investigation in Sentinel
- **Recommended Actions** — prioritized remediation steps
