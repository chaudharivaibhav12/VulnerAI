# /senso — Grounded Report Generation

This module sends the full audit trail to the Senso.ai API to generate a beautifully formatted, source-cited security posture report. This report is what the judges (and the Vercel dashboard) will read.

## Responsibility

- Compile the complete pipeline audit trail from ClickHouse
- Send it to Senso.ai with a structured prompt requesting a cited markdown report
- Save the output as `cited.md`
- Expose the report as a JSON endpoint for the frontend to consume

## Files to Build

| File | Description |
|------|-------------|
| `client.py` | Senso.ai API client |
| `report_builder.py` | Compiles ClickHouse data into the Senso.ai prompt payload |
| `cited.md` | Generated output — the final security report (auto-written by agent) |
| `server.py` | Tiny FastAPI server that serves `cited.md` as JSON to the frontend |

## Report Structure (what Senso.ai should produce)

```markdown
# AutoPatch-Agent Security Posture Report
Generated: <timestamp>

## Executive Summary
...

## Critical Finding: CVE-2024-6387 (OpenSSH RegreSSHion)
- CVSS Score: 9.8
- Host: <ip>
- Internet Exposed: YES ✅
- Active Exploit Confirmed: YES ✅
- Sources:
  - [NVD Advisory](https://nvd.nist.gov/vuln/detail/CVE-2024-6387)
  - [Qualys Blog](https://...)
- Action Taken: SSH config patched + restricted to VPN range
- Outcome: SUCCESS

## Deferred Findings (Low Priority)
| CVE | Host | Reason Deferred |
|-----|------|-----------------|
| CVE-2021-44228 | 10.0.1.3 | Internal host, not internet-exposed |
...

## Methodology & Data Sources
...
```

## Senso.ai API Call Pattern

```python
POST https://api.senso.ai/v1/generate
{
  "prompt": "Generate a security posture report...",
  "context": {
    "triage_results": [...],
    "remediation_log": [...],
    "exploit_sources": [...]
  },
  "format": "markdown",
  "citations": true
}
```
