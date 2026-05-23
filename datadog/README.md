# /datadog — Vulnerability Detection

This module handles all Datadog integration: fetching real CVE findings from Datadog Cloud Security Management (CSM) and providing mock payloads for local development.

## Responsibility

- Query the Datadog Security Findings API to pull active CVEs on EC2 instances
- Parse CVE ID, severity score, affected host, and public IP
- Provide a realistic mock payload so the pipeline can run end-to-end without live Datadog access

## Files to Build

| File | Description |
|------|-------------|
| `client.py` | Datadog API client — fetches CSM vulnerability findings |
| `parser.py` | Parses raw API response into a clean `CVEFinding` dataclass |
| `mock_cves.json` | 5 realistic mock CVE findings for local dev/demo |
| `webhook_handler.py` | (Optional) Flask endpoint to receive real-time Datadog webhook alerts |

## Data Shape (CVEFinding)

```python
@dataclass
class CVEFinding:
    cve_id: str           # e.g. "CVE-2024-6387"
    severity: str         # "critical" | "high" | "medium" | "low"
    cvss_score: float     # e.g. 9.8
    package_name: str     # e.g. "openssh-server"
    affected_version: str # e.g. "9.2p1"
    host_id: str          # EC2 instance ID
    host_ip: str          # Internal or public IP
    detected_at: str      # ISO timestamp
```

## Mock CVE IDs (planted for demo)

- `CVE-2024-6387` — OpenSSH RegreSSHion (CRITICAL, internet-exposed)
- `CVE-2023-44487` — HTTP/2 Rapid Reset (HIGH, internal only)
- `CVE-2021-44228` — Log4Shell (CRITICAL, internal only)
- `CVE-2023-23397` — Outlook NTLM Relay (MEDIUM, internal only)
- `CVE-2024-3094` — XZ Utils backdoor (HIGH, internal only)
