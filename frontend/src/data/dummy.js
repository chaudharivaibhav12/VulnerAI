export const SERVICES = [
  {
    id: 'svc-1',
    name: 'web-server-prod',
    host: '54.221.14.92',
    instance_id: 'i-0a1b2c3d4e5f6a7b8',
    software: 'OpenSSH 8.9p1',
    port: 22,
    internet_exposed: true,
    cve_count: 2,
    status: 'PATCHED',
    region: 'us-east-1',
  },
  {
    id: 'svc-2',
    name: 'api-server-internal',
    host: '10.0.1.45',
    instance_id: 'i-1b2c3d4e5f6a7b8c9',
    software: 'log4j 2.14.1',
    port: 8080,
    internet_exposed: false,
    cve_count: 2,
    status: 'DEFERRED',
    region: 'us-east-1',
  },
  {
    id: 'svc-3',
    name: 'db-backup-node',
    host: '10.0.2.11',
    instance_id: 'i-2c3d4e5f6a7b8c9d0',
    software: 'xz-utils 5.6.0',
    port: null,
    internet_exposed: false,
    cve_count: 1,
    status: 'DEFERRED',
    region: 'us-east-1',
  },
]

export const CVE_FINDINGS = [
  {
    id: 'CVE-2024-6387',
    service_id: 'svc-1',
    service_name: 'web-server-prod',
    cvss: 9.8,
    severity: 'CRITICAL',
    description: 'RegreSSHion — unauthenticated RCE in OpenSSH glibc-based systems',
    internet_exposed: true,
    exploit_in_wild: true,
    exploit_sources: [
      { title: 'Qualys Threat Research', url: 'https://blog.qualys.com/vulnerabilities-threat-research/2024/07/01/regresshion-remote-unauthenticated-code-execution-vulnerability-in-openssh-server' },
      { title: 'NVD Advisory', url: 'https://nvd.nist.gov/vuln/detail/CVE-2024-6387' },
      { title: 'GitHub PoC', url: 'https://github.com/advisories/GHSA-9hf4-67fc-4vf4' },
    ],
    priority: 'CRITICAL',
    status: 'PATCHED',
    action_taken: 'SSH config patched, restricted to VPN CIDR range',
    patched_at: '2024-07-15T14:32:01Z',
  },
  {
    id: 'CVE-2024-3094',
    service_id: 'svc-1',
    service_name: 'web-server-prod',
    cvss: 10.0,
    severity: 'CRITICAL',
    description: 'XZ Utils backdoor — malicious code in liblzma allowing SSH auth bypass',
    internet_exposed: true,
    exploit_in_wild: false,
    exploit_sources: [
      { title: 'NVD Advisory', url: 'https://nvd.nist.gov/vuln/detail/CVE-2024-3094' },
    ],
    priority: 'CRITICAL',
    status: 'PATCHED',
    action_taken: 'xz-utils downgraded to 5.4.6',
    patched_at: '2024-07-15T14:33:44Z',
  },
  {
    id: 'CVE-2021-44228',
    service_id: 'svc-2',
    service_name: 'api-server-internal',
    cvss: 10.0,
    severity: 'CRITICAL',
    description: 'Log4Shell — JNDI injection RCE in Apache Log4j 2.x',
    internet_exposed: false,
    exploit_in_wild: true,
    exploit_sources: [
      { title: 'NVD Advisory', url: 'https://nvd.nist.gov/vuln/detail/CVE-2021-44228' },
      { title: 'CISA Alert', url: 'https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-356a' },
    ],
    priority: 'LOW',
    status: 'DEFERRED',
    action_taken: null,
    deferred_reason: 'Internal host — not internet-exposed. Scheduled for maintenance window.',
    patched_at: null,
  },
  {
    id: 'CVE-2021-45046',
    service_id: 'svc-2',
    service_name: 'api-server-internal',
    cvss: 9.0,
    severity: 'CRITICAL',
    description: 'Log4j2 incomplete fix for CVE-2021-44228 — RCE via crafted lookup strings',
    internet_exposed: false,
    exploit_in_wild: false,
    exploit_sources: [],
    priority: 'LOW',
    status: 'DEFERRED',
    action_taken: null,
    deferred_reason: 'Internal host — not internet-exposed.',
    patched_at: null,
  },
  {
    id: 'CVE-2024-3094-xz',
    service_id: 'svc-3',
    service_name: 'db-backup-node',
    cvss: 10.0,
    severity: 'CRITICAL',
    description: 'XZ Utils backdoor present on backup node',
    internet_exposed: false,
    exploit_in_wild: false,
    exploit_sources: [],
    priority: 'LOW',
    status: 'DEFERRED',
    action_taken: null,
    deferred_reason: 'No network exposure. Queued for next patch cycle.',
    patched_at: null,
  },
]

export const AGENT_LOG = [
  { ts: '14:31:44', level: 'INFO',  module: 'DETECT',  msg: 'Datadog CSM scan complete — 5 CVEs found across 3 hosts' },
  { ts: '14:31:45', level: 'INFO',  module: 'DETECT',  msg: 'Parsed CI/CD deployment metadata — 3 instance IDs extracted' },
  { ts: '14:31:46', level: 'INFO',  module: 'NIMBLE',  msg: 'Querying exploit intel for CVE-2024-6387 (OpenSSH RegreSSHion)...' },
  { ts: '14:31:49', level: 'WARN',  module: 'NIMBLE',  msg: 'CVE-2024-6387 — active exploit CONFIRMED on 3 public sources' },
  { ts: '14:31:50', level: 'INFO',  module: 'NIMBLE',  msg: 'Probing 54.221.14.92:22 for internet exposure...' },
  { ts: '14:31:51', level: 'WARN',  module: 'NIMBLE',  msg: 'web-server-prod is INTERNET EXPOSED on port 22' },
  { ts: '14:31:52', level: 'INFO',  module: 'NIMBLE',  msg: 'Querying exploit intel for CVE-2021-44228 (Log4Shell)...' },
  { ts: '14:31:55', level: 'INFO',  module: 'NIMBLE',  msg: 'CVE-2021-44228 — exploit known but host 10.0.1.45 is INTERNAL' },
  { ts: '14:31:56', level: 'INFO',  module: 'CH',      msg: 'Writing 5 triage records to ClickHouse...' },
  { ts: '14:31:56', level: 'INFO',  module: 'CH',      msg: 'Triage query complete — 2 CRITICAL, 3 LOW priority' },
  { ts: '14:31:57', level: 'CRIT',  module: 'TRIAGE',  msg: 'CVE-2024-6387 on web-server-prod: CRITICAL — exposed + active exploit' },
  { ts: '14:31:57', level: 'INFO',  module: 'TRIAGE',  msg: 'CVE-2021-44228 on api-server-internal: LOW — internal host, deferring' },
  { ts: '14:31:58', level: 'CRIT',  module: 'PATCH',   msg: 'Executing patch_openssh.sh on i-0a1b2c3d4e5f6a7b8 via SSM...' },
  { ts: '14:32:01', level: 'INFO',  module: 'PATCH',   msg: 'SSH config updated — MaxAuthTries=3, AllowUsers restricted to VPN' },
  { ts: '14:32:03', level: 'INFO',  module: 'PATCH',   msg: 'Firewall rule applied — port 22 restricted to 10.0.0.0/8' },
  { ts: '14:32:05', level: 'OK',    module: 'PATCH',   msg: 'web-server-prod patched successfully — CVE-2024-6387 RESOLVED' },
  { ts: '14:32:06', level: 'INFO',  module: 'REPORT',  msg: 'Compiling audit trail — 2 patched, 3 deferred' },
  { ts: '14:32:08', level: 'OK',    module: 'REPORT',  msg: 'Security posture report generated → cited.md' },
  { ts: '14:32:08', level: 'OK',    module: 'AGENT',   msg: 'Cycle complete. System posture: HARDENED' },
]

export const REPORT_MD = `# AutoPatch-Agent Security Posture Report
**Generated:** 2024-07-15T14:32:08Z | **Cycle Duration:** 24s | **Agent:** AutoPatch v1.0

---

## Executive Summary

AutoPatch-Agent completed a full vulnerability triage cycle across **3 EC2 instances** and **5 detected CVEs**. The agent autonomously patched **2 critical vulnerabilities** on the internet-exposed host and safely deferred **3 findings** on internal-only services.

**No human intervention was required.**

---

## Critical Findings — PATCHED

### CVE-2024-6387 — OpenSSH RegreSSHion (CVSS 9.8)
- **Host:** web-server-prod (54.221.14.92)
- **Internet Exposed:** YES
- **Active Exploit in Wild:** YES — confirmed by 3 independent sources
- **Action Taken:** SSH config patched, access restricted to VPN CIDR range
- **Outcome:** SUCCESS

**Sources:**
1. [Qualys Threat Research — RegreSSHion](https://blog.qualys.com/vulnerabilities-threat-research/2024/07/01/regresshion-remote-unauthenticated-code-execution-vulnerability-in-openssh-server)
2. [NVD Advisory — CVE-2024-6387](https://nvd.nist.gov/vuln/detail/CVE-2024-6387)
3. [GitHub Security Advisory](https://github.com/advisories/GHSA-9hf4-67fc-4vf4)

---

## Deferred Findings — LOW PRIORITY

| CVE | Host | CVSS | Reason Deferred |
|-----|------|------|-----------------|
| CVE-2021-44228 | api-server-internal (10.0.1.45) | 10.0 | Internal host — no internet exposure verified by Nimble |
| CVE-2021-45046 | api-server-internal (10.0.1.45) | 9.0 | Internal host — no internet exposure |
| CVE-2024-3094 | db-backup-node (10.0.2.11) | 10.0 | No network exposure — queued for next maintenance window |

---

## Methodology

All threat intelligence was gathered autonomously via **Nimble API** — live web queries against NVD, security blogs, and GitHub advisories. Internet exposure was verified by active network probes, not assumed from configuration.

Triage priority was computed in **ClickHouse** using the formula:

\`\`\`
CRITICAL = has_active_exploit AND is_internet_exposed
LOW      = everything else
\`\`\`

Remediation scripts were executed via **AWS Systems Manager (SSM)** — no SSH credentials stored on the agent host.
`
