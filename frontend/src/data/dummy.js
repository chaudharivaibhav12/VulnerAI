export const SERVICES = [
  {
    id: 'svc-dvwa',
    name: 'dvwa-hack',
    host: 'dvwa.demo',
    instance_id: 'i-0a1b2c3d4e5f6a7b8',
    software: 'PHP 8.1 + Apache 2.4.57',
    port: 80,
    internet_exposed: true,
    cve_count: 4,
    status: 'AT_RISK',
    region: 'us-east-1',
  },
]

export const CVE_FINDINGS = [
  {
    id: 'VULN-001',
    service_id: 'svc-dvwa',
    service_name: 'dvwa-hack',
    cvss: 9.8,
    severity: 'CRITICAL',
    description: 'Command Injection — user-supplied "ip" parameter is concatenated into a shell_exec() call without sanitization, enabling arbitrary OS command execution as the web-server user.',
    internet_exposed: true,
    exploit_in_wild: true,
    exploit_sources: [
      { title: 'MITRE CWE-78', url: 'https://cwe.mitre.org/data/definitions/78.html' },
      { title: 'OWASP — Command Injection', url: 'https://owasp.org/www-community/attacks/Command_Injection' },
      { title: 'CISA KEV Catalog', url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog' },
    ],
    priority: 'CRITICAL',
    composite_score: 85.3,
    status: 'PATCHED',
    action_taken: 'PR opened: escapeshellarg() + IPv4 regex validation on the ip parameter',
    patched_at: '2026-05-23T18:16:30Z',
  },
  {
    id: 'VULN-002',
    service_id: 'svc-dvwa',
    service_name: 'dvwa-hack',
    cvss: 9.8,
    severity: 'CRITICAL',
    description: 'SQL Injection — the "id" GET parameter is interpolated directly into a SELECT statement, allowing UNION-based extraction of arbitrary tables including the users table.',
    internet_exposed: true,
    exploit_in_wild: true,
    exploit_sources: [
      { title: 'MITRE CWE-89', url: 'https://cwe.mitre.org/data/definitions/89.html' },
      { title: 'OWASP — SQL Injection', url: 'https://owasp.org/www-community/attacks/SQL_Injection' },
    ],
    priority: 'HIGH',
    composite_score: 64.1,
    status: 'PATCHED',
    action_taken: 'PDO prepared statement with integer-bound id parameter',
    patched_at: '2026-05-23T18:16:35Z',
  },
  {
    id: 'VULN-004',
    service_id: 'svc-dvwa',
    service_name: 'dvwa-hack',
    cvss: 6.1,
    severity: 'MEDIUM',
    description: 'Stored XSS — name and message fields in the guestbook are saved to the database and rendered to other users without HTML encoding, allowing persistent JavaScript injection.',
    internet_exposed: true,
    exploit_in_wild: true,
    exploit_sources: [
      { title: 'MITRE CWE-79', url: 'https://cwe.mitre.org/data/definitions/79.html' },
      { title: 'OWASP — XSS', url: 'https://owasp.org/www-community/attacks/xss/' },
    ],
    priority: 'HIGH',
    composite_score: 42.8,
    status: 'PATCHED',
    action_taken: 'htmlspecialchars() on output + strict CSP header script-src \'self\'',
    patched_at: '2026-05-23T18:16:40Z',
  },
  {
    id: 'VULN-003',
    service_id: 'svc-dvwa',
    service_name: 'dvwa-hack',
    cvss: 8.8,
    severity: 'HIGH',
    description: 'Unrestricted File Upload — the upload form accepts any extension and writes the result to a PHP-executable directory, enabling webshell upload.',
    internet_exposed: true,
    exploit_in_wild: false,
    exploit_sources: [
      { title: 'MITRE CWE-434', url: 'https://cwe.mitre.org/data/definitions/434.html' },
      { title: 'OWASP — Unrestricted File Upload', url: 'https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload' },
    ],
    priority: 'MEDIUM',
    composite_score: 24.3,
    status: 'DEFERRED',
    action_taken: null,
    deferred_reason: 'Composite 24.3 below remediation threshold — no live attack traffic observed in window despite high CVSS. Queued for next sprint.',
    patched_at: null,
  },
]

export const AGENT_LOG = [
  { ts: '18:15:44', level: 'INFO',  module: 'DETECT',  msg: 'Datadog CSM scan complete — 4 web-app vulns found on dvwa-hack' },
  { ts: '18:15:45', level: 'INFO',  module: 'DETECT',  msg: 'Loaded vuln_catalog.ndjson — VULN-001..004 staged for triage' },
  { ts: '18:15:46', level: 'INFO',  module: 'APM',     msg: 'read_apm(VULN-001): 2349 attack spans, 23 unique ASNs, trend 6.24× rising' },
  { ts: '18:15:46', level: 'INFO',  module: 'APM',     msg: 'read_apm(VULN-002): 296 sqlmap spans from RU/AS12389' },
  { ts: '18:15:46', level: 'INFO',  module: 'APM',     msg: 'read_apm(VULN-003): 0 attack spans in window' },
  { ts: '18:15:46', level: 'INFO',  module: 'APM',     msg: 'read_apm(VULN-004): 1 attack span — single XSS probe' },
  { ts: '18:15:47', level: 'INFO',  module: 'NIMBLE',  msg: 'search_nimble(VULN-001) — fetching cwe.mitre.org/data/definitions/78.html...' },
  { ts: '18:15:49', level: 'WARN',  module: 'NIMBLE',  msg: 'VULN-001 → MITRE confirms "in the wild" + 19 observed CVE refs' },
  { ts: '18:15:50', level: 'INFO',  module: 'NIMBLE',  msg: 'search_nimble(VULN-002) — KEV-listed, 47 ExploitDB PoCs, underground chatter 0.81' },
  { ts: '18:15:51', level: 'INFO',  module: 'NIMBLE',  msg: 'search_nimble(VULN-003) — no "in the wild" indicators on MITRE page' },
  { ts: '18:15:52', level: 'INFO',  module: 'NIMBLE',  msg: 'search_nimble(VULN-004) — MITRE confirms XSS "in the wild", 20 CVE refs' },
  { ts: '18:15:53', level: 'INFO',  module: 'RANK',    msg: 'Computing composite scores (0.50×active + 0.35×external + 0.15×static)...' },
  { ts: '18:15:54', level: 'CRIT',  module: 'RANK',    msg: 'VULN-001 composite 85.30 → CRITICAL (active 85.0 / external 80.3 / static 98.0)' },
  { ts: '18:15:54', level: 'WARN',  module: 'RANK',    msg: 'VULN-002 composite 64.13 → HIGH (active 36.3 / external 89.4 / static 98.0)' },
  { ts: '18:15:54', level: 'WARN',  module: 'RANK',    msg: 'VULN-004 composite 42.75 → HIGH (active 13.4 / external 76.8 / static 61.0)' },
  { ts: '18:15:54', level: 'INFO',  module: 'RANK',    msg: 'VULN-003 composite 24.27 → MEDIUM (active 0.0 / external 31.6 / static 88.0)' },
  { ts: '18:15:55', level: 'INFO',  module: 'CH',      msg: 'Ranking complete — 1 CRITICAL, 2 HIGH, 1 MEDIUM' },
  { ts: '18:15:55', level: 'OK',    module: 'RANK',    msg: 'Rank flip: VULN-004 (CVSS 6.1) above VULN-003 (CVSS 8.8) — runtime evidence overrode static severity' },
  { ts: '18:15:56', level: 'CRIT',  module: 'PATCH',   msg: 'execute_remediation(VULN-001) — escapeshellarg() + IPv4 regex…' },
  { ts: '18:15:58', level: 'OK',    module: 'PATCH',   msg: 'VULN-001 patched — pinging behavior preserved, injection blocked' },
  { ts: '18:15:59', level: 'WARN',  module: 'PATCH',   msg: 'execute_remediation(VULN-002) — PDO prepared statement…' },
  { ts: '18:16:01', level: 'OK',    module: 'PATCH',   msg: 'VULN-002 patched — UNION-based extraction blocked' },
  { ts: '18:16:02', level: 'WARN',  module: 'PATCH',   msg: 'execute_remediation(VULN-004) — htmlspecialchars() + CSP…' },
  { ts: '18:16:04', level: 'OK',    module: 'PATCH',   msg: 'VULN-004 patched — stored payload neutralized on render' },
  { ts: '18:16:05', level: 'INFO',  module: 'GITHUB',  msg: 'create_patch_pr(VULN-001) — top-ranked finding → PR' },
  { ts: '18:16:07', level: 'OK',    module: 'GITHUB',  msg: 'PR #4853 opened: [AutoPatch] VULN-001: Command Injection in ping form (CVSS 9.8)' },
  { ts: '18:16:08', level: 'INFO',  module: 'REPORT',  msg: 'Compiling audit trail — 3 patched, 1 deferred (MEDIUM)' },
  { ts: '18:16:09', level: 'OK',    module: 'REPORT',  msg: 'Security posture report generated' },
  { ts: '18:16:09', level: 'OK',    module: 'AGENT',   msg: 'Cycle complete. System posture: HARDENED' },
]

export const REPORT_MD = `# VulnerAI — Security Posture Report
**Generated:** 2026-05-23T18:16:09Z | **Cycle Duration:** 25s | **Agent:** Ranking Agent v0.2

---

## Executive Summary

VulnerAI completed an autonomous triage cycle across **1 host (dvwa-hack)** with **4 detected web-application vulnerabilities**. The Ranking Agent computed composite scores from live APM telemetry (read_apm) and external threat intelligence (search_nimble), then drove remediation for the top-ranked findings.

**Result:** 1 CRITICAL + 2 HIGH remediated, 1 MEDIUM deferred. 1 PR opened for the top pick.

**No human intervention was required.**

---

## What flipped the ranking

VULN-004 (Stored XSS, CVSS 6.1) ranks above VULN-003 (File Upload, CVSS 8.8) — runtime attack evidence and external threat pressure flipped the static-severity order. CVSS alone would have prioritized VULN-003.

---

## Critical Finding — PATCHED

### VULN-001 — Command Injection in ping form (CVSS 9.8) → composite 85.30
- **Host:** dvwa-hack (dvwa.demo)
- **Internet Exposed:** YES
- **Active Exploit Traffic:** 2,349 attempts/h from 23 ASNs across 9 countries; trend 6.24× rising
- **External Pressure:** MITRE CWE-78 confirms "in the wild" — 19 observed CVE refs, 23 public PoCs, KEV-listed
- **Action Taken:** \`escapeshellarg()\` + IPv4 regex validation on the ip parameter
- **Pull Request:** [AutoPatch — VULN-001](https://github.com/chaudharivaibhav12/VulnerAI/pull/4853)

---

## High Findings — PATCHED

### VULN-002 — SQL Injection in user lookup (CVSS 9.8) → composite 64.13
- **Active Exploit Traffic:** 296 sqlmap spans from RU
- **External Pressure:** KEV-listed, 47 ExploitDB PoCs, underground chatter 0.81
- **Action Taken:** PDO prepared statement, id bound as integer

### VULN-004 — Stored XSS in guestbook (CVSS 6.1) → composite 42.75
- **Active Exploit Traffic:** 1 attack span (single XSS probe)
- **External Pressure:** MITRE CWE-79 confirms "in the wild" — 20 observed CVE refs
- **Action Taken:** \`htmlspecialchars()\` on output + strict CSP \`script-src 'self'\`

---

## Medium Finding — DEFERRED

| Vuln | CVSS | Composite | Reason Deferred |
|------|------|-----------|-----------------|
| VULN-003 — Unrestricted File Upload | 8.8 | 24.27 | No live attack traffic in window despite high CVSS. Queued for next sprint. |

---

## Methodology

Runtime attack telemetry was pulled via the **read_apm** tool (backed by ClickHouse apm_spans) — attack count, unique source ASNs/countries, 15-min vs prior-45-min trend, and HTTP success rate.

External threat intelligence was gathered via the **search_nimble** tool — live Nimble Web API queries against the MITRE CWE catalogue, layered on top of canned ExploitDB / GitHub mentions / underground chatter baselines.

Composite priority was computed by the Ranking Agent using:

\`\`\`
composite = 0.50 × ACTIVE_EXPLOITATION
          + 0.35 × EXTERNAL_PRESSURE
          + 0.15 × STATIC_SEVERITY
\`\`\`

Active-exploitation evidence dominates because it is the only signal that proves the threat is real for this deployment at this moment. Static CVSS is a tiebreaker, not the primary input.

Remediation scripts ran via **AWS Systems Manager (SSM)**; the top-ranked finding additionally received an autonomous GitHub PR with the hardened patch diff.
`
