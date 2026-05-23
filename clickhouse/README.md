# /clickhouse — State Machine & Triage Engine

ClickHouse is the central nervous system of AutoPatch-Agent. Every piece of data in the pipeline flows through here, and the triage decision that drives remediation is a single SQL query run against these tables.

## Responsibility

- Store raw CVE findings from Datadog
- Store enrichment results from Nimble (exploit intel + exposure checks)
- Run the triage JOIN query to classify vulnerabilities as CRITICAL or LOW
- Store remediation outcomes and audit logs
- Serve data to the frontend dashboard

## Files to Build

| File | Description |
|------|-------------|
| `schema.sql` | All `CREATE TABLE` statements |
| `migrations/` | Versioned schema changes |
| `client.py` | Python ClickHouse client wrapper |
| `queries.py` | All named queries (triage, dashboard fetch, audit log) |
| `seed.py` | Seeds the DB with mock data for demo/dev |

## Tables

### `cve_findings`
Raw CVE data ingested from Datadog.
```sql
cve_id, severity, cvss_score, package_name,
affected_version, host_id, host_ip, detected_at
```

### `exploit_intel`
Exploit intelligence pulled from Nimble web searches.
```sql
cve_id, has_active_exploit, exploit_sources (Array),
summary, searched_at
```

### `exposure_checks`
Internet exposure verification results from Nimble.
```sql
host_ip, port, is_internet_exposed, response_code, checked_at
```

### `triage_results`
Output of the triage JOIN query — the agent's decision.
```sql
cve_id, host_ip, priority (CRITICAL|LOW),
reason, created_at
```

### `remediation_log`
Audit trail of every action taken by the agent.
```sql
cve_id, host_ip, action_taken, script_executed,
outcome (success|failed|deferred), executed_at
```

## The Triage Query (Core Logic)

```sql
SELECT
    c.cve_id,
    c.host_ip,
    c.cvss_score,
    e.has_active_exploit,
    ex.is_internet_exposed,
    CASE
        WHEN e.has_active_exploit = true AND ex.is_internet_exposed = true
            THEN 'CRITICAL'
        ELSE 'LOW'
    END AS priority
FROM cve_findings c
LEFT JOIN exploit_intel e ON c.cve_id = e.cve_id
LEFT JOIN exposure_checks ex ON c.host_ip = ex.host_ip
ORDER BY priority DESC, c.cvss_score DESC;
```
