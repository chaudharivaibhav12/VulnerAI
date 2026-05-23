"""
Named ClickHouse queries for the real client.
These mirror the SQLite logic in mock_client.py — same logic, ClickHouse SQL dialect.
"""

TRIAGE_QUERY = """
SELECT
    c.cve_id,
    c.host_ip,
    c.host_name,
    c.cvss_score,
    c.package_name,
    c.affected_version,
    c.host_id,
    e.has_active_exploit,
    ex.is_internet_exposed,
    multiIf(
        e.has_active_exploit = 1 AND ex.is_internet_exposed = 1, 'CRITICAL',
        'LOW'
    ) AS priority,
    multiIf(
        e.has_active_exploit = 1 AND ex.is_internet_exposed = 1,
            'Active exploit confirmed + host is internet-exposed',
        e.has_active_exploit = 1,
            'Active exploit exists but host is internal-only',
        ex.is_internet_exposed = 1,
            'Host is internet-exposed but no active exploit found',
        'Internal host, no active exploit — safe to defer'
    ) AS reason
FROM autopatch.cve_findings c
LEFT JOIN autopatch.exploit_intel e    ON c.cve_id  = e.cve_id
LEFT JOIN autopatch.exposure_checks ex ON c.host_ip = ex.host_ip
ORDER BY
    priority ASC,
    c.cvss_score DESC
"""

DASHBOARD_SUMMARY_QUERY = """
SELECT
    countIf(priority = 'CRITICAL') AS critical_count,
    countIf(priority = 'LOW')      AS low_count,
    countIf(outcome = 'success')   AS patched_count,
    countIf(outcome = 'deferred')  AS deferred_count
FROM autopatch.triage_results t
LEFT JOIN autopatch.remediation_log r ON t.cve_id = r.cve_id
"""

REMEDIATION_LOG_QUERY = """
SELECT *
FROM autopatch.remediation_log
ORDER BY executed_at DESC
"""

INSERT_CVE_FINDING = """
INSERT INTO autopatch.cve_findings VALUES
"""

INSERT_EXPLOIT_INTEL = """
INSERT INTO autopatch.exploit_intel VALUES
"""

INSERT_EXPOSURE_CHECK = """
INSERT INTO autopatch.exposure_checks VALUES
"""

INSERT_TRIAGE_RESULT = """
INSERT INTO autopatch.triage_results VALUES
"""

INSERT_REMEDIATION_LOG = """
INSERT INTO autopatch.remediation_log VALUES
"""
