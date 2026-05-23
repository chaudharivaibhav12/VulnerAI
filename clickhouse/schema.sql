-- AutoPatch-Agent ClickHouse Schema
-- Run this against your ClickHouse Cloud instance to initialize all tables.
-- Engine: MergeTree (ClickHouse default for analytics workloads)

CREATE DATABASE IF NOT EXISTS autopatch;

-- ─────────────────────────────────────────────
-- 1. Raw CVE findings from Datadog
-- ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS autopatch.cve_findings
(
    cve_id            String,
    severity          String,
    cvss_score        Float32,
    package_name      String,
    affected_version  String,
    fixed_version     String,
    host_id           String,
    host_name         String,
    host_ip           String,
    is_public_ip      Bool,
    description       String,
    detected_at       DateTime
)
ENGINE = MergeTree()
ORDER BY (detected_at, cve_id);

-- ─────────────────────────────────────────────
-- 2. Exploit intelligence from Nimble web search
-- ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS autopatch.exploit_intel
(
    cve_id              String,
    has_active_exploit  Bool,
    exploit_sources     Array(String),
    summary             String,
    searched_at         DateTime
)
ENGINE = MergeTree()
ORDER BY (searched_at, cve_id);

-- ─────────────────────────────────────────────
-- 3. Internet exposure checks from Nimble
-- ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS autopatch.exposure_checks
(
    host_ip              String,
    port                 UInt16,
    is_internet_exposed  Bool,
    response_code        Nullable(Int32),
    banner               Nullable(String),
    checked_at           DateTime
)
ENGINE = MergeTree()
ORDER BY (checked_at, host_ip);

-- ─────────────────────────────────────────────
-- 4. Triage results (agent decision output)
-- ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS autopatch.triage_results
(
    cve_id      String,
    host_ip     String,
    host_name   String,
    cvss_score  Float32,
    priority    String,   -- 'CRITICAL' | 'LOW'
    reason      String,
    created_at  DateTime
)
ENGINE = MergeTree()
ORDER BY (created_at, priority, cve_id);

-- ─────────────────────────────────────────────
-- 5. Remediation audit log
-- ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS autopatch.remediation_log
(
    cve_id          String,
    host_id         String,
    host_ip         String,
    action_taken    String,
    script_executed String,
    outcome         String,   -- 'success' | 'failed' | 'deferred' | 'dry_run'
    output          String,
    executed_at     DateTime
)
ENGINE = MergeTree()
ORDER BY (executed_at, cve_id);

-- ─────────────────────────────────────────────
-- Core triage query (run by the agent)
-- ─────────────────────────────────────────────
-- SELECT
--     c.cve_id,
--     c.host_ip,
--     c.host_name,
--     c.cvss_score,
--     e.has_active_exploit,
--     ex.is_internet_exposed,
--     CASE
--         WHEN e.has_active_exploit = true AND ex.is_internet_exposed = true THEN 'CRITICAL'
--         ELSE 'LOW'
--     END AS priority,
--     CASE
--         WHEN e.has_active_exploit = true AND ex.is_internet_exposed = true
--             THEN 'Active exploit confirmed + host is internet-exposed'
--         WHEN e.has_active_exploit = true
--             THEN 'Active exploit exists but host is internal-only'
--         WHEN ex.is_internet_exposed = true
--             THEN 'Host is internet-exposed but no active exploit found'
--         ELSE 'Internal host, no active exploit — safe to defer'
--     END AS reason
-- FROM autopatch.cve_findings c
-- LEFT JOIN autopatch.exploit_intel e   ON c.cve_id  = e.cve_id
-- LEFT JOIN autopatch.exposure_checks ex ON c.host_ip = ex.host_ip
-- ORDER BY priority DESC, c.cvss_score DESC;
