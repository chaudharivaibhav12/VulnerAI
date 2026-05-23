"""
ClickHouse Mock Client
─────────────────────
SQLite-backed mock that mirrors the exact ClickHouse interface.
Swap out for clickhouse/client.py when real credentials are available —
the calling code in the agent never needs to change.
"""

import sqlite3
import json
import os
from datetime import datetime
from typing import Any

DB_PATH = os.path.join(os.path.dirname(__file__), "mock_autopatch.db")


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create all tables if they don't exist. Call once at startup."""
    conn = _get_conn()
    cur = conn.cursor()

    cur.executescript("""
        CREATE TABLE IF NOT EXISTS cve_findings (
            cve_id           TEXT,
            severity         TEXT,
            cvss_score       REAL,
            package_name     TEXT,
            affected_version TEXT,
            fixed_version    TEXT,
            host_id          TEXT,
            host_name        TEXT,
            host_ip          TEXT,
            is_public_ip     INTEGER,
            description      TEXT,
            detected_at      TEXT
        );

        CREATE TABLE IF NOT EXISTS exploit_intel (
            cve_id             TEXT,
            has_active_exploit INTEGER,
            exploit_sources    TEXT,
            summary            TEXT,
            searched_at        TEXT
        );

        CREATE TABLE IF NOT EXISTS exposure_checks (
            host_ip             TEXT,
            port                INTEGER,
            is_internet_exposed INTEGER,
            response_code       INTEGER,
            banner              TEXT,
            checked_at          TEXT
        );

        CREATE TABLE IF NOT EXISTS triage_results (
            cve_id      TEXT,
            host_ip     TEXT,
            host_name   TEXT,
            cvss_score  REAL,
            priority    TEXT,
            reason      TEXT,
            created_at  TEXT
        );

        CREATE TABLE IF NOT EXISTS remediation_log (
            cve_id          TEXT,
            host_id         TEXT,
            host_ip         TEXT,
            action_taken    TEXT,
            script_executed TEXT,
            outcome         TEXT,
            output          TEXT,
            executed_at     TEXT
        );

        CREATE TABLE IF NOT EXISTS pr_log (
            cve_id        TEXT,
            host_ip       TEXT,
            branch_name   TEXT,
            pr_number     INTEGER,
            pr_url        TEXT,
            pr_status     TEXT,
            files_patched INTEGER,
            created_at    TEXT
        );
    """)
    conn.commit()
    conn.close()


def insert_cve_findings(findings: list[dict]):
    conn = _get_conn()
    cur = conn.cursor()
    for f in findings:
        cur.execute("""
            INSERT INTO cve_findings VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            f["cve_id"], f["severity"], f["cvss_score"], f["package_name"],
            f["affected_version"], f["fixed_version"], f["host_id"],
            f["host_name"], f["host_ip"], int(f["is_public_ip"]),
            f["description"], f["detected_at"]
        ))
    conn.commit()
    conn.close()


def insert_exploit_intel(intel_list: list[dict]):
    conn = _get_conn()
    cur = conn.cursor()
    for i in intel_list:
        cur.execute("""
            INSERT INTO exploit_intel VALUES (?,?,?,?,?)
        """, (
            i["cve_id"], int(i["has_active_exploit"]),
            json.dumps(i["exploit_sources"]),
            i["summary"], i["searched_at"]
        ))
    conn.commit()
    conn.close()


def insert_exposure_checks(checks: list[dict]):
    conn = _get_conn()
    cur = conn.cursor()
    for c in checks:
        cur.execute("""
            INSERT INTO exposure_checks VALUES (?,?,?,?,?,?)
        """, (
            c["host_ip"], c["port"], int(c["is_internet_exposed"]),
            c.get("response_code"), c.get("banner"), c["checked_at"]
        ))
    conn.commit()
    conn.close()


def insert_triage_results(results: list[dict]):
    conn = _get_conn()
    cur = conn.cursor()
    for r in results:
        cur.execute("""
            INSERT INTO triage_results VALUES (?,?,?,?,?,?,?)
        """, (
            r["cve_id"], r["host_ip"], r["host_name"], r["cvss_score"],
            r["priority"], r["reason"],
            datetime.utcnow().isoformat()
        ))
    conn.commit()
    conn.close()


def insert_remediation_log(entry: dict):
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO remediation_log VALUES (?,?,?,?,?,?,?,?)
    """, (
        entry["cve_id"], entry["host_id"], entry["host_ip"],
        entry["action_taken"], entry["script_executed"],
        entry["outcome"], entry["output"],
        datetime.utcnow().isoformat()
    ))
    conn.commit()
    conn.close()


def run_triage_query() -> list[dict]:
    """
    The core decision query. Joins CVE findings with exploit intel
    and exposure checks to produce a prioritised triage list.
    """
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("""
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
            CASE
                WHEN e.has_active_exploit = 1 AND ex.is_internet_exposed = 1
                    THEN 'CRITICAL'
                ELSE 'LOW'
            END AS priority,
            CASE
                WHEN e.has_active_exploit = 1 AND ex.is_internet_exposed = 1
                    THEN 'Active exploit confirmed + host is internet-exposed'
                WHEN e.has_active_exploit = 1
                    THEN 'Active exploit exists but host is internal-only'
                WHEN ex.is_internet_exposed = 1
                    THEN 'Host is internet-exposed but no active exploit found'
                ELSE 'Internal host, no active exploit — safe to defer'
            END AS reason
        FROM cve_findings c
        LEFT JOIN exploit_intel e    ON c.cve_id  = e.cve_id
        LEFT JOIN exposure_checks ex ON c.host_ip = ex.host_ip
        ORDER BY
            CASE WHEN priority = 'CRITICAL' THEN 0 ELSE 1 END,
            c.cvss_score DESC
    """)
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def replace_triage_results(results: list[dict]):
    """Delete all existing triage rows and insert the re-ranked set."""
    conn = _get_conn()
    cur  = conn.cursor()
    cur.execute("DELETE FROM triage_results")
    for r in results:
        cur.execute("""
            INSERT INTO triage_results VALUES (?,?,?,?,?,?,?)
        """, (
            r["cve_id"], r["host_ip"], r["host_name"], r["cvss_score"],
            r["priority"], r["reason"],
            datetime.utcnow().isoformat()
        ))
    conn.commit()
    conn.close()


def insert_pr_log(entry: dict):
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO pr_log VALUES (?,?,?,?,?,?,?,?)
    """, (
        entry["cve_id"], entry["host_ip"], entry["branch_name"],
        entry["pr_number"], entry["pr_url"], entry["pr_status"],
        entry["files_patched"], entry.get("created_at", datetime.utcnow().isoformat())
    ))
    conn.commit()
    conn.close()


def fetch_pr_context(cve_id: str, host_ip: str) -> dict:
    """
    Returns all data needed by create_patch_pr in one JOIN:
    CVE metadata + exploit intel + triage result + latest remediation outcome.
    """
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("""
        SELECT
            c.cve_id,
            c.host_ip,
            c.host_name,
            c.host_id,
            c.package_name,
            c.affected_version,
            c.fixed_version,
            c.cvss_score,
            c.description,
            e.has_active_exploit,
            e.exploit_sources,
            e.summary       AS exploit_summary,
            ex.is_internet_exposed,
            t.priority,
            t.reason,
            r.action_taken,
            r.script_executed,
            r.outcome       AS remediation_outcome,
            r.executed_at
        FROM cve_findings c
        LEFT JOIN exploit_intel e    ON c.cve_id  = e.cve_id
        LEFT JOIN exposure_checks ex ON c.host_ip = ex.host_ip
        LEFT JOIN triage_results  t  ON c.cve_id  = t.cve_id AND c.host_ip = t.host_ip
        LEFT JOIN remediation_log r  ON c.cve_id  = r.cve_id AND c.host_ip = r.host_ip
        WHERE c.cve_id = ? AND c.host_ip = ?
        ORDER BY r.executed_at DESC
        LIMIT 1
    """, (cve_id, host_ip))
    row = cur.fetchone()
    conn.close()
    if not row:
        return {}
    result = dict(row)
    # exploit_sources is stored as JSON string — deserialise it
    try:
        result["exploit_sources"] = json.loads(result.get("exploit_sources") or "[]")
    except (json.JSONDecodeError, TypeError):
        result["exploit_sources"] = []
    return result


def fetch_all(table: str) -> list[dict]:
    """Generic fetch for dashboard/reporting use."""
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM {table}")
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def reset_db():
    """Wipe all data — useful for re-running the demo."""
    conn = _get_conn()
    cur = conn.cursor()
    for table in ["cve_findings", "exploit_intel", "exposure_checks",
                  "triage_results", "remediation_log", "pr_log"]:
        cur.execute(f"DELETE FROM {table}")
    conn.commit()
    conn.close()
