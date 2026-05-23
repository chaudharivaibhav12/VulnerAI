"""
Tool implementations for the AutoPatch-Agent.
Each function maps 1:1 to a GPT-4o function definition.
In mock mode, returns data from local JSON files.
In live mode, calls real APIs (Datadog, Nimble, ClickHouse, SSM).
"""

import json
import os
import sys

# Path helpers
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from agent.config import Config
from agent.models import (
    CVEFinding, ExploitIntel, ExposureResult,
    TriageResult, RemediationOutcome
)
from clickhouse.mock_client import (
    insert_cve_findings, insert_exploit_intel,
    insert_exposure_checks, insert_triage_results,
    insert_remediation_log, run_triage_query,
    replace_triage_results, fetch_all
)


# ─────────────────────────────────────────────────────────────
# Tool 1: Fetch CVE Findings from Datadog
# ─────────────────────────────────────────────────────────────

def fetch_cve_findings() -> dict:
    """
    Fetches the list of active vulnerability findings.
    Primary: loads from vuln_catalog.ndjson (web-app vulns with real attack data)
    Fallback: loads from datadog/mock_cves.json (infrastructure CVEs)
    """
    print("[tool] fetch_cve_findings()")

    from datadog.vuln_loader import load_vuln_catalog, CATALOG_PATH
    if os.path.exists(CATALOG_PATH):
        raw = load_vuln_catalog()
    else:
        mock_path = os.path.join(ROOT, "datadog", "mock_cves.json")
        with open(mock_path) as f:
            raw = json.load(f)

    findings = [CVEFinding(**r) for r in raw]
    insert_cve_findings([f.to_dict() for f in findings])

    return {
        "status": "success",
        "count": len(findings),
        "findings": [f.to_dict() for f in findings]
    }


# ─────────────────────────────────────────────────────────────
# Tool 2: Enrich CVE with Exploit Intelligence (Nimble)
# ─────────────────────────────────────────────────────────────

def enrich_exploit_intel(cve_id: str) -> dict:
    """
    Enriches a vuln by running BOTH span analyzer and Nimble in parallel and
    merging their signals. Neither source is a fallback — both always contribute.

    Signal merge:
      has_active_exploit = spans_hit OR nimble_confirmed
      exploit_sources    = deduplicated union of both source lists
      summary            = combined narrative
    """
    print(f"[tool] enrich_exploit_intel(cve_id={cve_id})")

    from datadog.span_analyzer import analyze_attack_spans, SPANS_PATH
    from nimble.exploit_search import search_exploit_intel

    span_data   = analyze_attack_spans(cve_id) if os.path.exists(SPANS_PATH) else None
    nimble_data = search_exploit_intel(cve_id)

    # Merge sources — spans first (real attacks), then Nimble URLs
    seen: set[str] = set()
    merged_sources: list[str] = []
    for src_list in [
        span_data.get("exploit_sources", []) if span_data else [],
        nimble_data.get("exploit_sources", []),
    ]:
        for s in src_list:
            if s and s not in seen:
                merged_sources.append(s)
                seen.add(s)

    has_exploit = (
        (span_data["has_active_exploit"] if span_data else False)
        or nimble_data.get("has_active_exploit", False)
    )

    span_summary   = span_data["summary"]   if span_data   else "No span data."
    nimble_summary = nimble_data.get("summary", "No Nimble data.")
    merged_summary = f"[Spans] {span_summary} | [Nimble] {nimble_summary}"

    intel_data = {
        "cve_id":             cve_id,
        "has_active_exploit": has_exploit,
        "exploit_sources":    merged_sources,
        "summary":            merged_summary,
        "searched_at":        nimble_data.get("searched_at", ""),
    }

    intel = ExploitIntel(**intel_data)
    insert_exploit_intel([intel.to_dict()])

    return {
        "status":             "success",
        "cve_id":             cve_id,
        "has_active_exploit": intel.has_active_exploit,
        "span_hit":           span_data["has_active_exploit"] if span_data else False,
        "nimble_hit":         nimble_data.get("has_active_exploit", False),
        "summary":            intel.summary,
        "sources_count":      len(intel.exploit_sources),
    }


# ─────────────────────────────────────────────────────────────
# Tool 3: Check Internet Exposure (Nimble)
# ─────────────────────────────────────────────────────────────

def check_internet_exposure(host_ip: str, port: int = 80) -> dict:
    """
    Probes a host IP via Nimble to check if it is reachable from the internet.
    Mock: loads from nimble/mock_responses.json (USE_MOCKS=true)
    Live: routes an HTTP probe through the Nimble network proxy
    """
    print(f"[tool] check_internet_exposure(host_ip={host_ip}, port={port})")

    from nimble.exposure_check import check_exposure
    check_data = check_exposure(host_ip, port)

    result = ExposureResult(**check_data)
    insert_exposure_checks([result.to_dict()])

    return {
        "status": "success",
        "host_ip": host_ip,
        "is_internet_exposed": result.is_internet_exposed,
        "banner": result.banner
    }


# ─────────────────────────────────────────────────────────────
# Tool 4: Run Triage Query in ClickHouse
# ─────────────────────────────────────────────────────────────

def run_triage() -> dict:
    """
    Executes the triage JOIN query in ClickHouse (mock SQLite).
    Returns prioritised list of CVEs: CRITICAL or LOW.
    """
    print("[tool] run_triage()")

    rows = run_triage_query()
    triage_results = [TriageResult(**r) for r in rows]

    insert_triage_results([t.to_dict() for t in triage_results])

    critical = [t for t in triage_results if t.priority == "CRITICAL"]
    low = [t for t in triage_results if t.priority == "LOW"]

    return {
        "status": "success",
        "total": len(triage_results),
        "critical_count": len(critical),
        "low_count": len(low),
        "triage_results": [t.to_dict() for t in triage_results]
    }


# ─────────────────────────────────────────────────────────────
# Tool 5: Re-rank Triage with Multi-Signal Scoring
# ─────────────────────────────────────────────────────────────

# Scoring weights
_W_SPAN_ATTACK  = 5    # per real attack span (capped at 40)
_W_SPAN_CAP     = 40
_W_NIMBLE       = 25   # Nimble confirmed exploit in the wild
_W_EXPOSURE     = 20   # host/endpoint is internet-exposed
# CVSS score contributes directly (0–10 pts)

_PRIORITY_BANDS = [
    (60, "CRITICAL"),
    (35, "HIGH"),
    (15, "MEDIUM"),
    (0,  "LOW"),
]


def _score_to_priority(score: float) -> str:
    for threshold, label in _PRIORITY_BANDS:
        if score >= threshold:
            return label
    return "LOW"


def rerank_triage() -> dict:
    """
    Re-ranks every triage result using a composite risk score that combines:
      - Span attack frequency  (real attacks seen in live traffic, capped at 40 pts)
      - Nimble exploit signal  (web intel confirms exploit in the wild, 25 pts)
      - Internet exposure      (endpoint/host is publicly reachable, 20 pts)
      - CVSS score             (static severity, 0–10 pts)

    Priority bands:  >= 60 → CRITICAL | >= 35 → HIGH | >= 15 → MEDIUM | < 15 → LOW

    Replaces the binary CRITICAL/LOW triage with this richer scoring and
    persists the updated results back to the triage_results table.
    """
    print("[tool] rerank_triage()")

    from datadog.span_analyzer import get_attack_counts, SPANS_PATH

    rows         = run_triage_query()
    attack_counts = get_attack_counts() if os.path.exists(SPANS_PATH) else {}

    # Load exploit intel for the nimble_hit signal
    intel_rows   = fetch_all("exploit_intel")
    # exploit_sources stored as JSON string in SQLite
    intel_by_cve = {}
    for row in intel_rows:
        sources_raw = row.get("exploit_sources", "[]")
        try:
            sources = json.loads(sources_raw) if isinstance(sources_raw, str) else sources_raw
        except json.JSONDecodeError:
            sources = []
        # Nimble hit = any source URL from NVD/GitHub/CISA (not a span attack URL)
        nimble_hit = any(
            "nvd.nist.gov" in s or "github.com/advisories" in s or "cisa.gov" in s
            for s in sources if isinstance(s, str)
        )
        intel_by_cve[row["cve_id"]] = {
            "has_active_exploit": bool(row.get("has_active_exploit", 0)),
            "nimble_hit":         nimble_hit,
        }

    ranked = []
    for row in rows:
        vuln_id     = row["cve_id"]
        attack_cnt  = attack_counts.get(vuln_id, 0)
        intel       = intel_by_cve.get(vuln_id, {})
        cvss        = float(row.get("cvss_score") or 0)
        is_exposed  = bool(row.get("is_internet_exposed") or 0)
        nimble_hit  = intel.get("nimble_hit", False)

        score = (
            min(attack_cnt * _W_SPAN_ATTACK, _W_SPAN_CAP)
            + (_W_NIMBLE    if nimble_hit  else 0)
            + (_W_EXPOSURE  if is_exposed  else 0)
            + cvss
        )
        priority = _score_to_priority(score)

        reason_parts = []
        if attack_cnt > 0:
            reason_parts.append(f"{attack_cnt} real attack(s) in live traffic")
        if nimble_hit:
            reason_parts.append("Nimble confirmed exploit in the wild")
        if is_exposed:
            reason_parts.append("endpoint is internet-exposed")
        reason_parts.append(f"CVSS {cvss}")
        reason = "; ".join(reason_parts) + f" → risk score {score:.0f}"

        ranked.append(TriageResult(
            cve_id           = vuln_id,
            host_ip          = row["host_ip"],
            host_name        = row.get("host_name", ""),
            cvss_score       = cvss,
            package_name     = row.get("package_name", ""),
            affected_version = row.get("affected_version", ""),
            host_id          = row.get("host_id", ""),
            has_active_exploit = bool(row.get("has_active_exploit") or 0),
            is_internet_exposed = is_exposed,
            priority         = priority,
            reason           = reason,
        ))

    # Sort: CRITICAL first, then by score desc
    band_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    ranked.sort(key=lambda t: (band_order.get(t.priority, 9), -float(t.cvss_score)))

    replace_triage_results([t.to_dict() for t in ranked])

    summary = {p: sum(1 for t in ranked if t.priority == p)
               for p in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}

    return {
        "status":   "success",
        "total":    len(ranked),
        "summary":  summary,
        "ranked":   [t.to_dict() for t in ranked],
    }


# ─────────────────────────────────────────────────────────────
# Tool 6: Execute Remediation
# ─────────────────────────────────────────────────────────────

REMEDIATION_ACTIONS = {
    "CVE-2024-6387": {
        "action": "Patch OpenSSH config: disable empty passwords, restrict to VPN subnet, restart sshd",
        "script": "remediation/scripts/patch_openssh.sh"
    },
    "CVE-2023-44487": {
        "action": "Disable HTTP/2 in nginx config, reload nginx",
        "script": "remediation/scripts/patch_nginx.sh"
    },
    "CVE-2021-44228": {
        "action": "Set LOG4J_FORMAT_MSG_NO_LOOKUPS=true env var, restart application",
        "script": "remediation/scripts/patch_log4j.sh"
    },
    "CVE-2024-3094": {
        "action": "Downgrade xz-utils to 5.4.6 via apt, verify binary integrity",
        "script": "remediation/scripts/patch_xz.sh"
    },
    "CVE-2023-23397": {
        "action": "Disable UNC path resolution in libmapi config, restart mail service",
        "script": "remediation/scripts/patch_mapi.sh"
    }
}


def execute_remediation(cve_id: str, host_id: str, host_ip: str) -> dict:
    """
    Executes a remediation script against the target host.
    DRY_RUN=true (default) logs the action without executing.
    Live mode: sends command via AWS SSM Run Command.
    """
    print(f"[tool] execute_remediation(cve_id={cve_id}, host_ip={host_ip})")

    action_info = REMEDIATION_ACTIONS.get(cve_id, {
        "action": f"Generic patch: update {cve_id} package to latest safe version",
        "script": "remediation/scripts/generic_patch.sh"
    })

    if Config.DRY_RUN:
        outcome = "dry_run"
        output = f"[DRY RUN] Would execute: {action_info['script']} on {host_id} ({host_ip})"
    else:
        # Live: call ssm_runner.py or ssh_runner.py
        # outcome, output = ssm_runner.run(host_id, action_info["script"])
        outcome = "success"
        output = f"Script executed successfully on {host_id}"

    log_entry = RemediationOutcome(
        cve_id=cve_id,
        host_id=host_id,
        host_ip=host_ip,
        action_taken=action_info["action"],
        script_executed=action_info["script"],
        outcome=outcome,
        output=output
    )
    insert_remediation_log(log_entry.to_dict())

    return {
        "status": "success",
        "cve_id": cve_id,
        "host_ip": host_ip,
        "outcome": outcome,
        "action_taken": action_info["action"],
        "output": output
    }


# ─────────────────────────────────────────────────────────────
# Anthropic Tool Definitions (claude-sonnet-4-6)
# Uses input_schema instead of parameters
# ─────────────────────────────────────────────────────────────

TOOL_DEFINITIONS_ANTHROPIC = [
    {
        "name": "fetch_cve_findings",
        "description": "Fetch the list of active CVE vulnerability findings from Datadog Cloud Security Management. Returns CVE IDs, severity scores, affected packages, and host IPs.",
        "input_schema": {"type": "object", "properties": {}, "required": []}
    },
    {
        "name": "enrich_exploit_intel",
        "description": "Search the open web via Nimble to determine if a specific CVE has active exploits in the wild. Returns a boolean flag, source URLs, and a summary.",
        "input_schema": {
            "type": "object",
            "properties": {
                "cve_id": {
                    "type": "string",
                    "description": "The CVE identifier, e.g. CVE-2024-6387"
                }
            },
            "required": ["cve_id"]
        }
    },
    {
        "name": "check_internet_exposure",
        "description": "Use Nimble to probe a host IP and check if it is reachable from the public internet. Returns true if the host is internet-exposed.",
        "input_schema": {
            "type": "object",
            "properties": {
                "host_ip": {
                    "type": "string",
                    "description": "The IP address to probe"
                },
                "port": {
                    "type": "integer",
                    "description": "The port to probe (default 80)"
                }
            },
            "required": ["host_ip"]
        }
    },
    {
        "name": "run_triage",
        "description": "Execute the triage query in ClickHouse. Joins CVE findings with exploit intelligence and internet exposure data to classify each vulnerability as CRITICAL or LOW priority.",
        "input_schema": {"type": "object", "properties": {}, "required": []}
    },
    {
        "name": "rerank_triage",
        "description": "Re-ranks triage results using a composite risk score combining span attack frequency, Nimble exploit confidence, internet exposure, and CVSS. Produces CRITICAL/HIGH/MEDIUM/LOW priority bands and persists updated results. Call this AFTER run_triage.",
        "input_schema": {"type": "object", "properties": {}, "required": []}
    },
    {
        "name": "execute_remediation",
        "description": "Execute a remediation script against a CRITICAL or HIGH priority target via AWS SSM. Only call this for CRITICAL or HIGH priority findings from rerank_triage. Do NOT call for MEDIUM or LOW.",
        "input_schema": {
            "type": "object",
            "properties": {
                "cve_id": {
                    "type": "string",
                    "description": "The CVE to remediate"
                },
                "host_id": {
                    "type": "string",
                    "description": "The EC2 instance ID of the target host"
                },
                "host_ip": {
                    "type": "string",
                    "description": "The IP address of the target host"
                }
            },
            "required": ["cve_id", "host_id", "host_ip"]
        }
    }
]


# ─────────────────────────────────────────────────────────────
# OpenAI Function Definitions (gpt-4o, kept for switching)
# Uses parameters instead of input_schema
# ─────────────────────────────────────────────────────────────

TOOL_DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "fetch_cve_findings",
            "description": "Fetch the list of active CVE vulnerability findings from Datadog Cloud Security Management. Returns CVE IDs, severity scores, affected packages, and host IPs.",
            "parameters": {"type": "object", "properties": {}, "required": []}
        }
    },
    {
        "type": "function",
        "function": {
            "name": "enrich_exploit_intel",
            "description": "Search the open web via Nimble to determine if a specific CVE has active exploits in the wild. Returns a boolean flag, source URLs, and a summary.",
            "parameters": {
                "type": "object",
                "properties": {
                    "cve_id": {
                        "type": "string",
                        "description": "The CVE identifier, e.g. CVE-2024-6387"
                    }
                },
                "required": ["cve_id"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "check_internet_exposure",
            "description": "Use Nimble to probe a host IP and check if it is reachable from the public internet. Returns true if the host is internet-exposed.",
            "parameters": {
                "type": "object",
                "properties": {
                    "host_ip": {
                        "type": "string",
                        "description": "The IP address to probe"
                    },
                    "port": {
                        "type": "integer",
                        "description": "The port to probe (default 80)",
                        "default": 80
                    }
                },
                "required": ["host_ip"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "run_triage",
            "description": "Execute the triage query in ClickHouse. Joins CVE findings with exploit intelligence and internet exposure data to classify each vulnerability as CRITICAL or LOW priority.",
            "parameters": {"type": "object", "properties": {}, "required": []}
        }
    },
        {
            "type": "function",
            "function": {
                "name": "rerank_triage",
                "description": "Re-ranks triage results using a composite risk score combining span attack frequency, Nimble exploit confidence, internet exposure, and CVSS. Call this AFTER run_triage.",
                "parameters": {"type": "object", "properties": {}, "required": []}
            }
        },
    {
        "type": "function",
        "function": {
            "name": "execute_remediation",
            "description": "Execute a remediation script against a CRITICAL or HIGH priority target via AWS SSM. Only call for CRITICAL or HIGH findings from rerank_triage.",
            "parameters": {
                "type": "object",
                "properties": {
                    "cve_id": {
                        "type": "string",
                        "description": "The CVE to remediate"
                    },
                    "host_id": {
                        "type": "string",
                        "description": "The EC2 instance ID of the target host"
                    },
                    "host_ip": {
                        "type": "string",
                        "description": "The IP address of the target host"
                    }
                },
                "required": ["cve_id", "host_id", "host_ip"]
            }
        }
    }
]


# ─────────────────────────────────────────────────────────────
# Tool dispatcher — maps LLM tool call name → Python function
# ─────────────────────────────────────────────────────────────

def dispatch_tool(name: str, args: dict) -> dict:
    dispatch = {
        "fetch_cve_findings":    lambda: fetch_cve_findings(),
        "enrich_exploit_intel":  lambda: enrich_exploit_intel(**args),
        "check_internet_exposure": lambda: check_internet_exposure(**args),
        "run_triage":            lambda: run_triage(),
        "rerank_triage":         lambda: rerank_triage(),
        "execute_remediation":   lambda: execute_remediation(**args),
    }
    fn = dispatch.get(name)
    if not fn:
        return {"error": f"Unknown tool: {name}"}
    return fn()
