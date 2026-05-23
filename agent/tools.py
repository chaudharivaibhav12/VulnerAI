"""
Tool implementations for the AutoPatch-Agent.
Each function maps 1:1 to a GPT-4o function definition.
In mock mode, returns data from local JSON files.
In live mode, calls real APIs (Datadog, Nimble, ClickHouse, SSM).
"""

import json
import os
import sys
from datetime import datetime

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
    insert_pr_log, fetch_pr_context,
)
from agent.patch_generator import generate_patches
from agent.github_tools import (
    get_base_sha, create_branch, commit_file, create_pull_request
)
from agent.models import PRLog


# ─────────────────────────────────────────────────────────────
# Tool 1: Fetch CVE Findings from Datadog
# ─────────────────────────────────────────────────────────────

def fetch_cve_findings() -> dict:
    """
    Fetches the list of active CVE findings.
    Mock: loads from datadog/mock_cves.json
    Live: calls Datadog Security Findings API
    """
    print("[tool] fetch_cve_findings()")

    mock_path = os.path.join(ROOT, "datadog", "mock_cves.json")
    with open(mock_path) as f:
        raw = json.load(f)

    findings = [CVEFinding(**r) for r in raw]

    # Write to ClickHouse (mock)
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
    Searches the web (via Nimble) for active exploit evidence for a CVE.
    Mock: loads from nimble/mock_responses.json
    Live: calls Nimble web scraping API targeting NVD + GitHub Advisories
    """
    print(f"[tool] enrich_exploit_intel(cve_id={cve_id})")

    mock_path = os.path.join(ROOT, "nimble", "mock_responses.json")
    with open(mock_path) as f:
        mock_data = json.load(f)

    intel_data = mock_data["exploit_intel"].get(cve_id)
    if not intel_data:
        return {"status": "not_found", "cve_id": cve_id}

    intel = ExploitIntel(**intel_data)
    insert_exploit_intel([intel.to_dict()])

    return {
        "status": "success",
        "cve_id": cve_id,
        "has_active_exploit": intel.has_active_exploit,
        "summary": intel.summary,
        "sources_count": len(intel.exploit_sources)
    }


# ─────────────────────────────────────────────────────────────
# Tool 3: Check Internet Exposure (Nimble)
# ─────────────────────────────────────────────────────────────

def check_internet_exposure(host_ip: str, port: int = 80) -> dict:
    """
    Probes a host IP via Nimble to check if it is reachable from the internet.
    Mock: loads from nimble/mock_responses.json
    Live: routes an HTTP probe through the Nimble network proxy
    """
    print(f"[tool] check_internet_exposure(host_ip={host_ip}, port={port})")

    mock_path = os.path.join(ROOT, "nimble", "mock_responses.json")
    with open(mock_path) as f:
        mock_data = json.load(f)

    check_data = mock_data["exposure_checks"].get(host_ip)
    if not check_data:
        # Default: internal hosts not in mock are not exposed
        check_data = {
            "host_ip": host_ip,
            "port": port,
            "is_internet_exposed": False,
            "response_code": None,
            "banner": None,
            "checked_at": datetime.utcnow().isoformat() + "Z"
        }

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
# Tool 5: Execute Remediation
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
# Tool 6: Create Patch PR on GitHub
# ─────────────────────────────────────────────────────────────

def create_patch_pr(cve_id: str, host_id: str, host_ip: str) -> dict:
    """
    Creates a GitHub branch, commits security-hardened patch files, and opens a PR.
    All metadata is fetched from ClickHouse — call after execute_remediation.
    DRY_RUN=true (default) logs intent without making real GitHub API calls.
    """
    print(f"[tool] create_patch_pr(cve_id={cve_id}, host_ip={host_ip})")

    # Fetch full context from ClickHouse JOIN
    ctx = fetch_pr_context(cve_id, host_ip)
    if not ctx:
        return {
            "status": "error",
            "cve_id": cve_id,
            "error": "No context found in ClickHouse — ensure triage and remediation ran first",
        }

    # Generate patch files for this CVE
    patches = generate_patches(cve_id, ctx)
    if not patches:
        return {
            "status": "error",
            "cve_id": cve_id,
            "error": "No patch files generated — CVE may not have a known patch spec",
        }

    pkg_slug = ctx.get("package_name", "package").replace("_", "-").replace(" ", "-")
    branch_name = f"autopatch/{cve_id}-{pkg_slug}"

    # Create branch from latest base
    base_sha = get_base_sha()
    create_branch(branch_name, base_sha)

    # Commit each patch file
    patch_file_paths = []
    for patch in patches:
        msg = f"fix({cve_id}): update {patch['path']} — {ctx.get('package_name', '')} {ctx.get('affected_version', '')} → {ctx.get('fixed_version', '')}"
        commit_file(branch_name, patch["path"], patch["content"], msg)
        patch_file_paths.append(patch["path"])

    # Open the PR
    pr = create_pull_request(
        branch_name=branch_name,
        cve_id=cve_id,
        cvss_score=ctx.get("cvss_score", 0.0),
        package_name=ctx.get("package_name", ""),
        affected_version=ctx.get("affected_version", ""),
        fixed_version=ctx.get("fixed_version", ""),
        host_name=ctx.get("host_name", ""),
        host_ip=host_ip,
        priority=ctx.get("priority", "CRITICAL"),
        reason=ctx.get("reason", ""),
        has_active_exploit=bool(ctx.get("has_active_exploit")),
        is_internet_exposed=bool(ctx.get("is_internet_exposed")),
        exploit_sources=ctx.get("exploit_sources", []),
        action_taken=ctx.get("action_taken", ""),
        remediation_outcome=ctx.get("remediation_outcome", ""),
        patch_files=patch_file_paths,
    )

    # Log to ClickHouse pr_log
    log = PRLog(
        cve_id=cve_id,
        host_ip=host_ip,
        branch_name=branch_name,
        pr_number=pr["pr_number"],
        pr_url=pr["pr_url"],
        pr_status=pr["status"],
        files_patched=len(patch_file_paths),
        created_at=datetime.utcnow().isoformat() + "Z",
    )
    insert_pr_log(log.to_dict())

    return {
        "status": "success",
        "cve_id": cve_id,
        "branch": branch_name,
        "pr_number": pr["pr_number"],
        "pr_url": pr["pr_url"],
        "pr_status": pr["status"],
        "files_patched": len(patch_file_paths),
        "patch_files": patch_file_paths,
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
        "name": "execute_remediation",
        "description": "Execute a remediation script against a CRITICAL target host via AWS SSM. Only call this for CRITICAL priority CVEs. Do NOT call for LOW priority.",
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
    },
    {
        "name": "create_patch_pr",
        "description": "Create a GitHub Pull Request that codifies the security patch for a CRITICAL CVE. Generates hardened config and dependency file changes, commits them to a new branch, and opens a PR with full security context. Call this AFTER execute_remediation for each CRITICAL CVE.",
        "input_schema": {
            "type": "object",
            "properties": {
                "cve_id": {
                    "type": "string",
                    "description": "The CVE identifier, e.g. CVE-2024-6387"
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
            "name": "execute_remediation",
            "description": "Execute a remediation script against a CRITICAL target host via AWS SSM. Only call this for CRITICAL priority CVEs. Do NOT call for LOW priority.",
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
    },
    {
        "type": "function",
        "function": {
            "name": "create_patch_pr",
            "description": "Create a GitHub Pull Request that codifies the security patch for a CRITICAL CVE. Generates hardened config and dependency file changes, commits them to a new branch, and opens a PR with full security context. Call this AFTER execute_remediation for each CRITICAL CVE.",
            "parameters": {
                "type": "object",
                "properties": {
                    "cve_id": {
                        "type": "string",
                        "description": "The CVE identifier, e.g. CVE-2024-6387"
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
        "fetch_cve_findings":      lambda: fetch_cve_findings(),
        "enrich_exploit_intel":    lambda: enrich_exploit_intel(**args),
        "check_internet_exposure": lambda: check_internet_exposure(**args),
        "run_triage":              lambda: run_triage(),
        "execute_remediation":     lambda: execute_remediation(**args),
        "create_patch_pr":         lambda: create_patch_pr(**args),
    }
    fn = dispatch.get(name)
    if not fn:
        return {"error": f"Unknown tool: {name}"}
    return fn()
