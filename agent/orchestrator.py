"""
GPT-4o Reasoning Orchestrator
──────────────────────────────
Runs a tool-use loop where GPT-4o decides which tool to call next
based on the pipeline state. The LLM acts as a reasoning agent,
not just a text generator.

In mock mode (USE_MOCKS=true / no OPENAI_API_KEY), falls back to a
deterministic hardcoded pipeline that produces identical output.
"""

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from agent.config import Config
from agent.tools import TOOL_DEFINITIONS, dispatch_tool

try:
    from openai import OpenAI
    OPENAI_AVAILABLE = bool(Config.OPENAI_API_KEY)
except ImportError:
    OPENAI_AVAILABLE = False


SYSTEM_PROMPT = """You are AutoPatch-Agent, an autonomous security vulnerability triage and remediation system.

Your job is to run through the following pipeline steps IN ORDER using the tools available to you:

1. Call fetch_cve_findings to get the list of active CVEs from Datadog.
2. For EACH CVE found, call enrich_exploit_intel to check if there is an active exploit in the wild.
3. For EACH UNIQUE host IP in the findings, call check_internet_exposure to verify if the host is internet-reachable.
4. Call run_triage to execute the ClickHouse priority query — this classifies each CVE as CRITICAL or LOW.
5. For EACH CVE classified as CRITICAL, call execute_remediation with the correct host_id and host_ip.
6. Do NOT call execute_remediation for LOW priority CVEs.
7. Once all steps are done, respond with a final JSON summary of what you did.

Rules:
- Be methodical. Process all CVEs before running triage.
- Never skip enrichment or exposure checks — the triage query depends on this data.
- Only remediate CRITICAL findings. Explicitly state why LOW findings are deferred.
- Your final message must be valid JSON with keys: critical_patched, low_deferred, summary.
"""


def run_llm_pipeline(verbose: bool = True) -> dict:
    """
    Runs the full pipeline via GPT-4o tool-use loop.
    Falls back to deterministic mock pipeline if no API key.
    """
    if not OPENAI_AVAILABLE or not Config.OPENAI_API_KEY:
        print("[orchestrator] No OpenAI key — running deterministic mock pipeline.")
        return run_mock_pipeline(verbose)

    client = OpenAI(api_key=Config.OPENAI_API_KEY)
    messages = [{"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": "Start the AutoPatch pipeline now."}]

    if verbose:
        print(f"\n{'='*60}")
        print("  AutoPatch-Agent — LLM Pipeline Starting")
        print(f"{'='*60}\n")

    while True:
        response = client.chat.completions.create(
            model=Config.OPENAI_MODEL,
            messages=messages,
            tools=TOOL_DEFINITIONS,
            tool_choice="auto"
        )

        msg = response.choices[0].message
        messages.append(msg)

        # No more tool calls — LLM is done
        if not msg.tool_calls:
            if verbose:
                print(f"\n[orchestrator] Agent final response:\n{msg.content}\n")
            try:
                return json.loads(msg.content)
            except json.JSONDecodeError:
                return {"summary": msg.content}

        # Execute all tool calls in this turn
        for tc in msg.tool_calls:
            tool_name = tc.function.name
            tool_args = json.loads(tc.function.arguments)

            if verbose:
                print(f"[orchestrator] → Calling tool: {tool_name}({tool_args})")

            result = dispatch_tool(tool_name, tool_args)

            if verbose:
                print(f"[orchestrator] ← Result: {json.dumps(result, indent=2)}\n")

            messages.append({
                "role": "tool",
                "tool_call_id": tc.id,
                "content": json.dumps(result)
            })


def run_mock_pipeline(verbose: bool = True) -> dict:
    """
    Deterministic pipeline — same logic as the LLM loop but hardcoded.
    Produces identical ClickHouse state and output without an API key.
    Perfect for dev and demo without spending tokens.
    """
    if verbose:
        print(f"\n{'='*60}")
        print("  AutoPatch-Agent — Mock Pipeline Starting")
        print(f"{'='*60}\n")

    def step(name, fn, *args, **kwargs):
        if verbose:
            print(f"[pipeline] → {name}")
        result = fn(*args, **kwargs)
        if verbose:
            print(f"[pipeline] ← {json.dumps(result, indent=2)}\n")
        return result

    # Step 1: Fetch CVEs
    cve_result = step("fetch_cve_findings", dispatch_tool, "fetch_cve_findings", {})
    findings = cve_result["findings"]

    # Step 2: Enrich each CVE
    for f in findings:
        step(f"enrich_exploit_intel({f['cve_id']})",
             dispatch_tool, "enrich_exploit_intel", {"cve_id": f["cve_id"]})

    # Step 3: Check exposure for unique IPs
    seen_ips = set()
    for f in findings:
        if f["host_ip"] not in seen_ips:
            seen_ips.add(f["host_ip"])
            port = 22 if f.get("is_public_ip") else 80
            step(f"check_internet_exposure({f['host_ip']})",
                 dispatch_tool, "check_internet_exposure",
                 {"host_ip": f["host_ip"], "port": port})

    # Step 4: Run triage
    triage_result = step("run_triage", dispatch_tool, "run_triage", {})

    # Step 5: Remediate CRITICAL only
    critical_patched = []
    low_deferred = []

    for t in triage_result["triage_results"]:
        if t["priority"] == "CRITICAL":
            rem = step(f"execute_remediation({t['cve_id']})",
                       dispatch_tool, "execute_remediation", {
                           "cve_id": t["cve_id"],
                           "host_id": t["host_id"],
                           "host_ip": t["host_ip"]
                       })
            critical_patched.append({
                "cve_id": t["cve_id"],
                "host_ip": t["host_ip"],
                "action": rem.get("action_taken"),
                "outcome": rem.get("outcome")
            })
        else:
            low_deferred.append({
                "cve_id": t["cve_id"],
                "host_ip": t["host_ip"],
                "reason": t["reason"]
            })

    summary = {
        "critical_patched": critical_patched,
        "low_deferred": low_deferred,
        "summary": (
            f"AutoPatch-Agent completed. "
            f"{len(critical_patched)} critical CVE(s) remediated, "
            f"{len(low_deferred)} low-priority CVE(s) deferred."
        )
    }

    if verbose:
        print(f"\n{'='*60}")
        print("  Pipeline Complete")
        print(f"{'='*60}")
        print(json.dumps(summary, indent=2))

    return summary
