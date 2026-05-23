"""
Reasoning Orchestrator
──────────────────────
Runs a tool-use loop where Claude (or GPT-4o) decides which tool to
call next. Switch providers with LLM_PROVIDER=anthropic|openai in .env.

Default: Claude Sonnet (claude-sonnet-4-6)

Falls back to a deterministic mock pipeline if no API key is set.
"""

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from agent.config import Config
from agent.tools import TOOL_DEFINITIONS, TOOL_DEFINITIONS_ANTHROPIC, dispatch_tool

# ── Provider availability checks ─────────────────────────────
try:
    import anthropic as _anthropic_sdk
    ANTHROPIC_AVAILABLE = bool(Config.ANTHROPIC_API_KEY)
except ImportError:
    ANTHROPIC_AVAILABLE = False

try:
    from openai import OpenAI as _OpenAI
    OPENAI_AVAILABLE = bool(Config.OPENAI_API_KEY)
except ImportError:
    OPENAI_AVAILABLE = False


SYSTEM_PROMPT = """You are AutoPatch-Agent, an autonomous security vulnerability triage and remediation system.

Your job is to run through the following pipeline steps IN ORDER using the tools available to you:

1. Call fetch_cve_findings to get the list of active vulnerabilities.
2. For EACH vulnerability found, call enrich_exploit_intel — this runs BOTH live traffic span analysis AND Nimble web intel simultaneously and merges their signals.
3. For EACH UNIQUE host IP in the findings, call check_internet_exposure to verify if the host is internet-reachable.
4. Call run_triage to execute the ClickHouse JOIN query — initial CRITICAL/LOW classification.
5. Call rerank_triage to apply the multi-signal composite scoring model (span attack frequency + Nimble confidence + exposure + CVSS). This produces CRITICAL/HIGH/MEDIUM/LOW priority bands and replaces the initial triage.
6. For EACH finding classified as CRITICAL or HIGH by rerank_triage, call execute_remediation.
7. Do NOT remediate MEDIUM or LOW findings — state why each is deferred.
8. Once all steps are done, respond with a final JSON summary.

Rules:
- Be methodical. Process all vulnerabilities before running triage.
- Never skip enrichment or exposure checks — the scoring model depends on this data.
- Remediate CRITICAL and HIGH findings only.
- Your final message must be valid JSON with keys: critical_patched, high_patched, deferred, summary.
"""


# ─────────────────────────────────────────────────────────────
# Main entry point — routes to the right provider
# ─────────────────────────────────────────────────────────────

def run_llm_pipeline(verbose: bool = True) -> dict:
    provider = Config.LLM_PROVIDER.lower()

    if provider == "anthropic" and ANTHROPIC_AVAILABLE:
        return run_anthropic_pipeline(verbose)
    elif provider == "openai" and OPENAI_AVAILABLE:
        return run_openai_pipeline(verbose)
    else:
        print(f"[orchestrator] No API key for provider '{provider}' — running mock pipeline.")
        return run_mock_pipeline(verbose)


# ─────────────────────────────────────────────────────────────
# Claude (Anthropic) tool-use loop
# ─────────────────────────────────────────────────────────────

def run_anthropic_pipeline(verbose: bool = True) -> dict:
    import anthropic

    client = anthropic.Anthropic(api_key=Config.ANTHROPIC_API_KEY)
    messages = [{"role": "user", "content": "Start the AutoPatch pipeline now."}]

    if verbose:
        print(f"\n{'='*60}")
        print(f"  AutoPatch-Agent — Claude {Config.ANTHROPIC_MODEL}")
        print(f"{'='*60}\n")

    while True:
        response = client.messages.create(
            model=Config.ANTHROPIC_MODEL,
            max_tokens=4096,
            system=SYSTEM_PROMPT,
            tools=TOOL_DEFINITIONS_ANTHROPIC,
            messages=messages
        )

        # Append assistant turn
        messages.append({"role": "assistant", "content": response.content})

        # Check stop reason
        if response.stop_reason == "end_turn":
            # Extract final text block
            final_text = next(
                (b.text for b in response.content if hasattr(b, "text")), ""
            )
            if verbose:
                print(f"\n[orchestrator] Claude final response:\n{final_text}\n")
            try:
                return json.loads(final_text)
            except json.JSONDecodeError:
                return {"summary": final_text}

        # Process tool use blocks
        tool_results = []
        for block in response.content:
            if block.type != "tool_use":
                continue

            tool_name = block.name
            tool_args = block.input

            if verbose:
                print(f"[orchestrator] → Claude calling: {tool_name}({tool_args})")

            result = dispatch_tool(tool_name, tool_args)

            if verbose:
                print(f"[orchestrator] ← Result: {json.dumps(result, indent=2)}\n")

            tool_results.append({
                "type": "tool_result",
                "tool_use_id": block.id,
                "content": json.dumps(result)
            })

        # Feed all tool results back in one user turn
        messages.append({"role": "user", "content": tool_results})


# ─────────────────────────────────────────────────────────────
# OpenAI tool-use loop (kept for easy switching)
# ─────────────────────────────────────────────────────────────

def run_openai_pipeline(verbose: bool = True) -> dict:
    from openai import OpenAI

    client = OpenAI(api_key=Config.OPENAI_API_KEY)
    messages = [{"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": "Start the AutoPatch pipeline now."}]

    if verbose:
        print(f"\n{'='*60}")
        print(f"  AutoPatch-Agent — OpenAI {Config.OPENAI_MODEL}")
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

        if not msg.tool_calls:
            if verbose:
                print(f"\n[orchestrator] GPT final response:\n{msg.content}\n")
            try:
                return json.loads(msg.content)
            except json.JSONDecodeError:
                return {"summary": msg.content}

        for tc in msg.tool_calls:
            tool_name = tc.function.name
            tool_args = json.loads(tc.function.arguments)

            if verbose:
                print(f"[orchestrator] → GPT calling: {tool_name}({tool_args})")

            result = dispatch_tool(tool_name, tool_args)

            if verbose:
                print(f"[orchestrator] ← Result: {json.dumps(result, indent=2)}\n")

            messages.append({
                "role": "tool",
                "tool_call_id": tc.id,
                "content": json.dumps(result)
            })


# ─────────────────────────────────────────────────────────────
# Deterministic mock pipeline (no API key needed)
# ─────────────────────────────────────────────────────────────

def run_mock_pipeline(verbose: bool = True) -> dict:
    if verbose:
        print(f"\n{'='*60}")
        print("  AutoPatch-Agent — Mock Pipeline")
        print(f"{'='*60}\n")

    def step(name, fn, *args, **kwargs):
        if verbose:
            print(f"[pipeline] → {name}")
        result = fn(*args, **kwargs)
        if verbose:
            print(f"[pipeline] ← {json.dumps(result, indent=2)}\n")
        return result

    cve_result = step("fetch_cve_findings", dispatch_tool, "fetch_cve_findings", {})
    findings = cve_result["findings"]

    for f in findings:
        step(f"enrich_exploit_intel({f['cve_id']})",
             dispatch_tool, "enrich_exploit_intel", {"cve_id": f["cve_id"]})

    seen_ips = set()
    for f in findings:
        if f["host_ip"] not in seen_ips:
            seen_ips.add(f["host_ip"])
            port = 22 if f.get("is_public_ip") else 80
            step(f"check_internet_exposure({f['host_ip']})",
                 dispatch_tool, "check_internet_exposure",
                 {"host_ip": f["host_ip"], "port": port})

    step("run_triage", dispatch_tool, "run_triage", {})
    rerank_result = step("rerank_triage", dispatch_tool, "rerank_triage", {})

    critical_patched, high_patched, deferred = [], [], []
    for t in rerank_result.get("ranked", []):
        if t["priority"] in ("CRITICAL", "HIGH"):
            target = critical_patched if t["priority"] == "CRITICAL" else high_patched
            rem = step(f"execute_remediation({t['cve_id']})",
                       dispatch_tool, "execute_remediation", {
                           "cve_id": t["cve_id"],
                           "host_id": t.get("host_id", ""),
                           "host_ip": t["host_ip"]
                       })
            target.append({
                "cve_id": t["cve_id"], "host_ip": t["host_ip"],
                "priority": t["priority"],
                "action": rem.get("action_taken"), "outcome": rem.get("outcome")
            })
        else:
            deferred.append({
                "cve_id": t["cve_id"], "host_ip": t["host_ip"],
                "priority": t["priority"], "reason": t["reason"]
            })

    summary = {
        "critical_patched": critical_patched,
        "high_patched":     high_patched,
        "deferred":         deferred,
        "summary": (
            f"AutoPatch-Agent completed. "
            f"{len(critical_patched)} CRITICAL + {len(high_patched)} HIGH finding(s) remediated, "
            f"{len(deferred)} deferred."
        )
    }

    if verbose:
        print(f"\n{'='*60}")
        print("  Pipeline Complete")
        print(f"{'='*60}")
        print(json.dumps(summary, indent=2))

    return summary
