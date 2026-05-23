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


SYSTEM_PROMPT = """You are the Ranking Agent in an Active Security Graph. Your job is to triage a
list of known vulnerabilities and decide which one a human should patch FIRST.

You output a strict JSON document. You do not produce prose outside the JSON.

═══════════════════════════════════════════════════════════════════════
CORE PRINCIPLE
═══════════════════════════════════════════════════════════════════════

Static severity (CVSS, CWE, CRITICAL/HIGH labels) describes the WORST CASE
if a vulnerability is exploited. It does NOT describe whether exploitation
is happening, who is trying, or how the threat is evolving right now.

Two vulnerabilities with identical CVSS 9.8 are NOT equally urgent. The one
under live, distributed, accelerating attack is exponentially more urgent
than the one that is theoretically exploitable but currently dormant.

Your ranking MUST be dominated by ACTIVE RUNTIME EVIDENCE and EXTERNAL
THREAT PRESSURE, not by static labels. Static severity is a tiebreaker,
not a primary input.

═══════════════════════════════════════════════════════════════════════
SCORING RUBRIC  (compute each component, then combine — show your work)
═══════════════════════════════════════════════════════════════════════

For each vulnerability, compute three sub-scores. All sub-scores are
0..100. Higher means more urgent.

(A) ACTIVE_EXPLOITATION   — from read_apm()
    Reflects whether attack traffic is hitting the vulnerable endpoint
    RIGHT NOW, how distributed it is, and whether the trend is rising.

    components:
      volume_factor      = min(100, 20 * log10(attack_count_1h + 1))
      diversity_factor   = min(100, 4  * unique_asns)
      trend_factor       = min(100, 25 * trend_ratio)
          where trend_ratio = attacks_last_15min / max(attacks_prior_45min/3, 1)
          (i.e. ratio of recent rate to prior rate; 1.0 = flat, >1 = ramping)
      success_factor     = 100 * successful_attack_rate
          (fraction of attempts that returned 2xx with attack-pattern echo)

    ACTIVE_EXPLOITATION = (
        0.40 * volume_factor
      + 0.25 * diversity_factor
      + 0.25 * trend_factor
      + 0.10 * success_factor
    )

(B) EXTERNAL_PRESSURE     — from search_nimble()
    Reflects whether the attacker community is actively weaponizing this
    vulnerability class outside our environment.

    components:
      kev_listed             : 0 or 1   (CISA Known Exploited Vulns)
      exploit_db_count       : integer  (public PoCs in last 90 days)
      github_mentions_30d    : integer  (commits/issues citing CWE)
      underground_chatter    : 0..1     (Nimble dark-web/forum score)

    EXTERNAL_PRESSURE = (
        40 * kev_listed
      + 15 * min(1, log10(exploit_db_count + 1) / 2)
      + 15 * min(1, log10(github_mentions_30d + 1) / 3)
      + 30 * underground_chatter
    )

(C) STATIC_SEVERITY       — from the vuln_catalog row
    STATIC_SEVERITY = 10 * cvss_score      # 0..100

═══════════════════════════════════════════════════════════════════════
COMPOSITE SCORE
═══════════════════════════════════════════════════════════════════════

    composite = 0.50 * ACTIVE_EXPLOITATION
              + 0.35 * EXTERNAL_PRESSURE
              + 0.15 * STATIC_SEVERITY

Active dominates because it is the only signal that proves the threat is
real for THIS deployment at THIS moment. External is second because it
predicts where active is going. Static is least because it is environment-
independent and rarely changes.

═══════════════════════════════════════════════════════════════════════
PROCEDURE
═══════════════════════════════════════════════════════════════════════

1. You receive a list of vuln_ids in the user message.
2. For each vuln_id, call BOTH read_apm and search_nimble in PARALLEL.
3. For each vuln, compute ACTIVE_EXPLOITATION, EXTERNAL_PRESSURE,
   STATIC_SEVERITY, and the composite score using the formulas above.
4. Sort descending by composite score.
5. For the #1 ranked vuln, include one sample_trace_id and one
   sample_payload from the read_apm result. The patch agent needs them.
6. In the "reasoning" field for each vuln, quote SPECIFIC NUMBERS
   ("23 unique ASNs", "trend 2.08x"), not adjectives. The output is
   audit evidence; vague language is worthless here.
7. Add an "explanation" at the top that names what flipped the ranking
   away from static-CVSS order. If your top pick is NOT the highest
   CVSS, explicitly call that out — that contrast is the whole point
   of this system.

═══════════════════════════════════════════════════════════════════════
ANTI-PATTERNS  (do not do these)
═══════════════════════════════════════════════════════════════════════

✗ Do NOT rank by CVSS, severity label, or CWE alone.
✗ Do NOT invent numbers. If a tool returns zero, the sub-score is zero.
✗ Do NOT downweight a vuln because patching is "hard" — patchability is
  the patch agent's concern, not yours.
✗ Do NOT exclude a vuln from the output just because attack_count is
  zero. Dormant vulns still rank (with low scores) — the user needs to
  see them.
✗ Do NOT output prose, explanations, or markdown outside the JSON
  envelope. The output is consumed by another agent.

═══════════════════════════════════════════════════════════════════════
OUTPUT SCHEMA (strict JSON)
═══════════════════════════════════════════════════════════════════════

{
  "generated_at": "<ISO-8601 UTC>",
  "window": "1h",
  "explanation": "<1-2 sentence framing of what flipped the ranking>",
  "rankings": [
    {
      "rank": 1,
      "vuln_id": "VULN-XXX",
      "composite_score": 60.2,
      "sub_scores": {
        "active_exploitation": 88.0,
        "external_pressure":   71.0,
        "static_severity":     98.0
      },
      "evidence": {
        "attack_count_1h": 2349,
        "unique_asns": 23,
        "unique_ips": 2349,
        "countries": ["US","DE","RU","CN","GB","KR","IN","NL","FR"],
        "trend_ratio": 2.08,
        "successful_attack_rate": 0.97,
        "kev_listed": true,
        "exploit_db_count": 47,
        "github_mentions_30d": 312,
        "underground_chatter": 0.81,
        "cvss_score": 9.8
      },
      "sample_trace_id": "aca83604fe32426ab0bc54935a146470",
      "sample_payload": "127.0.0.1; cat /root/.aws/credentials",
      "reasoning": "Quote specific numbers. e.g. '2349 attacks/h from 23 ASNs across 8 countries; trend 2.08x vs prior 45min; KEV-listed; 47 public PoCs.'"
    }
  ]
}
"""


# ─────────────────────────────────────────────────────────────
# Catalog loader — used to build the user message
# ─────────────────────────────────────────────────────────────

def _load_catalog_rows() -> list[dict]:
    """Read vuln_catalog.ndjson into a list of dicts (for the user prompt)."""
    catalog_path = os.path.join(ROOT, "vuln_catalog.ndjson")
    rows = []
    try:
        with open(catalog_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        print(f"[orchestrator] WARNING: {catalog_path} not found")
    return rows


def _build_user_prompt(catalog_rows: list[dict]) -> str:
    """Build the per-invocation user prompt with catalog inlined."""
    return (
        "Rank the following open vulnerabilities by patching urgency, following the "
        "rubric in your system prompt.\n\n"
        "Catalog (one row per vulnerability):\n"
        f"{json.dumps(catalog_rows, indent=2)}\n\n"
        "Window: last 60 minutes.\n\n"
        "Call read_apm and search_nimble for every vuln in parallel before scoring.\n"
        "Return the JSON document only."
    )


# Tools available to the Ranking Agent (subset of full tool set)
def _ranking_tools_anthropic():
    allowed = {"read_apm", "search_nimble"}
    return [t for t in TOOL_DEFINITIONS_ANTHROPIC if t["name"] in allowed]


def _ranking_tools_openai():
    allowed = {"read_apm", "search_nimble"}
    return [t for t in TOOL_DEFINITIONS if t["function"]["name"] in allowed]


# ─────────────────────────────────────────────────────────────
# Post-ranking remediation driver (code, not LLM)
# Takes the ranking JSON and drives execute_remediation + create_patch_pr.
# ─────────────────────────────────────────────────────────────

REMEDIATION_COMPOSITE_THRESHOLD = 30.0   # remediate any vuln above this
PR_TOP_N                       = 1       # always create a PR for the #1


def _drive_remediation(ranking: dict, catalog_rows: list[dict], verbose: bool) -> dict:
    """Use the Ranking Agent's JSON output to drive remediation in code."""
    catalog_by_id = {r["vuln_id"]: r for r in catalog_rows}

    # DVWA host context — single host for all current catalog vulns
    DVWA_HOST_ID = "dvwa-hack"
    DVWA_HOST_IP = "dvwa.demo"

    remediated  : list[dict] = []
    deferred    : list[dict] = []
    pull_requests: list[dict] = []

    for i, entry in enumerate(ranking.get("rankings", [])):
        vuln_id = entry["vuln_id"]
        score   = float(entry.get("composite_score", 0))
        catalog = catalog_by_id.get(vuln_id, {})

        if score >= REMEDIATION_COMPOSITE_THRESHOLD:
            rem = dispatch_tool("execute_remediation", {
                "cve_id":  vuln_id,
                "host_id": DVWA_HOST_ID,
                "host_ip": DVWA_HOST_IP,
            })
            if verbose:
                print(f"[orchestrator] remediated {vuln_id} (composite {score:.1f})")
            remediated.append({
                "rank":            entry.get("rank", i + 1),
                "vuln_id":         vuln_id,
                "name":            catalog.get("name", ""),
                "composite_score": score,
                "host_ip":         DVWA_HOST_IP,
                "host_id":         DVWA_HOST_ID,
                "action":          rem.get("action_taken"),
                "outcome":         rem.get("outcome"),
            })

            if i < PR_TOP_N:
                pr = dispatch_tool("create_patch_pr", {
                    "cve_id":  vuln_id,
                    "host_id": DVWA_HOST_ID,
                    "host_ip": DVWA_HOST_IP,
                })
                pull_requests.append({
                    "rank":           entry.get("rank", i + 1),
                    "vuln_id":        vuln_id,
                    "pr_url":         pr.get("pr_url"),
                    "pr_number":      pr.get("pr_number"),
                    "branch":         pr.get("branch"),
                    "pr_status":      pr.get("pr_status"),
                    "files_patched":  pr.get("files_patched"),
                })
        else:
            deferred.append({
                "rank":            entry.get("rank", i + 1),
                "vuln_id":         vuln_id,
                "name":            catalog.get("name", ""),
                "composite_score": score,
                "reason":          entry.get("reasoning", "Below remediation threshold"),
            })

    return {
        "ranking":      ranking,
        "remediated":   remediated,
        "deferred":     deferred,
        "pull_requests": pull_requests,
        "summary": (
            f"Ranking Agent triaged {len(ranking.get('rankings', []))} vuln(s). "
            f"{len(remediated)} remediated, {len(pull_requests)} PR(s) created, "
            f"{len(deferred)} deferred."
        ),
    }


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

    catalog_rows = _load_catalog_rows()
    if not catalog_rows:
        print("[orchestrator] No catalog rows — aborting")
        return {"summary": "No vulnerabilities to rank.", "ranking": {}, "remediated": [], "deferred": [], "pull_requests": []}

    # Persist catalog into DB so downstream PR context joins still work
    dispatch_tool("fetch_cve_findings", {})

    client = anthropic.Anthropic(api_key=Config.ANTHROPIC_API_KEY)
    messages = [{"role": "user", "content": _build_user_prompt(catalog_rows)}]

    if verbose:
        print(f"\n{'='*60}")
        print(f"  Ranking Agent — Claude {Config.ANTHROPIC_MODEL}")
        print(f"{'='*60}\n")

    def _finalize_from_text(text: str) -> dict:
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            import re
            m = re.search(r"\{.*\}", text or "", re.DOTALL)
            if m:
                try:
                    return json.loads(m.group(0))
                except json.JSONDecodeError:
                    pass
            return {"explanation": text or "", "rankings": []}

    ranking_json: dict | None = None
    while True:
        response = client.messages.create(
            model=Config.ANTHROPIC_MODEL,
            max_tokens=8192,
            system=SYSTEM_PROMPT,
            tools=_ranking_tools_anthropic(),
            messages=messages
        )
        messages.append({"role": "assistant", "content": response.content})

        tool_uses = [b for b in response.content if getattr(b, "type", None) == "tool_use"]

        # If Claude stopped without asking for more tools, treat as final
        # (covers end_turn, max_tokens, stop_sequence — anything non-tool_use).
        if response.stop_reason != "tool_use" or not tool_uses:
            final_text = "".join(
                b.text for b in response.content if hasattr(b, "text")
            )
            if verbose:
                print(f"\n[orchestrator] Ranking Agent JSON ({response.stop_reason}):\n{final_text}\n")
            ranking_json = _finalize_from_text(final_text)
            break

        # Execute all tool calls in this turn in parallel — Claude often
        # batches read_apm + search_nimble for all 4 vulns into one turn,
        # and the search_nimble live web fetches are ~3s each.
        from concurrent.futures import ThreadPoolExecutor

        def _run_one(block):
            if verbose:
                print(f"[orchestrator] → Claude calling: {block.name}({block.input})")
            result = dispatch_tool(block.name, block.input)
            if verbose:
                print(f"[orchestrator] ← {block.name} done\n")
            return block.id, result

        with ThreadPoolExecutor(max_workers=min(8, len(tool_uses))) as pool:
            results_by_id = dict(pool.map(_run_one, tool_uses))

        tool_results = [
            {"type": "tool_result", "tool_use_id": b.id, "content": json.dumps(results_by_id[b.id])}
            for b in tool_uses
        ]
        messages.append({"role": "user", "content": tool_results})

    return _drive_remediation(ranking_json, catalog_rows, verbose)


# ─────────────────────────────────────────────────────────────
# OpenAI tool-use loop (kept for easy switching)
# ─────────────────────────────────────────────────────────────

def run_openai_pipeline(verbose: bool = True) -> dict:
    from openai import OpenAI

    catalog_rows = _load_catalog_rows()
    if not catalog_rows:
        print("[orchestrator] No catalog rows — aborting")
        return {"summary": "No vulnerabilities to rank.", "ranking": {}, "remediated": [], "deferred": [], "pull_requests": []}

    dispatch_tool("fetch_cve_findings", {})

    client = OpenAI(api_key=Config.OPENAI_API_KEY)
    messages = [{"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": _build_user_prompt(catalog_rows)}]

    if verbose:
        print(f"\n{'='*60}")
        print(f"  Ranking Agent — OpenAI {Config.OPENAI_MODEL}")
        print(f"{'='*60}\n")

    ranking_json: dict | None = None
    while True:
        response = client.chat.completions.create(
            model=Config.OPENAI_MODEL,
            messages=messages,
            tools=_ranking_tools_openai(),
            tool_choice="auto"
        )
        msg = response.choices[0].message
        messages.append(msg)

        if not msg.tool_calls:
            if verbose:
                print(f"\n[orchestrator] Ranking Agent JSON:\n{msg.content}\n")
            try:
                ranking_json = json.loads(msg.content)
            except json.JSONDecodeError:
                import re
                m = re.search(r"\{.*\}", msg.content or "", re.DOTALL)
                if m:
                    try:
                        ranking_json = json.loads(m.group(0))
                    except json.JSONDecodeError:
                        ranking_json = {"explanation": msg.content, "rankings": []}
                else:
                    ranking_json = {"explanation": msg.content, "rankings": []}
            break

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

    return _drive_remediation(ranking_json, catalog_rows, verbose)


# ─────────────────────────────────────────────────────────────
# Deterministic mock pipeline (no API key needed)
# ─────────────────────────────────────────────────────────────

def run_mock_pipeline(verbose: bool = True) -> dict:
    """
    Deterministic mock that mirrors what the Ranking Agent does:
      1. Load vuln catalog
      2. Call read_apm + search_nimble for each vuln
      3. Apply the scoring rubric from SYSTEM_PROMPT
      4. Emit ranking JSON in the schema the LLM would produce
      5. Drive remediation via _drive_remediation()
    """
    import math
    from datetime import datetime as _dt

    if verbose:
        print(f"\n{'='*60}")
        print("  Ranking Agent — Mock Pipeline")
        print(f"{'='*60}\n")

    catalog_rows = _load_catalog_rows()
    if not catalog_rows:
        return {"summary": "No vulnerabilities to rank.", "ranking": {}, "remediated": [], "deferred": [], "pull_requests": []}

    dispatch_tool("fetch_cve_findings", {})

    def step(name, fn, *args, **kwargs):
        if verbose:
            print(f"[pipeline] → {name}")
        result = fn(*args, **kwargs)
        if verbose:
            print(f"[pipeline] ← {json.dumps(result, indent=2)}\n")
        return result

    # Compute sub-scores per vuln using the exact formulas in SYSTEM_PROMPT
    rankings = []
    highest_cvss = max((float(r.get("cvss_score") or 0) for r in catalog_rows), default=0.0)
    highest_cvss_id = next(
        (r["vuln_id"] for r in catalog_rows if float(r.get("cvss_score") or 0) == highest_cvss),
        None,
    )

    for row in catalog_rows:
        vuln_id = row["vuln_id"]
        cvss    = float(row.get("cvss_score") or 0)

        apm    = step(f"read_apm({vuln_id})",
                      dispatch_tool, "read_apm",
                      {"vuln_id": vuln_id, "window_minutes": 60})
        nimble = step(f"search_nimble({vuln_id})",
                      dispatch_tool, "search_nimble",
                      {"vuln_id": vuln_id, "search_terms": row.get("nimble_search_terms", [])})

        # ── ACTIVE_EXPLOITATION ─────────────────────────────────
        attack_count       = apm.get("attack_count", 0)
        unique_asns        = apm.get("unique_asns", 0)
        att_15m            = apm.get("attacks_last_15min", 0)
        att_prior45        = apm.get("attacks_prior_45min", 0)
        successful_rate    = float(apm.get("successful_attack_rate", 0))

        volume_factor      = min(100.0, 20.0 * math.log10(attack_count + 1))
        diversity_factor   = min(100.0, 4.0  * unique_asns)
        trend_ratio        = att_15m / max(att_prior45 / 3.0, 1.0)
        trend_factor       = min(100.0, 25.0 * trend_ratio)
        success_factor     = 100.0 * successful_rate

        active_exploitation = (
              0.40 * volume_factor
            + 0.25 * diversity_factor
            + 0.25 * trend_factor
            + 0.10 * success_factor
        )

        # ── EXTERNAL_PRESSURE ───────────────────────────────────
        kev_listed         = 1 if nimble.get("kev_listed") else 0
        exploit_db_count   = int(nimble.get("exploit_db_count", 0))
        github_mentions    = int(nimble.get("github_mentions_30d", 0))
        underground_chat   = float(nimble.get("underground_chatter", 0))

        external_pressure = (
              40.0 * kev_listed
            + 15.0 * min(1.0, math.log10(exploit_db_count + 1) / 2.0)
            + 15.0 * min(1.0, math.log10(github_mentions + 1) / 3.0)
            + 30.0 * underground_chat
        )

        # ── STATIC_SEVERITY ─────────────────────────────────────
        static_severity = 10.0 * cvss

        composite = (
              0.50 * active_exploitation
            + 0.35 * external_pressure
            + 0.15 * static_severity
        )

        reasoning_bits = []
        if attack_count > 0:
            reasoning_bits.append(
                f"{attack_count} attacks/h from {unique_asns} ASNs "
                f"across {len(apm.get('countries', []))} countries"
            )
            reasoning_bits.append(f"trend {trend_ratio:.2f}x vs prior 45min")
            reasoning_bits.append(f"success rate {successful_rate:.0%}")
        else:
            reasoning_bits.append("no live attack traffic in window")
        if kev_listed:
            reasoning_bits.append("KEV-listed")
        reasoning_bits.append(f"{exploit_db_count} public PoCs")
        reasoning_bits.append(f"{github_mentions} GitHub mentions 30d")
        reasoning_bits.append(f"underground chatter {underground_chat:.2f}")
        reasoning_bits.append(f"CVSS {cvss}")

        rankings.append({
            "vuln_id":         vuln_id,
            "composite_score": round(composite, 2),
            "sub_scores": {
                "active_exploitation": round(active_exploitation, 2),
                "external_pressure":   round(external_pressure, 2),
                "static_severity":     round(static_severity, 2),
            },
            "evidence": {
                "attack_count_1h":        attack_count,
                "unique_asns":            unique_asns,
                "unique_ips":             apm.get("unique_ips", 0),
                "countries":              apm.get("countries", []),
                "trend_ratio":            round(trend_ratio, 2),
                "successful_attack_rate": round(successful_rate, 2),
                "kev_listed":             bool(kev_listed),
                "exploit_db_count":       exploit_db_count,
                "github_mentions_30d":    github_mentions,
                "underground_chatter":    underground_chat,
                "cvss_score":             cvss,
                "live_nimble_verified":   bool(nimble.get("live_nimble_verified")),
                "live_signals":           nimble.get("live_signals", {}),
                "evidence_urls":          nimble.get("evidence_urls", []),
            },
            "sample_trace_id": apm.get("sample_trace_id", ""),
            "sample_payload":  apm.get("sample_payload", ""),
            "reasoning":       "; ".join(reasoning_bits),
        })

    rankings.sort(key=lambda r: r["composite_score"], reverse=True)
    for i, r in enumerate(rankings, start=1):
        r["rank"] = i

    # Compute the static-CVSS-only order to detect rank flips
    cvss_order = [
        r["vuln_id"]
        for r in sorted(rankings, key=lambda r: r["evidence"]["cvss_score"], reverse=True)
    ]
    composite_order = [r["vuln_id"] for r in rankings]
    flips = [
        (composite_order[i], cvss_order[i])
        for i in range(len(rankings))
        if composite_order[i] != cvss_order[i]
    ]

    top_pick = rankings[0] if rankings else None
    if top_pick and flips:
        # Surface the most informative flip — the first one (highest impact)
        winner_id, loser_id = flips[0]
        winner = next(r for r in rankings if r["vuln_id"] == winner_id)
        loser  = next(r for r in rankings if r["vuln_id"] == loser_id)
        explanation = (
            f"{winner_id} (CVSS {winner['evidence']['cvss_score']}) ranks "
            f"above {loser_id} (CVSS {loser['evidence']['cvss_score']}) — "
            f"runtime attack evidence and external pressure flipped the "
            f"static-severity order. CVSS alone would have prioritized {loser_id}."
        )
    elif top_pick:
        explanation = (
            f"{top_pick['vuln_id']} ranks first by both static severity and "
            f"runtime attack evidence — static and dynamic signals agree."
        )
    else:
        explanation = "No vulnerabilities to rank."

    ranking_json = {
        "generated_at": _dt.utcnow().isoformat() + "Z",
        "window":       "1h",
        "explanation":  explanation,
        "rankings":     rankings,
    }

    if verbose:
        print(f"\n{'='*60}")
        print("  Ranking Agent — Output JSON")
        print(f"{'='*60}")
        print(json.dumps(ranking_json, indent=2))
        print()

    return _drive_remediation(ranking_json, catalog_rows, verbose)
