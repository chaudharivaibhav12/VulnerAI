"""
AutoPatch-Agent — Entry Point
──────────────────────────────
Run this to kick off the full autonomous pipeline.

Usage:
    python agent/main.py              # full pipeline
    python agent/main.py --dry-run    # log actions, don't execute
    python agent/main.py --reset      # wipe DB and re-run
"""

import sys
import os
import json
import argparse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from agent.config import Config
from agent.orchestrator import run_llm_pipeline
from clickhouse.mock_client import init_db, reset_db, fetch_all


def print_banner():
    banner = """
╔══════════════════════════════════════════════════════╗
║          AutoPatch-Agent  v0.1.0                     ║
║  Autonomous Vulnerability Triage & Remediation       ║
╚══════════════════════════════════════════════════════╝
"""
    try:
        print(banner)
    except UnicodeEncodeError:
        print("================================================")
        print("  AutoPatch-Agent v0.1.0")
        print("  Autonomous Vulnerability Triage & Remediation")
        print("================================================")


def print_final_report(summary: dict):
    print("\n" + "═" * 60)
    print("  RANKING AGENT — FINAL REPORT")
    print("═" * 60)

    ranking      = summary.get("ranking", {})
    rankings     = ranking.get("rankings", [])
    explanation  = ranking.get("explanation", "")
    remediated   = summary.get("remediated", [])
    deferred     = summary.get("deferred", [])
    prs          = summary.get("pull_requests", [])

    if explanation:
        print(f"\n💡  Explanation: {explanation}\n")

    print(f"📊  Ranking (n={len(rankings)}):")
    for r in rankings:
        score = r.get("composite_score", 0)
        sub   = r.get("sub_scores", {})
        print(
            f"  #{r.get('rank', '?'):<2} {r['vuln_id']:<10}  "
            f"composite {score:>6.2f}  │ "
            f"active {sub.get('active_exploitation', 0):>5.1f}  "
            f"external {sub.get('external_pressure', 0):>5.1f}  "
            f"static {sub.get('static_severity', 0):>5.1f}"
        )
        print(f"        ↳ {r.get('reasoning', '')}")

    if rankings:
        top = rankings[0]
        print(f"\n🥇  Top pick: {top['vuln_id']}")
        if top.get("sample_trace_id"):
            print(f"      trace_id : {top['sample_trace_id']}")
        if top.get("sample_payload"):
            print(f"      payload  : {top['sample_payload'][:80]}")

    print(f"\n✅  Remediated ({len(remediated)}):")
    for item in remediated:
        print(f"    • #{item.get('rank','?')} {item['vuln_id']:<10}  composite {item['composite_score']:.1f}")
        print(f"      Action : {item.get('action', 'N/A')}")
        print(f"      Outcome: {item.get('outcome', 'N/A')}")

    print(f"\n⏸️   Deferred ({len(deferred)}):")
    for item in deferred:
        print(f"    • #{item.get('rank','?')} {item['vuln_id']:<10}  composite {item['composite_score']:.1f}")
        print(f"      Reason : {item.get('reason', 'N/A')[:100]}")

    print(f"\n🔀  Pull Requests Created ({len(prs)}):")
    for pr in prs:
        status_icon = "✅" if pr.get("pr_status") == "created" else "🧪"
        print(f"    • #{pr.get('rank','?')} {pr['vuln_id']}  {status_icon} {pr.get('pr_status','').upper()}")
        print(f"      Branch : {pr.get('branch', 'N/A')}")
        print(f"      PR URL : {pr.get('pr_url', 'N/A')}")
        print(f"      Files  : {pr.get('files_patched', 0)} patched")

    print(f"\n📋  Summary: {summary.get('summary', '')}")
    print("\n" + "═" * 60)

    print("\n  ClickHouse: remediation_log")
    print("─" * 60)
    rows = fetch_all("remediation_log")
    for r in rows:
        icon = "✅" if r["outcome"] in ("success", "dry_run") else "❌"
        print(f"  {icon}  {r['cve_id']:<20}  {r['outcome']:<10}  {r['action_taken'][:50]}")

    print("\n  ClickHouse: pr_log")
    print("─" * 60)
    rows = fetch_all("pr_log")
    for r in rows:
        print(f"  🔀  {r['cve_id']:<20}  {r['pr_status']:<10}  {r['pr_url']}")

    print()


def main():
    parser = argparse.ArgumentParser(description="AutoPatch-Agent")
    parser.add_argument("--dry-run", action="store_true",
                        help="Log actions without executing remediation")
    parser.add_argument("--reset", action="store_true",
                        help="Wipe the mock DB before running")
    parser.add_argument("--quiet", action="store_true",
                        help="Suppress step-by-step logging")
    args = parser.parse_args()

    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    print_banner()

    # Override config from CLI flags
    if args.dry_run:
        os.environ["DRY_RUN"] = "true"

    Config.validate()

    # Always start with a clean DB for reproducible runs
    # (pass --no-reset to keep data from previous runs)
    if not getattr(args, 'no_reset', False):
        reset_db()
    init_db()

    # Run the pipeline
    summary = run_llm_pipeline(verbose=not args.quiet)

    # Print the final report
    print_final_report(summary)

    # Save summary to JSON for the frontend/Senso.ai to pick up
    output_path = os.path.join(ROOT, "pipeline_output.json")
    with open(output_path, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"[main] Pipeline output saved to: pipeline_output.json\n")


if __name__ == "__main__":
    main()
