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
    print("  FINAL PIPELINE REPORT")
    print("═" * 60)

    critical = summary.get("critical_patched", [])
    deferred = summary.get("low_deferred", [])

    print(f"\n✅  CRITICAL — Remediated ({len(critical)}):")
    for item in critical:
        print(f"    • {item['cve_id']} on {item['host_ip']}")
        print(f"      Action : {item.get('action', 'N/A')}")
        print(f"      Outcome: {item.get('outcome', 'N/A')}")

    print(f"\n⏸️   LOW — Deferred ({len(deferred)}):")
    for item in deferred:
        print(f"    • {item['cve_id']} on {item['host_ip']}")
        print(f"      Reason : {item.get('reason', 'N/A')}")

    prs = summary.get("pull_requests", [])
    print(f"\n🔀  Pull Requests Created ({len(prs)}):")
    for pr in prs:
        status_icon = "✅" if pr.get("pr_status") == "created" else "🧪"
        print(f"    • {pr['cve_id']}  {status_icon} {pr.get('pr_status','').upper()}")
        print(f"      Branch : {pr.get('branch', 'N/A')}")
        print(f"      PR URL : {pr.get('pr_url', 'N/A')}")
        print(f"      Files  : {pr.get('files_patched', 0)} patched")

    print(f"\n📋  Summary: {summary.get('summary', '')}")
    print("\n" + "═" * 60)

    # Show ClickHouse triage table
    print("\n  ClickHouse: triage_results")
    print("─" * 60)
    rows = fetch_all("triage_results")
    for r in rows:
        badge = "🔴 CRITICAL" if r["priority"] == "CRITICAL" else "🟡 LOW     "
        print(f"  {badge}  {r['cve_id']:<20}  {r['host_ip']:<16}  CVSS {r['cvss_score']}")

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
