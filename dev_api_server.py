"""
Local API server for the AutoPatch-Agent demo.

Purpose:
- Provide a simple backend for the React dashboard during local testing.
- Serve data from the SQLite ClickHouse mock and the latest pipeline output.

Endpoints:
  GET  /api/status
  POST /api/run?reset=1
  GET  /api/services
  GET  /api/triage
  GET  /api/remediation
  GET  /api/report

Run:
  python dev_api_server.py --port 8787
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

# Pipeline prints unicode (→, —, emojis); force UTF-8 stdout/stderr so the
# background thread that runs the agent doesn't crash on Windows cp1252.
for stream in (sys.stdout, sys.stderr):
    try:
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


ROOT = os.path.dirname(os.path.abspath(__file__))
PIPELINE_OUTPUT_PATH = os.path.join(ROOT, "pipeline_output.json")


def _json_response(handler: BaseHTTPRequestHandler, status: int, payload: dict):
    body = json.dumps(payload).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Access-Control-Allow-Origin", "*")
    handler.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
    handler.send_header("Access-Control-Allow-Headers", "Content-Type")
    handler.end_headers()
    handler.wfile.write(body)


def _text_response(handler: BaseHTTPRequestHandler, status: int, text: str):
    body = text.encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "text/plain; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Access-Control-Allow-Origin", "*")
    handler.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
    handler.send_header("Access-Control-Allow-Headers", "Content-Type")
    handler.end_headers()
    handler.wfile.write(body)


def _safe_read_json(path: str) -> dict | None:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return None
    except json.JSONDecodeError:
        return None


def _load_pipeline_output() -> dict | None:
    return _safe_read_json(PIPELINE_OUTPUT_PATH)


def _load_db_rows(table: str) -> list[dict]:
    from clickhouse.mock_client import fetch_all, init_db

    init_db()
    try:
        return fetch_all(table)
    except Exception:
        return []


def _load_services() -> list[dict]:
    findings = _load_db_rows("cve_findings")
    exposure = {row["host_ip"]: row for row in _load_db_rows("exposure_checks")}
    remediation = _load_db_rows("remediation_log")

    by_host: dict[str, dict] = {}
    for f in findings:
        host_ip = f.get("host_ip") or "unknown"
        host = by_host.setdefault(
            host_ip,
            {
                "id": host_ip,
                "name": f.get("host_name") or host_ip,
                "host": host_ip,
                "instance_id": f.get("host_id") or "",
                "software": f.get("package_name") or "",
                "port": None,
                "internet_exposed": bool(exposure.get(host_ip, {}).get("is_internet_exposed", 0)),
                "cve_count": 0,
                "status": "UNKNOWN",
                "region": os.getenv("AWS_REGION", "us-east-1"),
            },
        )
        host["cve_count"] += 1
        if not host["software"] and f.get("package_name"):
            host["software"] = f["package_name"]

    # Determine status per host based on triage + remediation outcomes
    triage = _load_db_rows("triage_results")
    critical_by_host = {}
    for t in triage:
        if t.get("priority") == "CRITICAL":
            critical_by_host.setdefault(t.get("host_ip"), 0)
            critical_by_host[t.get("host_ip")] += 1

    success_by_host = {}
    for r in remediation:
        if r.get("outcome") in ("success", "dry_run"):
            success_by_host.setdefault(r.get("host_ip"), 0)
            success_by_host[r.get("host_ip")] += 1

    for host_ip, svc in by_host.items():
        critical = critical_by_host.get(host_ip, 0)
        success = success_by_host.get(host_ip, 0)
        if critical == 0 and svc["cve_count"] > 0:
            svc["status"] = "DEFERRED"
        elif critical > 0 and success >= critical:
            svc["status"] = "PATCHED"
        elif critical > 0:
            svc["status"] = "AT_RISK"

    return list(by_host.values())


def _build_dashboard_findings() -> list[dict]:
    findings = _load_db_rows("cve_findings")
    triage_rows = _load_db_rows("triage_results")
    exposure_rows = _load_db_rows("exposure_checks")
    intel_rows = _load_db_rows("exploit_intel")
    remediation_rows = _load_db_rows("remediation_log")

    triage_by_key = {(t.get("cve_id"), t.get("host_ip")): t for t in triage_rows}
    exposure_by_ip = {e.get("host_ip"): e for e in exposure_rows}
    intel_by_cve = {i.get("cve_id"): i for i in intel_rows}
    remediation_by_cve = {}
    for r in remediation_rows:
        remediation_by_cve.setdefault(r.get("cve_id"), []).append(r)

    out: list[dict] = []
    for f in findings:
        cve_id = f.get("cve_id")
        host_ip = f.get("host_ip")
        t = triage_by_key.get((cve_id, host_ip), {})
        ex = exposure_by_ip.get(host_ip, {})
        intel = intel_by_cve.get(cve_id, {})

        try:
            raw_sources = json.loads(intel.get("exploit_sources") or "[]")
        except json.JSONDecodeError:
            raw_sources = []

        sources = []
        for s in raw_sources if isinstance(raw_sources, list) else []:
            if isinstance(s, dict):
                sources.append({"title": s.get("title", "Source"), "url": s.get("url", "")})
            elif isinstance(s, str):
                sources.append({"title": s, "url": s})

        rem_entries = remediation_by_cve.get(cve_id) or []
        last_rem = rem_entries[-1] if rem_entries else {}
        outcome = (last_rem.get("outcome") or "").lower()

        status = "DEFERRED"
        action_taken = None
        deferred_reason = None
        patched_at = None

        if t.get("priority") == "CRITICAL":
            if outcome in ("success", "dry_run"):
                status = "PATCHED"
                action_taken = last_rem.get("action_taken")
                patched_at = last_rem.get("executed_at")
            else:
                status = "AT_RISK"
        else:
            status = "DEFERRED"
            deferred_reason = t.get("reason") or "Deferred by triage policy."

        cvss_score = float(f.get("cvss_score") or 0.0)
        host_name = f.get("host_name") or host_ip

        out.append({
            # Fields expected by frontend/src/api.js normalization
            "cve_id": cve_id,
            "cvss_score": cvss_score,
            "host_ip": host_ip,
            "host_name": host_name,

            # Extra fields used directly by the dashboard components
            "severity": f.get("severity") or "",
            "description": f.get("description") or "",
            "internet_exposed": bool(ex.get("is_internet_exposed", 0)),
            "exploit_in_wild": bool(intel.get("has_active_exploit", 0)),
            "exploit_sources": sources,
            "priority": t.get("priority") or "LOW",
            "status": status,
            "action_taken": action_taken,
            "deferred_reason": deferred_reason,
            "patched_at": patched_at,
        })

    def _prio(v: str) -> int:
        return 0 if v == "CRITICAL" else 1

    out.sort(key=lambda r: (_prio(r.get("priority")), -float(r.get("cvss") or 0.0)))
    return out


def _build_report_markdown() -> str:
    findings = _load_db_rows("cve_findings")
    intel = {row["cve_id"]: row for row in _load_db_rows("exploit_intel")}
    triage = _load_db_rows("triage_results")
    remediation = _load_db_rows("remediation_log")

    rem_by_cve = {}
    for r in remediation:
        rem_by_cve.setdefault(r.get("cve_id"), []).append(r)

    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    lines: list[str] = []
    lines.append("# AutoPatch-Agent Security Posture Report")
    lines.append(f"**Generated:** {now}")
    lines.append("")

    total_hosts = len({f.get("host_ip") for f in findings if f.get("host_ip")})
    total_cves = len({f.get("cve_id") for f in findings if f.get("cve_id")})
    critical = [t for t in triage if t.get("priority") == "CRITICAL"]
    low = [t for t in triage if t.get("priority") != "CRITICAL"]

    lines.append("## Executive Summary")
    lines.append(
        f"AutoPatch-Agent triaged **{total_cves} CVEs** across **{total_hosts} hosts**. "
        f"**{len(critical)}** classified as CRITICAL and **{len(low)}** deferred."
    )
    lines.append("")

    if critical:
        lines.append("## Critical Findings — Remediation Log")
        for t in critical:
            cve_id = t.get("cve_id")
            host_ip = t.get("host_ip")
            host_name = t.get("host_name") or host_ip
            cvss = t.get("cvss_score")
            lines.append(f"### {cve_id} (CVSS {cvss})")
            lines.append(f"- **Host:** {host_name} ({host_ip})")
            lines.append(f"- **Reason:** {t.get('reason')}")

            entries = rem_by_cve.get(cve_id) or []
            if entries:
                last = entries[-1]
                lines.append(f"- **Action:** {last.get('action_taken')}")
                lines.append(f"- **Outcome:** {last.get('outcome')}")
            else:
                lines.append("- **Action:** (no remediation log entry found)")
                lines.append("- **Outcome:** unknown")

            intel_row = intel.get(cve_id) or {}
            try:
                raw_sources = json.loads(intel_row.get("exploit_sources") or "[]")
            except json.JSONDecodeError:
                raw_sources = []

            sources = []
            for s in raw_sources if isinstance(raw_sources, list) else []:
                if isinstance(s, dict):
                    sources.append({"title": s.get("title", "Source"), "url": s.get("url", "")})
                elif isinstance(s, str):
                    sources.append({"title": s, "url": s})

            if sources:
                lines.append("")
                lines.append("**Sources:**")
                for idx, s in enumerate(sources, start=1):
                    title = s.get("title", "Source")
                    url = s.get("url", "")
                    if url:
                        lines.append(f"{idx}. [{title}]({url})")
                    else:
                        lines.append(f"{idx}. {title}")
            lines.append("")

    if low:
        lines.append("## Deferred Findings — LOW Priority")
        lines.append("")
        lines.append("| CVE | Host | CVSS | Reason Deferred |")
        lines.append("|-----|------|------|-----------------|")
        for t in low:
            cve_id = t.get("cve_id")
            host_ip = t.get("host_ip")
            host_name = t.get("host_name") or host_ip
            cvss = t.get("cvss_score")
            reason = (t.get("reason") or "").replace("\n", " ")
            lines.append(f"| {cve_id} | {host_name} ({host_ip}) | {cvss} | {reason} |")
        lines.append("")

    if not triage and findings:
        lines.append("## Note")
        lines.append("CVE findings exist, but no triage results were found yet. Run the agent once.")
        lines.append("")

    if not findings:
        lines.append("## Note")
        lines.append("No findings found yet. Run the agent to generate demo data.")
        lines.append("")

    return "\n".join(lines).strip() + "\n"


def _build_ranking_report_markdown(output: dict) -> str:
    ranking = (output or {}).get("ranking") or {}
    rankings = ranking.get("rankings") or []
    remediated = (output or {}).get("remediated") or []
    deferred = (output or {}).get("deferred") or []
    prs = (output or {}).get("pull_requests") or []

    generated_at = ranking.get("generated_at") or ""
    window = ranking.get("window") or ""
    explanation = ranking.get("explanation") or ""

    lines: list[str] = []
    lines.append("# AutoPatch-Agent Security Posture Report")
    if generated_at:
        lines.append(f"**Generated:** {generated_at} | **Window:** {window}")
    lines.append("")

    if explanation:
        lines.append("## Rank-Flip Insight")
        lines.append(explanation)
        lines.append("")

    if rankings:
        top = rankings[0]
        lines.append("## Top Pick (Patch First)")
        lines.append(f"- **Rank:** #{top.get('rank')}")
        lines.append(f"- **Vuln:** `{top.get('vuln_id')}`")
        lines.append(f"- **Composite Score:** **{top.get('composite_score')}**")
        if top.get("sample_trace_id"):
            lines.append(f"- **Sample trace_id:** `{top.get('sample_trace_id')}`")
        if top.get("sample_payload"):
            payload = str(top.get("sample_payload")).replace("\n", " ")
            lines.append(f"- **Sample payload:** `{payload}`")
        lines.append("")

        lines.append("## Rankings")
        lines.append("")
        lines.append("| Rank | Vuln | Composite | Active | External | Static | Reasoning |")
        lines.append("|------|------|-----------|--------|----------|--------|-----------|")
        for r in rankings:
            ss = r.get("sub_scores") or {}
            reasoning = str(r.get("reasoning") or "").replace("\n", " ")
            lines.append(
                f"| {r.get('rank')} | {r.get('vuln_id')} | {r.get('composite_score')} | "
                f"{ss.get('active_exploitation')} | {ss.get('external_pressure')} | {ss.get('static_severity')} | {reasoning} |"
            )
        lines.append("")

    if remediated:
        lines.append("## Remediated")
        lines.append("")
        for r in remediated:
            lines.append(f"- **#{r.get('rank')} {r.get('vuln_id')}** (composite {r.get('composite_score')}): `{r.get('outcome')}`")
            if r.get("action"):
                lines.append(f"  - Action: {r.get('action')}")
        lines.append("")

    if prs:
        lines.append("## Pull Requests")
        lines.append("")
        for pr in prs:
            lines.append(f"- **#{pr.get('rank')} {pr.get('vuln_id')}**: {pr.get('pr_status')} — {pr.get('pr_url')}")
            if pr.get("branch"):
                lines.append(f"  - Branch: `{pr.get('branch')}`")
            if pr.get("files_patched") is not None:
                lines.append(f"  - Files patched: {pr.get('files_patched')}")
        lines.append("")

    if deferred:
        lines.append("## Deferred")
        lines.append("")
        for d in deferred:
            lines.append(f"- **#{d.get('rank')} {d.get('vuln_id')}** (composite {d.get('composite_score')}): {d.get('reason')}")
        lines.append("")

    if not any([rankings, remediated, deferred, prs]):
        lines.append("## Note")
        lines.append("No pipeline output found yet. Run the agent once.")
        lines.append("")

    return "\n".join(lines).strip() + "\n"


class _RunState:
    lock = threading.Lock()
    running = False
    last_started_at = None
    last_finished_at = None
    last_summary = None
    last_error = None


def _run_pipeline(reset: bool):
    from clickhouse.mock_client import init_db, reset_db
    from agent.orchestrator import run_llm_pipeline

    with _RunState.lock:
        if _RunState.running:
            return
        _RunState.running = True
        _RunState.last_started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        _RunState.last_error = None

    try:
        init_db()
        if reset:
            reset_db()
        summary = run_llm_pipeline(verbose=True)
        # Persist for the frontend to consume.
        try:
            with open(PIPELINE_OUTPUT_PATH, "w", encoding="utf-8") as f:
                json.dump(summary, f, indent=2)
        except Exception:
            pass
        with _RunState.lock:
            _RunState.last_summary = summary
    except Exception as e:
        with _RunState.lock:
            _RunState.last_error = str(e)
    finally:
        with _RunState.lock:
            _RunState.running = False
            _RunState.last_finished_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        # Keep stdout readable; Vite/agent already logs plenty.
        return

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/status":
            with _RunState.lock:
                running = _RunState.running
                last_run = _RunState.last_finished_at
                last_error = _RunState.last_error

            output = _load_pipeline_output()
            if running:
                status = "running"
            elif last_error:
                status = "error"
            elif output:
                status = "done"
            else:
                status = "idle"

            payload = {
                "status": status,
                "running": running,
                "last_run": last_run,
                "last_error": last_error,
                "output": output,
            }
            _json_response(self, 200, payload)
            return

        if path == "/api/services":
            _json_response(self, 200, {"services": _load_services()})
            return

        if path == "/api/triage":
            _json_response(self, 200, _build_dashboard_findings())
            return

        if path == "/api/remediation":
            _json_response(self, 200, _load_db_rows("remediation_log"))
            return

        if path == "/api/report":
            output = _load_pipeline_output()
            if output and output.get("ranking"):
                md = _build_ranking_report_markdown(output)
            else:
                md = _build_report_markdown()
            ready = bool(md and md.strip())
            _json_response(self, 200, {"ready": ready, "markdown": md if ready else None})
            return

        _json_response(self, 404, {"error": "not_found", "path": path})

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)

        if path == "/api/run":
            reset = qs.get("reset", ["0"])[0] in ("1", "true", "yes")
            with _RunState.lock:
                already = _RunState.running
            if already:
                _json_response(self, 409, {"status": "already_running"})
                return

            t = threading.Thread(target=_run_pipeline, args=(reset,), daemon=True)
            t.start()
            _json_response(self, 202, {"status": "started", "reset": reset})
            return

        _json_response(self, 404, {"error": "not_found", "path": path})


def main():
    parser = argparse.ArgumentParser(description="Local API server for AutoPatch-Agent demo")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    args = parser.parse_args()

    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"[dev_api_server] Listening on http://{args.host}:{args.port}")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
