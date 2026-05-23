"""
VulnerAI API Server
────────────────────
FastAPI backend that bridges the React dashboard and the agent pipeline.

Endpoints:
  GET  /api/status      — agent state: IDLE | RUNNING | HARDENED | ERROR
  GET  /api/triage      — CVE triage results from ClickHouse
  GET  /api/remediation — remediation audit log
  GET  /api/report      — cited.md markdown content
  POST /api/run         — trigger the agent (non-blocking)
  GET  /api/stream      — SSE stream: runs agent + pushes log lines live

Run:
  cd VulnerAI
  uvicorn report.server:app --reload --port 8000
"""

import asyncio
import json
import os
import sys
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sse_starlette.sse import EventSourceResponse

ROOT = Path(__file__).parent.parent
load_dotenv(ROOT / ".env")
sys.path.insert(0, str(ROOT))

from clickhouse.mock_client import init_db, run_triage_query, fetch_all
from report.generate import generate_report, REPORT_PATH

# ─────────────────────────────────────────────────────────────
# App setup
# ─────────────────────────────────────────────────────────────

app = FastAPI(title="VulnerAI API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],        # tighten to Vercel URL in production
    allow_methods=["*"],
    allow_headers=["*"],
)

STATE_FILE  = ROOT / "report" / "agent_state.json"
AGENT_ENTRY = ROOT / "agent" / "main.py"

# ─────────────────────────────────────────────────────────────
# State helpers
# ─────────────────────────────────────────────────────────────

def _read_state() -> dict:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except Exception:
            pass
    return {"status": "IDLE", "last_run": None}


def _write_state(status: str):
    STATE_FILE.write_text(
        json.dumps({"status": status, "last_run": datetime.utcnow().isoformat()}),
        encoding="utf-8",
    )


# ─────────────────────────────────────────────────────────────
# Startup
# ─────────────────────────────────────────────────────────────

@app.on_event("startup")
def startup():
    init_db()
    print("[server] VulnerAI API ready — http://localhost:8000")


# ─────────────────────────────────────────────────────────────
# REST endpoints
# ─────────────────────────────────────────────────────────────

@app.get("/api/status")
def get_status():
    return _read_state()


@app.get("/api/triage")
def get_triage():
    rows  = run_triage_query()
    intel = {r["cve_id"]: r for r in fetch_all("exploit_intel")}

    result = []
    for row in rows:
        cve_id = row["cve_id"]
        info   = intel.get(cve_id, {})

        raw_sources = info.get("exploit_sources", "[]")
        sources = (
            json.loads(raw_sources)
            if isinstance(raw_sources, str)
            else raw_sources or []
        )

        result.append({
            **row,
            "exploit_sources":    sources,
            "exploit_summary":    info.get("summary", ""),
            "internet_exposed":   bool(row.get("is_internet_exposed")),
            "exploit_in_wild":    bool(row.get("has_active_exploit")),
            "status":             "PATCHED" if row.get("priority") == "CRITICAL" else "DEFERRED",
        })

    return result


@app.get("/api/remediation")
def get_remediation():
    return fetch_all("remediation_log")


@app.get("/api/report")
def get_report():
    if REPORT_PATH.exists():
        return {"markdown": REPORT_PATH.read_text(encoding="utf-8"), "ready": True}
    return {"markdown": None, "ready": False}


@app.post("/api/run")
async def run_agent():
    state = _read_state()
    if state["status"] == "RUNNING":
        return JSONResponse({"error": "Agent is already running"}, status_code=409)
    _write_state("RUNNING")
    asyncio.create_task(_run_agent_background())
    return {"status": "started"}


# ─────────────────────────────────────────────────────────────
# SSE streaming endpoint — the money shot for the demo
# ─────────────────────────────────────────────────────────────

@app.get("/api/stream")
async def stream_agent(request: Request):
    """
    Runs the agent subprocess and pushes each stdout line as an SSE event.
    The React frontend opens an EventSource here when EXECUTE is clicked.

    Event data shape: {"ts": "14:31:46", "level": "INFO", "module": "NIMBLE", "msg": "..."}
    Special event:    {"done": true}  — tells frontend the cycle is complete
    """

    async def generator():
        _write_state("RUNNING")

        proc = await asyncio.create_subprocess_exec(
            sys.executable, str(AGENT_ENTRY),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=str(ROOT),
            env={**os.environ, "PYTHONUNBUFFERED": "1"},
        )

        async for raw_line in proc.stdout:
            if await request.is_disconnected():
                proc.kill()
                return

            line = raw_line.decode("utf-8", errors="replace").rstrip()
            if not line:
                continue

            # Skip banner box-drawing characters
            if any(line.startswith(c) for c in ("╔", "║", "╚", "═")):
                continue

            entry = _parse_line(line)
            yield {"data": json.dumps(entry)}

            # Small delay so browser renders each line visually
            await asyncio.sleep(0.05)

        await proc.wait()

        # Generate the markdown report after the agent finishes
        try:
            await asyncio.to_thread(generate_report)
        except Exception as e:
            print(f"[server] Report generation error: {e}")

        _write_state("HARDENED")

        # Send terminal events
        yield {"data": json.dumps(_make_entry("OK", "AGENT", "Pipeline complete — system posture: HARDENED"))}
        yield {"data": json.dumps(_make_entry("OK", "REPORT", "Security report generated → cited.md"))}
        yield {"data": json.dumps({"done": True})}

    return EventSourceResponse(generator())


# ─────────────────────────────────────────────────────────────
# Log line parser — maps agent stdout to frontend log format
# ─────────────────────────────────────────────────────────────

def _make_entry(level: str, module: str, msg: str) -> dict:
    return {
        "ts":     datetime.utcnow().strftime("%H:%M:%S"),
        "level":  level,
        "module": module,
        "msg":    msg,
    }


def _parse_line(line: str) -> dict:
    """
    Converts raw agent stdout into {ts, level, module, msg}.
    Agent prints lines like: [orchestrator] Tool call: fetch_cve_findings({})
    """
    ts = datetime.utcnow().strftime("%H:%M:%S")

    # Defaults
    level  = "INFO"
    module = "AGENT"
    msg    = line.strip()

    # Map known prefixes
    PREFIX_MAP = {
        "[orchestrator]": ("ORCH",   "INFO"),
        "[datadog]":      ("DETECT", "INFO"),
        "[nimble]":       ("NIMBLE", "INFO"),
        "[clickhouse]":   ("CH",     "INFO"),
        "[triage]":       ("TRIAGE", "INFO"),
        "[remediation]":  ("PATCH",  "CRIT"),
        "[report]":       ("REPORT", "INFO"),
        "[config]":       ("CONFIG", "INFO"),
        "[main]":         ("AGENT",  "INFO"),
    }

    for prefix, (mod, lvl) in PREFIX_MAP.items():
        if prefix in line.lower():
            module = mod
            level  = lvl
            # Strip the prefix from the message
            idx = line.lower().find(prefix)
            msg = line[idx + len(prefix):].strip().lstrip("]").strip()
            break

    # Override level based on content
    lower = line.lower()
    if any(k in lower for k in ("tool call:", "fetching", "querying", "checking")):
        level = "INFO"
    if any(k in lower for k in ("critical", "exploit confirmed", "internet exposed", "executing")):
        level = "CRIT"
    if any(k in lower for k in ("success", "patched", "complete", "done", "hardened")):
        level = "OK"
    if any(k in lower for k in ("warning", "warn", "no api key", "mock")):
        level = "WARN"
    if any(k in lower for k in ("error", "failed", "exception")):
        level = "WARN"

    return {"ts": ts, "level": level, "module": module, "msg": msg}
