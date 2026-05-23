# /agent — Core Orchestrator

This is the brain of AutoPatch-Agent. It is a Python-based LLM reasoning loop that coordinates all other modules.

## Responsibility

- Ingests CVE alerts from Datadog and deployment metadata from CI/CD logs
- Calls Nimble for web enrichment (exploit intelligence + IP exposure)
- Writes all enriched data to ClickHouse
- Queries ClickHouse to determine CRITICAL vs LOW priority
- Triggers remediation scripts for CRITICAL targets
- Sends the audit trail to Senso.ai for report generation

## Files to Build

| File | Description |
|------|-------------|
| `main.py` | Entry point — runs the full pipeline end-to-end |
| `orchestrator.py` | LLM reasoning loop — decides what tool to call next |
| `tools.py` | Tool definitions for the LLM (Datadog, Nimble, ClickHouse, Remediation, Senso) |
| `requirements.txt` | Python dependencies |
| `config.py` | Loads environment variables via python-dotenv |

## How to Run

```bash
cd agent
pip install -r requirements.txt
python main.py
```

## Key Dependencies

```
openai / anthropic      # LLM orchestration
clickhouse-driver       # ClickHouse client
boto3                   # AWS SSM for remote remediation
requests                # Nimble + Senso.ai API calls
datadog-api-client      # Datadog CVE fetching
python-dotenv           # Env var management
```
