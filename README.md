# AutoPatch-Agent 🛡️

> **Autonomous Vulnerability Triage & Remediation System**
> Built for the *Ship to Prod — Agentic Engineering Hackathon*

---

## What It Does

AutoPatch-Agent is a fully autonomous security pipeline that:
1. **Detects** CVEs on live EC2 instances via Datadog CSM
2. **Enriches** each CVE with real-time exploit intelligence via the Nimble API
3. **Triages** and prioritizes using ClickHouse as the decision engine
4. **Remediates** critical, internet-exposed vulnerabilities autonomously
5. **Reports** everything in a grounded, cited security posture report via Senso.ai — displayed on a live Vercel dashboard

---

## Architecture

```
Datadog CVEs
     │
     ▼
CI/CD Metadata (GitHub Actions)
     │
     ▼
Nimble API  ──── Web enrichment (exploit intel + internet exposure check)
     │
     ▼
ClickHouse  ──── Triage JOIN query (CRITICAL vs LOW priority)
     │
     ├──► Remediation Scripts (SSH / AWS SSM) ──► CRITICAL targets
     │
     └──► Senso.ai ──► cited.md report ──► Vercel React Dashboard
```

---

## Repository Structure

| Folder | Description |
|--------|-------------|
| [`/agent`](./agent/) | Core Python orchestrator — the LLM reasoning loop |
| [`/datadog`](./datadog/) | Datadog API integration + mock CVE payloads |
| [`/nimble`](./nimble/) | Nimble API client — exploit intel + IP exposure checks |
| [`/clickhouse`](./clickhouse/) | Schemas, migrations, and triage query logic |
| [`/remediation`](./remediation/) | Bash/Python scripts for patching and isolation |
| [`/senso`](./senso/) | Senso.ai integration — grounded report generation |
| [`/frontend`](./frontend/) | React dashboard deployed on Vercel |
| [`/infrastructure`](./infrastructure/) | AWS EC2 setup, dummy apps, SSM config |
| [`/.github/workflows`](./.github/workflows/) | GitHub Actions — deployment + pipeline trigger |

---

## Quickstart

```bash
# 1. Clone
git clone https://github.com/chaudharivaibhav12/VulnerAI.git
cd VulnerAI

# 2. Set up environment
cp .env.example .env
# Fill in your API keys (Datadog, Nimble, ClickHouse, Senso.ai, AWS)

# 3. Install dependencies
pip install -r agent/requirements.txt

# 4. Run the agent
python agent/main.py
```

---

## Environment Variables

Copy `.env.example` to `.env` and fill in your values.
