# /infrastructure — AWS EC2 + Dummy Applications

This module contains everything needed to spin up the demo environment: 3 EC2 instances running dummy applications with intentionally planted vulnerabilities, plus Datadog Agent configuration.

## Responsibility

- Provision EC2 instances with vulnerable software versions installed
- Configure the Datadog Agent on each instance for CSM + APM
- Expose one instance to the internet (for the CRITICAL demo scenario)
- Keep the other two instances internal-only (for the LOW priority scenario)

## Architecture

```
Internet
   │
   ▼
[EC2-1: app-public]   ← Publicly exposed (port 22, 80 open)
   - openssh-server 9.2p1   → CVE-2024-6387 (CRITICAL)
   - Datadog Agent installed

[EC2-2: app-internal-a]   ← Internal only (no public IP)
   - nginx + log4j 2.14.1   → CVE-2023-44487 + CVE-2021-44228
   - Datadog Agent installed

[EC2-3: app-internal-b]   ← Internal only (no public IP)
   - xz-utils 5.6.0         → CVE-2024-3094
   - Datadog Agent installed
```

## Files to Build

| File | Description |
|------|-------------|
| `setup_ec2.sh` | User-data script — installs vulnerable packages + Datadog Agent |
| `datadog_agent.yaml` | Datadog Agent config with CSM + APM enabled |
| `docker-compose.yml` | Alternative: run all 3 apps as local Docker containers |
| `terraform/` | (Optional) Terraform IaC to provision EC2s reproducibly |
| `mock_deployment_log.txt` | Realistic CI/CD log with `DEPLOYMENT_METADATA` block for the agent to parse |

## DEPLOYMENT_METADATA Block (parsed by agent)

The CI/CD log contains this block that the agent parses to extract infrastructure context:

```
=== DEPLOYMENT_METADATA ===
APP_NAME=app-public
AWS_REGION=us-east-1
INSTANCE_ID=i-0a1b2c3d4e5f67890
PUBLIC_IP=54.123.45.67
PRIVATE_IP=10.0.1.10
DEPLOYED_AT=2024-01-15T10:30:00Z
COMMIT_SHA=abc123def456
===========================
```

## Quick Docker Setup (no AWS needed for demo)

```bash
cd infrastructure
docker-compose up -d
# Spins up 3 containers with vulnerable software
# EC2-1 equivalent maps to localhost:8080 (publicly accessible)
```
