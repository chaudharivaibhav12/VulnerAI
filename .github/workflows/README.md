# /.github/workflows — CI/CD Pipeline

GitHub Actions workflows that simulate a real deployment pipeline and trigger the AutoPatch-Agent.

## Workflows to Build

| File | Trigger | Description |
|------|---------|-------------|
| `deploy.yml` | Push to `main` | Simulates app deployment, writes `DEPLOYMENT_METADATA` to logs |
| `trigger_agent.yml` | After `deploy.yml` | Calls the AutoPatch-Agent API to start a new scan cycle |
| `agent_ci.yml` | PR to `main` | Runs linting + unit tests on the agent code |

## deploy.yml — Key Section

This workflow intentionally outputs the `DEPLOYMENT_METADATA` block that the agent parses:

```yaml
- name: Output Deployment Metadata
  run: |
    echo "=== DEPLOYMENT_METADATA ==="
    echo "APP_NAME=${{ env.APP_NAME }}"
    echo "AWS_REGION=${{ secrets.AWS_REGION }}"
    echo "INSTANCE_ID=${{ secrets.INSTANCE_ID }}"
    echo "PUBLIC_IP=${{ secrets.PUBLIC_IP }}"
    echo "PRIVATE_IP=${{ secrets.PRIVATE_IP }}"
    echo "DEPLOYED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "COMMIT_SHA=${{ github.sha }}"
    echo "==========================="
```

## Secrets to Configure in GitHub

Go to `Settings → Secrets and variables → Actions` and add:

```
DATADOG_API_KEY
DATADOG_APP_KEY
AWS_REGION
INSTANCE_ID
PUBLIC_IP
PRIVATE_IP
AGENT_API_URL        ← URL of your running AutoPatch-Agent backend
```
