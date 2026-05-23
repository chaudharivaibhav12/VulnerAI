# /remediation — Autonomous Patching Scripts

This module contains the scripts the agent executes against CRITICAL targets. The agent invokes these via AWS Systems Manager (SSM) Run Command or direct SSH — no human in the loop.

## Responsibility

- Receive a target `host_id`, `cve_id`, and `package_name` from the orchestrator
- Execute the appropriate remediation action on the remote EC2 instance
- Return a structured outcome (success / failed) back to the orchestrator for logging

## Remediation Strategy by CVE

| CVE | Package | Action |
|-----|---------|--------|
| CVE-2024-6387 | openssh-server | Restart SSH with safe config + restrict to VPN IP |
| CVE-2023-44487 | nginx/apache | Disable HTTP/2, reload service |
| CVE-2021-44228 | log4j | Set `LOG4J_FORMAT_MSG_NO_LOOKUPS=true`, restart app |
| CVE-2023-23397 | outlook/mail | Disable external UNC path resolution via registry |
| CVE-2024-3094 | xz-utils | Downgrade to xz-utils 5.4.x via package manager |

## Files to Build

| File | Description |
|------|-------------|
| `executor.py` | Dispatches remediation via AWS SSM or SSH based on config |
| `ssm_runner.py` | Sends SSM Run Command to target EC2 instance |
| `ssh_runner.py` | Fallback SSH-based execution |
| `scripts/patch_openssh.sh` | Bash: patch/config-fix for CVE-2024-6387 |
| `scripts/patch_nginx.sh` | Bash: disable HTTP/2 for CVE-2023-44487 |
| `scripts/patch_log4j.sh` | Bash: env-var fix for CVE-2021-44228 |
| `scripts/isolate_container.sh` | Bash: drop all inbound traffic via iptables (emergency isolation) |

## Execution Flow

```python
# Called by the orchestrator for each CRITICAL entry
result = executor.run(
    host_id="i-0abc123def456",
    cve_id="CVE-2024-6387",
    package_name="openssh-server",
    method="ssm"   # or "ssh"
)
# Returns: {"status": "success", "output": "...", "executed_at": "..."}
```

## Safety Rules

- `DRY_RUN=true` in `.env` will log actions without executing them
- All scripts are **idempotent** — safe to run more than once
- LOW priority CVEs are **never touched** by this module
