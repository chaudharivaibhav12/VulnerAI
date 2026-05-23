"""
Datadog Response Parser
───────────────────────
Converts raw Datadog API dicts into CVEFinding dataclasses.
Also parses DEPLOYMENT_METADATA blocks from CI/CD logs.
"""

import re
from dataclasses import dataclass


@dataclass
class CVEFinding:
    cve_id: str
    severity: str
    cvss_score: float
    package_name: str
    affected_version: str
    fixed_version: str
    host_id: str
    host_name: str
    host_ip: str
    is_public_ip: bool
    description: str
    detected_at: str

    def to_dict(self) -> dict:
        return self.__dict__


@dataclass
class DeploymentMetadata:
    app_name: str
    aws_region: str
    instance_id: str
    public_ip: str
    private_ip: str
    deployed_at: str
    commit_sha: str

    def to_dict(self) -> dict:
        return self.__dict__


def parse_findings(raw_list: list[dict]) -> list[CVEFinding]:
    """Convert raw API dicts to CVEFinding dataclasses."""
    findings = []
    for r in raw_list:
        try:
            findings.append(CVEFinding(
                cve_id           = r["cve_id"],
                severity         = r.get("severity", "unknown"),
                cvss_score       = float(r.get("cvss_score", 0.0)),
                package_name     = r.get("package_name", "unknown"),
                affected_version = r.get("affected_version", "unknown"),
                fixed_version    = r.get("fixed_version", "unknown"),
                host_id          = r.get("host_id", ""),
                host_name        = r.get("host_name", ""),
                host_ip          = r.get("host_ip", ""),
                is_public_ip     = bool(r.get("is_public_ip", False)),
                description      = r.get("description", ""),
                detected_at      = r.get("detected_at", ""),
            ))
        except (KeyError, ValueError) as e:
            print(f"[parser] Skipping malformed finding: {e}")
    return findings


def parse_deployment_log(log_text: str) -> DeploymentMetadata | None:
    """
    Extracts the DEPLOYMENT_METADATA block from a GitHub Actions CI/CD log.

    Expected format in log:
        === DEPLOYMENT_METADATA ===
        APP_NAME=app-public
        AWS_REGION=us-east-1
        INSTANCE_ID=i-0a1b2c3d4e5f67890
        PUBLIC_IP=54.123.45.67
        PRIVATE_IP=10.0.1.10
        DEPLOYED_AT=2024-07-15T10:30:00Z
        COMMIT_SHA=abc123def456
        ===========================
    """
    pattern = r"=== DEPLOYMENT_METADATA ===(.*?)==========================="
    match = re.search(pattern, log_text, re.DOTALL)
    if not match:
        print("[parser] No DEPLOYMENT_METADATA block found in log.")
        return None

    block = match.group(1).strip()
    data = {}
    for line in block.splitlines():
        line = line.strip()
        if "=" in line:
            key, _, value = line.partition("=")
            data[key.strip()] = value.strip()

    try:
        return DeploymentMetadata(
            app_name    = data.get("APP_NAME", ""),
            aws_region  = data.get("AWS_REGION", "us-east-1"),
            instance_id = data.get("INSTANCE_ID", ""),
            public_ip   = data.get("PUBLIC_IP", ""),
            private_ip  = data.get("PRIVATE_IP", ""),
            deployed_at = data.get("DEPLOYED_AT", ""),
            commit_sha  = data.get("COMMIT_SHA", ""),
        )
    except Exception as e:
        print(f"[parser] Failed to parse DEPLOYMENT_METADATA: {e}")
        return None
