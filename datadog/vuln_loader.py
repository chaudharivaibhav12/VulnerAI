"""
Vulnerability Catalog Loader
Reads vuln_catalog.ndjson and maps each entry to the cve_findings table shape.
Replaces the mock datadog/mock_cves.json for web-app vulnerability scenarios.
"""

import json
import os
from datetime import datetime

ROOT        = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CATALOG_PATH = os.path.join(ROOT, "vuln_catalog.ndjson")

# DVWA host constants — all vulns live on this service
DVWA_HOST_ID = "dvwa-hack"
DVWA_HOST_IP = "dvwa.demo"
IS_PUBLIC    = True   # web app is internet-exposed by nature


def load_vuln_catalog() -> list[dict]:
    """
    Reads vuln_catalog.ndjson line-by-line and returns rows
    shaped to match the cve_findings ClickHouse table.
    """
    findings = []

    try:
        with open(CATALOG_PATH, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue

                findings.append({
                    "cve_id":           entry["vuln_id"],
                    "severity":         entry.get("static_severity", "MEDIUM"),
                    "cvss_score":       float(entry.get("cvss_score", 0.0)),
                    "package_name":     entry.get("name", entry["vuln_id"]),
                    "affected_version": str(entry.get("version", "1")),
                    "fixed_version":    "",
                    "host_id":          DVWA_HOST_ID,
                    "host_name":        DVWA_HOST_ID,
                    "host_ip":          DVWA_HOST_IP,
                    "is_public_ip":     IS_PUBLIC,
                    "description":      entry.get("description", ""),
                    "detected_at":      entry.get("discovered_at",
                                            datetime.utcnow().isoformat()),
                })

    except FileNotFoundError:
        print(f"[vuln_loader] WARNING: {CATALOG_PATH} not found — returning empty list")

    print(f"[vuln_loader] Loaded {len(findings)} vulnerabilities from catalog")
    return findings
