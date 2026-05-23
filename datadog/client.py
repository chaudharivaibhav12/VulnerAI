"""
Datadog Client
──────────────
Fetches active CVE findings from Datadog Cloud Security Management (CSM).
In mock mode, loads from datadog/mock_cves.json.
In live mode, calls the Datadog Security Findings API.
"""

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

MOCK_PATH = os.path.join(os.path.dirname(__file__), "mock_cves.json")
USE_MOCKS = os.getenv("USE_MOCKS", "true").lower() == "true"


def get_cve_findings() -> list[dict]:
    """
    Returns a list of CVE findings dicts.
    Each dict matches the CVEFinding dataclass shape.
    """
    if USE_MOCKS or not os.getenv("DATADOG_API_KEY"):
        return _load_mock_findings()
    return _fetch_live_findings()


def _load_mock_findings() -> list[dict]:
    print("[datadog] Using mock CVE data.")
    with open(MOCK_PATH) as f:
        return json.load(f)


def _fetch_live_findings() -> list[dict]:
    """
    Calls the Datadog Security Findings API to pull active CVEs.
    Filters for findings of type 'vulnerability' with status 'open'.
    """
    try:
        from datadog_api_client import ApiClient, Configuration
        from datadog_api_client.v2.api.security_monitoring_api import SecurityMonitoringApi
    except ImportError:
        print("[datadog] datadog-api-client not installed. Falling back to mock.")
        return _load_mock_findings()

    api_key    = os.getenv("DATADOG_API_KEY", "")
    app_key    = os.getenv("DATADOG_APP_KEY", "")
    site       = os.getenv("DATADOG_SITE", "datadoghq.com")

    configuration = Configuration()
    configuration.api_key["apiKeyAuth"] = api_key
    configuration.api_key["appKeyAuth"] = app_key
    configuration.server_variables["site"] = site

    findings = []
    with ApiClient(configuration) as api_client:
        api = SecurityMonitoringApi(api_client)
        response = api.list_findings(
            filter_status="open",
        )
        for finding in response.data:
            attrs = finding.attributes
            resource_attrs = attrs.resource_configuration or {}

            findings.append({
                "cve_id":            _extract_cve_id(attrs),
                "severity":          str(attrs.severity).lower() if attrs.severity else "unknown",
                "cvss_score":        float(attrs.evaluation.weight or 0),
                "package_name":      resource_attrs.get("package_name", "unknown"),
                "affected_version":  resource_attrs.get("package_version", "unknown"),
                "fixed_version":     resource_attrs.get("fixed_in_version", "unknown"),
                "host_id":           attrs.resource or "",
                "host_name":         resource_attrs.get("host_name", ""),
                "host_ip":           resource_attrs.get("public_ip_address")
                                     or resource_attrs.get("private_ip_address", ""),
                "is_public_ip":      bool(resource_attrs.get("public_ip_address")),
                "description":       attrs.message or "",
                "detected_at":       str(attrs.detected_at or ""),
            })

    print(f"[datadog] Fetched {len(findings)} live CVE findings.")
    return findings


def _extract_cve_id(attrs) -> str:
    """Pull CVE ID from finding tags or rule ID."""
    tags = getattr(attrs, "tags", []) or []
    for tag in tags:
        if tag.startswith("cve:"):
            return tag.split("cve:")[1].upper()
    return getattr(attrs, "rule_id", "CVE-UNKNOWN")
