"""
Internet Exposure Check (Nimble)
─────────────────────────────────
Probes a host IP via the Nimble network proxy to verify
whether it is reachable from the public internet.
In mock mode, loads from nimble/mock_responses.json.
"""

import json
import os
import sys
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

MOCK_PATH = os.path.join(os.path.dirname(__file__), "mock_responses.json")
USE_MOCKS  = os.getenv("USE_MOCKS", "true").lower() == "true"

# Ports to probe per service type
PROBE_PORTS = {
    "ssh":   22,
    "http":  80,
    "https": 443,
    "rdp":   3389,
}


def check_exposure(host_ip: str, port: int = 80) -> dict:
    """
    Probes host_ip:port to check public internet reachability.

    Returns:
        {
          host_ip, port, is_internet_exposed,
          response_code, banner, checked_at
        }
    """
    if USE_MOCKS or not os.getenv("NIMBLE_API_KEY"):
        return _load_mock_exposure(host_ip, port)
    return _live_check(host_ip, port)


def _load_mock_exposure(host_ip: str, port: int) -> dict:
    print(f"[nimble/exposure] Using mock data for {host_ip}:{port}")
    with open(MOCK_PATH) as f:
        data = json.load(f)
    result = data["exposure_checks"].get(host_ip)
    if not result:
        return {
            "host_ip":             host_ip,
            "port":                port,
            "is_internet_exposed": False,
            "response_code":       None,
            "banner":              None,
            "checked_at":          datetime.utcnow().isoformat() + "Z"
        }
    return result


def _live_check(host_ip: str, port: int) -> dict:
    from nimble.client import NimbleClient

    client = NimbleClient()
    target_url = f"http://{host_ip}:{port}"

    print(f"[nimble/exposure] Probing {target_url} via Nimble...")
    result = client.probe_host(target_url)

    is_exposed    = result.get("reachable", False)
    response_code = result.get("status_code")
    banner        = _extract_banner(result.get("raw", {}))

    return {
        "host_ip":             host_ip,
        "port":                port,
        "is_internet_exposed": is_exposed,
        "response_code":       response_code,
        "banner":              banner,
        "checked_at":          datetime.utcnow().isoformat() + "Z"
    }


def _extract_banner(raw_response: dict) -> str | None:
    """Try to extract a service banner from the Nimble response headers."""
    headers = raw_response.get("headers", {})
    server  = headers.get("server") or headers.get("Server")
    if server:
        return server
    via = headers.get("via") or headers.get("Via")
    return via
