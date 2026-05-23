"""
Nimble API Client
─────────────────
Base HTTP client for the Nimble Web API.
Handles auth, retries, and error logging.
All Nimble calls go through this client.
"""

import os
import time
import requests
from typing import Any

NIMBLE_BASE_URL = "https://api.webit.live/api/v1/realtime/web"
DEFAULT_TIMEOUT = 30
MAX_RETRIES = 3
RETRY_DELAY = 2   # seconds


class NimbleClient:
    def __init__(self, api_key: str | None = None):
        self.api_key = api_key or os.getenv("NIMBLE_API_KEY", "")
        if not self.api_key:
            print("[nimble] WARNING: NIMBLE_API_KEY not set — requests will fail in live mode.")

    def request(self, url: str, method: str = "GET", parse: bool = True) -> dict[str, Any]:
        """
        Sends a web request through the Nimble proxy.

        Args:
            url:    The target URL to fetch via Nimble
            method: HTTP method (GET/POST)
            parse:  Whether Nimble should parse/extract the page content

        Returns:
            Nimble API response dict
        """
        payload = {
            "url":    url,
            "method": method,
            "parse":  parse,
        }
        headers = {
            "Authorization": f"Basic {self.api_key}",
            "Content-Type":  "application/json",
        }

        for attempt in range(1, MAX_RETRIES + 1):
            try:
                resp = requests.post(
                    NIMBLE_BASE_URL,
                    json=payload,
                    headers=headers,
                    timeout=DEFAULT_TIMEOUT
                )
                resp.raise_for_status()
                return resp.json()
            except requests.exceptions.HTTPError as e:
                print(f"[nimble] HTTP error (attempt {attempt}/{MAX_RETRIES}): {e}")
            except requests.exceptions.Timeout:
                print(f"[nimble] Timeout (attempt {attempt}/{MAX_RETRIES})")
            except requests.exceptions.RequestException as e:
                print(f"[nimble] Request error (attempt {attempt}/{MAX_RETRIES}): {e}")

            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY)

        return {"error": "All Nimble retries exhausted", "url": url}

    def fetch_page(self, url: str) -> str:
        """Convenience wrapper — returns just the parsed page text."""
        result = self.request(url, parse=True)
        return result.get("parsing", {}).get("entities", [{}])[0].get("html", "") \
               or result.get("html_content", "")

    def probe_host(self, url: str) -> dict:
        """
        Probes a URL directly — used to check if a host is internet-exposed.
        Returns status_code and whether the request succeeded.
        """
        result = self.request(url, method="GET", parse=False)
        return {
            "reachable":     "error" not in result,
            "status_code":   result.get("status_code"),
            "response_size": result.get("content_length"),
            "raw":           result,
        }
