"""
Span Attack Analyzer
Reads spans.ndjson once (cached in memory) and extracts real attack evidence
per vuln_id. Returns data in the exploit_intel table shape.

spans.ndjson fields used:
  attack_attempt  — 1 if this is a real attack attempt
  vuln_id         — VULN-001 … VULN-004 (matches vuln_catalog entries)
  http_url        — full URL including attack payload for GET requests
  vuln_input      — the raw malicious input string
  source_ip       — attacker IP
  source_country  — 2-letter country code
  appsec_rule     — WAF rule that fired (e.g. crs-942-100)
  ts              — timestamp
"""

import json
import os
from collections import defaultdict
from datetime import datetime

ROOT       = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPANS_PATH = os.path.join(ROOT, "spans.ndjson")

# Module-level cache so the 3.4 MB file is read exactly once per process
_attacks_by_vuln: dict[str, list[dict]] | None = None


def _load_attacks() -> dict[str, list[dict]]:
    """Read spans.ndjson once, index attack spans by vuln_id."""
    global _attacks_by_vuln
    if _attacks_by_vuln is not None:
        return _attacks_by_vuln

    by_vuln: dict[str, list[dict]] = defaultdict(list)
    count = 0

    try:
        with open(SPANS_PATH, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    span = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if span.get("attack_attempt") == 1 and span.get("vuln_id"):
                    by_vuln[span["vuln_id"]].append(span)
                    count += 1
    except FileNotFoundError:
        print(f"[span_analyzer] WARNING: {SPANS_PATH} not found")

    _attacks_by_vuln = dict(by_vuln)
    total_vulns = len(_attacks_by_vuln)
    print(f"[span_analyzer] Indexed {count} attack spans across {total_vulns} vuln(s)")
    return _attacks_by_vuln


def analyze_attack_spans(vuln_id: str) -> dict:
    """
    Returns exploit_intel table shape for a given vuln_id,
    derived entirely from real attack spans.

    Returns:
        {cve_id, has_active_exploit, exploit_sources, summary, searched_at}
    """
    attacks_by_vuln = _load_attacks()
    attacks = attacks_by_vuln.get(vuln_id, [])

    has_active_exploit = len(attacks) > 0

    # Build exploit_sources from unique attack URLs (cap at 10)
    seen_urls: set[str] = set()
    exploit_sources: list[str] = []
    for a in attacks:
        url = a.get("http_url", "").strip()
        if url and url not in seen_urls:
            exploit_sources.append(url)
            seen_urls.add(url)
        if len(exploit_sources) >= 10:
            break

    # Build human-readable summary
    if has_active_exploit:
        countries  = sorted({a.get("source_country", "?") for a in attacks})
        unique_ips = len({a.get("source_ip") for a in attacks})
        latest_ts  = max((a.get("ts", "") for a in attacks), default="")
        rules      = sorted({a.get("appsec_rule", "") for a in attacks if a.get("appsec_rule")})
        summary = (
            f"{vuln_id}: {len(attacks)} active attack attempt(s) detected in live traffic. "
            f"{unique_ips} unique source IP(s) from {', '.join(countries[:5])}. "
            f"WAF rules fired: {', '.join(rules) or 'none'}. "
            f"Latest attack: {latest_ts}."
        )
    else:
        summary = f"No active attack attempts detected in spans for {vuln_id}."

    return {
        "cve_id":             vuln_id,
        "has_active_exploit": has_active_exploit,
        "exploit_sources":    exploit_sources,
        "summary":            summary,
        "searched_at":        datetime.utcnow().isoformat() + "Z",
    }


def get_attack_counts() -> dict[str, int]:
    """Returns {vuln_id: attack_count} for all vulns with real attacks."""
    return {vid: len(spans) for vid, spans in _load_attacks().items()}
