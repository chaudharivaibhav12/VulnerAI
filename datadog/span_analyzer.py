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
from collections import Counter, defaultdict
from datetime import datetime, timedelta

ROOT       = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPANS_PATH = os.path.join(ROOT, "spans.ndjson")

# Module-level cache so the 3.4 MB file is read exactly once per process
_attacks_by_vuln: dict[str, list[dict]] | None = None
_dataset_now:     datetime | None              = None  # max ts in dataset — used as reference "now"


def _parse_ts(s: str) -> datetime | None:
    try:
        # Accept both "2026-05-23 17:16:20.424" and ISO formats
        return datetime.fromisoformat(s.replace("Z", "").replace("T", " "))
    except (ValueError, AttributeError):
        return None


def _load_attacks() -> dict[str, list[dict]]:
    """Read spans.ndjson once, index attack spans by vuln_id."""
    global _attacks_by_vuln, _dataset_now
    if _attacks_by_vuln is not None:
        return _attacks_by_vuln

    by_vuln: dict[str, list[dict]] = defaultdict(list)
    count = 0
    max_ts: datetime | None = None

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
                    ts = _parse_ts(span.get("ts", ""))
                    if ts and (max_ts is None or ts > max_ts):
                        max_ts = ts
    except FileNotFoundError:
        print(f"[span_analyzer] WARNING: {SPANS_PATH} not found")

    _attacks_by_vuln = dict(by_vuln)
    _dataset_now     = max_ts
    total_vulns      = len(_attacks_by_vuln)
    print(f"[span_analyzer] Indexed {count} attack spans across {total_vulns} vuln(s); "
          f"dataset_now={max_ts}")
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


def read_apm_data(vuln_id: str, window_minutes: int = 60) -> dict:
    """
    APM-style telemetry read for a vulnerability over a time window ending at the
    dataset's reference "now" (the max ts across all spans). This is what
    ClickHouse's apm_spans table would return in production.

    Returns the read_apm output_schema:
      vuln_id, attack_count, unique_ips, unique_asns, countries,
      attacks_last_15min, attacks_prior_45min, successful_attack_rate,
      sample_trace_id, sample_payload, top_user_agents
    """
    attacks_by_vuln = _load_attacks()
    all_attacks     = attacks_by_vuln.get(vuln_id, [])

    if _dataset_now is None or not all_attacks:
        return _empty_apm_result(vuln_id)

    window_start  = _dataset_now - timedelta(minutes=window_minutes)
    cutoff_15min  = _dataset_now - timedelta(minutes=15)

    # Filter to within window
    in_window: list[dict] = []
    for a in all_attacks:
        ts = _parse_ts(a.get("ts", ""))
        if ts and ts >= window_start:
            in_window.append({**a, "_ts": ts})

    if not in_window:
        return _empty_apm_result(vuln_id)

    attacks_last_15min  = sum(1 for a in in_window if a["_ts"] > cutoff_15min)
    attacks_prior_45min = len(in_window) - attacks_last_15min

    successful = sum(
        1 for a in in_window
        if isinstance(a.get("http_status_code"), int)
        and 200 <= a["http_status_code"] <= 299
    )
    successful_rate = round(successful / len(in_window), 4) if in_window else 0.0

    sample              = in_window[0]
    sample_trace_id     = sample.get("trace_id", "")
    sample_payload      = sample.get("vuln_input", "") or sample.get("http_url", "")
    top_user_agents     = [ua for ua, _ in Counter(
        a.get("http_user_agent", "") for a in in_window if a.get("http_user_agent")
    ).most_common(3)]

    return {
        "vuln_id":                vuln_id,
        "attack_count":           len(in_window),
        "unique_ips":             len({a.get("source_ip") for a in in_window if a.get("source_ip")}),
        "unique_asns":            len({a.get("source_asn") for a in in_window if a.get("source_asn") is not None}),
        "countries":              sorted({a.get("source_country", "?") for a in in_window if a.get("source_country")}),
        "attacks_last_15min":     attacks_last_15min,
        "attacks_prior_45min":    attacks_prior_45min,
        "successful_attack_rate": successful_rate,
        "sample_trace_id":        sample_trace_id,
        "sample_payload":         sample_payload,
        "top_user_agents":        top_user_agents,
    }


def _empty_apm_result(vuln_id: str) -> dict:
    return {
        "vuln_id":                vuln_id,
        "attack_count":           0,
        "unique_ips":             0,
        "unique_asns":            0,
        "countries":              [],
        "attacks_last_15min":     0,
        "attacks_prior_45min":    0,
        "successful_attack_rate": 0.0,
        "sample_trace_id":        "",
        "sample_payload":         "",
        "top_user_agents":        [],
    }
