# /nimble — Web Enrichment & Exploit Intelligence

This module wraps the Nimble API to do two things that no static CVE database can do: confirm whether an exploit is actively being used in the wild, and verify whether a target IP is reachable from the public internet.

## Responsibility

1. **Exploit Intel Search** — Query Nimble's web scraping API to search NVD, GitHub Security Advisories, and security blogs for evidence of active exploitation for a given CVE
2. **Internet Exposure Check** — Send an HTTP probe via Nimble to a target IP:port to verify if the host is publicly reachable

## Files to Build

| File | Description |
|------|-------------|
| `client.py` | Nimble API client (handles auth, retries, rate limiting) |
| `exploit_search.py` | Searches the web for active exploit evidence for a CVE |
| `exposure_check.py` | Probes target IP via Nimble to verify internet exposure |
| `models.py` | `ExploitIntel` and `ExposureResult` dataclasses |

## Data Shapes

```python
@dataclass
class ExploitIntel:
    cve_id: str
    has_active_exploit: bool        # True if PoC/exploit found in the wild
    exploit_sources: list[str]      # URLs of blog posts, PoC repos, advisories
    summary: str                    # 1-2 sentence summary from Nimble results
    searched_at: str                # ISO timestamp

@dataclass
class ExposureResult:
    host_ip: str
    port: int
    is_internet_exposed: bool       # True if Nimble can reach the host
    response_code: int | None
    checked_at: str
```

## Nimble API Usage

```python
# Exploit search — uses Nimble's SERP/web scraping endpoint
POST https://api.webit.live/api/v1/realtime/web
{
  "url": "https://nvd.nist.gov/vuln/detail/CVE-XXXX-XXXX",
  "method": "GET",
  "parse": true
}

# Internet exposure check — uses Nimble's network request proxy
POST https://api.webit.live/api/v1/realtime/web
{
  "url": "http://<target_ip>:<port>",
  "method": "GET"
}
```
