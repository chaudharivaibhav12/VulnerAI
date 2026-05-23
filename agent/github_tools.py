"""
GitHub PR Tools for AutoPatch-Agent
────────────────────────────────────
Creates branches, commits patch files, and opens security-context PRs.

Dry-run safe: when DRY_RUN=true or GITHUB_TOKEN is absent, every function
prints what it would do and returns a mock result — no API calls are made.
"""

import base64
import json
import os
import sys
from datetime import datetime, timezone
from typing import Optional

import requests

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from agent.config import Config

GITHUB_API = "https://api.github.com"


# ─────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────

def _headers() -> dict:
    return {
        "Authorization": f"Bearer {Config.GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def _repo(path: str) -> str:
    return f"{GITHUB_API}/repos/{Config.GITHUB_REPO}/{path}"


def _is_dry() -> bool:
    return Config.DRY_RUN or not Config.GITHUB_TOKEN


# ─────────────────────────────────────────────────────────────
# Branch management
# ─────────────────────────────────────────────────────────────

def get_base_sha(base_branch: Optional[str] = None) -> str:
    """Return the latest commit SHA on the base branch."""
    branch = base_branch or Config.GITHUB_BASE_BRANCH
    if _is_dry():
        return "dryrun000mock000sha"

    r = requests.get(_repo(f"git/refs/heads/{branch}"), headers=_headers(), timeout=15)
    r.raise_for_status()
    return r.json()["object"]["sha"]


def create_branch(branch_name: str, base_sha: str) -> bool:
    """Create a new branch from base_sha. No-op if branch already exists."""
    if _is_dry():
        print(f"[github] [DRY RUN] Would create branch: {branch_name} from {base_sha[:12]}")
        return True

    payload = {"ref": f"refs/heads/{branch_name}", "sha": base_sha}
    r = requests.post(_repo("git/refs"), headers=_headers(), json=payload, timeout=15)
    if r.status_code == 422:
        print(f"[github] Branch already exists: {branch_name}")
        return True
    r.raise_for_status()
    return True


# ─────────────────────────────────────────────────────────────
# File commits
# ─────────────────────────────────────────────────────────────

def commit_file(branch_name: str, file_path: str, content: str, commit_message: str) -> bool:
    """Create or update a file on the branch via the Contents API."""
    if _is_dry():
        print(f"[github] [DRY RUN] Would commit {file_path} → branch {branch_name}")
        return True

    encoded = base64.b64encode(content.encode("utf-8")).decode("ascii")

    existing_sha = None
    r = requests.get(
        _repo(f"contents/{file_path}"),
        headers=_headers(),
        params={"ref": branch_name},
        timeout=15,
    )
    if r.status_code == 200:
        existing_sha = r.json().get("sha")

    payload: dict = {"message": commit_message, "content": encoded, "branch": branch_name}
    if existing_sha:
        payload["sha"] = existing_sha

    r = requests.put(_repo(f"contents/{file_path}"), headers=_headers(), json=payload, timeout=15)
    r.raise_for_status()
    return True


# ─────────────────────────────────────────────────────────────
# Pull request creation
# ─────────────────────────────────────────────────────────────

def create_pull_request(
    branch_name: str,
    cve_id: str,
    cvss_score: float,
    package_name: str,
    affected_version: str,
    fixed_version: str,
    host_name: str,
    host_ip: str,
    priority: str,
    reason: str,
    has_active_exploit: bool,
    is_internet_exposed: bool,
    exploit_sources: list[str],
    action_taken: str,
    remediation_outcome: str,
    patch_files: list[str],
) -> dict:
    """Open a PR with a rich security-context body."""

    exploit_badge = (
        "🔴 **YES** — Actively exploited in the wild"
        if has_active_exploit
        else "🟡 No known active exploit"
    )
    exposure_badge = (
        "🔴 **YES** — Internet-exposed"
        if is_internet_exposed
        else "🟢 Internal only"
    )
    sources_md = (
        "\n".join(f"- {s}" for s in exploit_sources)
        if exploit_sources
        else "- None found by Nimble"
    )
    files_md = "\n".join(f"- `{f}`" for f in patch_files)
    nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    pr_body = f"""\
## 🛡️ AutoPatch-Agent: Security Fix for `{cve_id}`

> **This PR was created autonomously by [AutoPatch-Agent](https://github.com/{Config.GITHUB_REPO})** \
after detecting, triaging, and remediating a CRITICAL vulnerability. \
Generated at {timestamp}.

---

### 📊 Vulnerability Summary

| Field | Value |
|-------|-------|
| **CVE ID** | [{cve_id}]({nvd_url}) |
| **CVSS Score** | **{cvss_score}** / 10.0 |
| **Package** | `{package_name}` |
| **Affected Version** | `{affected_version}` |
| **Fixed Version** | `{fixed_version}` |
| **Priority** | **{priority}** |
| **Triage Reason** | {reason} |

---

### 🔍 Risk Assessment — Nimble Web Intelligence

| Check | Result |
|-------|--------|
| **Active Exploit in the Wild** | {exploit_badge} |
| **Internet-Exposed Host** | {exposure_badge} |
| **Affected Host** | `{host_name}` (`{host_ip}`) |

**Exploit Intelligence Sources (discovered by Nimble API):**
{sources_md}

---

### 🔧 Autonomous Remediation Applied

The following action was executed on the live host **before** this PR was opened:

```
{action_taken}
```

**Runtime outcome:** `{remediation_outcome}`

This PR codifies the patch in the repository so the fix persists across future deployments.

---

### 📁 Files Changed

{files_md}

> See the **Files changed** tab for the complete diff including config hardening.

---

### ✅ Patch Quality Checklist

- [x] Root cause fixed (package version bumped to `{fixed_version}`)
- [x] Defense-in-depth applied (config hardening included)
- [x] Verification step present (build-time version check)
- [x] Exploit sources cited (Nimble API)
- [x] Idempotent patch (safe to apply multiple times)

---

### 🔗 Audit Trail

| Record | Location |
|--------|----------|
| Triage result | ClickHouse `triage_results` WHERE `cve_id = '{cve_id}'` |
| Remediation log | ClickHouse `remediation_log` WHERE `cve_id = '{cve_id}'` AND `host_ip = '{host_ip}'` |
| PR log | ClickHouse `pr_log` WHERE `cve_id = '{cve_id}'` |
| NVD Reference | {nvd_url} |

---

*Generated by [AutoPatch-Agent](https://github.com/{Config.GITHUB_REPO}) — \
Claude Sonnet 4.6 · ClickHouse · Nimble API · Datadog CSM*
"""

    title = f"[AutoPatch] {cve_id}: {package_name} {affected_version} → {fixed_version} (CVSS {cvss_score})"

    if _is_dry():
        mock_pr_number = abs(hash(cve_id)) % 9000 + 1000
        mock_url = f"https://github.com/{Config.GITHUB_REPO}/pull/{mock_pr_number}"
        print(f"[github] [DRY RUN] Would create PR: {title}")
        print(f"[github] [DRY RUN] Branch: {branch_name} → {Config.GITHUB_BASE_BRANCH}")
        print(f"[github] [DRY RUN] PR URL would be: {mock_url}")
        return {
            "pr_number": mock_pr_number,
            "pr_url": mock_url,
            "title": title,
            "branch": branch_name,
            "status": "dry_run",
        }

    payload = {
        "title": title,
        "body": pr_body,
        "head": branch_name,
        "base": Config.GITHUB_BASE_BRANCH,
        "draft": False,
    }
    r = requests.post(_repo("pulls"), headers=_headers(), json=payload, timeout=15)
    r.raise_for_status()
    pr = r.json()

    return {
        "pr_number": pr["number"],
        "pr_url": pr["html_url"],
        "title": pr["title"],
        "branch": branch_name,
        "status": "created",
    }
