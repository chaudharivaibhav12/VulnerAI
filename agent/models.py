"""
Data models for AutoPatch-Agent.
All inter-module data passes through these dataclasses.
"""

from dataclasses import dataclass, field
from typing import Optional


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
class ExploitIntel:
    cve_id: str
    has_active_exploit: bool
    exploit_sources: list[str]
    summary: str
    searched_at: str

    def to_dict(self) -> dict:
        return self.__dict__


@dataclass
class ExposureResult:
    host_ip: str
    port: int
    is_internet_exposed: bool
    response_code: Optional[int]
    banner: Optional[str]
    checked_at: str

    def to_dict(self) -> dict:
        return self.__dict__


@dataclass
class TriageResult:
    cve_id: str
    host_ip: str
    host_name: str
    cvss_score: float
    package_name: str
    affected_version: str
    host_id: str
    has_active_exploit: bool
    is_internet_exposed: bool
    priority: str        # 'CRITICAL' | 'LOW'
    reason: str

    def to_dict(self) -> dict:
        return self.__dict__


@dataclass
class RemediationOutcome:
    cve_id: str
    host_id: str
    host_ip: str
    action_taken: str
    script_executed: str
    outcome: str         # 'success' | 'failed' | 'deferred' | 'dry_run'
    output: str

    def to_dict(self) -> dict:
        return self.__dict__


@dataclass
class PipelineState:
    """Tracks the full pipeline run state — passed between agent steps."""
    cve_findings: list[CVEFinding] = field(default_factory=list)
    exploit_intel: list[ExploitIntel] = field(default_factory=list)
    exposure_results: list[ExposureResult] = field(default_factory=list)
    triage_results: list[TriageResult] = field(default_factory=list)
    remediation_outcomes: list[RemediationOutcome] = field(default_factory=list)
    report_markdown: str = ""
    errors: list[str] = field(default_factory=list)
