from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any


class Category(StrEnum):
    CONNECTIVITY = "connectivity"
    DATA = "data"
    RUNTIME = "runtime"
    SECURITY = "security"


CATEGORY_ORDER: tuple[Category, ...] = (
    Category.CONNECTIVITY,
    Category.DATA,
    Category.RUNTIME,
    Category.SECURITY,
)


class Severity(StrEnum):
    BLOCKER = "blocker"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_RANK: dict[Severity, int] = {
    Severity.BLOCKER: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


class CheckStatus(StrEnum):
    OK = "ok"
    ERROR = "error"
    TIMEOUT = "timeout"
    SKIPPED = "skipped"


class Verdict(StrEnum):
    READY = "ready"
    NOT_READY = "not_ready"
    PARTIAL = "partial"


@dataclass
class Finding:
    severity: Severity
    title: str
    summary: str
    remediation: str
    evidence: dict[str, Any] | None = None
    location: str | None = None
    check_id: str = ""
    category: Category | None = None


@dataclass
class CheckResult:
    check_id: str
    title: str
    category: Category
    status: CheckStatus
    summary: str
    findings: list[Finding] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)
    duration_ms: int = 0
    detail: str | None = None


@dataclass
class CategoryScore:
    category: Category
    score: int | None
    assessed: bool
    deductions: int


@dataclass
class Report:
    version: str
    target_name: str
    environment: str
    config_path: str
    started_at: datetime
    finished_at: datetime
    checks: list[CheckResult]
    scores: list[CategoryScore]
    verdict: Verdict
    exit_code: int
    partial: bool
    reason: str
    floor: int
    schema: int = 1


def iter_findings(report: Report) -> list[Finding]:
    return [finding for result in report.checks for finding in result.findings]
