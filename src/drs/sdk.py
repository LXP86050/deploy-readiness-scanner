from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from drs.context import ScanContext
from drs.models import Category, Finding, Severity

__all__ = ["Category", "Check", "Finding", "Outcome", "Severity", "Skip"]


class Skip(Exception):
    """The check has nothing to evaluate in this config. It does not fail the gate."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass
class Outcome:
    summary: str
    findings: list[Finding] | None = None
    stats: dict[str, Any] | None = None


class Check(Protocol):
    id: str
    title: str
    category: Category

    async def run(self, ctx: ScanContext) -> Outcome: ...
