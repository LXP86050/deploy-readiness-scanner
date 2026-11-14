from __future__ import annotations

from datetime import datetime

from drs import __version__
from drs.config import Config
from drs.models import (
    CATEGORY_ORDER,
    CategoryScore,
    CheckResult,
    CheckStatus,
    Report,
    Severity,
    Verdict,
)

# Points removed from a category that starts at 100. Incomplete means the check
# timed out or raised, so the category is not treated as clean.
DEDUCTIONS: dict[Severity, int] = {
    Severity.BLOCKER: 40,
    Severity.HIGH: 20,
    Severity.MEDIUM: 10,
    Severity.LOW: 4,
    Severity.INFO: 0,
}
INCOMPLETE_DEDUCTION = 15

_GATE: dict[str, set[Severity]] = {
    "blocker": {Severity.BLOCKER},
    "high": {Severity.BLOCKER, Severity.HIGH},
    "medium": {Severity.BLOCKER, Severity.HIGH, Severity.MEDIUM},
}


def score_categories(results: list[CheckResult]) -> list[CategoryScore]:
    scores: list[CategoryScore] = []
    for category in CATEGORY_ORDER:
        mine = [result for result in results if result.category == category]
        assessed = any(result.status != CheckStatus.SKIPPED for result in mine)
        if not assessed:
            scores.append(CategoryScore(category, None, False, 0))
            continue
        deductions = 0
        for result in mine:
            if result.status in {CheckStatus.ERROR, CheckStatus.TIMEOUT}:
                deductions += INCOMPLETE_DEDUCTION
            for finding in result.findings:
                deductions += DEDUCTIONS[finding.severity]
        scores.append(CategoryScore(category, max(0, 100 - deductions), True, deductions))
    return scores


def build_report(
    config: Config,
    results: list[CheckResult],
    started_at: datetime,
    finished_at: datetime,
) -> Report:
    scores = score_categories(results)
    assessed = [score for score in scores if score.assessed and score.score is not None]
    partial = any(result.status in {CheckStatus.ERROR, CheckStatus.TIMEOUT} for result in results)
    floor = config.thresholds.min_category_score
    if not assessed:
        return Report(
            version=__version__,
            target_name=config.name,
            environment=config.environment,
            config_path=str(config.path),
            started_at=started_at,
            finished_at=finished_at,
            checks=results,
            scores=scores,
            verdict=Verdict.NOT_READY,
            exit_code=1,
            partial=partial,
            reason="no checks assessed anything",
            floor=floor,
        )

    gate = _GATE[config.thresholds.fail_on]
    blocking = [finding for result in results for finding in result.findings if finding.severity in gate]
    below = [score for score in assessed if score.score is not None and score.score < floor]
    if blocking or below:
        verdict = Verdict.NOT_READY
        exit_code = 2
    elif partial:
        verdict = Verdict.PARTIAL
        exit_code = 3
    else:
        verdict = Verdict.READY
        exit_code = 0
    return Report(
        version=__version__,
        target_name=config.name,
        environment=config.environment,
        config_path=str(config.path),
        started_at=started_at,
        finished_at=finished_at,
        checks=results,
        scores=scores,
        verdict=verdict,
        exit_code=exit_code,
        partial=partial,
        reason=_reason(verdict, len(blocking), below, partial, floor),
        floor=floor,
    )


def _reason(
    verdict: Verdict,
    blocking: int,
    below: list[CategoryScore],
    partial: bool,
    floor: int,
) -> str:
    if verdict == Verdict.READY:
        return f"no findings at or above the gate, and every assessed category is at least {floor}"
    parts: list[str] = []
    if blocking:
        noun = "finding" if blocking == 1 else "findings"
        parts.append(f"{blocking} {noun} at or above the gate")
    if below:
        listed = ", ".join(f"{score.category.value} {score.score}" for score in below)
        parts.append(f"below {floor}: {listed}")
    if verdict == Verdict.PARTIAL:
        parts.append("some checks did not finish")
    elif partial:
        parts.append("results are partial")
    return "; ".join(parts)
