from __future__ import annotations

import json
from typing import Any

from drs.models import CategoryScore, CheckResult, CheckStatus, Finding, Report, Severity


def report_to_dict(report: Report) -> dict[str, Any]:
    return {
        "schema": report.schema,
        "tool": {"name": "drs", "version": report.version},
        "target": {"name": report.target_name, "environment": report.environment},
        "config": report.config_path,
        "started_at": report.started_at.isoformat(),
        "finished_at": report.finished_at.isoformat(),
        "verdict": report.verdict.value,
        "exit_code": report.exit_code,
        "partial": report.partial,
        "reason": report.reason,
        "floor": report.floor,
        "scores": [_score(score) for score in report.scores],
        "checks": [_check(result) for result in report.checks],
    }


def render_json(report: Report) -> str:
    return json.dumps(report_to_dict(report), indent=2, ensure_ascii=False) + "\n"


def render_sarif(report: Report) -> str:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for check in report.checks:
        for finding in check.findings:
            rules.setdefault(finding.check_id, _rule(check, finding))
            results.append(_sarif_result(finding))
    notifications = []
    for check in report.checks:
        if check.status == CheckStatus.TIMEOUT:
            notifications.append(_notice(f"{check.check_id} {check.summary}"))
        elif check.status == CheckStatus.ERROR:
            detail = check.detail or check.summary
            notifications.append(_notice(f"{check.check_id} failed: {detail}"))
    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "drs",
                        "version": report.version,
                        "informationUri": "https://github.com/LXP86050/deploy-readiness-scanner",
                        "rules": list(rules.values()),
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": not report.partial,
                        "exitCode": report.exit_code,
                        "toolExecutionNotifications": notifications,
                    }
                ],
                "results": results,
            }
        ],
    }
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


def _score(score: CategoryScore) -> dict[str, Any]:
    return {
        "category": score.category.value,
        "score": score.score,
        "assessed": score.assessed,
        "deductions": score.deductions,
    }


def _check(result: CheckResult) -> dict[str, Any]:
    body: dict[str, Any] = {
        "id": result.check_id,
        "title": result.title,
        "category": result.category.value,
        "status": result.status.value,
        "summary": result.summary,
        "duration_ms": result.duration_ms,
        "stats": result.stats,
        "findings": [_finding(finding) for finding in result.findings],
    }
    if result.detail:
        body["detail"] = result.detail
    return body


def _finding(finding: Finding) -> dict[str, Any]:
    body: dict[str, Any] = {
        "check_id": finding.check_id,
        "category": finding.category.value if finding.category else None,
        "severity": finding.severity.value,
        "title": finding.title,
        "summary": finding.summary,
        "remediation": finding.remediation,
        "evidence": finding.evidence or {},
    }
    if finding.location:
        body["location"] = finding.location
    return body


def _rule(check: CheckResult, finding: Finding) -> dict[str, Any]:
    return {
        "id": finding.check_id,
        "name": check.title,
        "shortDescription": {"text": check.title},
        "defaultConfiguration": {"level": _level(finding.severity)},
    }


def _sarif_result(finding: Finding) -> dict[str, Any]:
    text = finding.summary
    markdown = f"{finding.summary}\n\n{finding.remediation}"
    result: dict[str, Any] = {
        "ruleId": finding.check_id,
        "level": _level(finding.severity),
        "message": {"text": text, "markdown": markdown},
        "properties": {
            "severity": finding.severity.value,
            "title": finding.title,
            "evidence": finding.evidence or {},
        },
    }
    if finding.location:
        result["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": finding.location}}}]
    return result


def _notice(text: str) -> dict[str, Any]:
    return {"message": {"text": text}, "level": "error"}


def _level(severity: Severity) -> str:
    if severity in {Severity.BLOCKER, Severity.HIGH}:
        return "error"
    if severity == Severity.MEDIUM:
        return "warning"
    return "note"
