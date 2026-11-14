from datetime import UTC, datetime
from pathlib import Path

from tests.helpers import write_config

from drs.models import Category, CheckResult, CheckStatus, Finding, Severity
from drs.scoring import DEDUCTIONS, build_report


def _result(
    category: Category,
    status: CheckStatus = CheckStatus.OK,
    findings: list[Finding] | None = None,
    check_id: str = "sample",
) -> CheckResult:
    stamped = []
    for finding in findings or []:
        finding.check_id = check_id
        finding.category = category
        stamped.append(finding)
    return CheckResult(
        check_id=check_id,
        title=check_id,
        category=category,
        status=status,
        summary="done",
        findings=stamped,
    )


def test_blocker_deduction_and_gate(tmp_path: Path) -> None:
    config = write_config(
        tmp_path,
        """
        name: acme
        environment: dev
        thresholds:
          min_category_score: 70
          fail_on: blocker
        """,
    )
    finding = Finding(Severity.BLOCKER, "nope", "missing", "set it")
    report = build_report(
        config,
        [_result(Category.SECURITY, findings=[finding])],
        datetime.now(UTC),
        datetime.now(UTC),
    )
    security = next(score for score in report.scores if score.category == Category.SECURITY)
    assert security.score == 100 - DEDUCTIONS[Severity.BLOCKER]
    assert report.exit_code == 2
    data = next(score for score in report.scores if score.category == Category.DATA)
    assert data.assessed is False
    assert data.score is None


def test_high_respects_fail_on(tmp_path: Path) -> None:
    body = """
    name: acme
    environment: dev
    thresholds:
      min_category_score: 50
      fail_on: {fail_on}
    """
    finding = Finding(Severity.HIGH, "pii", "emails", "mask them")
    started = datetime.now(UTC)
    loose = write_config(tmp_path, body.format(fail_on="blocker"))
    strict = write_config(tmp_path, body.format(fail_on="high"))
    results = [_result(Category.DATA, findings=[finding])]
    assert build_report(loose, results, started, started).exit_code == 0
    assert build_report(strict, results, started, started).exit_code == 2


def test_partial_when_the_gate_would_pass(tmp_path: Path) -> None:
    config = write_config(
        tmp_path,
        """
        name: acme
        environment: dev
        thresholds:
          min_category_score: 70
        """,
    )
    started = datetime.now(UTC)
    report = build_report(
        config,
        [_result(Category.RUNTIME, CheckStatus.TIMEOUT, check_id="host_runtime")],
        started,
        started,
    )
    assert report.partial is True
    assert report.exit_code == 3
    assert report.verdict.value == "partial"


def test_nothing_assessed(tmp_path: Path) -> None:
    config = write_config(tmp_path, "name: acme\nenvironment: dev\n")
    started = datetime.now(UTC)
    report = build_report(
        config,
        [_result(Category.DATA, CheckStatus.SKIPPED)],
        started,
        started,
    )
    assert report.exit_code == 1
    assert "no checks assessed" in report.reason
