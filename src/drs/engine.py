from __future__ import annotations

import asyncio
import os
import time
from collections.abc import Mapping, Sequence
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any

import httpx

from drs import __version__
from drs.config import Config
from drs.context import ScanContext
from drs.models import CheckResult, CheckStatus, Finding, Report
from drs.redact import collect_secrets, scrub_result
from drs.scoring import build_report
from drs.sdk import Check, Skip


async def run_scan(
    config: Config,
    checks: Sequence[Check],
    *,
    env: Mapping[str, str] | None = None,
    trust_env: bool = True,
) -> Report:
    started = datetime.now(UTC)
    snapshot = dict(os.environ if env is None else env)
    secrets = collect_secrets(snapshot)
    timeout = httpx.Timeout(10.0, connect=5.0)
    headers = {"user-agent": f"drs/{__version__}"}
    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=True,
        trust_env=trust_env,
        headers=headers,
    ) as http:
        ctx = ScanContext(config=config, env=snapshot, http=http)
        results = await _execute(config, checks, ctx)
    finished = datetime.now(UTC)
    scrubbed = [scrub_result(result, secrets) for result in results]
    return build_report(config, scrubbed, started, finished)


async def _execute(
    config: Config,
    checks: Sequence[Check],
    ctx: ScanContext,
) -> list[CheckResult]:
    semaphore = asyncio.Semaphore(max(1, config.concurrency))

    async def run_one(check: Check) -> CheckResult:
        limit = config.timeouts.limit_for(check.id)
        async with semaphore:
            started = time.perf_counter()
            try:
                outcome = await asyncio.wait_for(check.run(ctx), limit)
            except Skip as exc:
                return _finish(check, CheckStatus.SKIPPED, exc.reason, [], {}, started, None)
            except TimeoutError:
                summary = f"timed out after {limit:g}s"
                return _finish(check, CheckStatus.TIMEOUT, summary, [], {}, started, None)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                detail = f"{type(exc).__name__}: {exc}"
                return _finish(check, CheckStatus.ERROR, "check failed", [], {}, started, detail)
            findings = [
                replace(
                    finding,
                    check_id=check.id,
                    category=check.category,
                    evidence=finding.evidence or {},
                )
                for finding in (outcome.findings or [])
            ]
            return _finish(
                check,
                CheckStatus.OK,
                outcome.summary,
                findings,
                outcome.stats or {},
                started,
                None,
            )

    tasks = [asyncio.create_task(run_one(check), name=check.id) for check in checks]
    if not tasks:
        return []
    budget = config.timeouts.scan_seconds
    if budget is None:
        await asyncio.gather(*tasks)
    else:
        _done, pending = await asyncio.wait(tasks, timeout=budget)
        for task in pending:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    results: list[CheckResult] = []
    for check, task in zip(checks, tasks, strict=True):
        if task.cancelled():
            elapsed = int((budget or 0) * 1000)
            results.append(
                CheckResult(
                    check_id=check.id,
                    title=check.title,
                    category=check.category,
                    status=CheckStatus.TIMEOUT,
                    summary="cancelled when the scan budget ran out",
                    duration_ms=elapsed,
                )
            )
            continue
        results.append(task.result())
    return results


def _finish(
    check: Check,
    status: CheckStatus,
    summary: str,
    findings: list[Finding],
    stats: dict[str, Any],
    started: float,
    detail: str | None,
) -> CheckResult:
    return CheckResult(
        check_id=check.id,
        title=check.title,
        category=check.category,
        status=status,
        summary=summary,
        findings=findings,
        stats=stats,
        duration_ms=int((time.perf_counter() - started) * 1000),
        detail=detail,
    )
