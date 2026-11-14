import asyncio
from pathlib import Path

from tests.helpers import write_config

from drs.engine import run_scan
from drs.models import Category, CheckStatus, Finding, Severity
from drs.sdk import Outcome, Skip


class _Check:
    def __init__(self, check_id: str, category: Category = Category.RUNTIME) -> None:
        self.id = check_id
        self.title = check_id
        self.category = category


class _Ok(_Check):
    async def run(self, ctx: object) -> Outcome:
        return Outcome("done")


class _Slow(_Check):
    async def run(self, ctx: object) -> Outcome:
        await asyncio.sleep(2)
        return Outcome("too late")


class _Boom(_Check):
    async def run(self, ctx: object) -> Outcome:
        raise RuntimeError("boom " + ctx.env["LLM_API_KEY"])  # type: ignore[attr-defined]


class _Quiet(_Check):
    async def run(self, ctx: object) -> Outcome:
        raise Skip("nothing to do")


class _Leaky(_Check):
    async def run(self, ctx: object) -> Outcome:
        secret = ctx.env["LLM_API_KEY"]  # type: ignore[attr-defined]
        return Outcome(
            f"saw {secret}",
            findings=[
                Finding(Severity.LOW, "leak", f"value {secret}", "stop printing it"),
            ],
        )


class _Overlap(_Check):
    def __init__(self, check_id: str, state: dict[str, object]) -> None:
        super().__init__(check_id)
        self.state = state

    async def run(self, ctx: object) -> Outcome:
        lock: asyncio.Lock = self.state["lock"]  # type: ignore[assignment]
        async with lock:
            current = int(self.state["current"]) + 1
            self.state["current"] = current
            self.state["max"] = max(int(self.state["max"]), current)
        await asyncio.sleep(0.05)
        async with lock:
            self.state["current"] = int(self.state["current"]) - 1
        return Outcome("ok")


def test_timeout_keeps_the_sibling(tmp_path: Path) -> None:
    config = write_config(
        tmp_path,
        """
        name: acme
        environment: dev
        concurrency: 2
        timeouts:
          default_seconds: 5
          scan_seconds: null
          per_check:
            slow: 0.2
        """,
    )
    report = asyncio.run(run_scan(config, [_Slow("slow"), _Ok("fast")], env={}, trust_env=False))
    by_id = {result.check_id: result for result in report.checks}
    assert by_id["slow"].status == CheckStatus.TIMEOUT
    assert by_id["fast"].status == CheckStatus.OK
    assert report.partial is True


def test_error_is_scrubbed(tmp_path: Path) -> None:
    config = write_config(
        tmp_path,
        """
        name: acme
        environment: dev
        timeouts:
          scan_seconds: null
        """,
    )
    secret = "supersecretvalue"
    report = asyncio.run(
        run_scan(
            config,
            [_Boom("boom"), _Leaky("leaky")],
            env={"LLM_API_KEY": secret},
            trust_env=False,
        )
    )
    rendered = report.checks[0].detail or ""
    leaked = next(result for result in report.checks if result.check_id == "leaky")
    assert secret not in rendered
    assert secret not in leaked.summary
    assert secret not in leaked.findings[0].summary
    assert "[redacted]" in leaked.summary


def test_working_directory_is_not_a_secret() -> None:
    from drs.redact import collect_secrets, scrub_text

    secrets = collect_secrets({"PWD": "/workspace", "DB_PWD": "supersecretvalue", "OPENAI_ADMIN_KEY": "sk-admin-value"})
    assert "/workspace" not in secrets
    assert "supersecretvalue" in secrets
    assert "sk-admin-value" in secrets
    text = scrub_text("/workspace/demo/config/app.yaml supersecretvalue", secrets)
    assert text.startswith("/workspace/")
    assert "supersecretvalue" not in text


def test_skip_and_scan_budget(tmp_path: Path) -> None:
    config = write_config(
        tmp_path,
        """
        name: acme
        environment: dev
        timeouts:
          default_seconds: 5
          scan_seconds: 0.2
        """,
    )
    report = asyncio.run(run_scan(config, [_Slow("one"), _Slow("two"), _Quiet("three")], env={}, trust_env=False))
    statuses = {result.check_id: result.status for result in report.checks}
    assert statuses["one"] == CheckStatus.TIMEOUT
    assert statuses["two"] == CheckStatus.TIMEOUT
    assert report.partial is True
    assert report.exit_code == 3


def test_concurrency_limit(tmp_path: Path) -> None:
    async def limited(value: int) -> int:
        state: dict[str, object] = {"current": 0, "max": 0, "lock": asyncio.Lock()}
        config = write_config(
            tmp_path,
            f"""
            name: acme
            environment: dev
            concurrency: {value}
            timeouts:
              default_seconds: 5
              scan_seconds: null
            """,
        )
        checks = [_Overlap("a", state), _Overlap("b", state)]
        await run_scan(config, checks, env={}, trust_env=False)
        return int(state["max"])

    assert asyncio.run(limited(1)) == 1
    assert asyncio.run(limited(2)) == 2
