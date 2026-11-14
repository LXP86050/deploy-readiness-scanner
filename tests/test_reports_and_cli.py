import asyncio
from io import StringIO
from pathlib import Path

import pytest
from rich.console import Console
from tests.helpers import write_config

from drs.cli import main
from drs.config import ConfigError
from drs.engine import run_scan
from drs.models import Category, Severity
from drs.registry import load_checks, select_checks
from drs.report.html import render_html
from drs.report.serialize import render_json, render_sarif
from drs.report.terminal import render_terminal
from drs.sdk import Finding, Outcome


class _Marked:
    id = "marked"
    title = "Marked"
    category = Category.SECURITY

    async def run(self, ctx: object) -> Outcome:
        return Outcome(
            "done",
            findings=[
                Finding(
                    Severity.BLOCKER,
                    "<img>",
                    "a & b",
                    "escape it",
                    location="config/app.yaml",
                )
            ],
        )


def test_reports_escape_and_map_severity(tmp_path: Path) -> None:
    config = write_config(tmp_path, 'name: "<script>"\nenvironment: dev\ntimeouts:\n  scan_seconds: null\n')
    report = asyncio.run(run_scan(config, [_Marked()], env={}, trust_env=False))
    html = render_html(report)
    assert "<script>" not in html
    assert "&lt;script&gt;" in html
    assert "&lt;img&gt;" in html
    assert "a &amp; b" in html
    document = render_json(report)
    assert '"exit_code": 2' in document
    sarif = render_sarif(report)
    assert '"level": "error"' in sarif
    assert "config/app.yaml" in sarif
    buffer = StringIO()
    render_terminal(report, Console(file=buffer, force_terminal=False, width=120))
    text = buffer.getvalue()
    assert "not ready" in text
    assert "marked" in text


def test_registry_ids() -> None:
    checks = load_checks()
    assert {check.id for check in checks} == {
        "credentials",
        "endpoint_reach",
        "dns_tls",
        "proxy_egress",
        "data_profile",
        "pii",
        "documents",
        "host_runtime",
        "llm_probe",
        "env_secrets",
        "listeners",
        "residency",
        "prompt_logging",
    }
    with pytest.raises(ConfigError, match="unknown check"):
        select_checks(checks, ["nope"], ())


def test_cli_gates_and_lists(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("DRS_TEST_TOKEN", raising=False)
    missing = tmp_path / "missing.yaml"
    assert main(["scan", "--config", str(missing)]) == 1
    assert "does not exist" in capsys.readouterr().err
    config = write_config(
        tmp_path,
        """
        name: acme
        environment: dev
        credentials:
          required_env: [DRS_TEST_TOKEN]
        thresholds:
          min_category_score: 70
          fail_on: blocker
        timeouts:
          scan_seconds: null
        checks:
          include: [credentials]
        """,
    )
    destination = tmp_path / "out" / "report.json"
    code = main(["scan", "--config", str(config.path), "--json", str(destination), "--only", "credentials"])
    assert code == 2
    body = destination.read_text(encoding="utf-8")
    assert "DRS_TEST_TOKEN" in body
    assert main(["list-checks"]) == 0
    assert "data_profile" in capsys.readouterr().out
    ready = write_config(
        tmp_path,
        """
        name: acme
        environment: dev
        runtime:
          min_python: "3.11"
          require_cuda: false
          min_memory_mb: 1
        thresholds:
          min_category_score: 0
        timeouts:
          scan_seconds: null
        checks:
          include: [host_runtime]
        """,
    )
    assert main(["scan", "--config", str(ready.path), "--only", "host_runtime"]) == 0


def test_version_flag() -> None:
    with pytest.raises(SystemExit) as caught:
        main(["--version"])
    assert caught.value.code == 0


def test_plugin_example(tmp_path: Path) -> None:
    import importlib.util

    from tests.helpers import ROOT, run_check

    spec = importlib.util.spec_from_file_location("budget_check", ROOT / "examples" / "budget_check.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    bare = write_config(tmp_path, "name: acme\nenvironment: dev\n")
    flagged = run_check(module.EmbeddingBudgetCheck(), bare)
    assert flagged.findings
    funded = write_config(
        tmp_path,
        """
        name: acme
        environment: dev
        embedding:
          budget_usd: 2.5
        """,
    )
    clean = run_check(module.EmbeddingBudgetCheck(), funded)
    assert not clean.findings
    assert "2.5" in clean.summary
