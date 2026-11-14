from pathlib import Path

from tests.helpers import run_check, write_config

from drs.checks.runtime import HostRuntimeCheck, assess_host, cuda_status, in_container, read_resources
from drs.checks.security import EnvSecretsCheck, ListenersCheck, PromptLoggingCheck, ResidencyCheck
from drs.config import RuntimeConfig
from drs.models import Severity


def test_runtime_decisions(tmp_path: Path) -> None:
    poor = assess_host(
        (3, 10, 0),
        {"cpu": 2, "available_mb": 128, "total_mb": 256},
        {"nvidia_smi": False, "torch": "not-installed"},
        False,
        RuntimeConfig(min_python="3.11", require_cuda=True, min_memory_mb=512),
    )
    titles = {finding.title for finding in poor.findings or []}
    assert "Python is older than the runtime requires" in titles
    assert "Not enough free memory" in titles
    assert "CUDA is required and was not found" in titles
    fine = assess_host(
        (3, 12, 0),
        {"cpu": 4, "available_mb": 2048, "total_mb": 4096},
        {"nvidia_smi": False, "torch": "not-installed"},
        False,
        RuntimeConfig(),
    )
    assert not fine.findings
    resources = read_resources()
    assert resources["cpu"] >= 1
    assert "torch" in cuda_status()
    (tmp_path / ".dockerenv").write_text("", encoding="utf-8")
    assert in_container(tmp_path)
    assert not in_container(tmp_path / "missing")
    live = run_check(
        HostRuntimeCheck(),
        write_config(
            tmp_path,
            """
            name: acme
            environment: dev
            runtime:
              min_python: "3.11"
              require_cuda: false
              min_memory_mb: 1
            """,
        ),
    )
    assert "Python" in live.summary


def test_residency_and_prompt_logging(tmp_path: Path) -> None:
    config = write_config(
        tmp_path,
        """
        name: acme
        environment: prod
        residency:
          region: us
          allowed: [us]
        endpoints:
          - name: db
            url: https://db.eu-west-1.amazonaws.com/health
          - name: local
            url: http://127.0.0.1:9/health
        security:
          prompt_logging:
            stores_prompts: false
            destination: stdout
        """,
    )
    residency = run_check(ResidencyCheck(), config)
    assert any(finding.severity == Severity.HIGH for finding in residency.findings or [])
    prompts = run_check(PromptLoggingCheck(), config, {"LOG_PROMPTS": "true"})
    assert any("disagrees" in finding.title for finding in prompts.findings or [])
    stored = write_config(
        tmp_path,
        """
        name: acme
        environment: staging
        security:
          prompt_logging:
            stores_prompts: true
            destination: stdout
        """,
    )
    outcome = run_check(PromptLoggingCheck(), stored)
    assert outcome.findings
    assert outcome.findings[0].severity == Severity.MEDIUM


def test_env_secret_check_flags_loose_files_and_checked_in_keys(tmp_path: Path) -> None:
    env_file = tmp_path / "customer.env"
    env_file.write_text("API_KEY=sk-test-value-123456\n", encoding="utf-8")
    env_file.chmod(0o644)
    nest = tmp_path / "config"
    nest.mkdir()
    (nest / "app.yaml").write_text("api_key: sk-live-oops-checked-in\n", encoding="utf-8")
    config = write_config(
        tmp_path,
        """
        name: acme
        environment: dev
        security:
          env_files: [customer.env]
          scan_paths: [config]
        """,
    )
    outcome = run_check(EnvSecretsCheck(), config)
    blob = str(outcome.findings)
    assert "sk-test-value-123456" not in blob
    assert "sk-live-oops-checked-in" not in blob
    assert any(finding.severity == Severity.BLOCKER for finding in outcome.findings or [])
    assert any(finding.severity == Severity.HIGH for finding in outcome.findings or [])


def test_listener_check_on_this_host(tmp_path: Path) -> None:
    config = write_config(
        tmp_path,
        """
        name: acme
        environment: dev
        security:
          listeners:
            - name: closed
              port: 1
              public_ok: false
        """,
    )
    outcome = run_check(ListenersCheck(), config)
    assert outcome.findings
    assert "closed" in outcome.summary or "listener" in outcome.summary
