from __future__ import annotations

import importlib
import math
import shutil
import sys
import time
from pathlib import Path
from typing import Any

import httpx
import psutil

from drs.config import RuntimeConfig
from drs.context import ScanContext
from drs.models import Category, Finding, Severity
from drs.sdk import Outcome, Skip


class HostRuntimeCheck:
    id = "host_runtime"
    title = "Host runtime"
    category = Category.RUNTIME

    async def run(self, ctx: ScanContext) -> Outcome:
        return assess_host(
            (sys.version_info.major, sys.version_info.minor, sys.version_info.micro),
            read_resources(),
            cuda_status(),
            in_container(),
            ctx.config.runtime,
        )


class LlmProbeCheck:
    id = "llm_probe"
    title = "LLM latency and rate limit"
    category = Category.RUNTIME

    async def run(self, ctx: ScanContext) -> Outcome:
        llm = ctx.config.llm
        if llm is None:
            raise Skip("no llm endpoint is configured")
        headers: dict[str, str] = {}
        api_key = ctx.env_value(llm.api_key_env)
        if api_key:
            headers["authorization"] = f"Bearer {api_key}"
        payload = {
            "model": llm.model,
            "messages": [{"role": "user", "content": "ping"}],
            "max_tokens": 4,
        }
        latencies: list[float] = []
        codes: list[str] = []
        remaining: list[int] = []
        retry_after: str | None = None
        for _index in range(llm.requests):
            started = time.perf_counter()
            try:
                response = await ctx.http.post(
                    llm.url,
                    json=payload,
                    headers=headers,
                    timeout=llm.timeout_seconds,
                )
            except httpx.HTTPError as exc:
                codes.append(type(exc).__name__)
                continue
            latencies.append((time.perf_counter() - started) * 1000)
            codes.append(str(response.status_code))
            header = response.headers.get("x-ratelimit-remaining-requests")
            if header and header.isdigit():
                remaining.append(int(header))
            if response.status_code == 429 and response.headers.get("retry-after"):
                retry_after = response.headers.get("retry-after")

        ok = sum(1 for code in codes if code.startswith("2"))
        findings: list[Finding] = []
        auth_failed = any(code in {"401", "403"} for code in codes)
        if auth_failed:
            findings.append(
                Finding(
                    severity=Severity.BLOCKER,
                    title="LLM endpoint rejected the credential",
                    summary=f"{llm.url} returned an auth error on a probe.",
                    remediation="Use the key this environment will run with. The value was not recorded.",
                    location=llm.url,
                )
            )
        elif ok == 0:
            findings.append(
                Finding(
                    severity=Severity.BLOCKER,
                    title="LLM endpoint did not answer",
                    summary=f"0/{llm.requests} probes to {llm.url} succeeded ({', '.join(codes)}).",
                    remediation=(
                        "Confirm the URL, the key, and that egress from this host is allowed. "
                        "No credential was recorded."
                    ),
                    location=llm.url,
                )
            )
        elif "429" in codes:
            extra = f" Retry-After was {retry_after}." if retry_after else ""
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    title="LLM endpoint returned 429",
                    summary=f"{codes.count('429')} of {llm.requests} probes were rate limited.{extra}",
                    remediation="Lower the deploy's concurrency or ask for a higher limit before go-live.",
                    location=llm.url,
                    evidence={"retry_after": retry_after} if retry_after else {},
                )
            )
        elif ok < llm.requests:
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    title="LLM probes were not all successful",
                    summary=f"{ok}/{llm.requests} probes returned a 2xx.",
                    remediation=(
                        "Look at the status mix in the stats and fix the endpoint before gating the deploy on it."
                    ),
                    location=llm.url,
                )
            )
        stats: dict[str, Any] = {"requests": llm.requests, "ok": ok, "statuses": codes}
        if latencies:
            stats["p50_ms"] = round(percentile(latencies, 50), 1)
            stats["p95_ms"] = round(percentile(latencies, 95), 1)
        if remaining:
            stats["rate_limit_remaining_min"] = min(remaining)
        if latencies:
            summary = f"{ok}/{llm.requests} ok, p50 {stats['p50_ms']} ms, p95 {stats['p95_ms']} ms"
        else:
            summary = f"{ok}/{llm.requests} ok"
        if remaining:
            summary += f", remaining {min(remaining)}"
        return Outcome(summary, findings, stats)


def assess_host(
    version: tuple[int, int, int],
    resources: dict[str, int],
    cuda: dict[str, Any],
    container: bool,
    runtime: RuntimeConfig,
) -> Outcome:
    findings: list[Finding] = []
    try:
        want = _parse_version(runtime.min_python)
    except ValueError:
        want = None
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                title="min_python is not a version",
                summary=f"runtime.min_python is {runtime.min_python!r}.",
                remediation='Set runtime.min_python to a string like "3.11".',
            )
        )
    if want is not None and version[:2] < want:
        findings.append(
            Finding(
                severity=Severity.HIGH,
                title="Python is older than the runtime requires",
                summary=f"This host has Python {version[0]}.{version[1]} and the config asks for {runtime.min_python}.",
                remediation="Install the required interpreter on the host that will run the service.",
            )
        )
    available = resources.get("available_mb", 0)
    if available < runtime.min_memory_mb:
        findings.append(
            Finding(
                severity=Severity.HIGH,
                title="Not enough free memory",
                summary=(f"Only {available} MB is available; the config asks for {runtime.min_memory_mb} MB."),
                remediation=(
                    "Free memory or pick a larger node before loading the model. "
                    "This is what the OS reported as available."
                ),
            )
        )
    cuda_ok = bool(cuda.get("nvidia_smi")) or cuda.get("torch") == "available"
    if runtime.require_cuda and not cuda_ok:
        findings.append(
            Finding(
                severity=Severity.BLOCKER,
                title="CUDA is required and was not found",
                summary="nvidia-smi is missing and torch does not report a CUDA device.",
                remediation=(
                    "Install the driver so nvidia-smi works, or set runtime.require_cuda to false "
                    "if this service is CPU-only."
                ),
            )
        )
    summary = f"Python {version[0]}.{version[1]}.{version[2]}, {resources.get('cpu', 0)} CPUs, {available} MB available"
    summary += ", in a container" if container else ", not in a container"
    summary += ", CUDA present" if runtime.require_cuda and cuda_ok else ""
    if runtime.require_cuda and not cuda_ok:
        summary += ", CUDA missing"
    elif not runtime.require_cuda:
        summary += ", CUDA not required"
    return Outcome(summary, findings, {"cuda": cuda, "container": container, **resources})


def read_resources() -> dict[str, int]:
    memory = psutil.virtual_memory()
    return {
        "cpu": int(psutil.cpu_count() or 0),
        "available_mb": int(memory.available / (1024 * 1024)),
        "total_mb": int(memory.total / (1024 * 1024)),
    }


def cuda_status() -> dict[str, Any]:
    torch_state = "not-installed"
    try:
        torch = importlib.import_module("torch")
    except ImportError:
        torch_state = "not-installed"
    else:
        cuda = getattr(torch, "cuda", None)
        available = getattr(cuda, "is_available", None)
        torch_state = "installed-without-cuda"
        if callable(available) and bool(available()):
            torch_state = "available"
    return {"nvidia_smi": shutil.which("nvidia-smi") is not None, "torch": torch_state}


def in_container(root: Path = Path("/")) -> bool:
    if (root / ".dockerenv").exists() or (root / "run/.containerenv").exists():
        return True
    cgroup = root / "proc/1/cgroup"
    if not cgroup.is_file():
        return False
    try:
        text = cgroup.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return any(marker in text for marker in ("docker", "kubepods", "containerd", "libpod"))


def percentile(values: list[float], pct: float) -> float:
    """Nearest-rank percentile. pct is between 0 and 100."""
    if not values:
        raise ValueError("no values")
    ordered = sorted(values)
    rank = math.ceil(pct / 100 * len(ordered))
    index = min(len(ordered), max(1, rank)) - 1
    return ordered[index]


def _parse_version(value: str) -> tuple[int, int]:
    parts = value.split(".")
    if len(parts) < 2 or not parts[0].isdigit() or not parts[1].isdigit():
        raise ValueError(value)
    return int(parts[0]), int(parts[1])
