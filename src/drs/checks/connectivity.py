from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import time
from datetime import UTC, datetime
from urllib.parse import urlsplit

import httpx
from sqlalchemy.engine.url import make_url
from sqlalchemy.exc import ArgumentError

from drs.config import Config, Endpoint
from drs.context import ScanContext
from drs.hosts import host_in_no_proxy, is_internal_host
from drs.models import Category, Finding, Severity
from drs.sdk import Outcome, Skip
from drs.tlsinfo import assess_certificate, fetch_certificate

_PLACEHOLDERS = {
    "changeme",
    "change-me",
    "password",
    "secret",
    "todo",
    "xxx",
    "your-api-key",
    "your_api_key",
    "replace-me",
    "placeholder",
    "sk-xxx",
    "none",
    "null",
    "undefined",
}
_ADMIN = re.compile(r"(admin|root|master|superuser)", re.IGNORECASE)
_SUPERUSERS = {"postgres", "root", "admin", "sa", "superuser"}
_LOCAL = {"localhost", "127.0.0.1", "::1"}


class CredentialsCheck:
    id = "credentials"
    title = "Credential presence"
    category = Category.CONNECTIVITY

    async def run(self, ctx: ScanContext) -> Outcome:
        required = ctx.config.required_env
        optional = ctx.config.optional_env
        if not required and not optional:
            raise Skip("no credentials are configured")
        findings: list[Finding] = []
        present: dict[str, str] = {}
        missing: list[str] = []
        for name in required:
            value = ctx.env_value(name)
            if value is None:
                missing.append(name)
                findings.append(
                    Finding(
                        severity=Severity.BLOCKER,
                        title=f"{name} is not set",
                        summary=f"The required variable {name} is missing or empty.",
                        remediation=(
                            f"Export {name} in the environment that will run the deploy. "
                            "The scanner reads the process environment, not a secret manager."
                        ),
                    )
                )
                continue
            present[name] = _bucket(len(value))
            if _placeholder(value):
                findings.append(_placeholder_finding(name, required=True))
            findings.extend(_privilege_findings(name, value))
        for name in optional:
            value = ctx.env_value(name)
            if value is None:
                continue
            present[name] = _bucket(len(value))
            if _placeholder(value):
                findings.append(_placeholder_finding(name, required=False))
            findings.extend(_privilege_findings(name, value))
        if missing:
            label = "variable" if len(missing) == 1 else "variables"
            summary = f"{len(missing)} required {label} missing"
        else:
            label = "variable" if len(required) == 1 else "variables"
            summary = f"{len(required)} required {label} set"
        return Outcome(summary, findings, {"present": present, "missing": missing})


class EndpointReachCheck:
    id = "endpoint_reach"
    title = "Endpoint reachability"
    category = Category.CONNECTIVITY

    async def run(self, ctx: ScanContext) -> Outcome:
        endpoints = ctx.config.endpoints
        if not endpoints:
            raise Skip("no endpoints are configured")
        probed = await asyncio.gather(*(_probe(ctx, endpoint) for endpoint in endpoints))
        findings = [item for item in probed if isinstance(item, Finding)]
        ok = [item for item in probed if isinstance(item, dict)]
        summary = f"{len(ok)}/{len(endpoints)} endpoints responded as expected"
        return Outcome(summary, findings, {"endpoints": ok})


class DnsTlsCheck:
    id = "dns_tls"
    title = "DNS and TLS"
    category = Category.CONNECTIVITY

    async def run(self, ctx: ScanContext) -> Outcome:
        targets = _targets(ctx.config)
        if not targets:
            raise Skip("no URLs are configured")
        findings: list[Finding] = []
        http_targets = [(name, url) for name, url in targets if urlsplit(url).scheme == "http"]
        if http_targets:
            remote = [url for _name, url in http_targets if not _host_is_local(urlsplit(url).hostname or "")]
            shown = [f"{name} ({url})" for name, url in http_targets]
            findings.append(
                Finding(
                    severity=Severity.HIGH if remote else Severity.LOW,
                    title="Endpoint is not using TLS",
                    summary="Plain HTTP: " + "; ".join(shown) + ".",
                    remediation=(
                        "Terminate TLS before this URL leaves the laptop. Local HTTP is only reasonable for a demo."
                    ),
                )
            )
        hosts: dict[str, int] = {}
        schemes: dict[str, str] = {}
        for _name, url in targets:
            parts = urlsplit(url)
            if not parts.hostname:
                continue
            port = parts.port or (443 if parts.scheme == "https" else 80)
            hosts.setdefault(parts.hostname, port)
            schemes.setdefault(parts.hostname, parts.scheme)
        resolved: list[str] = []
        for host, port in hosts.items():
            try:
                addresses = await asyncio.to_thread(_resolve, host, port)
            except socket.gaierror:
                findings.append(
                    Finding(
                        severity=Severity.HIGH,
                        title=f"DNS lookup failed for {host}",
                        summary=f"{host} did not resolve from this environment.",
                        remediation="Fix the name, or the resolver and search domain this host uses.",
                    )
                )
                continue
            resolved.append(f"{host} -> {', '.join(addresses)}")
            if schemes.get(host) != "https":
                continue
            try:
                cert = await asyncio.to_thread(fetch_certificate, host, port, 5)
            except (OSError, TimeoutError) as exc:
                findings.append(
                    Finding(
                        severity=Severity.HIGH,
                        title=f"TLS handshake failed for {host}",
                        summary=f"{host}:{port} did not complete TLS ({type(exc).__name__}).",
                        remediation="Confirm the port speaks TLS and that a proxy is not rewriting the handshake.",
                    )
                )
                continue
            for issue in assess_certificate(host, cert, datetime.now(UTC), local=_host_is_local(host)):
                findings.append(
                    Finding(
                        severity=issue.severity,
                        title=issue.title,
                        summary=issue.summary,
                        remediation=issue.remediation,
                        location=f"{host}:{port}",
                    )
                )
        if not resolved:
            summary = "no hosts resolved"
        else:
            label = "host" if len(resolved) == 1 else "hosts"
            summary = f"resolved {len(resolved)} {label}"
        return Outcome(summary, findings, {"resolved": resolved})


class ProxyEgressCheck:
    id = "proxy_egress"
    title = "Proxy and egress"
    category = Category.CONNECTIVITY

    async def run(self, ctx: ScanContext) -> Outcome:
        proxy = ctx.config.proxy
        http_proxy = _env_any(ctx, proxy.http_proxy_env)
        https_proxy = _env_any(ctx, proxy.https_proxy_env)
        no_proxy = _env_any(ctx, proxy.no_proxy_env) or ""
        configured = bool(http_proxy or https_proxy)
        findings: list[Finding] = []
        if proxy.expect_proxy and not configured:
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    title="Expected proxy is not set",
                    summary=(
                        f"{proxy.http_proxy_env} and {proxy.https_proxy_env} are empty, "
                        "and the config says this environment egresses through a proxy."
                    ),
                    remediation=(
                        "Export the proxy URL the customer's network requires, and put internal hosts in NO_PROXY."
                    ),
                )
            )
        leaked: list[str] = []
        if configured:
            for name, url in _targets(ctx.config):
                host = urlsplit(url).hostname
                if host and is_internal_host(host) and not host_in_no_proxy(host, no_proxy):
                    leaked.append(f"{name} ({host})")
        if leaked:
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    title="Internal host would be sent through the proxy",
                    summary="These hosts are internal and are not covered by NO_PROXY: " + "; ".join(leaked) + ".",
                    remediation=(
                        "Add them to NO_PROXY. A corporate proxy often cannot reach localhost or RFC1918 addresses."
                    ),
                )
            )
        if configured:
            summary = "a proxy is set"
        elif proxy.expect_proxy:
            summary = "proxy expected but unset"
        else:
            summary = "no proxy is set"
        return Outcome(
            summary,
            findings,
            {"proxy_set": configured, "no_proxy": bool(no_proxy)},
        )


def _privilege_findings(name: str, value: str) -> list[Finding]:
    findings: list[Finding] = []
    if _ADMIN.search(name):
        findings.append(
            Finding(
                severity=Severity.LOW,
                title=f"{name} looks like a broad credential",
                summary=f"The variable name {name} suggests an admin or root credential.",
                remediation=(
                    "Use a key scoped to the model and project this deploy needs, "
                    "and keep the admin key out of the app environment."
                ),
            )
        )
    user = _url_user(value)
    if user and user.lower() in _SUPERUSERS:
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                title=f"{name} uses a superuser",
                summary=f"{name} logs in as {user}.",
                remediation=(
                    "Create a role with SELECT on the profiled tables and put that user in the URL. "
                    "The app should not share a superuser."
                ),
            )
        )
    return findings


def _placeholder_finding(name: str, *, required: bool) -> Finding:
    severity = Severity.BLOCKER if required else Severity.MEDIUM
    return Finding(
        severity=severity,
        title=f"{name} is still a placeholder",
        summary=f"The value of {name} matches a placeholder such as changeme or your-api-key.",
        remediation=(
            f"Replace {name} with the credential this environment will actually use. The value was not recorded."
        ),
    )


def _placeholder(value: str) -> bool:
    folded = value.strip().strip("'\"").lower()
    if folded in _PLACEHOLDERS:
        return True
    return folded.startswith(("your-", "your_", "<", "todo", "changeme")) or "placeholder" in folded


def _bucket(length: int) -> str:
    if length < 8:
        return "under 8"
    if length < 16:
        return "8-15"
    if length < 32:
        return "16-31"
    if length < 64:
        return "32-63"
    return "64 or more"


def _url_user(value: str) -> str | None:
    if "://" not in value:
        return None
    try:
        return make_url(value).username
    except ArgumentError:
        return None


async def _probe(ctx: ScanContext, endpoint: Endpoint) -> Finding | dict[str, object]:
    headers = _auth_header(ctx, endpoint.api_key_env)
    started = time.perf_counter()
    try:
        response = await ctx.http.request(
            endpoint.method,
            endpoint.url,
            headers=headers,
            timeout=5,
        )
    except httpx.HTTPError as exc:
        return Finding(
            severity=Severity.HIGH,
            title=f"{endpoint.name} is unreachable",
            summary=f"{endpoint.url} failed ({type(exc).__name__}).",
            remediation="Confirm the host, port, and that this environment is allowed to egress there.",
            location=endpoint.url,
        )
    elapsed = round((time.perf_counter() - started) * 1000, 1)
    if response.status_code in {401, 403}:
        return Finding(
            severity=Severity.HIGH,
            title=f"{endpoint.name} rejected the credential",
            summary=f"{endpoint.url} returned {response.status_code}.",
            remediation="Check the API key in this environment. The value was not recorded.",
            location=endpoint.url,
            evidence={"status": response.status_code},
        )
    if response.status_code != endpoint.expect_status:
        severity = Severity.HIGH if response.status_code >= 500 else Severity.MEDIUM
        return Finding(
            severity=severity,
            title=f"{endpoint.name} returned {response.status_code}",
            summary=f"Expected {endpoint.expect_status} from {endpoint.url}.",
            remediation="Point the check at the health URL the process serves, or fix the service.",
            location=endpoint.url,
            evidence={"status": response.status_code, "elapsed_ms": elapsed},
        )
    return {"name": endpoint.name, "status": response.status_code, "elapsed_ms": elapsed}


def _auth_header(ctx: ScanContext, name: str | None) -> dict[str, str]:
    value = ctx.env_value(name)
    if not value:
        return {}
    return {"authorization": f"Bearer {value}"}


def _targets(config: Config) -> list[tuple[str, str]]:
    targets = [(endpoint.name, endpoint.url) for endpoint in config.endpoints]
    if config.llm is not None:
        targets.append(("llm", config.llm.url))
    return targets


def _resolve(host: str, port: int) -> list[str]:
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return sorted({str(item[4][0]) for item in infos})


def _host_is_local(host: str) -> bool:
    if host in _LOCAL:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _env_any(ctx: ScanContext, name: str) -> str | None:
    for candidate in (name, name.lower(), name.upper()):
        value = ctx.env_value(candidate)
        if value:
            return value
    return None
