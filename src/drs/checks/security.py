from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlsplit

from drs.config import Config, ListenerConfig
from drs.context import ScanContext
from drs.hosts import region_families
from drs.listeners import Listener, local_listeners
from drs.models import Category, Finding, Severity
from drs.sdk import Outcome, Skip
from drs.secrets import FileSecrets, iter_scan_files, scan_file

_PROD = re.compile(r"(^|[-_])prod(uction)?($|[-_])", re.IGNORECASE)
_PUBLIC = {"0.0.0.0", "::"}
_TRUE = {"1", "true", "yes", "on"}


class EnvSecretsCheck:
    id = "env_secrets"
    title = "Secrets on disk"
    category = Category.SECURITY

    async def run(self, ctx: ScanContext) -> Outcome:
        security = ctx.config.security
        if not security.env_files and not security.scan_paths:
            raise Skip("no files are configured for the secret scan")
        findings: list[Finding] = []
        scanned = 0
        flagged = 0
        seen: set[Path] = set()
        for relative in security.env_files:
            path = ctx.config.resolve(relative)
            seen.add(path)
            if not path.is_file():
                findings.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        title=f"{relative} is missing",
                        summary=f"The configured env file {path} does not exist.",
                        remediation=(
                            "Create it with mode 0600, or remove it from security.env_files "
                            "if the secret comes from somewhere else."
                        ),
                        location=str(path),
                    )
                )
                continue
            scanned += 1
            hit = scan_file(path)
            if hit is None:
                continue
            flagged += 1
            findings.append(_env_finding(hit))
        truncated = False
        for relative in security.scan_paths:
            root = ctx.config.resolve(relative)
            if not root.exists():
                findings.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        title=f"{relative} is missing",
                        summary=f"The secret scan path {root} does not exist.",
                        remediation=(
                            "Point security.scan_paths at the config directory that will ship with the service."
                        ),
                        location=str(root),
                    )
                )
                continue
            paths, cut = iter_scan_files(root)
            truncated = truncated or cut
            for path in paths:
                if path.resolve() in seen:
                    continue
                scanned += 1
                hit = scan_file(path)
                if hit is None:
                    continue
                if not (hit.real_keys or hit.url_password_keys or hit.private_key or hit.placeholder_keys):
                    continue
                flagged += 1
                findings.append(_file_finding(hit))
        file_label = "file" if scanned == 1 else "files"
        summary = f"scanned {scanned} {file_label}, {flagged} with secret-like assignments"
        if truncated:
            summary += "; file list truncated"
        return Outcome(summary, findings, {"scanned": scanned, "flagged": flagged})


class ListenersCheck:
    id = "listeners"
    title = "Listening ports"
    category = Category.SECURITY

    async def run(self, ctx: ScanContext) -> Outcome:
        expected = ctx.config.security.listeners
        if not expected:
            raise Skip("no listeners are configured")
        found = local_listeners()
        if found is None:
            return Outcome(
                "listener inspection is not available on this OS",
                [
                    Finding(
                        severity=Severity.LOW,
                        title="Could not read local listeners",
                        summary="This OS did not expose /proc/net/tcp.",
                        remediation="Run the scan on the Linux host that will serve these ports.",
                    )
                ],
            )
        return assess_listeners(expected, found)


class ResidencyCheck:
    id = "residency"
    title = "Data residency"
    category = Category.SECURITY

    async def run(self, ctx: ScanContext) -> Outcome:
        residency = ctx.config.residency
        if residency is None:
            raise Skip("residency is not configured")
        allowed = {item.lower() for item in residency.allowed}
        unknown: list[str] = []
        mismatch: list[str] = []
        ok = 0
        for name, url in _urls(ctx.config):
            host = urlsplit(url).hostname
            if not host:
                continue
            families = region_families(host)
            if not families:
                unknown.append(f"{name} ({host})")
            elif not families <= allowed:
                shown = ", ".join(sorted(families))
                mismatch.append(f"{name} ({host}) looks like {shown}")
            else:
                ok += 1
        findings: list[Finding] = []
        if mismatch:
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    title="Endpoint region is outside the residency policy",
                    summary="; ".join(mismatch) + f". Allowed: {', '.join(residency.allowed)}.",
                    remediation=(
                        "Move the service to an allowed region, or change residency.allowed if the contract covers it."
                    ),
                )
            )
        if unknown:
            findings.append(
                Finding(
                    severity=Severity.LOW,
                    title="Endpoint region is not in the URL",
                    summary="These hosts do not name a region: " + "; ".join(unknown) + ".",
                    remediation=(
                        f"Confirm the vendor region against the declared region ({residency.region}) before go-live."
                    ),
                )
            )
        summary = f"{ok} endpoint(s) match the residency policy"
        if mismatch or unknown:
            summary += f"; {len(mismatch)} outside, {len(unknown)} undeclared"
        return Outcome(summary, findings, {"allowed": list(residency.allowed)})


class PromptLoggingCheck:
    id = "prompt_logging"
    title = "Prompt logging"
    category = Category.SECURITY

    async def run(self, ctx: ScanContext) -> Outcome:
        declared = ctx.config.security.prompt_logging
        env_on = (ctx.env.get("LOG_PROMPTS") or "").strip().lower() in _TRUE
        if declared is None and not env_on:
            raise Skip("prompt logging posture is not configured")
        findings: list[Finding] = []
        if declared is not None and not declared.stores_prompts and env_on:
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    title="LOG_PROMPTS disagrees with the config",
                    summary="security.prompt_logging.stores_prompts is false, but LOG_PROMPTS is set.",
                    remediation="Unset LOG_PROMPTS, or change the config to the posture you are actually running.",
                )
            )
        stores = env_on if declared is None else declared.stores_prompts
        destination = None if declared is None else declared.destination
        if stores:
            prod = _PROD.search(ctx.config.environment) is not None
            where = f" Destination: {destination}." if destination else ""
            findings.append(
                Finding(
                    severity=Severity.HIGH if prod else Severity.MEDIUM,
                    title="Prompts are configured to be stored",
                    summary=f"This environment ({ctx.config.environment}) stores prompts.{where}",
                    remediation=(
                        "Stop storing prompts, or redact them and keep them in the residency region "
                        "with a retention limit. stdout in a shared cluster ends up in the log pipeline."
                    ),
                )
            )
            summary = "prompts are stored"
        else:
            summary = "prompts are not stored"
        return Outcome(summary, findings, {"stores_prompts": stores, "log_prompts_env": env_on})


def assess_listeners(
    expected: tuple[ListenerConfig, ...] | list[ListenerConfig],
    open_ports: list[Listener],
) -> Outcome:
    by_port: dict[int, list[Listener]] = {}
    for item in open_ports:
        by_port.setdefault(item.port, []).append(item)
    missing: list[str] = []
    exposed: list[str] = []
    local: list[str] = []
    for wanted in expected:
        binds = by_port.get(wanted.port, [])
        label = f"{wanted.name} ({wanted.port})"
        if not binds:
            missing.append(label)
            continue
        public = any(bind.host in _PUBLIC for bind in binds)
        if public and not wanted.public_ok:
            exposed.append(label)
        else:
            local.append(label)
    findings: list[Finding] = []
    if exposed:
        findings.append(
            Finding(
                severity=Severity.HIGH,
                title="Listeners are bound to every interface",
                summary="These ports are reachable beyond loopback: " + ", ".join(exposed) + ".",
                remediation=(
                    "Bind them to 127.0.0.1 or a private address, or set public_ok if that exposure is intentional."
                ),
            )
        )
    if missing:
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                title="Expected listener is not up",
                summary="Nothing is listening on " + ", ".join(missing) + ".",
                remediation=(
                    "Start the dependency, or remove it from security.listeners if this scan runs before it starts."
                ),
            )
        )
    parts = []
    if local:
        parts.append("loopback or allowed: " + ", ".join(local))
    if exposed:
        parts.append("public: " + ", ".join(exposed))
    if missing:
        parts.append("down: " + ", ".join(missing))
    summary = "; ".join(parts) if parts else "no listeners matched"
    return Outcome(summary, findings, {"open": len(open_ports)})


def _env_finding(hit: FileSecrets) -> Finding:
    keys = _key_list(hit)
    mode = oct(hit.mode)
    loose = bool(hit.mode & 0o077)
    if hit.private_key:
        severity = Severity.BLOCKER
        title = "Private key material is in an env file"
    elif loose and (hit.real_keys or hit.url_password_keys):
        severity = Severity.HIGH
        title = "Env file is readable beyond its owner"
    elif hit.real_keys or hit.url_password_keys:
        severity = Severity.LOW
        title = "Env file holds secrets"
    else:
        severity = Severity.LOW
        title = "Env file still has a placeholder"
    summary = f"{hit.path} (mode {mode}) references {keys}."
    if loose:
        summary += " Group or others can read it."
    remediation = (
        "chmod 600 the file, keep it out of the image and out of git, and rotate anything that was world-readable."
    )
    return Finding(
        severity=severity,
        title=title,
        summary=summary,
        remediation=remediation,
        location=hit.path,
        evidence={"keys": keys, "mode": mode},
    )


def _file_finding(hit: FileSecrets) -> Finding:
    keys = _key_list(hit)
    if hit.private_key or hit.real_keys or hit.url_password_keys:
        return Finding(
            severity=Severity.BLOCKER,
            title="Secret-like value outside an env file",
            summary=f"{hit.path} assigns {keys}.",
            remediation="Remove the value from the file and rotate it. Load it from the environment or a secret store.",
            location=hit.path,
            evidence={"keys": keys},
        )
    return Finding(
        severity=Severity.LOW,
        title="Placeholder secret in a non-env file",
        summary=f"{hit.path} assigns {keys}, and the value looks like a placeholder.",
        remediation="Replace the placeholder before shipping the file, or delete the key.",
        location=hit.path,
        evidence={"keys": keys},
    )


def _key_list(hit: FileSecrets) -> str:
    names = list(hit.real_keys) + list(hit.url_password_keys) + list(hit.placeholder_keys)
    if hit.private_key:
        names.append("private key")
    unique = list(dict.fromkeys(names))
    return ", ".join(unique) if unique else "secret material"


def _urls(config: Config) -> list[tuple[str, str]]:
    targets = [(endpoint.name, endpoint.url) for endpoint in config.endpoints]
    if config.llm is not None:
        targets.append(("llm", config.llm.url))
    return targets
