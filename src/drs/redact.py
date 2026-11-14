from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import replace
from typing import Any

from drs.models import CheckResult, Finding

SECRET_NAME = re.compile(
    r"(api[_-]?key|secret|token|password|passwd|credential|private[_-]?key|(?:^|_)(?:key|pwd)$)",
    re.IGNORECASE,
)
URL_PASSWORD = re.compile(r"[a-z][a-z0-9+.-]*://([^/\s:@]*):([^@\s/]+)@", re.IGNORECASE)


def collect_secrets(env: Mapping[str, str]) -> list[str]:
    found: list[str] = []
    for key, value in env.items():
        if not value or key.upper() in {"PWD", "OLDPWD"}:
            continue
        if len(value) >= 8 and (SECRET_NAME.search(key) or "://" in value):
            found.append(value)
        for match in URL_PASSWORD.finditer(value):
            password = match.group(2)
            if len(password) >= 4:
                found.append(password)
    return sorted(set(found), key=len, reverse=True)


def redact_url(url: str) -> str:
    return URL_PASSWORD.sub(lambda match: match.group(0).replace(match.group(2), "[redacted]"), url)


def scrub_text(text: str, secrets: Sequence[str]) -> str:
    for secret in secrets:
        if secret:
            text = text.replace(secret, "[redacted]")
    return redact_url(text)


def scrub_obj(value: Any, secrets: Sequence[str]) -> Any:
    if isinstance(value, str):
        return scrub_text(value, secrets)
    if isinstance(value, dict):
        return {str(key): scrub_obj(item, secrets) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [scrub_obj(item, secrets) for item in value]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return scrub_text(str(value), secrets)


def scrub_result(result: CheckResult, secrets: Sequence[str]) -> CheckResult:
    return replace(
        result,
        summary=scrub_text(result.summary, secrets),
        detail=None if result.detail is None else scrub_text(result.detail, secrets),
        findings=[_scrub_finding(finding, secrets) for finding in result.findings],
        stats=scrub_obj(result.stats, secrets),
    )


def _scrub_finding(finding: Finding, secrets: Sequence[str]) -> Finding:
    location = finding.location
    return replace(
        finding,
        title=scrub_text(finding.title, secrets),
        summary=scrub_text(finding.summary, secrets),
        remediation=scrub_text(finding.remediation, secrets),
        evidence=scrub_obj(finding.evidence or {}, secrets),
        location=None if location is None else scrub_text(location, secrets),
    )
