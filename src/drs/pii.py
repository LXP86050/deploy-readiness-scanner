from __future__ import annotations

import re
from dataclasses import dataclass

EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PHONE = re.compile(r"(?<!\w)(?:\+?1[-.\s]?)?(?:\(\d{3}\)|\d{3})[-.\s]\d{3}[-.\s]\d{4}(?!\w)")
SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")


@dataclass(frozen=True)
class PiiHit:
    kind: str
    sample: str | None = None


def mask_email(value: str) -> str:
    local, sep, domain = value.partition("@")
    if not sep:
        return "***"
    head = local[:1]
    return f"{head}***@{domain}"


def scan_text(text: str) -> list[PiiHit]:
    hits: list[PiiHit] = []
    for match in EMAIL.finditer(text):
        hits.append(PiiHit("email", mask_email(match.group(0))))
    hits.extend(PiiHit("phone") for _ in PHONE.finditer(text))
    hits.extend(PiiHit("ssn") for _ in SSN.finditer(text))
    return hits
