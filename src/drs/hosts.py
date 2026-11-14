from __future__ import annotations

import ipaddress
import re

_REGION = re.compile(
    r"(us-east-1|us-east-2|us-west-1|us-west-2|eu-west-1|eu-central-1|eu-north-1|"
    r"ap-southeast-1|ap-northeast-1|eastus|westus|westeurope|northeurope)",
    re.IGNORECASE,
)
_FAMILY = {
    "us-east-1": "us",
    "us-east-2": "us",
    "us-west-1": "us",
    "us-west-2": "us",
    "eastus": "us",
    "westus": "us",
    "eu-west-1": "eu",
    "eu-central-1": "eu",
    "eu-north-1": "eu",
    "westeurope": "eu",
    "northeurope": "eu",
    "ap-southeast-1": "ap",
    "ap-northeast-1": "ap",
}


def host_in_no_proxy(host: str, no_proxy: str) -> bool:
    cleaned = host.lower().rstrip(".")
    for raw in no_proxy.split(","):
        token = raw.strip().lower().lstrip(".")
        if not token:
            continue
        if token == "*" or cleaned == token or cleaned.endswith("." + token):
            return True
    return False


def is_internal_host(host: str) -> bool:
    cleaned = host.lower().rstrip(".")
    if cleaned in {"localhost", "localhost.localdomain"} or cleaned.endswith((".local", ".internal")):
        return True
    try:
        address = ipaddress.ip_address(cleaned)
    except ValueError:
        return False
    return address.is_private or address.is_loopback or address.is_link_local


def region_families(host: str) -> set[str]:
    cleaned = host.lower().rstrip(".")
    if cleaned in {"localhost", "127.0.0.1", "::1"}:
        return {"local"}
    return {_FAMILY[match.group(1).lower()] for match in _REGION.finditer(cleaned)}
