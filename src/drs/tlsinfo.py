from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from datetime import datetime

from cryptography import x509
from cryptography.x509.oid import NameOID

from drs.models import Severity


@dataclass(frozen=True)
class CertView:
    not_before: datetime
    not_after: datetime
    names: tuple[str, ...]
    trusted: bool
    trust_error: str | None


@dataclass(frozen=True)
class TlsIssue:
    severity: Severity
    title: str
    summary: str
    remediation: str


def host_matches(host: str, names: tuple[str, ...] | list[str]) -> bool:
    cleaned = host.lower().rstrip(".")
    for name in names:
        candidate = name.lower().rstrip(".")
        if candidate.startswith("*."):
            rest = candidate[2:]
            if cleaned.endswith("." + rest):
                left = cleaned[: -(len(rest) + 1)]
                if left and "." not in left:
                    return True
            continue
        if candidate == cleaned:
            return True
    return False


def fetch_certificate(host: str, port: int, timeout: float) -> CertView:
    der = _peer_der(host, port, timeout, verify=False)
    cert = x509.load_der_x509_certificate(der)
    trusted, error = _trust(host, port, timeout)
    return CertView(
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        names=_names(cert),
        trusted=trusted,
        trust_error=error,
    )


def assess_certificate(host: str, cert: CertView, now: datetime, *, local: bool) -> list[TlsIssue]:
    issues: list[TlsIssue] = []
    if now < cert.not_before:
        issues.append(
            TlsIssue(
                Severity.BLOCKER,
                "Certificate is not valid yet",
                f"The certificate for {host} starts at {cert.not_before.date().isoformat()}.",
                "Install a certificate whose validity window covers today.",
            )
        )
    remaining = cert.not_after - now
    if remaining.total_seconds() <= 0:
        issues.append(
            TlsIssue(
                Severity.BLOCKER,
                "Certificate is expired",
                f"The certificate for {host} expired on {cert.not_after.date().isoformat()}.",
                "Renew it and install the new chain before sending traffic.",
            )
        )
    else:
        days = int(remaining.total_seconds() // 86400)
        when = cert.not_after.date().isoformat()
        if days < 14:
            issues.append(
                TlsIssue(
                    Severity.HIGH,
                    "Certificate expires soon",
                    f"The certificate for {host} expires on {when} ({days} days).",
                    f"Renew the certificate before {when} and confirm the runtime trust store has the new chain.",
                )
            )
        elif days < 30:
            issues.append(
                TlsIssue(
                    Severity.MEDIUM,
                    "Certificate expires within 30 days",
                    f"The certificate for {host} expires on {when} ({days} days).",
                    f"Schedule the renewal before {when}.",
                )
            )
    if cert.names and not host_matches(host, cert.names):
        shown = ", ".join(cert.names)
        issues.append(
            TlsIssue(
                Severity.BLOCKER,
                "Certificate name does not match the host",
                f"{host} presented a certificate for {shown}.",
                f"Serve a certificate whose SAN includes {host}.",
            )
        )
    if not cert.trusted:
        detail = cert.trust_error or "verification failed"
        severity = Severity.MEDIUM if local else Severity.HIGH
        issues.append(
            TlsIssue(
                severity,
                "Certificate is not trusted",
                f"The default trust store rejected the certificate for {host} ({detail}).",
                "Use a certificate this process trusts, or add the private CA to the trust store the runtime uses.",
            )
        )
    return issues


def _names(cert: x509.Certificate) -> tuple[str, ...]:
    found: list[str] = []
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        ext = None
    if ext is not None:
        found.extend(ext.value.get_values_for_type(x509.DNSName))
    for attr in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
        if isinstance(attr.value, str) and attr.value not in found:
            found.append(attr.value)
    unique: list[str] = []
    for name in found:
        if name not in unique:
            unique.append(name)
    return tuple(unique)


def _peer_der(host: str, port: int, timeout: float, *, verify: bool) -> bytes:
    if verify:
        context: ssl.SSLContext = ssl.create_default_context()
    else:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    with (
        socket.create_connection((host, port), timeout=timeout) as sock,
        context.wrap_socket(sock, server_hostname=host) as tls,
    ):
        der = tls.getpeercert(binary_form=True)
    if not isinstance(der, bytes) or not der:
        raise ssl.SSLError("server did not present a certificate")
    return der


def _trust(host: str, port: int, timeout: float) -> tuple[bool, str | None]:
    try:
        _peer_der(host, port, timeout, verify=True)
    except ssl.SSLError as exc:
        return False, type(exc).__name__
    except OSError as exc:
        return False, type(exc).__name__
    return True, None
