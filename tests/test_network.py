import socket
import ssl
import threading
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from tests.helpers import ROOT, run_check, write_config

from drs.checks.connectivity import CredentialsCheck, DnsTlsCheck, EndpointReachCheck, ProxyEgressCheck
from drs.checks.runtime import LlmProbeCheck, percentile
from drs.hosts import host_in_no_proxy, is_internal_host, region_families
from drs.models import Severity
from drs.tlsinfo import CertView, assess_certificate, fetch_certificate, host_matches


def test_proxy_and_region_helpers() -> None:
    assert host_in_no_proxy("db.internal", ".internal,localhost")
    assert not host_in_no_proxy("api.openai.com", "localhost")
    assert is_internal_host("10.1.2.3")
    assert is_internal_host("localhost")
    assert not is_internal_host("api.openai.com")
    assert region_families("localhost") == {"local"}
    assert region_families("db.eu-west-1.amazonaws.com") == {"eu"}
    assert region_families("api.openai.com") == set()


def test_percentiles_and_certificate_window() -> None:
    assert percentile([10, 20, 30, 40, 50], 50) == 30
    assert percentile([10, 20, 30, 40, 50], 95) == 50
    now = datetime(2026, 1, 1, tzinfo=UTC)
    cert = CertView(
        not_before=now - timedelta(days=10),
        not_after=now - timedelta(days=1),
        names=("example.com",),
        trusted=True,
        trust_error=None,
    )
    issues = assess_certificate("example.com", cert, now, local=False)
    assert any(issue.severity == Severity.BLOCKER and "expired" in issue.title.lower() for issue in issues)
    assert host_matches("a.example.com", ["*.example.com"])
    assert not host_matches("a.b.example.com", ["*.example.com"])
    assert not host_matches("example.com", ["*.example.com"])


def test_credentials_and_proxy_checks(tmp_path: Path) -> None:
    config = write_config(
        tmp_path,
        """
        name: acme
        environment: dev
        credentials:
          required_env: [LLM_API_KEY, DATABASE_URL]
          optional_env: [OPENAI_ADMIN_KEY]
        proxy:
          expect_proxy: true
        endpoints:
          - name: db
            url: http://127.0.0.1:9/health
        """,
    )
    creds = run_check(
        CredentialsCheck(),
        config,
        {
            "DATABASE_URL": "postgresql+psycopg://postgres:s3cret-password@127.0.0.1/support",
            "OPENAI_ADMIN_KEY": "changeme",
        },
    )
    blob = str(creds.findings)
    assert "s3cret-password" not in blob
    assert any(finding.severity == Severity.BLOCKER for finding in creds.findings or [])
    assert any("superuser" in finding.title for finding in creds.findings or [])
    proxy = run_check(ProxyEgressCheck(), config, {})
    assert any(finding.severity == Severity.HIGH for finding in proxy.findings or [])
    bypassed = run_check(
        ProxyEgressCheck(),
        config,
        {"HTTP_PROXY": "http://proxy.example:8080", "NO_PROXY": "127.0.0.1"},
    )
    assert not bypassed.findings


def test_endpoint_and_dns(tmp_path: Path) -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(200)
            self.send_header("content-length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, fmt: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        config = write_config(
            tmp_path,
            f"""
            name: acme
            environment: dev
            endpoints:
              - name: llm
                url: http://127.0.0.1:{port}/health
            llm:
              url: http://127.0.0.1:{port}/v1/chat/completions
              requests: 1
              timeout_seconds: 2
            """,
        )
        reach = run_check(EndpointReachCheck(), config)
        assert reach.findings == [] or reach.findings is None
        assert "1/1" in reach.summary
        dns = run_check(DnsTlsCheck(), config)
        assert any(finding.severity == Severity.LOW for finding in dns.findings or [])
        assert any("127.0.0.1" in item for item in dns.stats["resolved"])  # type: ignore[index]
    finally:
        server.shutdown()
        server.server_close()


def test_tls_against_a_short_lived_cert() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(UTC)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=5))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(_pem_cert(cert), keyfile=_pem_key(key))
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(8)
    port = sock.getsockname()[1]
    stop = threading.Event()

    def accept() -> None:
        while not stop.is_set():
            try:
                sock.settimeout(0.2)
                conn, _addr = sock.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            try:
                tls = context.wrap_socket(conn, server_side=True)
                tls.recv(32)
                tls.close()
            except Exception:
                conn.close()

    thread = threading.Thread(target=accept, daemon=True)
    thread.start()
    try:
        view = fetch_certificate("localhost", port, 5)
        issues = assess_certificate("localhost", view, datetime.now(UTC), local=True)
    finally:
        stop.set()
        sock.close()
    titles = {issue.title for issue in issues}
    assert "Certificate expires soon" in titles
    assert "Certificate is not trusted" in titles
    assert view.names == ("localhost",)


def test_llm_probe_uses_the_demo_server(tmp_path: Path) -> None:
    import importlib.util

    spec = importlib.util.spec_from_file_location("mock_llm_server", ROOT / "demo" / "mock_llm" / "server.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    server = module.serve("127.0.0.1", 0)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        config = write_config(
            tmp_path,
            f"""
            name: acme
            environment: dev
            llm:
              url: http://127.0.0.1:{port}/v1/chat/completions
              api_key_env: LLM_API_KEY
              model: mock-small
              requests: 3
              timeout_seconds: 3
            """,
        )
        outcome = run_check(LlmProbeCheck(), config, {"LLM_API_KEY": "sk-demo-local-only"})
        assert not outcome.findings
        assert outcome.stats is not None
        assert outcome.stats["ok"] == 3
        assert "p50_ms" in outcome.stats
        refused = run_check(LlmProbeCheck(), config, {})
        assert any(finding.severity == Severity.BLOCKER for finding in refused.findings or [])
    finally:
        server.shutdown()
        server.server_close()


def _pem_cert(cert: x509.Certificate) -> str:
    return _temp_bytes(cert.public_bytes(serialization.Encoding.PEM))


def _pem_key(key: rsa.RSAPrivateKey) -> str:
    data = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    return _temp_bytes(data)


def _temp_bytes(data: bytes) -> str:
    import tempfile

    with tempfile.NamedTemporaryFile("wb", delete=False) as handle:
        handle.write(data)
        return handle.name
