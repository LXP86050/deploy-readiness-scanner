from pathlib import Path

from tests.helpers import ROOT

from drs.checks.security import assess_listeners
from drs.config import ListenerConfig
from drs.listeners import Listener, local_listeners, parse_proc_net
from drs.models import Severity
from drs.secrets import iter_scan_files, scan_file


def test_secret_scan_keeps_values_out(tmp_path: Path) -> None:
    env_file = tmp_path / "customer.env"
    env_file.write_text(
        "\n".join(
            [
                "API_KEY=sk-live-oops-checked-in",
                "TOKEN=changeme",
                "DATABASE_URL=postgresql://user:s3cret-password@localhost/db",
                "REGION=us-east-1",
            ]
        ),
        encoding="utf-8",
    )
    env_file.chmod(0o644)
    hit = scan_file(env_file)
    assert hit is not None
    assert hit.real_keys == ("API_KEY",)
    assert hit.placeholder_keys == ("TOKEN",)
    assert hit.url_password_keys == ("DATABASE_URL",)
    blob = repr(hit)
    assert "sk-live-oops-checked-in" not in blob
    assert "s3cret-password" not in blob

    locked = tmp_path / "locked.env"
    locked.write_text("API_KEY=real-value-here\n", encoding="utf-8")
    locked.chmod(0o600)
    locked_hit = scan_file(locked)
    assert locked_hit is not None
    assert locked_hit.mode == 0o600

    key_file = tmp_path / "id_rsa.txt"
    key_file.write_text("-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n", encoding="utf-8")
    private = scan_file(key_file)
    assert private is not None and private.private_key

    code = tmp_path / "scanner.py"
    code.write_text('SECRET = re.compile(r"token")\n', encoding="utf-8")
    assert scan_file(code) is None

    demo = scan_file(ROOT / "demo" / "customer.env")
    assert demo is not None
    assert "demo-not-a-secret" not in repr(demo)
    assert "sk-admin-demo-not-real" not in repr(demo)
    config_dir = ROOT / "demo" / "config"
    files, truncated = iter_scan_files(config_dir)
    assert not truncated
    assert any(path.name == "app.yaml" for path in files)
    app = scan_file(config_dir / "app.yaml")
    assert app is not None
    assert app.real_keys == ("api_key",)
    assert "sk-live-oops-checked-in" not in repr(app)


def test_proc_net_roundtrip_and_exposure() -> None:
    def encode(host: str, port: int) -> str:
        import socket

        raw = socket.inet_aton(host)
        return f"{int.from_bytes(raw, 'little'):08X}:{port:04X}"

    text = "header ignored\n" + f"0: {encode('0.0.0.0', 55432)} 00000000:0000 0A\n"
    text += f"1: {encode('127.0.0.1', 80)} 00000000:0000 0A\n"
    text += "2: 0100007F:0050 00000000:0000 01\n"
    found = parse_proc_net(text, ipv6=False)
    assert Listener("0.0.0.0", 55432) in found
    assert Listener("127.0.0.1", 80) in found
    assert all(item.port != 80 or item.host == "127.0.0.1" for item in found if item.port == 80)
    outcome = assess_listeners(
        [ListenerConfig("postgres", 55432, public_ok=False), ListenerConfig("admin", 80, public_ok=True)],
        found,
    )
    assert any(finding.severity == Severity.HIGH for finding in outcome.findings or [])
    assert "postgres" in (outcome.findings or [])[0].summary


def test_ipv6_and_missing_proc(tmp_path: Path) -> None:
    import socket

    raw = socket.inet_pton(socket.AF_INET6, "::1")
    words = [f"{int.from_bytes(raw[index : index + 4], 'little'):08X}" for index in range(0, 16, 4)]
    field = "".join(words) + ":1F90"
    found = parse_proc_net(f"header\n0: {field} 00000000:0000 0A\n", ipv6=True)
    assert found == [Listener("::1", 8080)]
    assert local_listeners(tmp_path) is None
