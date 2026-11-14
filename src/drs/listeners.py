from __future__ import annotations

import socket
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Listener:
    host: str
    port: int


def parse_proc_net(text: str, *, ipv6: bool) -> list[Listener]:
    listeners: list[Listener] = []
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 4 or parts[3] != "0A":
            continue
        try:
            host, port = _decode(parts[1], ipv6=ipv6)
        except ValueError:
            continue
        listeners.append(Listener(host, port))
    return listeners


def local_listeners(proc_net: Path | None = None) -> list[Listener] | None:
    root = proc_net or Path("/proc/net")
    tcp = root / "tcp"
    if not tcp.is_file():
        return None
    found = parse_proc_net(tcp.read_text(encoding="utf-8", errors="replace"), ipv6=False)
    tcp6 = root / "tcp6"
    if tcp6.is_file():
        found.extend(parse_proc_net(tcp6.read_text(encoding="utf-8", errors="replace"), ipv6=True))
    return found


def _decode(field: str, *, ipv6: bool) -> tuple[str, int]:
    # /proc/net/tcp stores each address word little-endian.
    addr_hex, port_hex = field.split(":")
    port = int(port_hex, 16)
    if not ipv6:
        raw = int(addr_hex, 16).to_bytes(4, "little")
        return socket.inet_ntoa(raw), port
    if len(addr_hex) != 32:
        raise ValueError(field)
    words = [int(addr_hex[index : index + 8], 16).to_bytes(4, "little") for index in range(0, 32, 8)]
    return socket.inet_ntop(socket.AF_INET6, b"".join(words)), port
