from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from drs.redact import SECRET_NAME, URL_PASSWORD

_ASSIGNMENT = re.compile(
    r"""^\s*(?:export\s+)?["']?(?P<key>[A-Za-z_][A-Za-z0-9_]*)["']?\s*[:=]\s*["']?(?P<value>[^"'#\n]*?)["']?\s*$"""
)
_PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
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
_INTERESTING = {".env", ".yaml", ".yml", ".json", ".toml", ".ini", ".py", ".txt", ".cfg", ".conf"}
_SKIP = {".git", ".venv", "node_modules", "__pycache__"}
_MAX_BYTES = 1_000_000
_FILE_LIMIT = 500


@dataclass(frozen=True)
class FileSecrets:
    path: str
    mode: int
    real_keys: tuple[str, ...]
    placeholder_keys: tuple[str, ...]
    url_password_keys: tuple[str, ...]
    private_key: bool


def scan_file(path: Path) -> FileSecrets | None:
    try:
        info = path.stat()
    except OSError:
        return None
    if not path.is_file() or info.st_size > _MAX_BYTES:
        return None
    raw = path.read_bytes()
    if b"\0" in raw[:1024]:
        return None
    text = raw.decode("utf-8", errors="replace")
    real: list[str] = []
    placeholders: list[str] = []
    url_keys: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _ASSIGNMENT.match(line)
        if match is None:
            continue
        key = match.group("key")
        value = match.group("value").strip()
        if not value or any(char in value for char in "(){}[]"):
            continue
        if URL_PASSWORD.search(value):
            url_keys.append(key)
        if not SECRET_NAME.search(key):
            continue
        if _placeholder(value):
            placeholders.append(key)
        else:
            real.append(key)
    private = _PRIVATE_KEY.search(text) is not None
    if not (real or placeholders or url_keys or private):
        return None
    return FileSecrets(
        path=str(path),
        mode=info.st_mode & 0o777,
        real_keys=tuple(dict.fromkeys(real)),
        placeholder_keys=tuple(dict.fromkeys(placeholders)),
        url_password_keys=tuple(dict.fromkeys(url_keys)),
        private_key=private,
    )


def iter_scan_files(root: Path, limit: int = _FILE_LIMIT) -> tuple[list[Path], bool]:
    if root.is_file():
        return [root], False
    if not root.is_dir():
        return [], False
    found: list[Path] = []
    truncated = False
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        relative = path.relative_to(root)
        if any(part in _SKIP for part in relative.parts):
            continue
        if not _interesting(path):
            continue
        if len(found) >= limit:
            truncated = True
            break
        found.append(path)
    return found, truncated


def _interesting(path: Path) -> bool:
    name = path.name
    if name.startswith(".env") or name.endswith(".env"):
        return True
    return path.suffix.lower() in _INTERESTING


def _placeholder(value: str) -> bool:
    folded = value.strip().strip("'\"").lower()
    if folded in _PLACEHOLDERS:
        return True
    if folded.startswith(("your-", "your_", "<", "${", "todo", "changeme", "replace-me")):
        return True
    return "placeholder" in folded
