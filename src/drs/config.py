from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import yaml

SOURCE_KINDS = {"csv", "parquet", "postgres", "documents"}
FAIL_ON = {"blocker", "high", "medium"}
HTTP_METHODS = {"GET", "HEAD", "POST"}


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class Endpoint:
    name: str
    url: str
    method: str = "GET"
    api_key_env: str | None = None
    expect_status: int = 200


@dataclass(frozen=True)
class LlmConfig:
    url: str
    model: str
    api_key_env: str | None
    requests: int
    timeout_seconds: float


@dataclass(frozen=True)
class Source:
    name: str
    kind: str
    path: str | None
    url_env: str | None
    schema_id: str | None
    tables: tuple[str, ...]
    sample_limit: int


@dataclass(frozen=True)
class ProxyConfig:
    expect_proxy: bool = False
    http_proxy_env: str = "HTTP_PROXY"
    https_proxy_env: str = "HTTPS_PROXY"
    no_proxy_env: str = "NO_PROXY"


@dataclass(frozen=True)
class RuntimeConfig:
    min_python: str = "3.11"
    require_cuda: bool = False
    min_memory_mb: int = 512


@dataclass(frozen=True)
class ListenerConfig:
    name: str
    port: int
    public_ok: bool = False


@dataclass(frozen=True)
class PromptLoggingConfig:
    stores_prompts: bool
    destination: str | None = None


@dataclass(frozen=True)
class SecurityConfig:
    env_files: tuple[str, ...] = ()
    scan_paths: tuple[str, ...] = ()
    listeners: tuple[ListenerConfig, ...] = ()
    prompt_logging: PromptLoggingConfig | None = None


@dataclass(frozen=True)
class EmbeddingConfig:
    chunk_tokens: int = 512
    dollars_per_million_tokens: float | None = None
    budget_usd: float | None = None


@dataclass(frozen=True)
class Thresholds:
    min_category_score: int = 70
    fail_on: str = "blocker"


@dataclass(frozen=True)
class Timeouts:
    default_seconds: float = 20
    scan_seconds: float | None = 120
    per_check: dict[str, float] | None = None

    def limit_for(self, check_id: str) -> float:
        overrides = self.per_check or {}
        return overrides.get(check_id, self.default_seconds)


@dataclass(frozen=True)
class ResidencyConfig:
    region: str
    allowed: tuple[str, ...]


@dataclass(frozen=True)
class Config:
    name: str
    environment: str
    path: Path
    residency: ResidencyConfig | None
    endpoints: tuple[Endpoint, ...]
    llm: LlmConfig | None
    sources: tuple[Source, ...]
    required_env: tuple[str, ...]
    optional_env: tuple[str, ...]
    proxy: ProxyConfig
    runtime: RuntimeConfig
    security: SecurityConfig
    embedding: EmbeddingConfig
    thresholds: Thresholds
    timeouts: Timeouts
    concurrency: int
    include: tuple[str, ...]
    exclude: tuple[str, ...]

    def resolve(self, value: str) -> Path:
        path = Path(value)
        if path.is_absolute():
            return path
        return (self.path.parent / path).resolve()


def load_config(path: Path) -> Config:
    if not path.is_file():
        raise ConfigError(f"{path} does not exist")
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ConfigError(f"{path} must be a mapping")
    return _parse(cast(dict[str, Any], loaded), path.resolve())


def _parse(data: dict[str, Any], path: Path) -> Config:
    _reject_unknown(
        data,
        {
            "name",
            "environment",
            "residency",
            "thresholds",
            "concurrency",
            "timeouts",
            "credentials",
            "proxy",
            "endpoints",
            "llm",
            "sources",
            "embedding",
            "runtime",
            "security",
            "checks",
        },
        str(path),
    )
    credentials = _section(data, "credentials", {})
    _reject_unknown(credentials, {"required_env", "optional_env"}, "credentials")
    checks = _section(data, "checks", {})
    _reject_unknown(checks, {"include", "exclude"}, "checks")
    return Config(
        name=_string(data, "name", str(path), required=True),
        environment=_string(data, "environment", str(path), required=True),
        path=path,
        residency=_residency(data),
        endpoints=_endpoints(data),
        llm=_llm(data),
        sources=_sources(data),
        required_env=_strings(credentials, "required_env", "credentials"),
        optional_env=_strings(credentials, "optional_env", "credentials"),
        proxy=_proxy(data),
        runtime=_runtime(data),
        security=_security(data),
        embedding=_embedding(data),
        thresholds=_thresholds(data),
        timeouts=_timeouts(data),
        concurrency=_bounded_int(data, "concurrency", str(path), default=8, low=1, high=64),
        include=_strings(checks, "include", "checks"),
        exclude=_strings(checks, "exclude", "checks"),
    )


def _residency(data: dict[str, Any]) -> ResidencyConfig | None:
    if "residency" not in data or data["residency"] is None:
        return None
    section = _mapping(data["residency"], "residency")
    _reject_unknown(section, {"region", "allowed"}, "residency")
    region = _string(section, "region", "residency", required=True)
    allowed = _strings(section, "allowed", "residency")
    if not allowed:
        allowed = (region,)
    return ResidencyConfig(region=region, allowed=allowed)


def _endpoints(data: dict[str, Any]) -> tuple[Endpoint, ...]:
    raw = data.get("endpoints", [])
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise ConfigError("endpoints must be a list")
    endpoints: list[Endpoint] = []
    for index, item in enumerate(raw):
        where = f"endpoints[{index}]"
        body = _mapping(item, where)
        _reject_unknown(body, {"name", "url", "method", "api_key_env", "expect_status"}, where)
        method = _string(body, "method", where, default="GET").upper()
        if method not in HTTP_METHODS:
            raise ConfigError(f"{where}.method must be GET, HEAD, or POST")
        url = _http_url(_string(body, "url", where, required=True), f"{where}.url")
        endpoints.append(
            Endpoint(
                name=_string(body, "name", where, required=True),
                url=url,
                method=method,
                api_key_env=_optional_string(body, "api_key_env", where),
                expect_status=_bounded_int(body, "expect_status", where, default=200, low=100, high=599),
            )
        )
    return tuple(endpoints)


def _llm(data: dict[str, Any]) -> LlmConfig | None:
    if "llm" not in data or data["llm"] is None:
        return None
    section = _mapping(data["llm"], "llm")
    _reject_unknown(section, {"url", "model", "api_key_env", "requests", "timeout_seconds"}, "llm")
    return LlmConfig(
        url=_http_url(_string(section, "url", "llm", required=True), "llm.url"),
        model=_string(section, "model", "llm", default="unspecified"),
        api_key_env=_optional_string(section, "api_key_env", "llm"),
        requests=_bounded_int(section, "requests", "llm", default=5, low=1, high=50),
        timeout_seconds=_bounded_float(section, "timeout_seconds", "llm", default=8, low=0.1, high=120),
    )


def _sources(data: dict[str, Any]) -> tuple[Source, ...]:
    raw = data.get("sources", [])
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise ConfigError("sources must be a list")
    sources: list[Source] = []
    for index, item in enumerate(raw):
        where = f"sources[{index}]"
        body = _mapping(item, where)
        _reject_unknown(
            body,
            {"name", "kind", "path", "url_env", "schema_id", "tables", "sample_limit"},
            where,
        )
        kind = _string(body, "kind", where, required=True)
        if kind not in SOURCE_KINDS:
            raise ConfigError(f"{where}.kind must be one of {', '.join(sorted(SOURCE_KINDS))}")
        path = _optional_string(body, "path", where)
        url_env = _optional_string(body, "url_env", where)
        if kind == "postgres" and not url_env:
            raise ConfigError(f"{where}.url_env is required for postgres")
        if kind != "postgres" and not path:
            raise ConfigError(f"{where}.path is required for {kind}")
        tables = _strings(body, "tables", where)
        if kind == "postgres" and not tables:
            raise ConfigError(f"{where}.tables is required for postgres")
        sources.append(
            Source(
                name=_string(body, "name", where, required=True),
                kind=kind,
                path=path,
                url_env=url_env,
                schema_id=_optional_string(body, "schema_id", where),
                tables=tables,
                sample_limit=_bounded_int(body, "sample_limit", where, default=1000, low=1, high=20000),
            )
        )
    return tuple(sources)


def _proxy(data: dict[str, Any]) -> ProxyConfig:
    section = _section(data, "proxy", {})
    _reject_unknown(
        section,
        {"expect_proxy", "http_proxy_env", "https_proxy_env", "no_proxy_env"},
        "proxy",
    )
    return ProxyConfig(
        expect_proxy=_bool(section, "expect_proxy", "proxy", default=False),
        http_proxy_env=_string(section, "http_proxy_env", "proxy", default="HTTP_PROXY"),
        https_proxy_env=_string(section, "https_proxy_env", "proxy", default="HTTPS_PROXY"),
        no_proxy_env=_string(section, "no_proxy_env", "proxy", default="NO_PROXY"),
    )


def _runtime(data: dict[str, Any]) -> RuntimeConfig:
    section = _section(data, "runtime", {})
    _reject_unknown(section, {"min_python", "require_cuda", "min_memory_mb"}, "runtime")
    return RuntimeConfig(
        min_python=_string(section, "min_python", "runtime", default="3.11"),
        require_cuda=_bool(section, "require_cuda", "runtime", default=False),
        min_memory_mb=_bounded_int(section, "min_memory_mb", "runtime", default=512, low=1, high=10_000_000),
    )


def _security(data: dict[str, Any]) -> SecurityConfig:
    section = _section(data, "security", {})
    _reject_unknown(section, {"env_files", "scan_paths", "listeners", "prompt_logging"}, "security")
    return SecurityConfig(
        env_files=_strings(section, "env_files", "security"),
        scan_paths=_strings(section, "scan_paths", "security"),
        listeners=_listeners(section),
        prompt_logging=_prompt_logging(section),
    )


def _listeners(section: Mapping[str, Any]) -> tuple[ListenerConfig, ...]:
    raw = section.get("listeners", [])
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise ConfigError("security.listeners must be a list")
    listeners: list[ListenerConfig] = []
    for index, item in enumerate(raw):
        where = f"security.listeners[{index}]"
        body = _mapping(item, where)
        _reject_unknown(body, {"name", "port", "public_ok"}, where)
        listeners.append(
            ListenerConfig(
                name=_string(body, "name", where, required=True),
                port=_bounded_int(body, "port", where, low=1, high=65535, required=True),
                public_ok=_bool(body, "public_ok", where, default=False),
            )
        )
    return tuple(listeners)


def _prompt_logging(section: Mapping[str, Any]) -> PromptLoggingConfig | None:
    if "prompt_logging" not in section or section["prompt_logging"] is None:
        return None
    body = _mapping(section["prompt_logging"], "security.prompt_logging")
    _reject_unknown(body, {"stores_prompts", "destination"}, "security.prompt_logging")
    return PromptLoggingConfig(
        stores_prompts=_bool(body, "stores_prompts", "security.prompt_logging", required=True),
        destination=_optional_string(body, "destination", "security.prompt_logging"),
    )


def _embedding(data: dict[str, Any]) -> EmbeddingConfig:
    section = _section(data, "embedding", {})
    _reject_unknown(
        section,
        {"chunk_tokens", "dollars_per_million_tokens", "budget_usd"},
        "embedding",
    )
    return EmbeddingConfig(
        chunk_tokens=_bounded_int(section, "chunk_tokens", "embedding", default=512, low=1, high=100_000),
        dollars_per_million_tokens=_optional_float(section, "dollars_per_million_tokens", "embedding"),
        budget_usd=_optional_float(section, "budget_usd", "embedding"),
    )


def _thresholds(data: dict[str, Any]) -> Thresholds:
    section = _section(data, "thresholds", {})
    _reject_unknown(section, {"min_category_score", "fail_on"}, "thresholds")
    fail_on = _string(section, "fail_on", "thresholds", default="blocker")
    if fail_on not in FAIL_ON:
        raise ConfigError("thresholds.fail_on must be blocker, high, or medium")
    return Thresholds(
        min_category_score=_bounded_int(section, "min_category_score", "thresholds", default=70, low=0, high=100),
        fail_on=fail_on,
    )


def _timeouts(data: dict[str, Any]) -> Timeouts:
    section = _section(data, "timeouts", {})
    _reject_unknown(section, {"default_seconds", "scan_seconds", "per_check"}, "timeouts")
    per_check: dict[str, float] = {}
    raw = section.get("per_check", {})
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ConfigError("timeouts.per_check must be a mapping")
    for key, value in raw.items():
        if not isinstance(key, str):
            raise ConfigError("timeouts.per_check keys must be check ids")
        per_check[key] = _as_float(value, f"timeouts.per_check.{key}", low=0.1, high=600)
    scan = section.get("scan_seconds", 120)
    scan_seconds = None if scan is None else _as_float(scan, "timeouts.scan_seconds", low=0.1, high=3600)
    return Timeouts(
        default_seconds=_bounded_float(section, "default_seconds", "timeouts", default=20, low=0.1, high=600),
        scan_seconds=scan_seconds,
        per_check=per_check,
    )


def _section(data: Mapping[str, Any], key: str, default: dict[str, Any]) -> dict[str, Any]:
    if key not in data or data[key] is None:
        return default
    return _mapping(data[key], key)


def _mapping(value: Any, where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigError(f"{where} must be a mapping")
    return cast(dict[str, Any], value)


def _reject_unknown(data: Mapping[str, Any], allowed: set[str], where: str) -> None:
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise ConfigError(f"{where}: unknown keys: {', '.join(unknown)}")


def _string(
    data: Mapping[str, Any],
    key: str,
    where: str,
    *,
    default: str | None = None,
    required: bool = False,
) -> str:
    if key not in data or data[key] is None:
        if required:
            raise ConfigError(f"{where}.{key} is required")
        if default is None:
            raise ConfigError(f"{where}.{key} is required")
        return default
    value = data[key]
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{where}.{key} must be a non-empty string")
    return value.strip()


def _optional_string(data: Mapping[str, Any], key: str, where: str) -> str | None:
    if key not in data or data[key] is None:
        return None
    value = data[key]
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{where}.{key} must be a non-empty string")
    return value.strip()


def _strings(data: Mapping[str, Any], key: str, where: str) -> tuple[str, ...]:
    if key not in data or data[key] is None:
        return ()
    value = data[key]
    if not isinstance(value, list) or not all(isinstance(item, str) and item.strip() for item in value):
        raise ConfigError(f"{where}.{key} must be a list of strings")
    return tuple(item.strip() for item in value)


def _bool(
    data: Mapping[str, Any],
    key: str,
    where: str,
    *,
    default: bool | None = None,
    required: bool = False,
) -> bool:
    if key not in data or data[key] is None:
        if required or default is None:
            raise ConfigError(f"{where}.{key} is required")
        return default
    value = data[key]
    if not isinstance(value, bool):
        raise ConfigError(f"{where}.{key} must be true or false")
    return value


def _bounded_int(
    data: Mapping[str, Any],
    key: str,
    where: str,
    *,
    default: int | None = None,
    low: int,
    high: int,
    required: bool = False,
) -> int:
    if key not in data or data[key] is None:
        if required or default is None:
            raise ConfigError(f"{where}.{key} is required")
        return default
    value = data[key]
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{where}.{key} must be an integer")
    if value < low or value > high:
        raise ConfigError(f"{where}.{key} must be between {low} and {high}")
    return value


def _bounded_float(
    data: Mapping[str, Any],
    key: str,
    where: str,
    *,
    default: float,
    low: float,
    high: float,
) -> float:
    if key not in data or data[key] is None:
        return default
    return _as_float(data[key], f"{where}.{key}", low=low, high=high)


def _optional_float(data: Mapping[str, Any], key: str, where: str) -> float | None:
    if key not in data or data[key] is None:
        return None
    return _as_float(data[key], f"{where}.{key}", low=0, high=1_000_000_000)


def _as_float(value: Any, where: str, *, low: float, high: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"{where} must be a number")
    number = float(value)
    if number < low or number > high:
        raise ConfigError(f"{where} must be between {low} and {high}")
    return number


def _http_url(value: str, where: str) -> str:
    if not value.startswith(("http://", "https://")):
        raise ConfigError(f"{where} must start with http:// or https://")
    return value
