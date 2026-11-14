from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

import httpx

from drs.config import Config


@dataclass
class ScanContext:
    config: Config
    env: Mapping[str, str]
    http: httpx.AsyncClient

    def env_value(self, name: str | None) -> str | None:
        if not name:
            return None
        value = self.env.get(name)
        if value is None or not value.strip():
            return None
        return value
