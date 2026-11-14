from __future__ import annotations

import asyncio
import textwrap
from pathlib import Path

import httpx

from drs.config import Config, load_config
from drs.context import ScanContext
from drs.sdk import Check, Outcome

ROOT = Path(__file__).resolve().parents[1]


def write_config(directory: Path, body: str) -> Config:
    path = directory / "drs.yaml"
    path.write_text(textwrap.dedent(body).strip() + "\n", encoding="utf-8")
    return load_config(path)


def run_check(check: Check, config: Config, env: dict[str, str] | None = None) -> Outcome:
    async def _run() -> Outcome:
        async with httpx.AsyncClient(trust_env=False) as http:
            ctx = ScanContext(config, dict(env or {}), http)
            return await check.run(ctx)

    return asyncio.run(_run())
