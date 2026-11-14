from __future__ import annotations

import argparse
import asyncio
import sys
from dataclasses import replace
from pathlib import Path

from drs import __version__
from drs.config import ConfigError, load_config
from drs.engine import run_scan
from drs.registry import load_checks, select_checks
from drs.report.html import render_html
from drs.report.serialize import render_json, render_sarif
from drs.report.terminal import render_terminal


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "list-checks":
            return _list_checks()
        return _scan(args)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="drs",
        description="Preflight a customer environment before an LLM deploy.",
    )
    parser.add_argument("--version", action="version", version=f"drs {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="run checks and write a report")
    scan.add_argument("--config", default="drs.yaml", help="path to drs.yaml")
    scan.add_argument("--html", help="write an HTML report to this path")
    scan.add_argument("--json", help="write a JSON report to this path")
    scan.add_argument("--sarif", help="write a SARIF report to this path")
    scan.add_argument("--only", help="comma-separated check ids, instead of checks.include")
    scan.add_argument("--exclude", help="comma-separated check ids, instead of checks.exclude")
    scan.add_argument("--min-score", type=int, help="override thresholds.min_category_score")
    commands.add_parser("list-checks", help="list checks discovered from entry points")
    return parser


def _scan(args: argparse.Namespace) -> int:
    config = load_config(Path(args.config))
    if args.min_score is not None:
        if not 0 <= args.min_score <= 100:
            raise ConfigError("--min-score must be between 0 and 100")
        config = replace(
            config,
            thresholds=replace(config.thresholds, min_category_score=args.min_score),
        )
    include = _names(args.only) if args.only is not None else config.include
    exclude = _names(args.exclude) if args.exclude is not None else config.exclude
    checks = load_checks()
    selected = select_checks(
        checks,
        include,
        exclude,
        tuple(config.timeouts.per_check or {}),
    )
    report = asyncio.run(run_scan(config, selected))
    render_terminal(report)
    if args.html:
        _write(Path(args.html), render_html(report))
    if args.json:
        _write(Path(args.json), render_json(report))
    if args.sarif:
        _write(Path(args.sarif), render_sarif(report))
    return report.exit_code


def _list_checks() -> int:
    for check in select_checks(load_checks(), (), ()):
        print(f"{check.id:<16} {check.category.value:<14} {check.title}")
    return 0


def _names(value: str) -> tuple[str, ...]:
    return tuple(part.strip() for part in value.split(",") if part.strip())


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
