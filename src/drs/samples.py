from __future__ import annotations

import csv
import io
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from drs.config import Config, Source
from drs.redact import redact_url

_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_TEXTUAL_NULLS = {"null", "none", "n/a", "na", "nil"}
_ISO_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}(?:[ T]\d{2}:\d{2}(?::\d{2})?)?(?:Z|[+-]\d{2}:?\d{2})?$")
_US_DATE = re.compile(r"^\d{1,2}/\d{1,2}/\d{4}$")
_SKIP_DIRS = {".git", ".venv", "node_modules", "__pycache__", ".mypy_cache", ".ruff_cache"}
TEXT_SUFFIXES = {".txt", ".md", ".markdown", ".html", ".htm", ".rst", ".json", ".csv"}
SOURCE_READ_SECONDS = 8


class SourceProblem(Exception):
    def __init__(self, message: str, remediation: str, location: str | None = None) -> None:
        super().__init__(message)
        self.remediation = remediation
        self.location = location


@dataclass
class TabularFrame:
    source: str
    kind: str
    location: str
    schema_id: str | None
    columns: list[str]
    rows: list[dict[str, object]]
    total_rows: int | None
    truncated: bool


@dataclass(frozen=True)
class ColumnStat:
    name: str
    nulls: int
    textual_nulls: int


@dataclass(frozen=True)
class Drift:
    schema_id: str
    source: str
    baseline: str
    missing: tuple[str, ...]
    extra: tuple[str, ...]


@dataclass(frozen=True)
class DocumentFile:
    path: str
    suffix: str
    size: int
    text: str | None


def quote_ident(name: str) -> str:
    if not _IDENT.fullmatch(name):
        raise SourceProblem(
            f"unsupported table name: {name}",
            "Use a simple table name made of letters, numbers, and underscores.",
        )
    return f'"{name}"'


def cell(value: object) -> tuple[str | None, bool]:
    if value is None:
        return None, False
    text = value if isinstance(value, str) else str(value)
    stripped = text.strip()
    if stripped == "":
        return None, False
    if stripped.lower() in _TEXTUAL_NULLS:
        return None, True
    return stripped, False


def column_stats(frame: TabularFrame) -> list[ColumnStat]:
    stats: list[ColumnStat] = []
    for name in frame.columns:
        nulls = 0
        textual = 0
        for row in frame.rows:
            cleaned, was_textual = cell(row.get(name))
            if cleaned is None:
                nulls += 1
            if was_textual:
                textual += 1
        stats.append(ColumnStat(name, nulls, textual))
    return stats


def duplicate_ids(frame: TabularFrame) -> list[str]:
    if "id" not in frame.columns:
        return []
    seen: dict[str, int] = {}
    for row in frame.rows:
        cleaned, _was_textual = cell(row.get("id"))
        if cleaned is None:
            continue
        seen[cleaned] = seen.get(cleaned, 0) + 1
    return sorted(value for value, count in seen.items() if count > 1)


def date_formats(frame: TabularFrame) -> dict[str, dict[str, int]]:
    found: dict[str, dict[str, int]] = {}
    for name in frame.columns:
        if not _date_name(name):
            continue
        counts = {"iso": 0, "us": 0, "other": 0}
        for row in frame.rows:
            cleaned, _was_textual = cell(row.get(name))
            if cleaned is None:
                continue
            if _ISO_DATE.fullmatch(cleaned):
                counts["iso"] += 1
            elif _US_DATE.fullmatch(cleaned):
                counts["us"] += 1
            else:
                counts["other"] += 1
        if any(counts.values()):
            found[name] = counts
    return found


def schema_drift(frames: Sequence[TabularFrame]) -> list[Drift]:
    groups: dict[str, list[TabularFrame]] = {}
    for frame in frames:
        if frame.schema_id:
            groups.setdefault(frame.schema_id, []).append(frame)
    drifts: list[Drift] = []
    for schema_id, members in groups.items():
        baseline = members[0]
        base_cols = set(baseline.columns)
        for other in members[1:]:
            cols = set(other.columns)
            missing = tuple(sorted(base_cols - cols))
            extra = tuple(sorted(cols - base_cols))
            if missing or extra:
                drifts.append(Drift(schema_id, other.source, baseline.source, missing, extra))
    return drifts


def read_structured(config: Config, source: Source, env: Mapping[str, str]) -> list[TabularFrame]:
    if source.kind in {"csv", "parquet"}:
        path = config.resolve(source.path or "")
        if not path.is_file():
            raise SourceProblem(
                f"{source.name}: {path} does not exist",
                "Point the source at the file the job will actually read.",
                str(path),
            )
        if source.kind == "csv":
            return [read_csv(path, source)]
        return [read_parquet(path, source)]
    url = env.get(source.url_env or "", "")
    if not url.strip():
        raise SourceProblem(
            f"{source.name}: {source.url_env} is not set",
            f"Export {source.url_env} with the SQLAlchemy URL the service uses.",
        )
    return read_sql_tables(url, source)


def read_csv(path: Path, source: Source) -> TabularFrame:
    try:
        text = path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise SourceProblem(
            f"{source.name}: could not read {path.name}",
            "Check that the file is readable by the user running the scan.",
            str(path),
        ) from exc
    except UnicodeError as exc:
        raise SourceProblem(
            f"{source.name}: {path.name} is not valid UTF-8",
            "Re-export the file as UTF-8.",
            str(path),
        ) from exc
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise SourceProblem(
            f"{source.name}: {path.name} has no header",
            "Write a header row before scanning.",
            str(path),
        )
    columns = [name.strip() for name in reader.fieldnames]
    if any(not name for name in columns):
        raise SourceProblem(
            f"{source.name}: {path.name} has an empty column name",
            "Name every column in the header.",
            str(path),
        )
    if len(set(columns)) != len(columns):
        raise SourceProblem(
            f"{source.name}: {path.name} has duplicate column names",
            "Rename columns so each name appears once.",
            str(path),
        )
    reader.fieldnames = columns
    rows: list[dict[str, object]] = []
    truncated = False
    for index, raw in enumerate(reader):
        if index >= source.sample_limit:
            truncated = True
            break
        rows.append({column: raw.get(column) for column in columns})
    return TabularFrame(
        source=source.name,
        kind="csv",
        location=str(path),
        schema_id=source.schema_id,
        columns=columns,
        rows=rows,
        total_rows=None if truncated else len(rows),
        truncated=truncated,
    )


def read_parquet(path: Path, source: Source) -> TabularFrame:
    import pyarrow
    import pyarrow.parquet as pq

    try:
        parquet = pq.ParquetFile(path)
    except (OSError, pyarrow.ArrowInvalid) as exc:
        raise SourceProblem(
            f"{source.name}: could not read {path.name}",
            "Rebuild the parquet file or point the source at the CSV the export came from.",
            str(path),
        ) from exc
    columns = list(parquet.schema_arrow.names)
    batch = None
    for candidate in parquet.iter_batches(batch_size=source.sample_limit):
        batch = candidate
        break
    rows = [] if batch is None else list(batch.to_pylist())
    total = parquet.metadata.num_rows if parquet.metadata is not None else None
    truncated = total is not None and total > len(rows)
    return TabularFrame(
        source=source.name,
        kind="parquet",
        location=str(path),
        schema_id=source.schema_id,
        columns=columns,
        rows=rows,
        total_rows=total,
        truncated=truncated,
    )


def read_sql_tables(url: str, source: Source) -> list[TabularFrame]:
    from sqlalchemy import create_engine, inspect, text
    from sqlalchemy.exc import SQLAlchemyError
    from sqlalchemy.pool import NullPool

    connect_args: dict[str, object] = {}
    if url.startswith("postgresql"):
        connect_args = {"connect_timeout": 5, "options": "-c statement_timeout=8000"}
    engine = create_engine(url, poolclass=NullPool, connect_args=connect_args)
    try:
        with engine.connect() as conn:
            present = sorted(name for name in inspect(engine).get_table_names() if not str(name).startswith("sqlite_"))
            missing = [table for table in source.tables if table not in present]
            if missing:
                found = ", ".join(present) or "(none)"
                raise SourceProblem(
                    f"{source.name}: missing table(s) {', '.join(missing)}; database has {found}",
                    "Update sources[].tables to names that exist, or create the tables before the scan.",
                    redact_url(url),
                )
            frames: list[TabularFrame] = []
            for table in source.tables:
                ident = quote_ident(table)
                total_raw = conn.execute(text(f"SELECT count(*) FROM {ident}")).scalar_one()
                result = conn.execute(
                    text(f"SELECT * FROM {ident} LIMIT :n"),
                    {"n": source.sample_limit},
                )
                columns = [str(name) for name in result.keys()]  # noqa: SIM118
                rows = [{column: mapping[column] for column in columns} for mapping in result.mappings()]
                label = source.name if len(source.tables) == 1 else f"{source.name}.{table}"
                frames.append(
                    TabularFrame(
                        source=label,
                        kind="postgres",
                        location=f"{redact_url(url)} table {table}",
                        schema_id=source.schema_id,
                        columns=columns,
                        rows=rows,
                        total_rows=int(total_raw),
                        truncated=int(total_raw) > len(rows),
                    )
                )
            return frames
    except SourceProblem:
        raise
    except SQLAlchemyError as exc:
        sqlstate = getattr(getattr(exc, "orig", None), "sqlstate", None)
        detail = type(exc).__name__ if not sqlstate else f"{type(exc).__name__} sqlstate {sqlstate}"
        raise SourceProblem(
            f"{source.name}: could not read the database ({detail})",
            "Check the URL, the network path, and that the role has SELECT on the table.",
            redact_url(url),
        ) from exc
    finally:
        engine.dispose()


def read_documents(root: Path, file_limit: int = 500) -> tuple[list[DocumentFile], bool]:
    if not root.exists():
        raise SourceProblem(
            f"{root} does not exist",
            "Point the source at the directory the embedding job will read.",
            str(root),
        )
    if not root.is_dir():
        raise SourceProblem(
            f"{root} is not a directory",
            "Document sources are folders, not single files.",
            str(root),
        )
    files: list[DocumentFile] = []
    truncated = False
    paths = sorted(path for path in root.rglob("*") if path.is_file())
    for path in paths:
        relative = path.relative_to(root)
        if any(part in _SKIP_DIRS for part in relative.parts):
            continue
        if len(files) >= file_limit:
            truncated = True
            break
        size = path.stat().st_size
        suffix = path.suffix.lower() or "(none)"
        text: str | None = None
        if path.suffix.lower() in TEXT_SUFFIXES and size <= 2_000_000:
            text = path.read_text(encoding="utf-8", errors="replace")
        files.append(DocumentFile(str(path), suffix, size, text))
    return files, truncated


def estimate_tokens(text: str) -> int:
    if not text:
        return 0
    return max(1, len(text) // 4)


def _date_name(name: str) -> bool:
    lowered = name.lower()
    return lowered in {"date", "opened", "created"} or lowered.endswith(("_at", "_date", "_on"))
