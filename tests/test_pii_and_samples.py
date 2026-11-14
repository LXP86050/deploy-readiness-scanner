from pathlib import Path

from demo.prepare import write_parquet
from sqlalchemy import create_engine, text
from tests.helpers import ROOT, run_check, write_config

from drs.checks.data import DataProfileCheck, DocumentsCheck, PiiCheck
from drs.config import Source
from drs.models import Severity
from drs.pii import scan_text
from drs.samples import (
    SourceProblem,
    column_stats,
    date_formats,
    duplicate_ids,
    quote_ident,
    read_csv,
    read_documents,
    read_sql_tables,
    schema_drift,
)


def _source(name: str, kind: str, path: str | None = None, **kwargs: object) -> Source:
    return Source(
        name=name,
        kind=kind,
        path=path,
        url_env=kwargs.get("url_env"),  # type: ignore[arg-type]
        schema_id=kwargs.get("schema_id"),  # type: ignore[arg-type]
        tables=kwargs.get("tables", ()),  # type: ignore[arg-type]
        sample_limit=int(kwargs.get("sample_limit", 100)),
    )


def test_demo_csv_shape() -> None:
    frame = read_csv(ROOT / "demo" / "data" / "tickets.csv", _source("tickets-csv", "csv", "x", schema_id="tickets"))
    priority = next(item for item in column_stats(frame) if item.name == "priority")
    assert len(frame.rows) == 13
    assert priority.nulls == 4
    assert priority.textual_nulls == 1
    assert duplicate_ids(frame) == ["1001"]
    opened = date_formats(frame)["opened_at"]
    assert opened == {"iso": 11, "us": 1, "other": 1}
    hits = [hit for row in frame.rows for value in row.values() if isinstance(value, str) for hit in scan_text(value)]
    assert sum(hit.kind == "email" for hit in hits) == 3
    assert sum(hit.kind == "phone" for hit in hits) == 3
    assert sum(hit.kind == "ssn" for hit in hits) == 2
    assert all(hit.sample is None or "alex.morgan" not in (hit.sample or "") for hit in hits)
    assert any(hit.sample == "a***@northwind.example" for hit in hits)


def test_schema_drift_between_demo_exports() -> None:
    first = read_csv(
        ROOT / "demo" / "data" / "tickets.csv",
        _source("tickets-csv", "csv", schema_id="tickets"),
    )
    second = read_csv(
        ROOT / "demo" / "data" / "tickets_week2.csv",
        _source("tickets-week2", "csv", schema_id="tickets"),
    )
    drifts = schema_drift([first, second])
    assert drifts[0].missing == ("channel",)
    assert drifts[0].extra == ("sentiment",)


def test_profile_check_reports_drift_and_pii(tmp_path: Path) -> None:
    ticket = tmp_path / "tickets.csv"
    ticket.write_text(
        "id,opened_at,body\n1,2024-01-02,hi\n1,01/03/2024,mail a@ex.example\n",
        encoding="utf-8",
    )
    other = tmp_path / "other.csv"
    other.write_text("id,note\n2,plain\n", encoding="utf-8")
    config = write_config(
        tmp_path,
        f"""
        name: acme
        environment: dev
        sources:
          - name: a
            kind: csv
            path: {ticket.name}
            schema_id: tickets
          - name: b
            kind: csv
            path: {other.name}
            schema_id: tickets
        """,
    )
    profile = run_check(DataProfileCheck(), config)
    titles = {finding.title for finding in profile.findings or []}
    assert "Schema drift across sources that share a schema id" in titles
    assert "Duplicate ids in the sample" in titles
    pii = run_check(PiiCheck(), config)
    assert pii.findings
    assert pii.findings[0].severity == Severity.HIGH
    blob = str(pii.findings[0].evidence)
    assert "a@ex.example" not in blob
    assert "a***@ex.example" in blob


def test_sqlite_profile_and_rejected_names(tmp_path: Path) -> None:
    url = f"sqlite:///{tmp_path / 'demo.db'}"
    engine = create_engine(url)
    with engine.begin() as conn:
        conn.execute(text("create table tickets (id integer, body text)"))
        conn.execute(text("insert into tickets values (1, NULL), (2, 'ok')"))
    engine.dispose()
    frames = read_sql_tables(url, _source("db", "postgres", url_env="DATABASE_URL", tables=("tickets",)))
    assert frames[0].total_rows == 2
    body = next(item for item in column_stats(frames[0]) if item.name == "body")
    assert body.nulls == 1
    try:
        quote_ident("tickets;drop")
    except SourceProblem as exc:
        assert "unsupported table name" in str(exc)
    else:
        raise AssertionError("expected a rejected table name")
    missing = _source("db", "postgres", url_env="DATABASE_URL", tables=("absent",))
    try:
        read_sql_tables(url, missing)
    except SourceProblem as exc:
        assert "missing table" in str(exc)
    else:
        raise AssertionError("expected a missing table")


def test_postgres_error_hides_the_password() -> None:
    source = _source(
        "db",
        "postgres",
        url_env="DATABASE_URL",
        tables=("tickets",),
    )
    url = "postgresql+psycopg://postgres:s3cret-password@127.0.0.1:1/support"
    try:
        read_sql_tables(url, source)
    except SourceProblem as exc:
        assert "s3cret-password" not in str(exc)
        assert exc.location is not None and "s3cret-password" not in exc.location
    else:
        raise AssertionError("expected a connection failure")


def test_parquet_roundtrip_and_documents(tmp_path: Path) -> None:
    csv_path = tmp_path / "rows.csv"
    csv_path.write_text("id,body\n1,hello\n", encoding="utf-8")
    dest = tmp_path / "rows.parquet"
    write_parquet(csv_path, dest)
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "note.md").write_text("hello ops@northwind.example", encoding="utf-8")
    (docs / "empty.txt").write_text("", encoding="utf-8")
    (docs / "legacy.pdf").write_bytes(b"%PDF-1.4")
    config = write_config(
        tmp_path,
        """
        name: acme
        environment: dev
        sources:
          - name: rows
            kind: parquet
            path: rows.parquet
          - name: docs
            kind: documents
            path: docs
        embedding:
          chunk_tokens: 8
          dollars_per_million_tokens: 10
          budget_usd: 0.0000001
        """,
    )
    documents = run_check(DocumentsCheck(), config)
    assert documents.stats is not None
    assert documents.stats["tokens"] > 0
    assert any(finding.severity == Severity.HIGH for finding in documents.findings or [])
    loaded, _truncated = read_documents(docs)
    assert any(item.text is None for item in loaded)
    pii = run_check(PiiCheck(), config)
    assert pii.stats is not None
    assert pii.stats["emails"] == 1
