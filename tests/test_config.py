from pathlib import Path

import pytest
from tests.helpers import ROOT, write_config

from drs.config import ConfigError, load_config


def test_minimal_config_and_relative_path(tmp_path: Path) -> None:
    config = write_config(
        tmp_path,
        """
        name: acme
        environment: dev
        sources:
          - name: tickets
            kind: csv
            path: data/tickets.csv
        """,
    )
    assert config.name == "acme"
    assert config.concurrency == 8
    assert config.resolve("data/tickets.csv") == (tmp_path / "data" / "tickets.csv").resolve()


def test_unknown_key_and_bad_kind(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="unknown keys"):
        write_config(tmp_path, "name: acme\nenvironment: dev\nregion: us\n")
    with pytest.raises(ConfigError, match="kind"):
        write_config(
            tmp_path,
            """
            name: acme
            environment: dev
            sources:
              - name: t
                kind: sqlite
                path: t.db
            """,
        )


def test_postgres_requires_tables_and_url(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="url_env"):
        write_config(
            tmp_path,
            """
            name: acme
            environment: dev
            sources:
              - name: db
                kind: postgres
                tables: [tickets]
            """,
        )
    with pytest.raises(ConfigError, match="tables"):
        write_config(
            tmp_path,
            """
            name: acme
            environment: dev
            sources:
              - name: db
                kind: postgres
                url_env: DATABASE_URL
            """,
        )


def test_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="does not exist"):
        load_config(tmp_path / "missing.yaml")


def test_demo_config_loads() -> None:
    config = load_config(ROOT / "demo" / "drs.yaml")
    assert config.name == "northwind-support"
    assert config.llm is not None
    assert config.resolve("data/tickets.csv").name == "tickets.csv"
    assert config.timeouts.limit_for("pii") == 30
