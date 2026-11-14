from __future__ import annotations

import csv
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq


def write_parquet(csv_path: Path, dest: Path) -> None:
    with csv_path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        columns = list(reader.fieldnames or [])
        rows = list(reader)
    if not columns:
        raise SystemExit(f"{csv_path} has no header")
    schema = pa.schema([(name, pa.string()) for name in columns])
    table = pa.Table.from_pylist(rows, schema=schema)
    dest.parent.mkdir(parents=True, exist_ok=True)
    pq.write_table(table, dest)


def main() -> None:
    root = Path(__file__).resolve().parent
    write_parquet(root / "data" / "tickets.csv", root / "data" / "tickets.parquet")


if __name__ == "__main__":
    main()
