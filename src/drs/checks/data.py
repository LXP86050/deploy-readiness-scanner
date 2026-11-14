from __future__ import annotations

import asyncio
from collections import Counter
from pathlib import Path

from drs.config import Source
from drs.context import ScanContext
from drs.models import Category, Finding, Severity
from drs.pii import scan_text
from drs.samples import (
    SOURCE_READ_SECONDS,
    ColumnStat,
    DocumentFile,
    SourceProblem,
    TabularFrame,
    column_stats,
    date_formats,
    duplicate_ids,
    estimate_tokens,
    read_documents,
    read_structured,
    schema_drift,
)
from drs.sdk import Outcome, Skip

_NULL_RATE = 0.2


class DataProfileCheck:
    id = "data_profile"
    title = "Tabular data profile"
    category = Category.DATA

    async def run(self, ctx: ScanContext) -> Outcome:
        sources = [source for source in ctx.config.sources if source.kind in {"csv", "parquet", "postgres"}]
        if not sources:
            raise Skip("no tabular sources are configured")
        frames, failures = await _load_frames(ctx, sources)
        findings = [_read_finding(source, problem) for source, problem in failures]
        findings.extend(_quality_findings(frames))
        failed = len(failures)
        if frames:
            bits = [_row_bit(frame) for frame in frames]
            summary = "profiled " + "; ".join(bits)
        else:
            summary = "no tabular source could be read"
        if failed:
            summary += f"; {failed} failed"
        stats = {"sources": [_frame_stats(frame) for frame in frames]}
        return Outcome(summary, findings, stats)


class PiiCheck:
    id = "pii"
    title = "PII patterns"
    category = Category.DATA

    async def run(self, ctx: ScanContext) -> Outcome:
        structured = [source for source in ctx.config.sources if source.kind in {"csv", "parquet", "postgres"}]
        documents = [source for source in ctx.config.sources if source.kind == "documents"]
        if not structured and not documents:
            raise Skip("no sources are configured")
        frames, failures = await _load_frames(ctx, structured)
        emails = 0
        phones = 0
        ssns = 0
        columns: set[str] = set()
        docs: set[str] = set()
        samples: set[str] = set()
        unscanned = [source.name for source, _problem in failures]

        for frame in frames:
            for row in frame.rows:
                for column in frame.columns:
                    cleaned = row.get(column)
                    if not isinstance(cleaned, str) or not cleaned.strip():
                        continue
                    for hit in scan_text(cleaned):
                        if hit.kind == "email":
                            emails += 1
                            if hit.sample:
                                samples.add(hit.sample)
                        elif hit.kind == "phone":
                            phones += 1
                        else:
                            ssns += 1
                        columns.add(f"{frame.source}.{column}")

        for source in documents:
            try:
                loaded, _truncated = await asyncio.wait_for(
                    asyncio.to_thread(read_documents, ctx.config.resolve(source.path or "")),
                    SOURCE_READ_SECONDS,
                )
            except TimeoutError:
                unscanned.append(source.name)
                continue
            except SourceProblem:
                unscanned.append(source.name)
                continue
            for document in loaded:
                if not document.text:
                    continue
                found = scan_text(document.text)
                if not found:
                    continue
                docs.add(Path(document.path).name)
                for hit in found:
                    if hit.kind == "email":
                        emails += 1
                        if hit.sample:
                            samples.add(hit.sample)
                    elif hit.kind == "phone":
                        phones += 1
                    else:
                        ssns += 1

        findings: list[Finding] = []
        total = emails + phones + ssns
        if total:
            findings.append(_pii_finding(emails, phones, ssns, columns, docs, samples))
        summary = f"{emails} emails, {phones} phone numbers, {ssns} SSN-like values"
        if unscanned:
            summary += "; not scanned: " + ", ".join(unscanned)
        return Outcome(
            summary,
            findings,
            {"emails": emails, "phones": phones, "ssn_like": ssns},
        )


class DocumentsCheck:
    id = "documents"
    title = "Document corpus"
    category = Category.DATA

    async def run(self, ctx: ScanContext) -> Outcome:
        sources = [source for source in ctx.config.sources if source.kind == "documents"]
        if not sources:
            raise Skip("no document sources are configured")
        findings: list[Finding] = []
        documents: list[DocumentFile] = []
        truncated = False
        for source in sources:
            path = ctx.config.resolve(source.path or "")
            try:
                loaded, cut = await asyncio.wait_for(
                    asyncio.to_thread(read_documents, path),
                    SOURCE_READ_SECONDS,
                )
            except TimeoutError:
                findings.append(
                    Finding(
                        severity=Severity.HIGH,
                        title=f"Could not read {source.name}",
                        summary=f"{source.name}: still running after {SOURCE_READ_SECONDS}s.",
                        remediation="Narrow the folder or raise the check timeout.",
                        location=str(path),
                    )
                )
                continue
            except SourceProblem as problem:
                findings.append(
                    Finding(
                        severity=Severity.HIGH,
                        title=f"Could not read {source.name}",
                        summary=str(problem),
                        remediation=problem.remediation,
                        location=problem.location,
                    )
                )
                continue
            documents.extend(loaded)
            truncated = truncated or cut

        if documents and not any(document.size for document in documents):
            findings.append(_empty_folder(documents[0]))
        elif not documents and not findings:
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    title="Document folder is empty",
                    summary="The configured folder has no files to embed.",
                    remediation="Put the corpus in that folder, or remove the source until it exists.",
                )
            )
        empty = [document for document in documents if document.size == 0]
        if empty and any(document.size for document in documents):
            findings.append(
                Finding(
                    severity=Severity.LOW,
                    title="Empty documents in the corpus",
                    summary=(
                        f"1 file is 0 bytes: {Path(empty[0].path).name}."
                        if len(empty) == 1
                        else f"{len(empty)} files are 0 bytes, including {Path(empty[0].path).name}."
                    ),
                    remediation="Remove empty files so they are not treated as documents.",
                    location=empty[0].path,
                )
            )

        tokens = sum(estimate_tokens(document.text or "") for document in documents if document.text)
        chunk_size = ctx.config.embedding.chunk_tokens
        chunks = 0 if tokens == 0 else (tokens + chunk_size - 1) // chunk_size
        rate = ctx.config.embedding.dollars_per_million_tokens
        cost = None if rate is None else tokens / 1_000_000 * rate
        budget = ctx.config.embedding.budget_usd
        if cost is not None and budget is not None and cost > budget:
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    title="Estimated embedding cost is over budget",
                    summary=f"The corpus estimates at {_money(cost)}, over the budget of {_money(budget)}.",
                    remediation=(
                        "Cut the corpus, raise embedding.budget_usd, "
                        "or lower the chunk size if the estimate is the problem."
                    ),
                )
            )
        suffixes = dict(sorted(Counter(document.suffix for document in documents).items()))
        unparsed = sum(1 for document in documents if document.text is None and document.size > 0)
        chunk_label = "chunk" if chunks == 1 else "chunks"
        summary = f"{len(documents)} files, {tokens} tokens (characters/4), {chunks} {chunk_label} of {chunk_size}"
        if cost is not None:
            summary += f", {_money(cost)}"
        if unparsed:
            summary += f", {unparsed} unparsed"
        if truncated:
            summary += "; file list truncated"
        stats: dict[str, object] = {
            "files": len(documents),
            "bytes": sum(document.size for document in documents),
            "tokens": tokens,
            "chunks": chunks,
            "suffixes": suffixes,
        }
        if cost is not None:
            stats["estimated_usd"] = round(cost, 6)
        return Outcome(summary, findings, stats)


def _read_finding(source: Source, problem: SourceProblem) -> Finding:
    return Finding(
        severity=Severity.HIGH,
        title=f"Could not read {source.name}",
        summary=str(problem),
        remediation=problem.remediation,
        location=problem.location,
    )


def _empty_folder(document: DocumentFile) -> Finding:
    return Finding(
        severity=Severity.MEDIUM,
        title="Document folder has no content",
        summary="Every file in the folder is empty.",
        remediation="Replace the placeholders before embedding.",
        location=str(Path(document.path).parent),
    )


async def _load_frames(
    ctx: ScanContext, sources: list[Source]
) -> tuple[list[TabularFrame], list[tuple[Source, SourceProblem]]]:
    if not sources:
        return [], []

    async def one(source: Source) -> tuple[Source, list[TabularFrame] | SourceProblem]:
        try:
            frames = await asyncio.wait_for(
                asyncio.to_thread(read_structured, ctx.config, source, dict(ctx.env)),
                SOURCE_READ_SECONDS,
            )
        except TimeoutError:
            return source, SourceProblem(
                f"{source.name}: still running after {SOURCE_READ_SECONDS}s",
                "Check the network path and query cost. Postgres reads set a statement timeout.",
            )
        except SourceProblem as problem:
            return source, problem
        return source, frames

    loaded = await asyncio.gather(*(one(source) for source in sources))
    frames: list[TabularFrame] = []
    failures: list[tuple[Source, SourceProblem]] = []
    for source, result in loaded:
        if isinstance(result, SourceProblem):
            failures.append((source, result))
        else:
            frames.extend(result)
    return frames, failures


def _quality_findings(frames: list[TabularFrame]) -> list[Finding]:
    findings: list[Finding] = []
    nulls = _null_finding(frames)
    if nulls is not None:
        findings.append(nulls)
    dates = _date_finding(frames)
    if dates is not None:
        findings.append(dates)
    dupes = _duplicate_finding(frames)
    if dupes is not None:
        findings.append(dupes)
    drift = _drift_finding(frames)
    if drift is not None:
        findings.append(drift)
    return findings


def _null_finding(frames: list[TabularFrame]) -> Finding | None:
    hot: list[str] = []
    textual: list[str] = []
    for frame in frames:
        total = len(frame.rows)
        if total == 0:
            continue
        for stat in column_stats(frame):
            if stat.nulls / total >= _NULL_RATE:
                hot.append(f"{frame.source}.{stat.name} {stat.nulls}/{total}")
            if stat.textual_nulls:
                textual.append(f"{frame.source}.{stat.name} {stat.textual_nulls}")
    if not hot and not textual:
        return None
    if hot:
        summary = "Nulls at or above 20% of the scanned rows: " + "; ".join(hot) + "."
        if textual:
            summary += " Textual nulls: " + "; ".join(textual) + "."
        return Finding(
            severity=Severity.MEDIUM,
            title="High null rates in the sample",
            summary=summary,
            remediation=(
                "Decide whether those columns are optional before you embed them. "
                "A textual NULL is stored as the word NULL unless the extractor normalizes it."
            ),
        )
    return Finding(
        severity=Severity.LOW,
        title="Textual nulls in the sample",
        summary="Cells used NULL, N/A, or similar: " + "; ".join(textual) + ".",
        remediation="Normalize those sentinels to empty before chunking, or they will be embedded as words.",
    )


def _date_finding(frames: list[TabularFrame]) -> Finding | None:
    notes: list[str] = []
    for frame in frames:
        for column, counts in date_formats(frame).items():
            used = [name for name, count in counts.items() if count]
            if len(used) > 1 or counts["other"]:
                rendered = ", ".join(f"{count} {name}" for name, count in counts.items() if count)
                notes.append(f"{frame.source}.{column} ({rendered})")
    if not notes:
        return None
    return Finding(
        severity=Severity.MEDIUM,
        title="Date columns are not in one format",
        summary="Mixed or unparsed dates: " + "; ".join(notes) + ".",
        remediation=(
            "Parse these columns into one timezone-aware format before chunking. Mixed formats sort and filter wrong."
        ),
    )


def _duplicate_finding(frames: list[TabularFrame]) -> Finding | None:
    notes: list[str] = []
    for frame in frames:
        dupes = duplicate_ids(frame)
        if dupes:
            shown = ", ".join(dupes[:5])
            extra = f" and {len(dupes) - 5} more" if len(dupes) > 5 else ""
            notes.append(f"{frame.source}: {shown}{extra}")
    if not notes:
        return None
    return Finding(
        severity=Severity.LOW,
        title="Duplicate ids in the sample",
        summary="; ".join(notes) + ".",
        remediation="Deduplicate on id before embedding, or the index will return the same record more than once.",
    )


def _drift_finding(frames: list[TabularFrame]) -> Finding | None:
    drifts = schema_drift(frames)
    if not drifts:
        return None
    notes = []
    for drift in drifts:
        parts = []
        if drift.missing:
            parts.append("missing " + ", ".join(drift.missing))
        if drift.extra:
            parts.append("extra " + ", ".join(drift.extra))
        notes.append(f"{drift.source} vs {drift.baseline}: " + "; ".join(parts))
    return Finding(
        severity=Severity.MEDIUM,
        title="Schema drift across sources that share a schema id",
        summary="; ".join(notes) + ".",
        remediation=(
            "Align the export with the table the app expects, or give the drifted file its own schema_id "
            "so it is not treated as the same shape."
        ),
        evidence={"schema_ids": sorted({item.schema_id for item in drifts})},
    )


def _pii_finding(
    emails: int,
    phones: int,
    ssns: int,
    columns: set[str],
    docs: set[str],
    samples: set[str],
) -> Finding:
    bits = []
    if emails:
        bits.append(f"{emails} emails")
    if phones:
        bits.append(f"{phones} phone numbers")
    if ssns:
        bits.append(f"{ssns} SSN-like values")
    where = []
    if columns:
        where.append("columns " + ", ".join(sorted(columns)))
    if docs:
        where.append("documents " + ", ".join(sorted(docs)))
    summary = ", ".join(bits) + "."
    if where:
        summary += " In " + "; ".join(where) + "."
    redact: dict[str, str] = {}
    if emails:
        redact["email"] = "keep the domain, replace the local part"
    if phones:
        redact["phone"] = "replace the whole value with ***-***-****"
    if ssns:
        redact["ssn"] = "replace the whole value with ***-**-****"
    title = "SSN-like patterns are in the embed corpus" if ssns else "Contact details are in the embed corpus"
    return Finding(
        severity=Severity.HIGH,
        title=title,
        summary=summary,
        remediation=(
            "Remove SSN-like values before this data leaves the environment. "
            "Mask emails if you still need the domain, and drop phone numbers. Do not embed the raw text."
        ),
        evidence={
            "emails": emails,
            "phones": phones,
            "ssn_like": ssns,
            "columns": sorted(columns),
            "documents": sorted(docs),
            "email_samples": sorted(samples)[:5],
            "redact": redact,
        },
    )


def _frame_stats(frame: TabularFrame) -> dict[str, object]:
    total = len(frame.rows)
    rates: dict[str, float] = {}
    textual: dict[str, int] = {}
    stat: ColumnStat
    for stat in column_stats(frame):
        if total and stat.nulls:
            rates[stat.name] = round(stat.nulls / total, 4)
        if stat.textual_nulls:
            textual[stat.name] = stat.textual_nulls
    body: dict[str, object] = {
        "name": frame.source,
        "kind": frame.kind,
        "rows": total,
        "columns": frame.columns,
        "location": frame.location,
    }
    if frame.total_rows is not None:
        body["total_rows"] = frame.total_rows
    if rates:
        body["null_rates"] = rates
    if textual:
        body["textual_nulls"] = textual
    return body


def _row_bit(frame: TabularFrame) -> str:
    rows = len(frame.rows)
    if frame.total_rows is not None and frame.truncated:
        return f"{frame.source} {rows}/{frame.total_rows} rows"
    return f"{frame.source} {rows} rows, {len(frame.columns)} columns"


def _money(value: float) -> str:
    rendered = f"${value:.6f}".rstrip("0").rstrip(".")
    if rendered.endswith("$"):
        return "$0"
    return rendered
