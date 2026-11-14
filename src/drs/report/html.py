from __future__ import annotations

import json
from html import escape

from drs.models import SEVERITY_RANK, CategoryScore, CheckResult, Finding, Report, iter_findings

_CSS = """
:root {
  --ink: #221e1a;
  --muted: #6d655c;
  --paper: #f3efe6;
  --panel: #faf7f1;
  --rule: #ddd4c6;
  --ready: #1e6b45;
  --not_ready: #9c3412;
  --partial: #8a6414;
  --blocker: #8f2d2d;
  --high: #9a4e12;
  --medium: #8a6414;
  --low: #2d5d50;
  --info: #6d655c;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--paper);
  color: var(--ink);
  font: 17px/1.5 "Iowan Old Style", Palatino, Georgia, serif;
}
main { max-width: 880px; margin: 0 auto; padding: 48px 24px 80px; }
header { border-bottom: 1px solid var(--ink); padding-bottom: 20px; }
.brand {
  margin: 0;
  letter-spacing: 0.14em;
  text-transform: uppercase;
  font: 12px/1.2 ui-monospace, Menlo, Consolas, monospace;
  color: var(--muted);
}
h1 { margin: 8px 0 0; font-size: 40px; font-weight: 600; letter-spacing: -0.03em; }
.meta, .reason { color: var(--muted); margin: 8px 0 0; }
.verdict { margin: 18px 0 0; font-size: 22px; font-weight: 600; text-transform: capitalize; }
.verdict.ready { color: var(--ready); }
.verdict.not_ready { color: var(--not_ready); }
.verdict.partial { color: var(--partial); }
.banner {
  margin-top: 16px;
  padding: 8px 12px;
  border: 1px solid var(--partial);
  color: var(--partial);
  font: 13px/1.4 ui-monospace, Menlo, Consolas, monospace;
}
h2 {
  margin: 36px 0 12px;
  font-size: 13px;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  font-weight: 600;
}
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; padding: 7px 8px 7px 0; vertical-align: baseline; }
th {
  font: 12px/1.2 ui-monospace, Menlo, Consolas, monospace;
  color: var(--muted);
  font-weight: 500;
  border-bottom: 1px solid var(--rule);
}
td { border-bottom: 1px solid var(--rule); }
.num, .mono, .stats, .evidence dd { font: 13px/1.45 ui-monospace, Menlo, Consolas, monospace; }
.bar { display: inline-block; width: 128px; height: 8px; background: #e4ddd0; }
.bar i { display: block; height: 8px; background: var(--ready); }
.bar.weak i { background: var(--not_ready); }
.finding { padding: 16px 0 16px 14px; border-top: 1px solid var(--rule); border-left: 3px solid var(--rule); }
.finding.blocker { border-left-color: var(--blocker); }
.finding.high { border-left-color: var(--high); }
.finding.medium { border-left-color: var(--medium); }
.finding.low { border-left-color: var(--low); }
.finding h3 { margin: 0; font-size: 18px; }
.kicker { margin: 0 0 4px; font: 12px/1.2 ui-monospace, Menlo, Consolas, monospace; color: var(--muted); }
.remediation { margin: 10px 0 0; }
.evidence { margin: 10px 0 0; }
.evidence div { display: grid; grid-template-columns: 140px 1fr; gap: 8px; }
.evidence dt { color: var(--muted); }
.evidence dd { margin: 0; overflow-wrap: anywhere; }
footer { margin-top: 40px; color: var(--muted); font-size: 14px; }
@media print {
  body { background: white; }
  main { padding: 0; }
}
"""


def render_html(report: Report) -> str:
    findings = sorted(iter_findings(report), key=lambda item: (SEVERITY_RANK[item.severity], item.check_id))
    banner = ""
    if report.partial:
        banner = '<p class="banner">Some checks timed out or failed. Scores use only what finished.</p>'
    meta = f"{escape(report.environment)} · {escape(report.started_at.isoformat())} · drs {escape(report.version)}"
    body = f"""<main>
<header>
<p class="brand">Deploy readiness</p>
<h1>{escape(report.target_name)}</h1>
<p class="meta">{meta}</p>
<p class="verdict {report.verdict.value}">{escape(report.verdict.value.replace("_", " "))}</p>
<p class="reason">{escape(report.reason)}</p>
{banner}
</header>
<h2>Categories</h2>
<table>
<thead><tr><th>Category</th><th>Score</th><th></th></tr></thead>
<tbody>
{"".join(_score_row(report, score) for score in report.scores)}
</tbody>
</table>
<h2>Findings</h2>
{"".join(_finding(item) for item in findings) or "<p>No findings.</p>"}
<h2>Checks</h2>
<table>
<thead><tr><th>Check</th><th>Status</th><th>ms</th><th>Summary</th></tr></thead>
<tbody>
{"".join(_check_row(result) for result in report.checks)}
</tbody>
</table>
<footer>
<p>{escape(report.config_path)}</p>
<p>Finished {escape(report.finished_at.isoformat())}. Floor {report.floor}. Exit {report.exit_code}.</p>
</footer>
</main>"""
    title = escape(report.target_name)
    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>{title} readiness</title>\n<style>{_CSS}</style>\n</head>\n<body>\n"
        f"{body}\n</body>\n</html>\n"
    )


def _score_row(report: Report, score: CategoryScore) -> str:
    if score.score is None:
        return "<tr><td>" + escape(score.category.value) + '</td><td class="num">n/a</td><td></td></tr>'
    width = max(0, min(100, score.score))
    weak = " weak" if score.score < report.floor else ""
    bar = f'<span class="bar{weak}"><i style="width:{width}%"></i></span>'
    return f'<tr><td>{escape(score.category.value)}</td><td class="num">{score.score}</td><td>{bar}</td></tr>'


def _check_row(result: CheckResult) -> str:
    return (
        "<tr>"
        f'<td class="mono">{escape(result.check_id)}</td>'
        f'<td class="mono">{escape(result.status.value)}</td>'
        f'<td class="num">{result.duration_ms}</td>'
        f"<td>{escape(result.summary)}</td>"
        "</tr>"
    )


def _finding(finding: Finding) -> str:
    evidence = finding.evidence or {}
    rows = []
    for key, value in evidence.items():
        rendered = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
        rows.append(f"<dt>{escape(str(key))}</dt><dd>{escape(rendered)}</dd>")
    extra = f'<dl class="evidence"><div>{"".join(rows)}</div></dl>' if rows else ""
    location = f'<p class="mono">{escape(finding.location)}</p>' if finding.location else ""
    category = finding.category.value if finding.category else ""
    return (
        f'<article class="finding {finding.severity.value}">'
        f'<p class="kicker">{escape(finding.severity.value)} · {escape(finding.check_id)} · {escape(category)}</p>'
        f"<h3>{escape(finding.title)}</h3>"
        f"<p>{escape(finding.summary)}</p>"
        f'<p class="remediation">{escape(finding.remediation)}</p>'
        f"{location}{extra}"
        "</article>"
    )
