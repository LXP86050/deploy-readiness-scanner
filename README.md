# deploy-readiness-scanner

The `drs` CLI is a preflight an engineer runs inside a customer's environment before an LLM system is turned on.

[![ci](https://img.shields.io/github/actions/workflow/status/LXP86050/deploy-readiness-scanner/ci.yml?branch=main&label=ci&style=flat)](https://github.com/LXP86050/deploy-readiness-scanner/actions/workflows/ci.yml)
[![license](https://img.shields.io/github/license/LXP86050/deploy-readiness-scanner?style=flat)](LICENSE)

The usual failure is not the model. It is the environment: the API is on the wrong side of a proxy, the export the job will embed still has phone numbers in it, the database URL is the superuser, or a config file that will ship with the service has a key in it. `drs` reads a `drs.yaml` for that environment, runs a set of checks, and writes a report with a score per category and a remediation for each finding. The process exit code is meant to fail a CI job.

Checks are plugins. The built-in ones cover connectivity, data, the host, and a few security settings. A team adds its own by publishing an entry point.

## Architecture

```mermaid
flowchart TB
  cfg[drs.yaml] --> loader[config loader]
  env[process environment] --> ctx[ScanContext]
  loader --> ctx
  points[drs.checks entry points] --> engine[async engine]
  ctx --> engine
  engine --> pool[checks, bounded concurrency]
  pool --> net[HTTP, DNS, TLS]
  pool --> data[CSV, Parquet, Postgres, documents]
  pool --> host[CPU, memory, listeners, files]
  pool --> results[results, including timeouts]
  results --> score[category scores and gate]
  score --> term[terminal]
  score --> html[HTML]
  score --> json[JSON]
  score --> sarif[SARIF]
```

Each check has its own timeout. A check that raises or runs past the scan budget is recorded as an error or a timeout, and the report is still written. A category is scored only when at least one of its checks actually ran. Skipped checks, which means the config had nothing for them to look at, stay out of the gate.

## Quickstart

Requires Python 3.11+ and, for the demo, Docker.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
make demo
```

`make demo` builds a parquet file from the sample CSV, starts Postgres and a local OpenAI-compatible HTTP server, and runs `drs scan` against `demo/drs.yaml`. The fixture is supposed to fail the gate. On the run below the exit code was 2. Reports land in `demo/out/`.

To scan another environment:

```bash
drs scan --config /path/to/drs.yaml \
  --html report.html \
  --json report.json \
  --sarif report.sarif
```

`--only` and `--exclude` replace `checks.include` and `checks.exclude`. `--min-score` replaces `thresholds.min_category_score`. `drs list-checks` prints the checks this install can run.

Paths in the config are resolved relative to the config file, not the working directory.

## Sample config

The file that produced the report below is [`demo/drs.yaml`](demo/drs.yaml):

```yaml
name: northwind-support
environment: staging

residency:
  region: us
  allowed: [us, local]

thresholds:
  min_category_score: 70
  fail_on: blocker

concurrency: 8

timeouts:
  default_seconds: 30
  scan_seconds: 90

credentials:
  required_env: [LLM_API_KEY, DATABASE_URL]
  optional_env: [OPENAI_ADMIN_KEY]

proxy:
  expect_proxy: false

endpoints:
  - name: llm
    url: http://127.0.0.1:18089/health
  - name: vector
    url: http://127.0.0.1:18089/vector/health

llm:
  url: http://127.0.0.1:18089/v1/chat/completions
  api_key_env: LLM_API_KEY
  model: mock-small
  requests: 5
  timeout_seconds: 8

sources:
  - name: tickets-csv
    kind: csv
    path: data/tickets.csv
    schema_id: tickets
    sample_limit: 1000
  - name: tickets-week2
    kind: csv
    path: data/tickets_week2.csv
    schema_id: tickets
    sample_limit: 1000
  - name: tickets-parquet
    kind: parquet
    path: data/tickets.parquet
    schema_id: tickets
    sample_limit: 1000
  - name: tickets-db
    kind: postgres
    url_env: DATABASE_URL
    schema_id: tickets
    tables: [tickets]
    sample_limit: 1000
  - name: policy-docs
    kind: documents
    path: data/docs

embedding:
  chunk_tokens: 512
  dollars_per_million_tokens: 0.02
  budget_usd: 5

runtime:
  min_python: "3.11"
  require_cuda: false
  min_memory_mb: 256

security:
  env_files:
    - customer.env
  scan_paths:
    - config
  listeners:
    - name: postgres
      port: 55432
      public_ok: false
    - name: llm
      port: 18089
      public_ok: false
  prompt_logging:
    stores_prompts: true
    destination: stdout

checks:
  include: []
  exclude: []
```

`min_python` has to be quoted. Unquoted `3.11` is a YAML float. Unknown keys are errors, so a typo does not silently drop a section. Postgres sources require `tables`; the scanner will not walk every table in a customer database on its own.

## Scores and exit codes

A category starts at 100. Findings remove points: blocker 40, high 20, medium 10, low 4, info 0. A check that times out or raises removes another 15, and its findings are whatever it managed to return before that, which is usually nothing. The floor is `thresholds.min_category_score` (70 in the sample). `fail_on` is `blocker`, `high`, or `medium`: any finding at that severity or worse fails the gate even if the score is still above the floor.

| Exit | Meaning |
| --- | --- |
| 0 | Every assessed category is at least the floor, and nothing at or above the gate was found. |
| 1 | The config is invalid, or no check assessed anything. |
| 2 | The gate failed. |
| 3 | Some checks did not finish, and the findings that did come back would have passed. |

Exit 3 is not a pass. A job that treats only 0 as success will refuse a partial scan.

## Demo report

This is the terminal output from one `make demo` run, including the line wraps from that console. Durations, the latency percentiles, and the free-memory figure are from that process and will differ on another machine. The row counts, null counts, PII counts, token estimate, and dollar figure are what the scanner computed from `demo/data` and the seeded Postgres table. The exit code was 2.

```
northwind-support  staging  not ready
1 finding at or above the gate; below 70: data 42, security 10

category      score
connectivity     82  #############---
data             42  #######---------
runtime         100  ################
security         10  ##--------------

check           status   ms  summary
credentials     ok        0  2 required variables set
dns_tls         ok       35  resolved 1 host
endpoint_reach  ok       54  2/2 endpoints responded as expected
proxy_egress    ok        0  no proxy is set
data_profile    ok      156  profiled tickets-csv 13 rows, 6 columns;
                             tickets-week2 4 rows, 6 columns; tickets-parquet 13
                             rows, 6 columns; tickets-db 8 rows, 6 columns
documents       ok       33  6 files, 260 tokens (characters/4), 1 chunk of 512,
                             $0.000005, 1 unparsed
pii             ok      157  10 emails, 7 phone numbers, 5 SSN-like values
host_runtime    ok        1  Python 3.12.3, 4 CPUs, 4788 MB available, not in a
                             container, CUDA not required
llm_probe       ok      261  5/5 ok, p50 58.3 ms, p95 74.4 ms, remaining 55
env_secrets     ok        0  scanned 2 files, 2 with secret-like assignments
listeners       ok        1  public: postgres (55432), llm (18089)
prompt_logging  ok        0  prompts are stored
residency       ok        0  3 endpoint(s) match the residency policy

blocker  env_secrets  Secret-like value outside an env file
  /workspace/demo/config/app.yaml assigns api_key.
  Remove the value from the file and rotate it. Load it from the environment or
a secret store.

high     env_secrets  Env file is readable beyond its owner
  /workspace/demo/customer.env (mode 0o644) references LLM_API_KEY,
OPENAI_ADMIN_KEY, DATABASE_URL. Group or others can read it.
  chmod 600 the file, keep it out of the image and out of git, and rotate
anything that was world-readable.

high     listeners  Listeners are bound to every interface
  These ports are reachable beyond loopback: postgres (55432), llm (18089).
  Bind them to 127.0.0.1 or a private address, or set public_ok if that exposure
is intentional.

high     pii  SSN-like patterns are in the embed corpus
  10 emails, 7 phone numbers, 5 SSN-like values. In columns tickets-csv.body,
tickets-db.body, tickets-parquet.body, tickets-week2.body; documents runbook.md.
  Remove SSN-like values before this data leaves the environment. Mask emails if
you still need the domain, and drop phone numbers. Do not embed the raw text.

medium   credentials  DATABASE_URL uses a superuser
  DATABASE_URL logs in as postgres.
  Create a role with SELECT on the profiled tables and put that user in the URL.
The app should not share a superuser.

medium   data_profile  High null rates in the sample
  Nulls at or above 20% of the scanned rows: tickets-csv.priority 4/13;
tickets-week2.priority 1/4; tickets-week2.sentiment 1/4;
tickets-parquet.priority 4/13. Textual nulls: tickets-csv.priority 1;
tickets-csv.body 1; tickets-parquet.priority 1; tickets-parquet.body 1.
  Decide whether those columns are optional before you embed them. A textual
NULL is stored as the word NULL unless the extractor normalizes it.

medium   data_profile  Date columns are not in one format
  Mixed or unparsed dates: tickets-csv.opened_at (11 iso, 1 us, 1 other);
tickets-week2.opened_at (3 iso, 1 us); tickets-parquet.opened_at (11 iso, 1 us,
1 other).
  Parse these columns into one timezone-aware format before chunking. Mixed
formats sort and filter wrong.

medium   data_profile  Schema drift across sources that share a schema id
  tickets-week2 vs tickets-csv: missing channel; extra sentiment.
  Align the export with the table the app expects, or give the drifted file its
own schema_id so it is not treated as the same shape.

medium   prompt_logging  Prompts are configured to be stored
  This environment (staging) stores prompts. Destination: stdout.
  Stop storing prompts, or redact them and keep them in the residency region
with a retention limit. stdout in a shared cluster ends up in the log pipeline.

low      credentials  OPENAI_ADMIN_KEY looks like a broad credential
  The variable name OPENAI_ADMIN_KEY suggests an admin or root credential.
  Use a key scoped to the model and project this deploy needs, and keep the
admin key out of the app environment.

low      data_profile  Duplicate ids in the sample
  tickets-csv: 1001; tickets-parquet: 1001.
  Deduplicate on id before embedding, or the index will return the same record
more than once.

low      dns_tls  Endpoint is not using TLS
  Plain HTTP: llm (http://127.0.0.1:18089/health); vector
(http://127.0.0.1:18089/vector/health); llm
(http://127.0.0.1:18089/v1/chat/completions).
  Terminate TLS before this URL leaves the laptop. Local HTTP is only reasonable
for a demo.

low      documents  Empty documents in the corpus
  1 file is 0 bytes: empty.txt.
  Remove empty files so they are not treated as documents.
```

The HTML report is a single file with the same findings and the per-check stats. JSON is the full document (`schema` 1). SARIF 2.1.0 carries each finding as a result and each timed-out or failed check as a tool notification. `executionSuccessful` is false when the scan is partial. The exit code, not the SARIF flag, is the gate: a finished scan that is not ready still executed.

Secret values are not part of the report. The demo's API keys and the database password were checked against `demo/out/report.json`, the HTML, and the SARIF from this run and were absent. A Postgres URL is printed with the password replaced, for example `postgresql+psycopg://postgres:[redacted]@127.0.0.1:55432/support`. The names of the variables are reported on purpose.

The PII in the fixture is synthetic (`.example` addresses, `555` numbers, and SSN-shaped strings). Email samples in the JSON keep the domain and replace the local part (`a***@northwind.example`). Phone numbers and SSN-like values are counted, not copied.

## Writing a check

A check is an object with `id`, `title`, `category`, and an async `run`. Raise `Skip` when the config has nothing for it to do. That does not fail the gate. Return an `Outcome` otherwise. Put the interesting numbers in `stats` and the problems in `findings`. Read environment variables from `ctx.env` or `ctx.env_value`, not `os.environ`, so the same snapshot is what the report scrubber sees.

`examples/budget_check.py` is a complete check. It is not registered by this package. To ship it, point an entry point at the class. The entry point name has to equal `id`:

```toml
[project.entry-points."drs.checks"]
embedding_budget = "budget_check:EmbeddingBudgetCheck"
```

```python
from drs.context import ScanContext
from drs.sdk import Category, Finding, Outcome, Severity

class EmbeddingBudgetCheck:
    id = "embedding_budget"
    title = "Embedding budget"
    category = Category.DATA

    async def run(self, ctx: ScanContext) -> Outcome:
        budget = ctx.config.embedding.budget_usd
        if budget is None:
            return Outcome(
                summary="no embedding budget is configured",
                findings=[
                    Finding(
                        severity=Severity.MEDIUM,
                        title="Embedding spend is uncapped",
                        summary="embedding.budget_usd is not set, so a large corpus has no ceiling.",
                        remediation=(
                            "Set embedding.budget_usd to the amount the account owner will pay. "
                            "The document check compares its token estimate to that number."
                        ),
                    )
                ],
            )
        return Outcome(summary=f"embedding budget is ${budget:g}", stats={"budget_usd": budget})
```

Built-in check ids: `credentials`, `endpoint_reach`, `dns_tls`, `proxy_egress`, `data_profile`, `pii`, `documents`, `host_runtime`, `llm_probe`, `env_secrets`, `listeners`, `residency`, `prompt_logging`.

## Tradeoffs

Checks run at the same time, up to `concurrency`, each with its own timeout, and the whole scan stops at `timeouts.scan_seconds`. Inside `data_profile` and `pii`, each source is read on a worker thread with an 8 second cap. Postgres connections also set `statement_timeout` to 8 seconds. `pii` reads the sources again rather than sharing a cache with `data_profile`. A shared in-flight read is easy to cancel by accident when one waiter times out, and reading a thousand-row sample twice is cheap next to that bug.

The score is a deduction table, not a weighted model of risk. Splitting one problem into many findings would punish it more than once, so the built-in checks emit one finding per issue and list the sources in the evidence. A blocker in a checked-in config file and a high PII finding are different findings because they are different problems.

Credential checks record that a variable is set and a length bucket (`32-63`, and so on). They do not record a prefix. Several vendors put an account id in the prefix.

## Limitations

PII detection is three regular expressions: an email, a NANP-style phone number, and a `\d{3}-\d{2}-\d{4}` pattern. It misses names, non-US identifiers, and phones written as digits with no separator. It will flag an order number that happens to look like an SSN. The finding says so by calling them SSN-like.

Token counts are `len(text) // 4`. That is not a model tokenizer. PDF and docx files are counted in the size distribution and are not parsed, so they add no tokens. The dollar figure is `tokens / 1_000_000 * embedding.dollars_per_million_tokens` and nothing else.

TLS inspection uses the process trust store. There is no setting for a private CA bundle. Certificate dates come from the leaf the server presented; a failed verify still reports expiry when the handshake can be completed without verification.

Listener inspection reads `/proc/net/tcp` and `/proc/net/tcp6`. It does not scan the network, and it does not work on a host without those files. Region checks look for a region token in the hostname (`eu-west-1`, `eastus`, and a short list of others). `api.openai.com` carries no region, and the check says that instead of guessing.

Schema drift compares column names for sources that share a `schema_id`. It does not compare types. Null rates are computed on the scanned sample, not on the whole table, except that Postgres also runs `count(*)`. Empty strings and the words `NULL`, `N/A`, `none`, `na`, and `nil` count as nulls. A textual null is called out because it will be embedded as a word if nobody normalizes it.

The secret scan looks at configured env files and at a capped walk of `scan_paths` (500 files, 1 MB each, skipping binaries). It reports key names. A value that contains parentheses is ignored so that a line of code is not treated as a password. That heuristic will miss a secret that happens to include them.

`asyncio.to_thread` cannot kill a stuck read. The connect timeout and the Postgres statement timeout are what actually bound a database call. A hung local disk read can outlive the check.

## Roadmap

- A saved report to diff against the next scan, so a customer visit has a baseline.
- Source plugins for object storage and warehouses. The entry point is the extension point; the core should not grow a client for each of them.
- A path to a customer CA bundle for the TLS check.
- Streaming profiles for files that should not be held in memory.

## Development

```bash
make lint
make test
```

`make lint` runs ruff and mypy. `make test` runs pytest with a coverage floor of 85 percent. Tests talk to local sockets and an in-memory SQLite database. They do not need Docker. The CI workflow runs the same checks on Python 3.11 and 3.12.

## License

MIT. See [LICENSE](LICENSE).
