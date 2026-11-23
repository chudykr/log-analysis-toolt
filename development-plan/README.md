# Development Plan: Security Log Analysis Tool

## Goal

A command-line tool that reads one or more log files (`webserver.log`, `auth.log`), finds suspicious activity using configurable rules, links findings that come from the same source across files, and prints a report someone can act on.

Two rules guide every story:

1. **Super simple to use.** One command, no required flags, nothing to install beyond Python.
2. **Quality first.** Every story ships with tests. An end-to-end test runs the tool on the sample logs and checks the exact findings.

## How the tool will be used

```bash
python -m loganalyzer samples/webserver.log samples/auth.log          # human-readable report
python -m loganalyzer samples/*.log --json > findings.json            # machine-readable
python -m loganalyzer samples/*.log --rules my-rules.toml             # custom rules
```

Exit codes: `0` no findings, `1` findings, `2` usage or input error.

## Design decisions

All stories refer to these decisions. Change them here first, then update the affected stories.

| # | Topic | Decision | Why |
|---|---|---|---|
| D1 | Usage | `python -m loganalyzer FILE [FILE ...]`; optional flags `--rules`, `--json`, `--year` | Simple to use |
| D2 | Runtime | Python 3.11+, standard library only (`argparse`, `re`, `tomllib`, `dataclasses`, `json`) | Nothing to install to run it |
| D3 | Format detection | Each line is matched against the known parsers in order; no `--format` flag | One command works for any mix of files |
| D4 | Rules | Default `loganalyzer/rules.toml` ships with the tool; `--rules` replaces it | Configurable without code changes |
| D5 | Rule types | `pattern` (regex on one event field) and `threshold` (N matching events per key inside a time window) | Two types cover every case in the samples |
| D6 | Volume | Files are read line by line through generators; threshold state lives in per-key `deque`s that drop events older than the window | Memory stays flat as file size grows |
| D7 | Bad input | Malformed lines are counted and listed in the report; they never stop the run | The sample contains one |
| D8 | Output | Text by default, `--json` on request; incidents grouped by source and sorted by severity | Clear and actionable |
| D9 | Exit codes | `0` / `1` / `2` as above | Usable in CI pipelines and cron jobs |
| D10 | Tests | `pytest` (only dev dependency), `pytest-cov` for coverage; unit tests per module plus an e2e test on the sample logs | Basic but meaningful coverage |
| D11 | Extensibility | Parsers are registered in a list; adding a format means adding one parser function and its tests | "Evolving environment" |
| D12 | Continuous mode | For now batch only: continuous processing means scheduled runs (e.g. cron). The live mode in US-10 (`--follow`, stdin, gzip, findings as they happen) is planned but its implementation is deferred | Decided 2026-11-23: not needed for now |

## Code layout (target)

```
loganalyzer/
  __init__.py
  __main__.py        # entry point: python -m loganalyzer
  cli.py             # argument parsing, wiring, exit codes
  models.py          # Event, Finding, Incident dataclasses
  parsers.py         # webserver + auth parsers, parser registry, file reader
  rules.py           # TOML loading and validation
  rules.toml         # default rules
  detector.py        # pattern + threshold engine
  correlator.py      # groups findings into incidents across files
  report.py          # text and JSON renderers
samples/
  webserver.log      # copied verbatim from qa-assessment.md
  auth.log
tests/
  conftest.py
  test_parsers.py  test_rules.py  test_detector.py
  test_correlator.py  test_report.py  test_cli.py  test_e2e.py
pyproject.toml
README.md
```

## User stories

| ID | Story | Estimate | Depends on |
|---|---|---|---|
| [US-01](US-01-run-with-one-command.md) | Run the tool with one command on one or more files | S | – |
| [US-02](US-02-parse-webserver-log.md) | Parse the web server access log | M | US-01 |
| [US-03](US-03-parse-auth-log.md) | Parse the auth log | M | US-01 |
| [US-04](US-04-configurable-rules.md) | Configure detection rules without touching code | M | US-01 |
| [US-05](US-05-detect-suspicious-activity.md) | Detect suspicious activity | L | US-02, US-03, US-04 |
| [US-06](US-06-correlate-across-files.md) | Correlate findings across files | M | US-05 |
| [US-07](US-07-actionable-report.md) | Read a clear, actionable report | M | US-06 |
| [US-08](US-08-test-coverage-and-e2e.md) | Trust the tool through tests (unit + e2e) | M | runs alongside all stories; e2e after US-07 |
| [US-09](US-09-docs-and-submission.md) | Understand and submit the tool | S | US-07 |
| [US-10](US-10-continuous-production-mode.md) | Run continuously on live, high-volume logs (**planned, implementation deferred**) | L | US-05, US-07 |

Estimates: **S** under half a day, **M** about one day, **L** one to two days.

### Suggested order

```
US-01 ─┬─ US-02 ─┐
       ├─ US-03 ─┼─ US-05 ── US-06 ── US-07 ── US-09
       └─ US-04 ─┘
US-08: unit tests are written inside each story; the e2e and volume tests are finished after US-07.
US-10: planned, implemented later (after US-09); it adds its own follow-mode and long-run memory tests.
```

US-02, US-03 and US-04 can be worked on in parallel.

## Requirement coverage

| Requirement in `qa-assessment.md` | Covered by |
|---|---|
| Input: one or more log files | US-01 |
| Parsing: handle the provided formats | US-02, US-03 |
| Detection: configurable rules | US-04, US-05 |
| Output: clear, actionable format | US-07 |
| Process both files and correlate findings | US-06, US-08 (e2e) |
| Production context: high volume | D6, US-02/03 (streaming), US-05 (bounded windows), US-08 (volume smoke test) |
| Production context: continuously | Now: scheduled batch runs, exit codes and JSON for automation (US-01, US-07). Later: live mode, US-10 (D12) |
| Production context: evolving environment | D4, D11, US-04 (rules without code changes), malformed lines reported (US-02/03); later US-10 (warning when the log format changes) |
| README explaining how to run | US-09 |
| AI conversation history | US-09 |

## Expected findings on the sample logs

This table is the reference for the e2e test (US-08) and was checked line by line against `qa-assessment.md`.

| Source | Finding | Rule ID | Severity |
|---|---|---|---|
| `10.0.0.50` | 4 × `POST /login` 401 then 200 at 10:00:03–07 | `web-login-bruteforce` | high → **critical** (success followed) |
| `10.0.0.50` | 4 × SSH `Failed password for admin` then `Accepted password` at 10:00:03–07 | `ssh-bruteforce` | high → **critical** (success followed) |
| `10.0.0.50` | Seen in both files: one correlated incident | correlation | **critical** |
| `203.0.113.5` | `/admin`, `/admin/`, `/admin/config` all 403 at 10:00:09–11 | `admin-probing` | medium |
| `203.0.113.5` | `GET /admin/../../../etc/passwd` | `path-traversal` | high |
| `203.0.113.5` | SSH invalid users `test`, `root`, `ubuntu` at 10:00:09–11 | `ssh-invalid-users` | medium |
| `203.0.113.5` | Seen in both files: one correlated incident | correlation | high → **critical** (cross-file boost, US-06) |
| `10.0.0.88` | `UNION SELECT` and `DROP TABLE` in `/search?q=` | `sql-injection` | high |
| `172.16.0.20` | 6 sensitive paths in 2 s (`/admin`, `/phpmyadmin`, `/wp-admin`, `/administrator`, `/.env`, `/config.php`) | `sensitive-path-scan` | medium |
| `10.0.0.99` | 5 × `POST /api/users` in 2 s | `request-flood` | medium |
| `10.0.0.99` | Server answered 429 Too Many Requests | `rate-limited` | low (same incident as above) |
| `johndoe` | `sudo` to root running `/bin/cat /etc/shadow` | `sensitive-sudo` | high |
| `webserver.log:26` | `[MALFORMED ENTRY - system restart` | parse stats | – |

Must **not** produce findings:

- `192.168.1.14` with `q=O'Brien` (a legitimate apostrophe, the false-positive guard for SQL injection)
- `deploy` running `sudo systemctl restart nginx`, and `Accepted publickey for deploy`
- Normal traffic from `192.168.1.10`–`.13`, `.15`–`.18`
- `Connection closed by 10.0.0.50 ... [preauth]` (shown as context in the 10.0.0.50 incident only, no separate finding)

## Known limitations (accepted for this version)

- `auth.log` lines carry no year and no timezone. The tool uses `--year` (default: current year) and assumes UTC, so both files line up on the sample data. Correlation is by source IP, and the time span of each side is shown so the reader can judge.
- Batch only until US-10 is implemented. With scheduled runs, a threshold window does not span two runs.
- No state is saved between restarts, and the tool runs as one process. Scaling beyond one machine (log shipper in front, split by source IP, JSON into a SIEM) is described in the README, not built.
- Detection is rule-based only: no anomaly scoring and no IP reputation lookups.

## Definition of Done (every story)

- Acceptance criteria met and checked by an automated test where possible
- `pytest --cov` passes locally (all tests run locally; no CI for now)
- New code has unit tests; overall line coverage stays at 85% or higher
- No new runtime dependencies (D2)
- README updated if usage or rules changed
- Code reviewed (or self-reviewed against this checklist), with a short PR description
