# US-07: Read a clear, actionable report

**Estimate:** M · **Depends on:** US-06 · **Decisions:** D8, D9

## Story

As a **security analyst on call**
I want **a short report that says what happened, how bad it is, where the evidence is, and what to do next**
so that **I can respond in minutes without searching the raw logs**.

## Description

Two renderers work from the same list of incidents.

### Text report (default)

Plain text, no colour codes by default so it pastes cleanly into tickets. Use colour only when stdout is a TTY and `NO_COLOR` is not set. Layout:

```
Security Log Analysis Report
Files: samples/webserver.log (33 lines), samples/auth.log (12 lines)
Events parsed: 44   Malformed lines: 1   Incidents: 6 (critical 2, high 2, medium 2)

[CRITICAL] 10.0.0.50 - correlated across webserver.log, auth.log
  10.0.0.50: login brute force on web and SSH, followed by successful login (2 sources, 10:00:03-10:00:07).
  Findings:
    - web-login-bruteforce  Web login brute force   5 events  ESCALATED
    - ssh-bruteforce        SSH password brute force 5 events  ESCALATED
  Evidence:
    webserver.log:3   10.0.0.50 - - [03/Jul/2025:10:00:03 +0000] "POST /login HTTP/1.1" 401 54
    ...
    auth.log:5        Jul  3 10:00:07 server sshd[1234]: Accepted password for admin from 10.0.0.50 ...
  Context:
    auth.log:12       Jul  3 10:00:25 server sshd[1245]: Connection closed by 10.0.0.50 port 52345 [preauth]
  Recommended actions:
    1. Block the IP, reset the password of the targeted account and review its sessions.
    2. ...

[CRITICAL] 203.0.113.5 - correlated across webserver.log, auth.log
...

Malformed lines (1):
  webserver.log:26  [MALFORMED ENTRY - system restart
```

Rules for the text output:

- Incidents in the correlator's order (severity, then time).
- Evidence capped at 5 lines per finding, followed by `... and N more`.
- Long lines cut to 160 characters with `…`, so terminal output stays readable.
- With no incidents, print `No suspicious activity found.` plus the parse stats.
- Show at most 10 malformed lines, then `... and N more`.

### JSON report (`--json`)

Stable schema with a `schema_version` field, so other tools can depend on it:

```json
{
  "schema_version": 1,
  "generated_at": "2026-11-23T10:00:00Z",
  "files": [{"path": "samples/webserver.log", "lines": 33}],
  "stats": {"events": 44, "malformed": 1, "incidents": 6, "by_severity": {"critical": 2, "high": 2, "medium": 2, "low": 0}},
  "incidents": [
    {
      "key": "10.0.0.50", "key_type": "ip", "severity": "critical", "correlated": true,
      "sources": ["auth.log", "webserver.log"],
      "first_seen": "2025-07-03T10:00:03+00:00", "last_seen": "2025-07-03T10:00:07+00:00",
      "summary": "...", "actions": ["..."],
      "findings": [
        {"rule_id": "web-login-bruteforce", "severity": "critical", "escalated": true, "count": 5,
         "evidence": [{"file": "webserver.log", "line": 3, "raw": "..."}]}
      ],
      "context": [{"file": "auth.log", "line": 12, "raw": "..."}]
    }
  ],
  "malformed": [{"file": "webserver.log", "line": 26, "raw": "[MALFORMED ENTRY - system restart"}]
}
```

Lists are sorted (sources alphabetically, evidence by file then line) so output is deterministic and easy to compare in tests. `generated_at` is the only field that changes between runs, and tests ignore it.

## Acceptance criteria

1. **Given** the sample files, **then** the text report header shows `Events parsed: 44   Malformed lines: 1   Incidents: 6`.
2. **Given** the sample files, **then** the first two incidents shown are `10.0.0.50` and `203.0.113.5`, both `[CRITICAL]`, both marked correlated.
3. Every evidence line shows `file:line` matching the real line in the sample file.
4. Every incident has at least one recommended action.
5. **Given** `--json`, **then** stdout is valid JSON (parsed by `json.loads` in the test) with `schema_version: 1` and the same incident keys and severities as the text report.
6. **Given** clean input, **then** the text report says `No suspicious activity found.` and the exit code is `0`.
7. With stdout not a TTY, the text output contains no ANSI escape codes.

## Tasks

### T-07.1 Text renderer
`render_text(incidents, stats, files, *, color: bool) -> str`. Returning a string (instead of printing) keeps it easy to test.
*Files:* `loganalyzer/report.py`
*Test:* `tests/test_report.py`: header numbers, incident order, evidence cap and `... and N more`, line truncation, empty report, no ANSI codes when `color=False`.

### T-07.2 JSON renderer
`render_json(...) -> str` using `json.dumps(indent=2, sort_keys=False)`, built from plain dicts. Datetimes are written as ISO 8601.
*Files:* `loganalyzer/report.py`
*Test:* round-trip with `json.loads`; schema keys present; sorted lists; ignore `generated_at` when comparing.

### T-07.3 Wire into the CLI
`cli.main` runs read → parse → detect → correlate → render, prints to stdout, sends errors to stderr, and returns exit code `1` if there are incidents, otherwise `0`. Colour is on only when `sys.stdout.isatty()` and `NO_COLOR` is not set.
*Files:* `loganalyzer/cli.py`
*Test:* `tests/test_cli.py` calls `main([...])` with `capsys` and checks stdout, stderr and the exit code.

### T-07.4 Action texts review
Read every `action` in `rules.toml` and check it is a concrete next step (what to block, reset, check), not a restatement of the finding.
*Files:* `loganalyzer/rules.toml`
*Test:* a unit test asserting every rule has a non-empty `action` of at least 20 characters; the wording itself is checked in review.

## Out of scope

- HTML, CSV or SIEM-specific formats (the JSON output is the integration point)
- Sending alerts (email, Slack); exit code `1` lets a wrapper script do it
