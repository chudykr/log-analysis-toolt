# US-10: Run continuously on live, high-volume logs

> **Status: planned, implementation deferred.** Decided on 2026-11-23 that the implementation is not needed for now. Until it is built, the tool is batch-only and continuous processing means scheduled runs (see the root README, "Production notes"). Implement it only when the user asks.

**Estimate:** L · **Depends on:** US-05 (detector), US-07 (output formats) · **Decisions:** D6, D9, D11, D12

## Story

As a **platform / security operations engineer**
I want **to run the tool continuously on growing and rotated log files and get findings as they happen**
so that **it can be deployed as a long-running detector that feeds alerting, without memory growth or silent failures**.

## Description

The assessment's production context says the tool "may be deployed in an evolving environment processing high volumes of log data continuously". US-01 to US-07 already cover part of this: streaming reads, single-pass detection, bounded windows, configurable rules, and a parser registry. This story closes the remaining gaps without changing the simple default: `python -m loganalyzer FILE...` still runs once and prints a report. Everything below is opt-in.

### 1. More input sources

| Input | How | Notes |
|---|---|---|
| stdin | `-` as a file name, e.g. `tail -F /var/log/auth.log \| loganalyzer -` | Shown as `<stdin>` in evidence |
| gzip | Any file starting with the gzip magic bytes `1f 8b` | Detected by content, not extension, so rotated `auth.log.1` and `auth.log.2.gz` both work |
| Growing files | `--follow` (see 2) | |

### 2. Follow mode (`--follow`)

Like `tail -F`: read each file to its end, then keep polling for new lines.

- Poll every 0.5 s (constant `FOLLOW_POLL_SECONDS`). Polling instead of inotify/kqueue keeps the tool standard-library-only and cross-platform.
- **Partial lines:** a line without a trailing newline is buffered until the newline arrives, so a line written in two chunks is never parsed as two broken lines.
- **Rotation:** if the file's inode changes (renamed, then a new file created) or its size shrinks (truncated by `copytruncate`), read what is left of the old handle, then reopen the path and start from the beginning.
- **Missing file:** a missing file is an error at start-up (exit 2, as in US-01). If it disappears after start-up (between rotation steps), wait and retry instead of exiting.
- **Stopping:** on `SIGINT` (Ctrl+C) or `SIGTERM`, stop reading, close every open finding, print the final summary, and exit with `1` if any finding was reported, otherwise `0`.
- `--follow` cannot be combined with `-` (stdin is already a stream) and gives a usage error.

### 3. Findings as they happen

In batch mode the report is printed at the end (US-07). In follow mode, waiting for the end is useless, so the detector reports through a callback:

```python
Detector(rules, on_change=callback)   # callback(finding, change) with change in {"opened", "escalated", "closed"}
```

- **opened:** a pattern rule matched for a new key, or a threshold rule reached its count
- **escalated:** an `escalate_on` event raised the severity (e.g. brute force followed by a successful login)
- **closed:** no new matching event for the key within the rule's window (threshold rules) or within `PATTERN_IDLE_SECONDS = 300` (pattern rules)

Output in follow mode:

- **Text:** one line per change, e.g.
  `2025-07-03T10:00:07Z ESCALATED [CRITICAL] ssh-bruteforce source_ip=10.0.0.50 (5 events) auth.log:1-5`
- **`--json`:** JSON Lines, one object per change, flushed immediately so a pipe consumer gets it at once:
  `{"type": "finding", "change": "escalated", "schema_version": 1, "finding": {...same fields as the US-07 JSON...}}`

Correlation (US-06) also runs incrementally: when a finding opens for a key that already has an open finding from another file, the change carries `"correlated": true` and the raised incident severity.

### 4. Memory stays flat in a long-running process

Batch mode keeps every finding until the end, which is fine for a run that finishes. A process running for days must not. In follow mode:

- Closed findings are emitted, then dropped from `Detector.findings` and `_pattern_findings`. Only a counter per severity is kept for the final summary.
- The idle-state sweep also runs on a wall-clock timer (every 30 s), not only every 10,000 events, so state is cleared during quiet periods too.
- Hard caps on open state: `MAX_OPEN_KEYS = 100_000` threshold windows. When the cap is reached, the least recently seen key is dropped, and a one-time warning is printed to stderr. This protects against an attacker spraying from millions of IPs.

Memory then depends on the number of *currently active* sources, not on how long the tool has run or how many lines it has read.

### 5. Warning when the log format changes

If a web server or syslog config changes, every line may become malformed, and detection goes quiet with no error. To make that visible:

- Track the malformed rate per file over the last 1,000 lines.
- If it goes above 5% (with at least 50 lines seen), print one warning to stderr:
  `warning: samples/webserver.log: 37% of the last 1000 lines did not match any known format; check whether the log format changed`
- The warning re-arms when the rate falls back below the threshold, so a later change is reported again.
- In batch mode the same check adds a warning line to the report (text and JSON `warnings` list), and still exits `0`/`1` as usual, since a format warning is not a finding.

On the sample files: 1 malformed line out of 33 (3%) gives no warning. That is intended, since one restart marker is normal.

### 6. Measured, not claimed

US-08 adds the batch volume smoke test (200k lines). This story adds a follow-mode check that memory stays flat over a long stream (see T-10.7).

## Acceptance criteria

1. **Given** `cat samples/auth.log | python -m loganalyzer - --year 2025`, **then** the auth findings are reported, as for the file, with evidence shown as `<stdin>:N`.
2. **Given** a gzip copy of `webserver.log` named `webserver.log.1`, **then** the findings equal those for the plain file.
3. **Given** `--follow` on a temp file, **when** a brute force sequence (4 × 401 then 200) is appended, **then** within 2 seconds stdout shows an `opened` line and then an `escalated` line for that IP.
4. **Given** `--follow --json`, **then** every stdout line is a valid JSON object with `type`, `change` and `schema_version`.
5. **Given** `--follow`, **when** a line is written in two chunks 0.3 s apart, **then** it is parsed once, as one event, and not counted as malformed.
6. **Given** `--follow`, **when** the file is rotated (renamed and recreated) and new attack lines are written to the new file, **then** they are detected, and no line from the old file is lost or read twice.
7. **Given** `--follow`, **when** `SIGINT` is sent, **then** open findings are emitted as `closed`, a final summary is printed, and the exit code is `1` if anything was found.
8. **Given** a file where 50% of the last 1,000 lines are garbage, **then** exactly one format warning is printed to stderr; the samples produce none.
9. **Given** 1,000,000 events from 1,000,000 distinct IPs fed to the detector in follow mode, **then** the number of open threshold windows never exceeds `MAX_OPEN_KEYS`, and closed findings are not kept.
10. Default batch behaviour and output from US-01 to US-07 are unchanged; all earlier tests pass without changes.

## Tasks

### T-10.1 stdin and gzip input
Extend `read_lines` so `-` reads `sys.stdin` (named `<stdin>`), and files starting with `1f 8b` open through `gzip.open(..., "rt", encoding="utf-8", errors="replace")`. Update `check_inputs` so `-` is not checked as a path, and a corrupt gzip file gives exit 2 with a clear message.
*Files:* `loganalyzer/parsers.py`, `loganalyzer/cli.py`
*Test:* `tests/test_reader.py`: gzip file with and without a `.gz` extension, corrupt gzip, stdin through `monkeypatch`; `tests/test_cli.py`: subprocess with `input=` for `-`.

### T-10.2 File follower
New module `loganalyzer/follow.py` with `follow_lines(paths, stop_event, poll=0.5) -> Iterator[(path, line_no, line)]`: one state per file (handle, inode, position, partial buffer, line counter); round-robin reads; rotation and truncation detection; retry on a briefly missing file. `stop_event` is a `threading.Event`, so tests can stop it without signals.
*Files:* `loganalyzer/follow.py`
*Test:* `tests/test_follow.py` with a writer thread: lines appended later are yielded; partial line joined; rename-and-recreate rotation; `copytruncate`-style truncation; stop event ends the iterator within one poll interval. Use `poll=0.05` in tests to keep them fast.

### T-10.3 Detector change callback and closing findings
Add `on_change` to `Detector`. Call it on open, on escalation, and on close. Closing happens in the sweep: a threshold finding closes when its window has passed since `last_seen`; a pattern finding closes after `PATTERN_IDLE_SECONDS`. Add `Detector.close_all()` for shutdown. In follow mode (`keep_closed=False`), closed findings are removed from memory. Batch mode keeps today's behaviour: no callback, everything kept, `results()` at the end.
*Files:* `loganalyzer/detector.py`
*Test:* `tests/test_detector.py`: callback order `opened → escalated → closed` for the sample brute force; pattern finding closes after idle time; `close_all` closes everything once; batch results unchanged.

### T-10.4 Bounded state and time-based sweep
Add `MAX_OPEN_KEYS` with least-recently-seen eviction (`OrderedDict.move_to_end` on each event) and a one-time stderr warning. Run the sweep when either 10,000 events or 30 s of wall-clock time have passed.
*Files:* `loganalyzer/detector.py`
*Test:* with `MAX_OPEN_KEYS` patched to 10, feeding 100 distinct IPs keeps 10 windows and warns once; a time-based sweep runs with a patched clock.

### T-10.5 Streaming output and incremental correlation
In `report.py`, add `render_change_text(finding, change, incident_info)` and `render_change_json(...)` (one JSON Lines object, `sort_keys` for stable output). Keep a small map of open keys to their source files, so a change can be marked `correlated` without keeping closed findings.
*Files:* `loganalyzer/report.py`, `loganalyzer/correlator.py`
*Test:* `tests/test_report.py`: exact text line; JSON Lines object parses and has the expected keys; correlation flag set when the same IP has an open finding from another file.

### T-10.6 CLI `--follow` and graceful shutdown
Add `--follow` to `cli.py`, wire `follow_lines → parse_stream → Detector(on_change=print_change)`, flush stdout after each line, and handle `SIGINT`/`SIGTERM` by setting the stop event, then `close_all()`, the summary, and the exit code. Usage error for `--follow` with `-`.
*Files:* `loganalyzer/cli.py`
*Test:* `tests/test_e2e.py` subprocess test: start `--follow --json` on a temp file, append the sample brute force lines, read stdout until `escalated` (timeout 5 s), send `SIGINT`, assert exit code `1` and a summary line on stdout. Mark it `slow` and skip the signal part on Windows.

### T-10.7 Format-drift warning
Add a `MalformedRateMonitor` to `ParseStats` (a rolling `deque(maxlen=1000)` of booleans per file, plus a running sum) with a callback for the warning. Batch report: add a `warnings` list to the text and JSON output.
*Files:* `loganalyzer/models.py`, `loganalyzer/parsers.py`, `loganalyzer/report.py`
*Test:* 50% garbage → one warning; recovery then a new spike → a second warning; samples → no warning; fewer than 50 lines → no warning.

### T-10.8 Long-run memory test
`tests/test_volume.py::test_follow_mode_memory_is_flat` (marker `slow`): feed 1,000,000 generated events (unique IP every 10 events, timestamps moving forward) straight into `Detector(keep_closed=False)` and assert that open windows stay at or below `MAX_OPEN_KEYS`, that `len(detector.findings)` stays bounded, and that peak RSS growth during the second half is under 20 MB.
*Files:* `tests/test_volume.py`

### T-10.9 Documentation
README "Production notes" (US-09): follow mode, stdin, gzip, JSON Lines, the format warning, memory bounds, an example systemd unit / `tail -F | loganalyzer -` pipeline, and how to scale beyond one machine (log shipper in front, split by source IP, JSON into a SIEM).
*Files:* `README.md`

## Out of scope

- Merging several live files strictly by timestamp (state is kept per file; correlation links them). Listed as future work.
- Saving state between restarts (checkpointing file positions and open windows)
- inotify/kqueue file watching (polling is enough at 0.5 s)
- Alert delivery (Slack, email, webhooks); JSON Lines on stdout is the integration point
- Syslog year rollover across New Year (still a known limitation)
- Running as several coordinated processes; the README explains how to split work instead
