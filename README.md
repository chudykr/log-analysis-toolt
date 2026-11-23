# Security log analysis tool

A command-line tool that reads web server and SSH/sudo auth logs, finds suspicious activity with configurable rules, links activity from the same attacker across files, and prints a report you can act on.

Built for the QA Engineer technical assessment ([`qa-assessment.md`](qa-assessment.md)). The planning (user stories and tasks) is in [`development-plan/`](development-plan/README.md).

## Quick start

You need **Python 3.11 or newer**. Nothing else to install to run it.

```bash
git clone https://github.com/chudykr/log-analysis-toolt.git
cd log-analysis-toolt
python3 -m loganalyzer samples/webserver.log samples/auth.log --year 2025
```

On macOS, `python3` is often 3.9. The tool then says so and exits; use a newer interpreter, e.g. `brew install python@3.12` and run `python3.12 -m loganalyzer ...`.

To run the tests:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## Example output

This is the real output on the two sample files from the assessment. A test (`tests/test_readme.py`) fails if it ever stops matching what the tool prints.

<!-- example-output:start -->
```text
$ python3 -m loganalyzer samples/webserver.log samples/auth.log --year 2025
Security Log Analysis Report
Files: samples/webserver.log (33 lines), samples/auth.log (12 lines)
Events parsed: 44   Malformed lines: 1   Incidents: 6 (critical 2, high 2, medium 2)

[CRITICAL] 10.0.0.50 - correlated across samples/auth.log, samples/webserver.log
  10.0.0.50: SSH password brute force; Web login brute force, followed by a successful attempt (2 sources, 2025-07-03 10:00:03-10:00:07 UTC).
  Findings:
    - ssh-bruteforce [critical]: SSH password brute force (5 events, ESCALATED)
        samples/auth.log:1  Jul  3 10:00:03 server sshd[1234]: Failed password for admin from 10.0.0.50 port 52341 ssh2
        samples/auth.log:2  Jul  3 10:00:04 server sshd[1234]: Failed password for admin from 10.0.0.50 port 52342 ssh2
        samples/auth.log:3  Jul  3 10:00:05 server sshd[1234]: Failed password for admin from 10.0.0.50 port 52343 ssh2
        samples/auth.log:4  Jul  3 10:00:06 server sshd[1234]: Failed password for admin from 10.0.0.50 port 52344 ssh2
        samples/auth.log:5  Jul  3 10:00:07 server sshd[1234]: Accepted password for admin from 10.0.0.50 port 52345 ssh2
    - web-login-bruteforce [critical]: Web login brute force (5 events, ESCALATED)
        samples/webserver.log:3  10.0.0.50 - - [03/Jul/2025:10:00:03 +0000] "POST /login HTTP/1.1" 401 54
        samples/webserver.log:4  10.0.0.50 - - [03/Jul/2025:10:00:04 +0000] "POST /login HTTP/1.1" 401 54
        samples/webserver.log:5  10.0.0.50 - - [03/Jul/2025:10:00:05 +0000] "POST /login HTTP/1.1" 401 54
        samples/webserver.log:6  10.0.0.50 - - [03/Jul/2025:10:00:06 +0000] "POST /login HTTP/1.1" 401 54
        samples/webserver.log:7  10.0.0.50 - - [03/Jul/2025:10:00:07 +0000] "POST /login HTTP/1.1" 200 3842
  Context:
    samples/auth.log:12  Jul  3 10:00:25 server sshd[1245]: Connection closed by 10.0.0.50 port 52345 [preauth]
  Recommended actions:
    1. Block the source IP, reset the targeted account's password, check its SSH sessions and disable password login in favour of keys.
    2. Block the source IP, force a password reset for the targeted web account and review its recent sessions.

[CRITICAL] 203.0.113.5 - correlated across samples/auth.log, samples/webserver.log
  203.0.113.5: Path traversal attempt; Admin area probing; SSH username enumeration (2 sources, 2025-07-03 10:00:09-10:00:12 UTC).
  Findings:
    - path-traversal [high]: Path traversal attempt (1 event)
        samples/webserver.log:12  203.0.113.5 - - [03/Jul/2025:10:00:12 +0000] "GET /admin/../../../etc/passwd HTTP/1.1" 400 0
    - admin-probing [medium]: Admin area probing (3 events)
        samples/webserver.log:9   203.0.113.5 - - [03/Jul/2025:10:00:09 +0000] "GET /admin HTTP/1.1" 403 128
        samples/webserver.log:10  203.0.113.5 - - [03/Jul/2025:10:00:10 +0000] "GET /admin/ HTTP/1.1" 403 128
        samples/webserver.log:11  203.0.113.5 - - [03/Jul/2025:10:00:11 +0000] "GET /admin/config HTTP/1.1" 403 128
    - ssh-invalid-users [medium]: SSH username enumeration (3 events)
        samples/auth.log:6  Jul  3 10:00:09 server sshd[1235]: Failed password for invalid user test from 203.0.113.5 port 44123 ssh2
        samples/auth.log:7  Jul  3 10:00:10 server sshd[1235]: Failed password for invalid user root from 203.0.113.5 port 44124 ssh2
        samples/auth.log:8  Jul  3 10:00:11 server sshd[1235]: Failed password for invalid user ubuntu from 203.0.113.5 port 44125 ssh2
  Recommended actions:
    1. Block the source IP and confirm the server did not return any file outside the web root (check response sizes for this IP).
    2. Block the source IP and confirm the admin area is reachable only from trusted networks.
    3. Block the source IP at the firewall and make sure root login and password authentication are disabled in sshd_config.

[HIGH] 10.0.0.88 - samples/webserver.log
  10.0.0.88: SQL injection attempt (1 source, 2025-07-03 10:00:14-10:00:16 UTC).
  Findings:
    - sql-injection [high]: SQL injection attempt (2 events)
        samples/webserver.log:14  10.0.0.88 - - [03/Jul/2025:10:00:14 +0000] "GET /search?q=' UNION SELECT * FROM users-- HTTP/1.1" 200 54
        samples/webserver.log:16  10.0.0.88 - - [03/Jul/2025:10:00:16 +0000] "GET /search?q=1; DROP TABLE users-- HTTP/1.1" 200 54
  Recommended actions:
    1. Block the source IP, check the database and application logs for this request, and verify the search endpoint uses parameterised queries.

[HIGH] user:johndoe - samples/auth.log
  user:johndoe: Sensitive command run as root (1 source, 2025-07-03 10:00:15 UTC).
  Findings:
    - sensitive-sudo [high]: Sensitive command run as root (1 event)
        samples/auth.log:9  Jul  3 10:00:15 server sudo: johndoe : TTY=pts/0 ; PWD=/home/johndoe ; USER=root ; COMMAND=/bin/cat /etc/shadow
  Recommended actions:
    1. Confirm with the user and their manager that this command was authorised; if not, lock the account and rotate any exposed credentials.

[MEDIUM] 172.16.0.20 - samples/webserver.log
  172.16.0.20: Sensitive path scan (1 source, 2025-07-03 10:00:18-10:00:19 UTC).
  Findings:
    - sensitive-path-scan [medium]: Sensitive path scan (6 events)
        samples/webserver.log:19  172.16.0.20 - - [03/Jul/2025:10:00:18 +0000] "GET /admin HTTP/1.1" 403 128
        samples/webserver.log:20  172.16.0.20 - - [03/Jul/2025:10:00:18 +0000] "GET /phpmyadmin HTTP/1.1" 404 0
        samples/webserver.log:21  172.16.0.20 - - [03/Jul/2025:10:00:18 +0000] "GET /wp-admin HTTP/1.1" 404 0
        samples/webserver.log:22  172.16.0.20 - - [03/Jul/2025:10:00:18 +0000] "GET /administrator HTTP/1.1" 404 0
        samples/webserver.log:23  172.16.0.20 - - [03/Jul/2025:10:00:19 +0000] "GET /.env HTTP/1.1" 404 0
        ... and 1 more
  Recommended actions:
    1. Block the source IP and check that none of the probed files (.env, config.php, ...) are publicly served.

[MEDIUM] 10.0.0.99 - samples/webserver.log
  10.0.0.99: Request flood on one endpoint; Client was rate-limited (HTTP 429) (1 source, 2025-07-03 10:00:23-10:00:24 UTC).
  Findings:
    - request-flood [medium]: Request flood on one endpoint (5 events)
        samples/webserver.log:28  10.0.0.99 - - [03/Jul/2025:10:00:23 +0000] "POST /api/users HTTP/1.1" 200 54
        samples/webserver.log:29  10.0.0.99 - - [03/Jul/2025:10:00:23 +0000] "POST /api/users HTTP/1.1" 200 54
        samples/webserver.log:30  10.0.0.99 - - [03/Jul/2025:10:00:23 +0000] "POST /api/users HTTP/1.1" 200 54
        samples/webserver.log:31  10.0.0.99 - - [03/Jul/2025:10:00:24 +0000] "POST /api/users HTTP/1.1" 200 54
        samples/webserver.log:32  10.0.0.99 - - [03/Jul/2025:10:00:24 +0000] "POST /api/users HTTP/1.1" 429 32
    - rate-limited [low]: Client was rate-limited (HTTP 429) (1 event)
        samples/webserver.log:32  10.0.0.99 - - [03/Jul/2025:10:00:24 +0000] "POST /api/users HTTP/1.1" 429 32
  Recommended actions:
    1. Rate-limit or block the source IP and check whether the requests created data (e.g. accounts via POST /api/users).
    2. Review what the client was doing before it was rate-limited; repeated 429s from one IP usually mean automation.

Malformed lines (1):
  samples/webserver.log:26  [MALFORMED ENTRY - system restart
```
<!-- example-output:end -->

## Options

```
python3 -m loganalyzer FILE [FILE ...] [--rules PATH] [--json] [--year YEAR]
```

| Option | Meaning | Default |
|---|---|---|
| `FILE ...` | One or more log files, in any order and any mix of formats. The format is detected per line. | required |
| `--rules PATH` | Use this rules file instead of the bundled [`loganalyzer/rules.toml`](loganalyzer/rules.toml) | bundled rules |
| `--json` | Print the report as JSON instead of text | text |
| `--year YEAR` | Year for auth.log timestamps, which have no year (`Jul  3 10:00:03`). Use `--year 2025` for the samples. | current year |
| `--version`, `-h` | Version, help | |

| Exit code | Meaning |
|---|---|
| `0` | Ran successfully, nothing suspicious found |
| `1` | Ran successfully, incidents reported |
| `2` | Usage or input error: missing/unreadable file, invalid rules file, unsupported Python |

So the tool fits in scripts and cron jobs: `python3 -m loganalyzer /var/log/nginx/access.log --json > findings.json || alert`.

### Supported formats

| Log | Format | Example |
|---|---|---|
| Web server | Common Log Format | `10.0.0.50 - - [03/Jul/2025:10:00:03 +0000] "POST /login HTTP/1.1" 401 54` |
| Auth | syslog: `sshd` failed/accepted/closed, `sudo` | `Jul  3 10:00:03 server sshd[1234]: Failed password for admin from 10.0.0.50 port 52341 ssh2` |

Lines that match no format (like `[MALFORMED ENTRY - system restart`) are counted and listed at the end of the report; they never stop the run. Other syslog lines (e.g. `pam_unix`) are accepted and ignored by the default rules.

## What it detects

Default rules, from [`loganalyzer/rules.toml`](loganalyzer/rules.toml):

| Rule | Type | Fires when | Severity |
|---|---|---|---|
| `web-login-bruteforce` | threshold | 3+ `POST /login` with 401 from one IP within 60 s | high, **critical** if a successful login follows |
| `ssh-bruteforce` | threshold | 3+ failed SSH passwords for an existing account from one IP within 60 s | high, **critical** if a successful login follows |
| `ssh-invalid-users` | threshold | 3+ different non-existent usernames from one IP within 5 min | medium |
| `sql-injection` | pattern | SQL keywords in the URL (`UNION SELECT`, `; DROP`, `OR 1=1`, `'--`, `SLEEP(`), also URL-encoded. A plain apostrophe (`O'Brien`) is not enough. | high |
| `path-traversal` | pattern | `../` in the URL, also URL-encoded | high |
| `admin-probing` | threshold | 3+ requests to `/admin*` refused with 403 from one IP within 60 s | medium |
| `sensitive-path-scan` | threshold | 5+ *different* well-known sensitive paths (`/phpmyadmin`, `/wp-admin`, `/.env`, `/config.php`, ...) from one IP within 10 s | medium |
| `request-flood` | threshold | 5+ requests to the same endpoint from one IP within 2 s | medium |
| `rate-limited` | pattern | The server answered 429 Too Many Requests | low |
| `sensitive-sudo` | pattern | `sudo` to root touching `/etc/shadow`, `/etc/sudoers`, `passwd`, `useradd`, ... (routine commands like `systemctl restart nginx` are not matched) | high |

### Incidents and correlation

Findings about the same actor are grouped into one **incident**: the source IP, or the local user for sudo (`user:johndoe`). The incident severity is:

1. the highest severity among its findings,
2. raised one level if the actor appears in **two or more files** (e.g. web *and* SSH attacks from one IP),
3. **critical** if an attack was followed by a success (brute force, then a successful login).

On the samples this turns `10.0.0.50` (web and SSH brute force, both followed by a successful login) and `203.0.113.5` (admin probing, path traversal and SSH username guessing at the same time) into critical, correlated incidents.

Each incident lists its evidence lines as `file:line`, recent related lines (e.g. `Connection closed by 10.0.0.50`), and concrete recommended actions.

## Writing your own rules

Rules are TOML. Copy [`loganalyzer/rules.toml`](loganalyzer/rules.toml), edit it, and run with `--rules my-rules.toml`. The file replaces the defaults completely. An invalid file is rejected with every problem listed at once (exit code 2), so you never run with half a rule set.

Fields every rule has:

| Field | Required | Meaning |
|---|---|---|
| `id` | yes | Unique, kebab-case, shown in the report |
| `title` | yes | Human-readable name |
| `type` | yes | `pattern` or `threshold` |
| `severity` | yes | `low`, `medium`, `high` or `critical` |
| `kinds` | yes | Event kinds the rule looks at (see below) |
| `where` | no | Field filters, all must match: `{ status = '^401$', method = '^POST$' }` |
| `group_by` | no | Who the rule is about: `"source_ip"` (default), another field like `"user"`, or a list for a compound key |
| `action` | yes | The recommended next step shown in the report |
| `enabled` | no | `false` turns the rule off; default `true` |

`pattern` rules fire on every event whose `field` matches `regex`:

```toml
[[rule]]
id = "sql-injection"
title = "SQL injection attempt"
type = "pattern"
severity = "high"
kinds = ["http_request"]
field = "path_decoded"
regex = '(?i)(\bunion\b.+\bselect\b|;\s*drop\s+table)'
action = "Block the source IP and check the database logs."
```

`threshold` rules fire when `count` matching events from one key fall within `window_seconds`. Optional: `distinct = "field"` counts different values instead of events, and `escalate_on` raises the severity when a matching event from the same key follows:

```toml
[[rule]]
id = "ssh-bruteforce"
title = "SSH password brute force"
type = "threshold"
severity = "high"
kinds = ["ssh_failed"]
where = { invalid_user = '^false$' }
count = 3
window_seconds = 60
escalate_on = { kinds = ["ssh_accepted"], severity = "critical" }
action = "Block the source IP and reset the account's password."
```

Event kinds and their fields (`source_ip` is available on all but `sudo` and `auth_other`):

| Kind | Fields |
|---|---|
| `http_request` | `method`, `path`, `path_decoded` (URL-decoded), `protocol`, `status`, `size`, `user` |
| `ssh_failed` | `user`, `port`, `method`, `invalid_user` (`"true"`/`"false"`) |
| `ssh_accepted` | `user`, `port`, `method` (`password`, `publickey`) |
| `ssh_closed` | `port`, `preauth` (`"true"`/`"false"`), `user` (if logged) |
| `sudo` | `user`, `target_user`, `command`, `tty`, `pwd` |
| `auth_other` | `program`, `message` |

Regexes use TOML literal strings (`'...'`), so backslashes need no escaping. To try a new rule: `python3 -m loganalyzer --rules my-rules.toml samples/*.log --year 2025`.

## How it works

```
read lines ──> parse ──> detect ──> correlate ──> report
 (streaming)  (per line)  (rules)   (incidents)   (text / JSON)
```

| Stage | Module | What it does |
|---|---|---|
| Read | `parsers.read_lines` | Reads each file line by line (never the whole file), keeps file name and line number |
| Parse | `parsers.parse_stream` | Tries each known format per line, turns it into an `Event`; counts malformed lines |
| Detect | `detector.Detector` | One pass over the events; pattern rules per event, threshold rules with a sliding time window per key |
| Correlate | `correlator.correlate` | Groups findings per IP or user, applies the severity rules, builds summary and actions |
| Report | `report.render_text`, `render_json` | Text for people, versioned JSON (`schema_version: 1`) for other tools |

Main design decisions (full list in [`development-plan/README.md`](development-plan/README.md#design-decisions)):

- **Simple to use:** one command, no required flags, standard library only.
- **Format detection per line:** no `--format` flag; files can be given in any order.
- **Rules are data:** detection is tuned in TOML, not in code.
- **Bad input is reported, not fatal:** malformed lines are listed; the run continues.
- **Memory does not grow with file size:** streaming reads, windows hold only events inside their time span, idle per-IP state is cleaned up regularly, evidence is capped at 20 events per finding.

## Testing approach

All tests run locally (there is no CI for this internal tool):

| Command | Use |
|---|---|
| `pytest` | Full suite, including the volume test (about 4 s) |
| `pytest -m "not slow"` | Quick check while coding (under 1 s) |
| `pytest --cov` | Full suite with coverage; fails below 85% (currently about 98%) |

| Level | Files | What it checks |
|---|---|---|
| Unit | `test_parsers.py`, `test_rules.py`, `test_detector.py`, `test_correlator.py`, `test_report.py`, `test_reader.py` | Every sample line shape, bad lines, rule validation messages, window boundaries (exactly 60 s fires, 61 s does not), escalation, severity rules, report layout |
| CLI | `test_cli.py` | Flags, exit codes, error messages, colour only on a terminal, old Python versions |
| End-to-end | `test_e2e.py` | Runs the real command on the sample logs (cases E1-E14): exact incidents and order, correlation, escalation, every rule firing on the right source, evidence lines equal the real log lines, file order does not matter, custom and invalid rules |
| Volume | `test_volume.py` (slow) | 200,000 generated lines: finishes in under 10 s (about 1.7 s), finds the hidden brute force, peak memory under 150 MB and no growth compared with 20,000 lines |
| Docs | `test_readme.py` | The example output above matches the real output |

**False-positive guards** are tested as carefully as detections: `q=O'Brien`, `q=laptop`, the `deploy` user's public-key login and `sudo systemctl restart nginx`, and all normal traffic must produce no incident.

**Do the tests catch real bugs?** Checked by breaking the code on purpose, one change at a time, then reverting:

| Deliberate bug | Caught by |
|---|---|
| SQL injection rule matches any apostrophe | 5 e2e tests, incl. the `O'Brien` guard |
| Web brute-force threshold 3 → 6 | 5 e2e tests |
| No severity boost for cross-file activity | 2 e2e tests |
| Window boundary `<` → `<=` | detector unit test |
| Idle state never cleaned up | volume test (peak 447 MB) |
| Whole file read into memory | volume test (memory grew with file size) |

## Production notes

The assessment says the tool may run "in an evolving environment processing high volumes of log data continuously". Today the tool covers:

- **High volume:** streaming, single pass, bounded memory, measured at about 115,000 lines/s and a flat 42 MB peak.
- **Evolving environment:**
  - Rules change without code changes.
  - A new log format is one parser function added to `parsers.PARSERS`.
  - Unexpected lines are reported, not fatal.
  - The JSON schema is versioned.
- **Automation:** exit codes and JSON output for scripts, cron and log pipelines.

Planned in [US-10](development-plan/US-10-continuous-production-mode.md), not built yet:

- `--follow` for growing and rotated files
- stdin (`-`) and gzip input
- findings printed as they happen (JSON Lines)
- memory bounds for processes running for days
- a warning when the log format seems to have changed (many malformed lines)

At larger scale this tool is the detection step, not the whole pipeline. A log shipper (e.g. Vector, Fluent Bit) would feed it, work would be split by source IP across instances, and the JSON output would go into a SIEM.

## Limitations and future work

- **auth.log has no year or timezone.** The year comes from `--year`, and UTC is assumed. Logs that cross New Year get the wrong year.
- **Files are not merged by time.** Each file is assumed to be in time order. Activity across files is linked by IP/user, not by exact timing.
- **Rule-based only.** There are no allow-lists for trusted networks, no IP reputation and no anomaly scoring.
- **Next steps:**
  - US-10 (continuous mode)
  - more formats (nginx combined, journald JSON)
  - property-based tests (Hypothesis) and automated mutation testing (mutmut)

## AI usage

This project was built with Claude Code (Anthropic) as a pair programmer. The full conversation is in [`ai-transcript/`](ai-transcript/).

How the work was split:

- **Planning:** I asked for user stories with tasks and detailed descriptions (no epics). The AI wrote [`development-plan/`](development-plan/). I reviewed it, asked how the "Production Context" requirement is covered, and had US-10 added.
- **Implementation:** one story at a time (US-01 → US-08), with a commit after each. The expected findings for the sample logs were worked out line by line before any detection code was written. They became the e2e test oracle.
- **Steering:** I made the decisions along the way, e.g. dropping CI in favour of local test runs.
- **Checks on AI output:**
  - Every story was run by hand on the sample logs.
  - Tests were verified by breaking the code on purpose (table above).
  - Several problems were caught in review and fixed: a too-loose memory limit, a casing bug in summaries ("sSH"), an exit-code clash for old Python versions, and the `.gitignore` hiding the sample logs.
