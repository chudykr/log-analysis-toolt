# Architecture

## Pipeline

```
cli.main
  │  check_inputs (all paths, rules file)      → exit 2 on any problem, before reading
  │  rules.load_rules                          → exit 2 on RulesError
  ▼
parsers.read_lines(paths)        yields (path, line_no, line)         lazy, line by line
  ▼
parsers.parse_stream(..., ctx, stats)  yields Event                   malformed → ParseStats
  ▼
detector.run(events, rules) → Detector   .results() → [Finding]       single pass
                                         .context   → {ip: [Event]}
  ▼
correlator.correlate(findings, context) → [Incident]                  pure function
  ▼
report.render_text(...) / report.render_json(...) → str               pure functions
  ▼
cli prints; returns 1 if incidents else 0
```

Everything up to the detector is a generator chain, so a file is never held in memory. `cli.main(argv)` returns an int and never calls `sys.exit`; `__main__.py` does that. This keeps `main` testable in-process.

## Modules

| Module | Responsibility | Key names |
|---|---|---|
| `loganalyzer/__init__.py` | Version, Python version check at import | `__version__`, `MIN_PYTHON`, `python_supported()` |
| `loganalyzer/__main__.py` | `python -m loganalyzer` entry point | – |
| `loganalyzer/cli.py` | Arguments, input checks, wiring, exit codes, colour decision | `main`, `build_parser`, `check_inputs`, `use_color`, `EXIT_OK/FINDINGS/ERROR` |
| `loganalyzer/models.py` | Shared data classes and constants | `Event`, `ParseStats`, `Finding`, `Incident`, `Severity`, event kind constants, `KNOWN_KINDS`, `MAX_*` caps |
| `loganalyzer/parsers.py` | File reading, per-format parsers, parser registry | `read_lines`, `parse_webserver`, `parse_auth`, `PARSERS`, `parse_line`, `parse_stream`, `ParseContext`, `Parsed` |
| `loganalyzer/rules.py` | TOML loading and validation, rule objects | `load_rules`, `parse_rules`, `RulesError`, `Filter`, `Rule`, `PatternRule`, `ThresholdRule`, `Escalation` |
| `loganalyzer/rules.toml` | The 10 default rules (package data) | – |
| `loganalyzer/detector.py` | Rule engine | `Detector`, `run`, `detect`, `SWEEP_EVERY`, `CONTEXT_KINDS` |
| `loganalyzer/correlator.py` | Findings → incidents, severity rules, summary | `correlate`, `incident_key`, `incident_severity`, `summarize`, `format_span` |
| `loganalyzer/report.py` | Text and JSON renderers | `render_text`, `render_json`, `SCHEMA_VERSION`, `EVIDENCE_PER_FINDING`, `MAX_LINE_WIDTH` |

## Data model (`models.py`)

| Class | Fields that matter | Notes |
|---|---|---|
| `Event` (frozen, slots) | `source_file`, `line_no`, `timestamp`, `source_ip`, `kind`, `fields: dict[str, str]`, `raw` | `source_file` is the path **as given on the command line**. `timestamp` is always timezone-aware UTC. All field values are strings. `event.get(name)` also resolves `source_ip` and `kind`. |
| `ParseStats` | `total_lines`, `parsed`, `malformed_count`, `malformed` (first 100), `lines_per_file` | Counts **non-blank** lines; blank lines are skipped but line numbers still count them. |
| `Severity` (IntEnum) | `LOW=1 … CRITICAL=4` | `str(sev)` is lowercase; `Severity.parse("high")`. Compare and `max()` directly. |
| `Finding` | `rule_id`, `title`, `severity`, `key_field`, `key`, `source_file`, `first_seen`, `last_seen`, `count`, `escalated`, `evidence` (first 20), `action` | `key_field` is the rule's first `group_by` field (`source_ip` or e.g. `user`); `key` is its value (`"unknown"` if missing). One finding belongs to **one file**. |
| `Incident` | `key`, `key_type`, `severity`, `findings`, `sources` (sorted), `first_seen`, `last_seen`, `correlated`, `summary`, `actions`, `context` | `key` is the IP, or `"<field>:<value>"` such as `user:johndoe`. |

Event kinds (constants in `models.py`, the only values a rule's `kinds` may use): `http_request`, `ssh_failed`, `ssh_accepted`, `ssh_closed`, `sudo`, `auth_other`. Fields per kind are listed in the root README and in the header comment of `rules.toml`.

## Parsers (`parsers.py`)

- A parser is `(line: str, ctx: ParseContext) -> Parsed | None`. **It must never raise.** It returns `None` for "not my format" or invalid content (bad date, bad month).
- `PARSERS` is an ordered list: web server first, then auth. `parse_line` returns the first non-`None` result. Format is detected **per line**, so file order and mixed files do not matter.
- Web server (Common Log Format): the path is everything between the method and the last `HTTP/x.y` before the closing quote, so request lines with spaces (SQL injection) parse. `path_decoded` = `urllib.parse.unquote_plus(path)`; attack rules match on it so URL-encoded attacks are caught. `size` `-` becomes `"0"`.
- Auth (syslog): a valid syslog header **always** yields an event. Known sshd and sudo messages get a specific kind; anything else becomes `auth_other` (not malformed). Only lines with an invalid header are malformed.
- Timestamps: month names come from a fixed English table (`MONTHS`), never the locale. Syslog year comes from `ParseContext.year` (the `--year` flag); UTC is assumed.
- `ssh_failed` always has `invalid_user` (`"true"`/`"false"`) and `ssh_closed` always has `preauth`, because rule filters treat a missing field as "no match".
- `sudo` events have `source_ip=None`; their actor is `user`.

## Rules (`rules.py`, `rules.toml`)

- `load_rules(path=None)` loads the bundled file via `importlib.resources` when `path` is `None`; `--rules` **replaces** the defaults (no merge). It returns **enabled rules only**.
- `parse_rules(data, source)` validates a parsed TOML dict and raises `RulesError(errors)` listing **every** problem. It rejects unknown keys, unknown kinds, invalid regexes, duplicate ids, bad types. Use it directly in tests instead of writing files.
- `Filter.matches(event)`: kind in `kinds` and every `where` regex `search`es the field; a missing field means no match.
- `Rule.key_of(event)` returns the tuple of `group_by` values (`"unknown"` for missing).
- Regexes are compiled once at load time.

## Detector (`detector.py`)

`Detector(rules)` indexes rules by event kind (`_main_by_kind`, `_escalation_by_kind`), so each event only meets rules that can match it. `feed(event)` processes one event; `run()` feeds a whole stream; `results()` sorts findings by `(-severity, first_seen, rule_id, key)`.

**Pattern rules:** every hit is added to one finding per `(rule id, key, source file)` for the whole run.

**Threshold rules:** state per `(rule id, group key tuple, source file)` in a `_Window`:
- `events`: deque of `(timestamp, distinct value, event)` inside the window. Expiry drops items with `timestamp < now - window`, so an event exactly `window_seconds` old still counts (3 failures at 0, 30, 60 s fire; at 0, 30, 61 s they do not).
- When the count (or number of distinct values, with `distinct`) reaches `count`, a finding is created **with all window events as evidence**, and the window is cleared.
- While a finding is open, further matching events within `window_seconds` of `finding.last_seen` extend it (one burst → one finding, even for 10,000 events). A gap longer than the window closes it; a later burst becomes a new finding.
- `escalate_on`: a matching event from the same key and file, within the window after the finding's `last_seen`, raises severity (default critical), sets `escalated`, and is added as evidence. Once per finding. Escalations before the threshold is reached do nothing.
- Every `SWEEP_EVERY` (10,000) events, windows idle for longer than their rule's window (compared with the latest timestamp seen in that file) are deleted. This keeps memory flat with many distinct IPs (`request-flood` creates a window per IP+method+path).

**State is per file.** Files are read one after another and are not merged by time, so a window never mixes events from two files. Cross-file linking is the correlator's job.

**Context events:** an event of `CONTEXT_KINDS` (`ssh_accepted`, `ssh_closed`) that **no rule used**, from a source IP that already has a finding, is kept in `Detector.context[ip]` (deque, max `MAX_CONTEXT` = 5). That is how `Connection closed by 10.0.0.50` appears under its incident. `feed` tracks a `used` flag (pattern hit, threshold match, or escalation) to decide this.

## Correlator (`correlator.py`)

- Groups findings by `incident_key`: IP findings by IP; others as `"<key_field>:<key>"` (so `user:bob` never merges with IP `bob`).
- `incident_severity`: max finding severity; +1 level if findings come from 2+ files (`correlated`), capped at critical; critical if any finding is escalated.
- `summary` is a fixed template: `"<key>: <titles joined by '; '>[, followed by a successful attempt] (<n> source(s), <time span> UTC)."`. Titles are used exactly as written in the rules (no case changes).
- `actions` are de-duplicated in finding order. Context is attached only to IP incidents.
- Sort: incidents by `(-severity, first_seen, key)`; findings inside an incident by `(-severity, first_seen, rule_id)`.

## Report (`report.py`)

- Both renderers are pure and return a string; `cli` prints it.
- Text: header (files with line counts, event/malformed/incident counts by severity), then one block per incident (findings with up to `EVIDENCE_PER_FINDING`=5 evidence lines and `... and N more`, context, numbered actions), then malformed lines (up to 10). Lines are clipped to `MAX_LINE_WIDTH`=160 with `…`. Colour (ANSI) only when `color=True`, which `cli.use_color` sets for a TTY without `NO_COLOR`.
- JSON: `schema_version` 1; every list sorted (sources, evidence by file then line, malformed); timestamps ISO 8601 UTC. **Changing the JSON shape means bumping `SCHEMA_VERSION`** and updating the US-07 story.

## Invariants (do not break)

| Invariant | Enforced by |
|---|---|
| Runtime uses the standard library only | review; `pyproject.toml` has `dependencies = []` |
| Input is streamed; memory does not grow with file size | `tests/test_volume.py` (peak < 150 MB, growth 20k→200k lines < 10 MB) |
| One pass over events | `tests/test_detector.py::test_single_pass` |
| Parsers never raise; malformed lines never stop a run | parser tests, e2e E7 |
| Exit codes 0 / 1 / 2 | `tests/test_cli.py`, e2e E1, E11, E12, E14 |
| Deterministic output (apart from `generated_at`) | `test_report.py::test_json_is_stable_apart_from_generated_at`, e2e E9 |
| All buffers capped (`MAX_EVIDENCE`, `MAX_CONTEXT`, `MAX_STORED_MALFORMED`) | unit tests for each cap |
| README example output equals real output | `tests/test_readme.py` |
| `loganalyzer/__init__.py` stays parseable by old Pythons (3.6+: no f-strings with `=`, no `|` types, no walrus) | `test_cli.py::test_old_python_gets_a_clear_message` (runs `/usr/bin/python3` if it is older than 3.11) |
