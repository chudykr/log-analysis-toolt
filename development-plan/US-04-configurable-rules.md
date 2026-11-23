# US-04: Configure detection rules without touching code

**Estimate:** M · **Depends on:** US-01 · **Decisions:** D4, D5

## Story

As a **security engineer**
I want **detection rules defined in a readable config file**
so that **I can tune thresholds, add patterns or turn rules off without changing or redeploying code**.

## Description

Rules live in TOML (read with `tomllib`, standard library). TOML allows comments, and literal strings (`'...'`) mean regexes need no double escaping. The tool ships `loganalyzer/rules.toml`; `--rules other.toml` replaces it completely, so there is no hidden merging.

### Rule schema

Fields shared by every rule:

| Field | Required | Meaning |
|---|---|---|
| `id` | yes | Unique, kebab-case, shown in the report |
| `title` | yes | Human-readable name |
| `type` | yes | `pattern` or `threshold` |
| `severity` | yes | `low`, `medium`, `high`, `critical` |
| `kinds` | yes | Event kinds the rule looks at, e.g. `["http_request"]` |
| `where` | no | Field filters, all must match: `{ field = "regex" }` |
| `action` | yes | Suggested next step, shown in the report |
| `enabled` | no | Default `true` |

`pattern` rules add:

| Field | Meaning |
|---|---|
| `field` | Event field to test, e.g. `path`, `command` |
| `regex` | Python regex; the rule fires once per matching event |

`threshold` rules add:

| Field | Meaning |
|---|---|
| `group_by` | Key for counting: `source_ip` (default), another field such as `user`, or a list for a compound key, e.g. `["source_ip", "method", "path"]` |
| `count` | Fire when this many matching events fall in the window |
| `window_seconds` | Sliding window size |
| `distinct` | Optional field; count distinct values instead of events (e.g. distinct `path`) |
| `escalate_on` | Optional `{ kinds = [...], where = {...}, severity = "critical" }`: if a matching event from the same key arrives within the window after the threshold was hit, raise severity |

### Example

```toml
[[rule]]
id = "ssh-bruteforce"
title = "SSH password brute force"
type = "threshold"
severity = "high"
kinds = ["ssh_failed"]
where = { invalid_user = '^false$' }      # valid accounts only
group_by = "source_ip"
count = 3
window_seconds = 60
escalate_on = { kinds = ["ssh_accepted"], severity = "critical" }
action = "Block the IP, reset the password of the targeted account and review its sessions."
```

### Validation

Load errors exit with code `2` and an exact message, e.g.
`error: rules.toml: rule 'ssh-bruteforce': 'count' must be a positive integer`.
The loader checks required fields, known `type` and `severity` values, unique `id`s, positive `count` and `window_seconds`, and that every regex compiles. It reports **all** errors in one go, not only the first.

## Acceptance criteria

1. **Given** no `--rules` flag, **then** the bundled `rules.toml` is loaded.
2. **Given** `--rules custom.toml` with one rule, **then** only that rule runs.
3. **Given** a rule with `enabled = false`, **then** it never produces findings.
4. **Given** a rules file with an invalid regex and a duplicate `id`, **then** both errors appear on stderr and the exit code is `2`.
5. **Given** a file that is not valid TOML, **then** the error includes the line number from `tomllib` and the exit code is `2`.
6. Regexes are compiled once at load time, not per event.

## Tasks

### T-04.1 Rule model
Create `Rule`, `PatternRule`, `ThresholdRule` and `Escalation` dataclasses in `rules.py`, holding compiled regexes. Severity is an `IntEnum` (`LOW=1 … CRITICAL=4`) so it can be sorted and compared.
*Files:* `loganalyzer/rules.py`
*Test:* `Severity.HIGH > Severity.MEDIUM`; building a rule compiles its regexes.

### T-04.2 Loader and validator
`load_rules(path) -> list[Rule]` reads TOML, validates each `[[rule]]` table, collects all errors, and raises `RulesError(list_of_messages)` if any. `cli.main` turns `RulesError` into exit `2`.
*Files:* `loganalyzer/rules.py`, `loganalyzer/cli.py`
*Test:* `tests/test_rules.py`: valid file loads; each validation error separately; several errors reported together; invalid TOML; `enabled = false` is filtered out.

### T-04.3 Default rules file
Write `loganalyzer/rules.toml` with the default rules listed in US-05, each with a comment explaining what it catches and why the threshold was chosen. Include it as package data in `pyproject.toml` and load it with `importlib.resources`, so it is found after `pip install` too.
*Files:* `loganalyzer/rules.toml`, `pyproject.toml`
*Test:* the bundled file loads with zero errors and contains the expected rule IDs.

### T-04.4 Rule authoring docs
Write a short section in the main README: the schema table, one example per rule type, and how to test a new rule (`python -m loganalyzer --rules my.toml samples/*.log`).
*Files:* `README.md`
*Test:* none (doc); checked in review.

## Out of scope

- Hot reload of rules while running
- Rule expressions beyond field regex filters (no AND/OR across events beyond the threshold escalation)
