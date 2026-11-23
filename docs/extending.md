# Extending the tool

Recipes for the common changes. Each lists the files to touch and the tests to add. After any of them: `.venv/bin/pytest --cov`, then update the docs that describe the changed behaviour.

## Add or change a detection rule

Usually no Python change is needed.

1. Edit `loganalyzer/rules.toml`. Add a comment above the rule saying what it catches and why the threshold is what it is. Use TOML literal strings (`'...'`) for regexes.
2. Match attack content on `path_decoded`, not `path`, so URL-encoded attacks are caught.
3. Write a concrete `action` (what to block, reset or check); `test_rules.py` requires at least 20 characters.
4. Tests in `tests/test_detector.py`: one case where it fires, at least one realistic case where it must **not** fire (false-positive guard), and boundary cases for thresholds.
5. If it fires on the sample logs, update every table in [testing.md](testing.md#expected-results-that-move-together), regenerate the README example output, and add the rule to the README "What it detects" table. Also update `DEFAULT_RULE_IDS` in `tests/test_rules.py` and the rule count (10) in `test_e2e.py::test_e5…`.

Rule features available: `where` filters, `group_by` (string or list; the first field becomes the incident key), threshold `count` / `window_seconds` / `distinct` / `escalate_on`, `enabled = false`. Full schema: root README, "Writing your own rules".

## Add a field to an event

1. Set it in the parser (`parsers.py`), always as a **string**. If rules may filter on its absence, always set it (e.g. `"false"`), because a missing field never matches.
2. Document it in the header comment of `rules.toml` and the "Event kinds and their fields" table in the README.
3. Parser test asserting the value for a sample line.

## Add a new log format

1. Write `parse_<format>(line, ctx) -> Parsed | None` in `parsers.py`. It must return `None` (never raise) for lines that are not in its format or have invalid content.
2. If it produces a new event kind, add the constant to `models.py` and to `KNOWN_KINDS` (otherwise rules using it are rejected).
3. Register it in `PARSERS`. Order matters only if two formats could match the same line; put the stricter parser first.
4. Add a sample file under `samples/` (check `.gitignore`: `*.log` is ignored except `samples/*.log`), parser tests for each line shape and for bad lines, and an e2e case that runs the real command on it.
5. Add rules for it in `rules.toml`, and update the README "Supported formats" table.

Keep the year/timezone rules in mind: CLF lines carry a timezone and are converted to UTC; formats without a year must take it from `ParseContext`.

## Add a CLI flag

1. `cli.build_parser()`: add the argument with a one-line help text. Keep the default behaviour unchanged ("one command, no required flags").
2. Validate in argparse (`type=` function raising `ArgumentTypeError`) so bad values give exit code 2.
3. Tests in `tests/test_cli.py` (in-process `main([...])`) and, if user-visible, one e2e case.
4. Update the README "Options" table. `test_cli.py::test_help_lists_every_flag` lists the flags it expects.

## Change the report

- Text layout (`report.render_text`): regenerate the README example output and update the header assertions listed in [testing.md](testing.md#expected-results-that-move-together). Keep lines ≤ `MAX_LINE_WIDTH` and output free of ANSI codes when `color=False`.
- JSON (`report.render_json`): keep lists sorted. Adding a field is compatible; renaming or removing one is not, so bump `SCHEMA_VERSION` and update the schema in `development-plan/US-07-actionable-report.md`. Update `test_report.py::test_json_incident_shape`.

## Change correlation or severity

`correlator.incident_severity` is the single place for severity rules; it has a table-driven test (`test_correlator.py::test_incident_severity`). A change here usually changes expected severities on the samples, so update the tables in [testing.md](testing.md#expected-results-that-move-together) and the README "Incidents and correlation" section.

## Change limits and caps

Caps live in `models.py` (`MAX_EVIDENCE`, `MAX_CONTEXT`, `MAX_STORED_MALFORMED`), `report.py` (`EVIDENCE_PER_FINDING`, `MAX_MALFORMED_SHOWN`, `MAX_LINE_WIDTH`) and `detector.py` (`SWEEP_EVERY`). Tests import these constants. Any change that could keep more data in memory must still pass `tests/test_volume.py`.
