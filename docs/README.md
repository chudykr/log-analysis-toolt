# Developer and agent guide

Start here before changing anything in this repository. These pages describe how the code is built, the rules it follows, and the traps already found. User-facing documentation is the root [`README.md`](../README.md); the original assignment is [`qa-assessment.md`](../qa-assessment.md); the work plan (user stories) is [`development-plan/`](../development-plan/README.md).

## What this is

`loganalyzer` is a Python command-line tool for a QA Engineer assessment. It reads web server access logs and SSH/sudo auth logs, detects attacks with rules defined in TOML, groups findings about the same attacker across files into incidents, and prints a text or JSON report. Quality engineering (tests, determinism, honest verification) is what the assessment evaluates, so it matters as much as the features.

## Read in this order

| Page | Read it when |
|---|---|
| [architecture.md](architecture.md) | Always: pipeline, modules, data model, invariants you must not break |
| [development.md](development.md) | Always: environment, commands, conventions, workflow with the user, gotchas |
| [testing.md](testing.md) | Before changing behaviour: test map, the expected results that must change together |
| [extending.md](extending.md) | When adding a rule, event field, log format, CLI flag or report field |
| [status.md](status.md) | Before starting new work: what is done, what is still open (incl. deferred US-10), known limitations, where code differs from the plan |

## Ten things to know before you start

1. **Use the project venv.** `.venv/bin/python` and `.venv/bin/pytest` (Python 3.12). The system `python3` on this machine is 3.9 and is not supported (the tool exits with code 2 and a message).
2. **Run `.venv/bin/pytest --cov` before saying work is done.** It runs all ~245 tests in about 4 s and fails below 85% coverage. There is **no CI** on purpose; all checks are local.
3. **Runtime code uses the standard library only.** `pytest` and `pytest-cov` are dev dependencies; add nothing to `dependencies`.
4. **Always pass `--year 2025`** when running on `samples/`. auth.log has no year; the default is the current year.
5. **Exit codes are a contract:** `0` nothing found, `1` incidents reported, `2` usage/input/environment error. Never use `sys.exit("message")` (that exits 1).
6. **Changing detection changes several expected-result tables at once** (see [testing.md](testing.md#expected-results-that-move-together)), including the README example output, which a test compares with the real output.
7. **Parsers never raise** on bad input; they return `None`. Malformed lines are counted, not fatal.
8. **Memory must not grow with input size.** No `read()`/`readlines()`, keep every buffer capped. `tests/test_volume.py` measures this.
9. **Output is deterministic.** Everything is sorted; only `generated_at` in the JSON differs between runs.
10. **Commit only when the user asks**, never push, and never commit `.idea/` (the user's IDE folder).
