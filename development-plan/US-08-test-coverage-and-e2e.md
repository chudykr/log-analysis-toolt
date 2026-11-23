# US-08: Trust the tool through tests (unit + e2e)

**Estimate:** M · **Depends on:** unit tests are written inside each story; the e2e test needs US-07 · **Decisions:** D10

## Story

As a **QA engineer**
I want **automated unit tests for each module and an end-to-end test on the provided sample logs**
so that **every change is checked locally against the known attacks and known false positives before it is committed**.

## Description

### Test strategy

| Level | What | Where | Speed |
|---|---|---|---|
| Unit | Each parser shape, rule loader validation, detector windows, correlator severity, renderers | `tests/test_*.py` | < 1 s total |
| Integration | `cli.main([...])` in-process with temp files and `capsys` | `tests/test_cli.py` | < 1 s |
| End-to-end | Runs `python -m loganalyzer samples/webserver.log samples/auth.log` as a **subprocess**, exactly as a user would | `tests/test_e2e.py` | ~1 s |
| Volume smoke | Generates a 200k-line file, checks the run finishes in time and memory stays flat | `tests/test_volume.py`, marker `@pytest.mark.slow` | ~3 s, part of the full local run; skip with `-m "not slow"` for a quick check |

Each story's tasks already list the unit tests they need. This story adds the shared fixtures, the e2e and volume tests, and the coverage gate. All tests run locally; there is no CI for now (internal use).

### Shared fixtures (`tests/conftest.py`)

- `samples_dir`: path to `samples/`
- `web_lines`, `auth_lines`: sample lines as lists, for tests that need one line
- `make_event(**overrides)`: builds an `Event` with sensible defaults, for detector and correlator tests
- `write_log(tmp_path, name, lines)`: writes a temp log file and returns its path
- `default_rules`: the bundled rules, loaded once per session

### End-to-end test cases (`tests/test_e2e.py`)

All run the real CLI as a subprocess with `--year 2025`, using `sys.executable -m loganalyzer`, so they test the actual entry point.

| # | Case | Assert |
|---|---|---|
| E1 | Both sample files, text output | Exit code `1`; header shows `Events parsed: 44`, `Malformed lines: 1`, `Incidents: 6` |
| E2 | Both sample files, `--json` | Valid JSON; incident keys and severities match the expected table exactly (see below) |
| E3 | Correlation | In the JSON, `10.0.0.50` and `203.0.113.5` have `correlated: true` and both sources; the others have `correlated: false` |
| E4 | Escalation | Both `10.0.0.50` findings have `escalated: true`; evidence includes `webserver.log:7` and `auth.log:5` |
| E5 | Detections per rule | Each expected `rule_id` appears under the right key (table in `development-plan/README.md`) |
| E6 | False-positive guards | No incident for `192.168.1.14` (O'Brien), `192.168.1.100` (deploy publickey), `user:deploy`, or any of `192.168.1.10–.13, .15–.18` |
| E7 | Malformed line | `malformed` holds exactly one entry: `webserver.log`, line 26 |
| E8 | Evidence traceability | For every evidence entry, the `raw` text equals line `line` of the named sample file |
| E9 | File order does not matter | `auth.log webserver.log` gives the same JSON (ignoring `generated_at`) as the other order |
| E10 | Single file | Only `auth.log`: incidents for `10.0.0.50`, `203.0.113.5`, `user:johndoe`, none correlated |
| E11 | Clean file | A file with only normal lines (`192.168.1.10`–`.13`) gives exit `0` and `No suspicious activity found.` |
| E12 | Missing file | Exit `2`, file name on stderr, nothing on stdout |
| E13 | Custom rules | `--rules` with only `sql-injection` gives exactly one incident (`10.0.0.88`) |
| E14 | Invalid rules | Bad regex in `--rules` gives exit `2` with the rule ID in the error |

Expected incident table for E2, kept as a Python constant in the test so a change in behaviour shows as a clear diff:

```python
EXPECTED = {
    "10.0.0.50":    ("critical", {"web-login-bruteforce", "ssh-bruteforce"}),
    "203.0.113.5":  ("critical", {"admin-probing", "path-traversal", "ssh-invalid-users"}),
    "10.0.0.88":    ("high",     {"sql-injection"}),
    "user:johndoe": ("high",     {"sensitive-sudo"}),
    "172.16.0.20":  ("medium",   {"sensitive-path-scan"}),
    "10.0.0.99":    ("medium",   {"request-flood", "rate-limited"}),
}
```

### Volume smoke test

Generate 200,000 web lines (mixed normal traffic plus one brute force burst) into `tmp_path`, run the CLI as a subprocess, and assert:

- it finishes in under 10 seconds,
- the brute force is found,
- peak memory, measured with `resource.getrusage` in the child on Linux/macOS, stays under 150 MB. Skip this check on Windows.

This guards the "high volume" requirement without needing a benchmark setup.

### Running the tests locally

There is no CI for now: the tool is for internal use, and every test runs on a developer machine.

| Command | Use |
|---|---|
| `pytest` | Full suite, including the volume test (about 5 s) |
| `pytest -m "not slow"` | Quick check while coding (under 1 s) |
| `pytest --cov` | Full suite with coverage; fails below 85% (`fail_under` in `pyproject.toml`) |

- Settings live in `pyproject.toml` under `[tool.pytest.ini_options]` and `[tool.coverage]`.
- Run `pytest --cov` before every commit. Adding CI later only means running this same command.

## Acceptance criteria

1. `pytest` runs every test and passes on a clean checkout after `pip install -e .[dev]`.
2. Cases E1–E14 are implemented and pass.
3. Line coverage of `loganalyzer/` is 85% or higher, and `pytest --cov` fails below that.
4. The volume smoke test passes locally as part of `pytest` and can be skipped with `-m "not slow"`.
5. Breaking a default rule (for example changing the SQL injection regex so `O'Brien` matches) makes at least one e2e test fail with a readable message. Check this once by hand and note the result in the commit message.

## Tasks

### T-08.1 Test tooling and fixtures
Add the pytest and coverage settings to `pyproject.toml`, register the `slow` marker, and write `tests/conftest.py` with the fixtures above.
*Files:* `pyproject.toml`, `tests/conftest.py`

### T-08.2 Unit test review
Go through US-02 to US-07 and confirm every task's test note has a matching test. Fill the gaps. Use `pytest.mark.parametrize` for parser and rule cases so new cases are one line each.
*Files:* `tests/test_parsers.py`, `tests/test_rules.py`, `tests/test_detector.py`, `tests/test_correlator.py`, `tests/test_report.py`, `tests/test_cli.py`

### T-08.3 End-to-end tests
Implement E1–E14 in `tests/test_e2e.py` with a helper `run_cli(*args) -> CompletedProcess` (subprocess, `sys.executable -m loganalyzer`, `--year 2025`, `cwd` set to the repo root, `timeout=30`).
*Files:* `tests/test_e2e.py`

### T-08.4 Volume smoke test
Implement the generator and the three checks above in `tests/test_volume.py`, marked `slow`.
*Files:* `tests/test_volume.py`

### T-08.5 Local test commands
Set the coverage gate (`fail_under = 85`) in `pyproject.toml` and document the three commands above in the README (US-09). No CI workflow for now.
*Files:* `pyproject.toml`, `README.md`

### T-08.6 Mutation check by hand
Break three things on purpose, one at a time: the SQL injection regex, the brute force `count`, and the correlation boost. Confirm a test fails each time, then revert. Record the results in the commit message. This shows the tests actually catch regressions, which matters for a QA submission.

## Out of scope

- Property-based testing (Hypothesis) and automated mutation testing (mutmut). Both are good next steps, listed as future work in the README.
- Performance benchmarking beyond the smoke test
