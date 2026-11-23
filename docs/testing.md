# Testing

## Test map

| File | Level | Covers |
|---|---|---|
| `tests/conftest.py` | helpers | `REPO_ROOT`, `SAMPLES_DIR`, `SAMPLE_YEAR` (2025), `T0` (2025-07-03 10:00:00 UTC), `make_event(kind, seconds=, ip=, file=, line_no=, **fields)`, `sample_lines(name)`, `parse_samples(*names)`, fixtures `samples_dir`, `write_log`, `default_rules` |
| `tests/test_reader.py` | unit | `read_lines`: order, line numbers, blank lines, CRLF, invalid UTF-8, laziness, sample line counts |
| `tests/test_parsers.py` | unit | every sample line shape, bad lines, timezones, URL decoding, sudo commands with `;`/`=`, registry, `ParseStats` cap |
| `tests/test_rules.py` | unit | default rules load, every validation message, all errors reported together, filters, invalid TOML |
| `tests/test_detector.py` | unit | window boundaries, bursts, distinct, compound keys, escalation cases, pattern merging, single pass, sweep, **expected findings on the samples**, SQL-injection positives and false positives |
| `tests/test_correlator.py` | unit | grouping, user vs IP keys, severity table, context buffer, summary text, **expected incidents on the samples** |
| `tests/test_report.py` | unit | text header/order/evidence/caps/clipping/colour, JSON shape, sorting, stability |
| `tests/test_cli.py` | integration | `main()` in-process: flags, exit codes, errors, colour decision, read errors, Python version check |
| `tests/test_e2e.py` | end-to-end | the real command as a subprocess on `samples/`, cases **E1–E14** (numbering matches `development-plan/US-08-…md`) |
| `tests/test_volume.py` | volume (`slow`) | 200k generated lines: < 10 s, attack found, peak < 150 MB, growth vs 20k lines < 10 MB |
| `tests/test_readme.py` | docs | README example output block equals the real output |

## Conventions

- Prefer `parse_rules({"rule": [...]})` and `make_event(...)` over files; use `write_log`/`tmp_path` when a file is needed.
- Parametrize lists of cases (`@pytest.mark.parametrize`) so a new case is one line.
- Tests that render text must use **relative** sample paths and run from `REPO_ROOT` (see the clipping gotcha in [development.md](development.md#gotchas-already-hit)).
- e2e tests call `sys.executable -m loganalyzer` with `cwd=REPO_ROOT`, `timeout=30`, and always `--year 2025`.
- Anything taking more than ~1 s gets `@pytest.mark.slow`.
- False-positive guards are first-class: every new detection rule needs at least one "must not fire" case.

## Expected results that move together

The sample logs have one agreed set of expected results (worked out line by line from `qa-assessment.md`). It is written down in several places on purpose: each level checks it independently. **If you change a rule, threshold, severity, correlation or report layout, update all that apply:**

| Where | What |
|---|---|
| `tests/test_detector.py` | `EXPECTED` (rule, key) → (severity, count, escalated); evidence line numbers in `test_sample_evidence_lines` |
| `tests/test_correlator.py` | `EXPECTED_INCIDENTS`; exact summary string for `10.0.0.50` |
| `tests/test_e2e.py` | `EXPECTED`, `INNOCENT_KEYS`; evidence entry count (33) in E8 |
| `tests/test_report.py` | header numbers; checked evidence line count (33) |
| `tests/test_cli.py` | header line `Incidents: 6 (critical 2, high 2, medium 2)`; JSON `stats` |
| `README.md` | example output (regenerate, below) and the "What it detects" table |
| `development-plan/README.md` | "Expected findings on the sample logs" table |

Current expected incidents (both sample files, `--year 2025`):

| Key | Severity | Correlated | Rules |
|---|---|---|---|
| `10.0.0.50` | critical | yes | `ssh-bruteforce`, `web-login-bruteforce` (both escalated) |
| `203.0.113.5` | critical | yes | `path-traversal`, `admin-probing`, `ssh-invalid-users` |
| `10.0.0.88` | high | no | `sql-injection` (2 events) |
| `user:johndoe` | high | no | `sensitive-sudo` |
| `172.16.0.20` | medium | no | `sensitive-path-scan` (6 events) |
| `10.0.0.99` | medium | no | `request-flood`, `rate-limited` |

Must stay clean: `192.168.1.14` (`O'Brien`), `192.168.1.13` (`laptop`), `192.168.1.100` / `user:deploy` (publickey login, `systemctl restart nginx`), and all other `192.168.1.x`. Totals: 44 events, 1 malformed line (`webserver.log:26`), 6 incidents.

### Regenerating the README example output

`tests/test_readme.py` fails with "README example output is out of date" when the report changes. Regenerate it from the real output:

```bash
.venv/bin/python - <<'EOF'
import re, subprocess, sys
from pathlib import Path
args = ["samples/webserver.log", "samples/auth.log", "--year", "2025"]
out = subprocess.run([sys.executable, "-m", "loganalyzer", *args], capture_output=True, text=True).stdout.rstrip("\n")
block = ("<!-- example-output:start -->\n```text\n$ python3 -m loganalyzer " + " ".join(args)
         + "\n" + out + "\n```\n<!-- example-output:end -->")
p = Path("README.md")
p.write_text(re.sub(r"<!-- example-output:start -->.*?<!-- example-output:end -->",
                    lambda _: block, p.read_text(), flags=re.S))
EOF
```

Then read the diff: the change must be the one you intended.

## Deliberate-break check

Passing tests prove little unless they can fail. After changing detection logic, limits or the tests themselves, break the code on purpose, run the tests, and restore it (back up the file first, e.g. to the session scratchpad). Results so far:

| Break | Caught by |
|---|---|
| SQL-injection regex matches any apostrophe | 5 e2e tests incl. `test_e6_false_positive_guards[192.168.1.14]` |
| Web brute-force `count` 3 → 6 | 5 e2e tests |
| No cross-file severity boost | 2 e2e tests (8 tests in the full suite) |
| Window expiry `<` → `<=` | `test_detector.py` boundary test |
| Context events disabled | 6 tests |
| Sweep disabled | volume test (peak 447 MB) |
| `readlines()` instead of streaming | volume test (growth limit 10 MB) |
| README output edited by one character | `test_readme.py` |

Record new results in the commit message when the user asks to commit.
