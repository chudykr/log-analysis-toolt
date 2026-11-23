# Status and next steps

## Stories

| Story | State | Commit |
|---|---|---|
| Development plan (US-01 to US-09) | done | `3ff99d8` |
| US-01 Run with one command | done | `eda808e` |
| US-02 Parse web server log | done | `1312f36` |
| US-03 Parse auth log | done | `1312f36` |
| US-04 Configurable rules | done | `1312f36` |
| US-05 Detect suspicious activity | done | `1312f36` |
| US-10 added to the plan | done | `0ad2d87` |
| US-06 Correlate across files | done | `9fb8c7e` |
| US-07 Actionable report | done | `9fb8c7e` |
| US-08 Tests (e2e, volume, coverage gate) | done; CI dropped at the user's request | `3cdaa9b` |
| US-09 README and submission | done except the items below | `d9630fd` |
| US-10 Continuous production mode | **planned, implementation deferred** (user decision, 2026-11-23) | – |

Still open from US-09:

1. **AI transcript:** the user exports the session with `/export` into `ai-transcript/session.md`. Before it is committed, remove e-mail addresses and replace `/Users/<name>/` paths with `~/`, then check with `grep -nE "@[a-z0-9.-]+\.[a-z]{2,}|/Users/" ai-transcript/session.md`. `ai-transcript/README.md` describes the file.
2. **Submission (user's task):** merge `task` into `master`, make the GitHub repository public, send the link.
3. Python 3.11 has not been tested locally (only 3.12 and the 3.9 rejection path).

## US-10 (continuous mode): planned, implementation deferred

US-10 stays in the plan, but the user decided on 2026-11-23 that its implementation is **not needed for now**. Do not start it unless the user asks. Until then the tool is batch-only and the README "Production notes" describe continuous use as scheduled runs; update that section when US-10 is built.

Spec: [`development-plan/US-10-continuous-production-mode.md`](../development-plan/US-10-continuous-production-mode.md). Notes for implementing it against the current code:

| US-10 item | Where it plugs in | Watch out |
|---|---|---|
| stdin `-`, gzip by magic bytes | `parsers.read_lines`, `cli.check_inputs` (skip path checks for `-`) | Evidence label `<stdin>`; corrupt gzip → exit 2 |
| `--follow` | new `loganalyzer/follow.py` producing the same `(path, line_no, line)` tuples as `read_lines` | Partial lines, rotation (inode change or shrink), stop via `threading.Event` so tests need no signals |
| Findings as they happen | `Detector.feed` is already incremental; add `on_change(finding, change)` called where findings are created (`_pattern`, `_threshold`), escalated (`_escalate`) and closed (sweep) | Batch mode must stay byte-for-byte the same; all current tests must pass unchanged |
| Bounded memory over days | `Detector.findings` and `_pattern_findings` currently grow for the whole run; pattern findings are never closed | Close and drop findings in follow mode only; add a wall-clock sweep; cap open windows (`MAX_OPEN_KEYS`) |
| Format-change warning | `parse_stream` / `ParseStats` | The samples (1 malformed in 33 lines, 3%) must not warn |
| Incremental correlation | `correlator` currently works on a finished list | Keep a small map of open keys → files instead of all findings |

## Known limitations (accepted)

- auth.log has no year/timezone: `--year` and UTC are assumed; logs crossing New Year get the wrong year.
- Files are not merged by time; detector state is per file and correlation links by IP/user only.
- Rule-based only: no allow-lists, IP reputation or anomaly scoring.
- Batch only until US-10 is implemented; with scheduled runs a threshold window does not span two runs.
- Single process; scaling (log shipper, split by source IP, JSON into a SIEM) is described in the README, not built.

## Where the code differs from the plan

The plan in `development-plan/` was written before the code. These differences are deliberate; the code (and these docs) are authoritative:

| Plan said | Code does | Why |
|---|---|---|
| Rules match `path` | Web events also have `path_decoded`; attack rules match it | Catches URL-encoded attacks |
| Pattern rules key on source IP | Pattern rules accept `group_by` too | `sensitive-sudo` keys on `user` |
| Finding has `key` | Finding has `key_field` and `key` | Correlator needs to know whether the key is an IP or a user |
| One evidence block per incident | Evidence listed under each finding | Shows which lines triggered which rule |
| Hand-written summary example ("login brute force on web and SSH…") | Generic template from rule titles | Custom rules may not be about logins |
| Sources shown as `auth.log` | Paths shown as given on the command line | Two files with the same name in different folders stay distinct |
| Context = "events forwarded for keys with findings" | Context = events of `CONTEXT_KINDS` that no rule used, from IPs that already have a finding | Avoids showing evidence twice; O(1) per event |
| CI with GitHub Actions (US-08) | No CI; tests run locally | User decision |
| – | Python version check in `__init__.py`, exit 2 | macOS default `python3` is 3.9 |
| – | `tests/test_readme.py` checks the README example output | Keeps the documented output honest |
