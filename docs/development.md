# Development

## Environment

| Item | Value |
|---|---|
| Python | 3.11+ required. This machine: `.venv` built from pyenv `~/.pyenv/versions/3.12.4`. System `python3` is 3.9: do not use it (except for the old-Python test). |
| Install | `.venv/bin/pip install -e ".[dev]"` (quote the extras: the user's shell is zsh) |
| Run | `.venv/bin/python -m loganalyzer samples/webserver.log samples/auth.log --year 2025` |
| Packaging | `pyproject.toml` (setuptools); `rules.toml` is package data; console script `loganalyzer` |
| Git | Work on branch `task`; `master` is the main branch. Remote `origin` is the user's GitHub repo. |

If `.venv` is missing: `~/.pyenv/versions/3.12.4/bin/python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"`.

## Commands

| Command | Use |
|---|---|
| `.venv/bin/pytest -m "not slow"` | Quick check while coding (< 1 s) |
| `.venv/bin/pytest` | Full suite incl. the volume test (~4 s) |
| `.venv/bin/pytest --cov` | Full suite + coverage; fails below 85% (currently ~98%). **Run this before reporting work as done.** |
| `.venv/bin/pytest -s tests/test_volume.py` | Prints throughput and peak memory |

There is **no CI** (the user decided this; do not add `.github/workflows` or badges). All verification is local.

## How the user works

- Work goes **story by story** from `development-plan/` (`US-01` … `US-10`; US-10 is planned but deferred: implement it only when the user asks). The user says "continue with US-xx"; at the end they say "commit US-xx".
- **Commit only when asked. Never push.** Stage only the files of the story; never stage `.idea/`.
- Commit message style used so far:

  ```
  US-08: end-to-end and volume tests, local coverage gate

  - bullet per notable change
  - ...

  Co-Authored-By: <the attribution line the session's instructions give>
  ```

  When the user dictates a message (e.g. `git commit -m "mvp - US01 to US05"`), use it as given plus the attribution trailer.
- When the implementation deviates from a story, say so in the summary and update the story or [status.md](status.md#where-the-code-differs-from-the-plan) so the plan stays true.
- The user may edit files in their IDE between turns. If a file changed unexpectedly (e.g. an accidental indent broke `tests/test_parsers.py` once), report it instead of silently reverting it.

## Code conventions

- Type hints everywhere; `X | None`, built-in generics (`list[str]`). Data classes with `slots=True`; `frozen=True` where values must not change (`Event`, rule objects).
- Module-level `UPPER_CASE` constants for every limit or tunable (caps, windows, widths). Tests import them instead of repeating numbers.
- Compile regexes once (module level or at rule load).
- Comments explain **why** (e.g. why `" +"` in the syslog regex: day padding), not what.
- Functions that build output return strings; only `cli.main` prints.
- Errors for the user: `error: <message>` on stderr, exit code 2. Collect and report all problems at once where possible (`check_inputs`, `parse_rules`).
- Keep the package importable without side effects, except the Python version check in `__init__.py`.

## Gotchas already hit

| Problem | What to do |
|---|---|
| `.gitignore` (Python template) ignores `*.log`, which hid `samples/*.log` | The file has `!samples/*.log`. New fixture logs elsewhere need their own exception. |
| Report tests failed only in a clone with a long path: absolute paths made evidence lines exceed 160 chars and get clipped | Use **relative** paths (`samples/webserver.log`, run from `REPO_ROOT`) in any test that compares rendered text. |
| `sys.exit("message")` exits with code 1, which means "incidents found" | Print to stderr, then `sys.exit(2)`. |
| Lowercasing rule titles in the summary produced "sSH" | Never change the case of user-provided text. |
| A memory-growth limit of 25 MB missed a `readlines()` regression (growth was ~25 MB) | Limits must be checked by breaking the code on purpose; the current limit is 10 MB (normal growth ≈ 0). |
| `sed -i ''` on macOS; zsh has `$pipestatus`, not `$PIPESTATUS` | Prefer small Python scripts for multi-line edits in shell. |
| auth.log year defaults to the current year | Always pass `--year 2025` with the samples, in tests and examples. |

## Definition of done (from the plan)

- Acceptance criteria of the story met and covered by automated tests where possible.
- `.venv/bin/pytest --cov` passes locally (≥ 85%).
- No new runtime dependencies.
- README updated if usage, rules or output changed (the README example test will tell you about output).
- For changes to detection or limits: break the change on purpose once and confirm a test fails (see [testing.md](testing.md#deliberate-break-check)).
