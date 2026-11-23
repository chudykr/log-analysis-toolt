# US-01: Run the tool with one command on one or more files

**Estimate:** S · **Depends on:** – · **Decisions:** D1, D2, D6, D9

## Story

As a **security analyst**
I want to **run the tool with a single command and pass any number of log files**
so that **I can start an analysis without reading docs or setting anything up**.

## Description

This story creates the project skeleton and the command-line entry point. Later stories plug parsing, detection and reporting into it.

The command is `python -m loganalyzer FILE [FILE ...]`. Files may be given in any order and any mix of formats; format detection belongs to US-02 and US-03. The only optional flags are:

| Flag | Meaning | Default |
|---|---|---|
| `--rules PATH` | Rules file to use instead of the bundled one | `loganalyzer/rules.toml` |
| `--json` | Print JSON instead of the text report | off |
| `--year YYYY` | Year assumed for syslog timestamps that have no year | current year |
| `--version`, `-h/--help` | Standard | – |

Files are opened with `encoding="utf-8", errors="replace"` and read line by line through a generator, so a very large file is never loaded into memory at once. Each yielded item carries `(file_name, line_number, raw_line)`, so findings can point back to their exact line.

Exit codes:

- `0`: ran successfully, no findings
- `1`: ran successfully, findings reported
- `2`: usage error, missing or unreadable file, invalid rules file

A missing file prints a one-line error on stderr (`error: file not found: foo.log`) and exits `2` before any analysis starts, so a typo never yields a half-finished report.

## Acceptance criteria

1. **Given** the two sample files, **when** I run `python -m loganalyzer samples/webserver.log samples/auth.log`, **then** the tool runs and exits with code `1`.
2. **Given** no arguments, **when** I run `python -m loganalyzer`, **then** usage help appears on stderr and the exit code is `2`.
3. **Given** one existing and one missing file, **when** I run the tool, **then** stderr names the missing file and the exit code is `2`.
4. **Given** a file containing invalid UTF-8 bytes, **when** I run the tool, **then** it does not crash.
5. **Given** an empty file, **when** I run the tool on it, **then** it reports zero events and exits `0`.
6. `python -m loganalyzer --help` lists every flag with a one-line description.

## Tasks

### T-01.1 Project skeleton
Create `pyproject.toml` (name `loganalyzer`, `requires-python = ">=3.11"`, no runtime dependencies, dev extra `pytest`, `pytest-cov`), the `loganalyzer/` package with `__init__.py` (holds `__version__`) and `__main__.py` that calls `cli.main()` and passes its return value to `sys.exit`. Add a `[project.scripts] loganalyzer = "loganalyzer.cli:main"` entry so `pip install -e .` also provides a `loganalyzer` command.
*Files:* `pyproject.toml`, `loganalyzer/__init__.py`, `loganalyzer/__main__.py`
*Test:* `python -m loganalyzer --version` prints the version.

### T-01.2 Argument parsing
Implement `cli.build_parser()` with `argparse`: positional `files` (`nargs="+"`), `--rules`, `--json`, `--year` (int, validated to 1970–2100), `--version`. Keep `main(argv=None) -> int` free of `sys.exit` calls so tests can call it directly.
*Files:* `loganalyzer/cli.py`
*Test:* `tests/test_cli.py`: no args gives exit 2; `--help` lists the flags; `--year abc` gives exit 2.

### T-01.3 Streaming file reader
Implement `parsers.read_lines(paths) -> Iterator[tuple[str, int, str]]` that opens each file in turn, yields `(path, line_no, line.rstrip("\n"))` with line numbers starting at 1, and skips blank lines. Never use `read()` or `readlines()`.
*Files:* `loganalyzer/parsers.py`
*Test:* reading two temp files yields lines in order with correct numbers; a 100k-line temp file is consumed lazily (check the result is a generator).

### T-01.4 Input validation and exit codes
Before analysis, check every path exists and is a readable file; collect all problems and report them together. Map outcomes to exit codes 0/1/2 in one place (`cli.main`).
*Files:* `loganalyzer/cli.py`
*Test:* missing file gives exit 2 and the file name on stderr; a directory passed as a file gives exit 2; an empty file gives exit 0.

## Out of scope

- Reading from stdin or following a growing file (future work, see US-09)
- Globbing inside the tool (the shell expands `*.log`)
