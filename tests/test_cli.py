import datetime
import json
import os
import subprocess
import sys

import pytest

from loganalyzer import __version__
from loganalyzer.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, main
from tests.conftest import REPO_ROOT


def test_runs_on_both_sample_files(samples_dir, capsys):
    code = main([str(samples_dir / "webserver.log"), str(samples_dir / "auth.log"), "--year", "2025"])

    assert code == EXIT_FINDINGS
    assert "Events parsed: 44   Malformed lines: 1   Incidents: 6 (critical 2, high 2, medium 2)" in capsys.readouterr().out


def test_no_arguments_is_usage_error(capsys):
    assert main([]) == EXIT_ERROR
    assert "usage: loganalyzer" in capsys.readouterr().err


def test_help_lists_every_flag(capsys):
    assert main(["--help"]) == EXIT_OK
    out = capsys.readouterr().out
    for flag in ("--rules", "--json", "--year", "--version", "FILE"):
        assert flag in out


def test_version(capsys):
    assert main(["--version"]) == EXIT_OK
    assert capsys.readouterr().out.strip() == f"loganalyzer {__version__}"


def test_missing_file_is_named_and_nothing_is_analysed(write_log, capsys):
    existing = write_log("ok.log", ["line"])

    code = main([existing, "does-not-exist.log"])

    captured = capsys.readouterr()
    assert code == EXIT_ERROR
    assert "error: file not found: does-not-exist.log" in captured.err
    assert captured.out == ""


def test_all_input_errors_are_reported_together(tmp_path, capsys):
    code = main(["missing-1.log", str(tmp_path), "missing-2.log"])

    err = capsys.readouterr().err
    assert code == EXIT_ERROR
    assert "file not found: missing-1.log" in err
    assert f"not a file: {tmp_path}" in err
    assert "file not found: missing-2.log" in err


@pytest.mark.skipif(sys.platform == "win32" or os.geteuid() == 0, reason="needs POSIX permissions, non-root")
def test_unreadable_file(write_log, capsys):
    path = write_log("secret.log", ["line"])
    os.chmod(path, 0)
    try:
        assert main([path]) == EXIT_ERROR
        assert f"file not readable: {path}" in capsys.readouterr().err
    finally:
        os.chmod(path, 0o600)


def test_missing_rules_file(write_log, capsys):
    code = main([write_log("a.log", ["line"]), "--rules", "nope.toml"])

    assert code == EXIT_ERROR
    assert "error: rules file not found: nope.toml" in capsys.readouterr().err


def test_empty_file_exits_ok(write_log, capsys):
    assert main([write_log("empty.log", "")]) == EXIT_OK
    out = capsys.readouterr().out
    assert "Events parsed: 0" in out
    assert "No suspicious activity found." in out


def test_invalid_utf8_does_not_crash(tmp_path):
    path = tmp_path / "bad.log"
    path.write_bytes(b"\xff\xfe\x00 garbage\n")

    assert main([str(path)]) == EXIT_OK


@pytest.mark.parametrize("year", ["abc", "1969", "2101"])
def test_invalid_year_is_usage_error(write_log, year, capsys):
    assert main([write_log("a.log", ["line"]), "--year", year]) == EXIT_ERROR
    assert "--year" in capsys.readouterr().err


def test_year_defaults_to_current_year():
    from loganalyzer.cli import build_parser

    args = build_parser().parse_args(["a.log"])

    assert args.year == datetime.date.today().year


def test_module_entry_point_exit_codes(samples_dir):
    """Run the real entry point the way a user does: python -m loganalyzer."""
    ok = subprocess.run(
        [sys.executable, "-m", "loganalyzer", str(samples_dir / "webserver.log"), str(samples_dir / "auth.log")],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=30,
    )
    missing = subprocess.run(
        [sys.executable, "-m", "loganalyzer", "missing.log"],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=30,
    )

    assert ok.returncode == EXIT_FINDINGS, ok.stderr
    assert missing.returncode == EXIT_ERROR
    assert "file not found: missing.log" in missing.stderr


def test_json_output_is_valid(samples_dir, capsys):
    code = main([str(samples_dir / "webserver.log"), str(samples_dir / "auth.log"), "--year", "2025", "--json"])

    data = json.loads(capsys.readouterr().out)
    assert code == EXIT_FINDINGS
    assert data["stats"] == {"events": 44, "malformed": 1, "incidents": 6,
                             "by_severity": {"critical": 2, "high": 2, "medium": 2, "low": 0}}
    assert data["malformed"][0]["line"] == 26


def test_clean_input_exits_ok(write_log, capsys):
    path = write_log("clean.log", [
        '192.168.1.10 - - [03/Jul/2025:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 1234',
        '192.168.1.11 - - [03/Jul/2025:10:00:02 +0000] "GET /about.html HTTP/1.1" 200 982',
    ])

    assert main([path]) == EXIT_OK
    assert "No suspicious activity found." in capsys.readouterr().out


def test_invalid_rules_file_is_reported(write_log, tmp_path, capsys):
    rules = tmp_path / "bad.toml"
    rules.write_text("""
[[rule]]
id = "broken"
title = "Broken"
type = "pattern"
severity = "high"
kinds = ["http_request"]
field = "path"
regex = '(unclosed'
action = "Nothing."
""")

    code = main([write_log("a.log", ["line"]), "--rules", str(rules)])

    err = capsys.readouterr().err
    assert code == EXIT_ERROR
    assert "rule 'broken'" in err
    assert "invalid regex" in err


def test_custom_rules_replace_defaults(samples_dir, tmp_path, capsys):
    rules = tmp_path / "only-sqli.toml"
    rules.write_text("""
[[rule]]
id = "sql-injection"
title = "SQL injection attempt"
type = "pattern"
severity = "high"
kinds = ["http_request"]
field = "path_decoded"
regex = '(?i)union.+select'
action = "Block the IP and review the database logs."
""")

    code = main([str(samples_dir / "webserver.log"), "--rules", str(rules), "--json"])

    incidents = json.loads(capsys.readouterr().out)["incidents"]
    assert code == EXIT_FINDINGS
    assert [(i["key"], [f["rule_id"] for f in i["findings"]]) for i in incidents] == [
        ("10.0.0.88", ["sql-injection"])]


class FakeStream:
    def __init__(self, tty):
        self.tty = tty

    def isatty(self):
        return self.tty


@pytest.mark.parametrize("tty, no_color, expected", [
    (True, False, True),
    (True, True, False),
    (False, False, False),
])
def test_color_only_for_terminals_without_no_color(monkeypatch, tty, no_color, expected):
    from loganalyzer.cli import use_color

    monkeypatch.delenv("NO_COLOR", raising=False)
    if no_color:
        monkeypatch.setenv("NO_COLOR", "1")

    assert use_color(FakeStream(tty)) is expected


def test_piped_output_has_no_ansi_codes(samples_dir):
    result = subprocess.run(
        [sys.executable, "-m", "loganalyzer", str(samples_dir / "webserver.log"), "--year", "2025"],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=30,
    )

    assert "[CRITICAL]" in result.stdout
    assert "\033[" not in result.stdout
