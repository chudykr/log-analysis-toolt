import datetime
import os
import subprocess
import sys

import pytest

from loganalyzer import __version__
from loganalyzer.cli import EXIT_ERROR, EXIT_OK, main
from tests.conftest import REPO_ROOT


def test_runs_on_both_sample_files(samples_dir, capsys):
    code = main([str(samples_dir / "webserver.log"), str(samples_dir / "auth.log")])

    assert code == EXIT_OK
    assert "Read 45 lines from 2 file(s)." in capsys.readouterr().out


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
    assert "Read 0 lines" in capsys.readouterr().out


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

    assert ok.returncode == EXIT_OK, ok.stderr
    assert missing.returncode == EXIT_ERROR
    assert "file not found: missing.log" in missing.stderr
