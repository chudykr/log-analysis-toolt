from datetime import datetime, timezone

import pytest

from loganalyzer.models import MAX_STORED_MALFORMED, ParseStats
from loganalyzer.parsers import (
    ParseContext,
    parse_auth,
    parse_clf_timestamp,
    parse_line,
    parse_stream,
    parse_webserver,
)
from tests.conftest import SAMPLE_YEAR, parse_samples, sample_lines

CTX = ParseContext(year=SAMPLE_YEAR)
WEB = sample_lines("webserver.log")
AUTH = sample_lines("auth.log")


def utc(*args):
    return datetime(*args, tzinfo=timezone.utc)


# --- Web server log (US-02) ------------------------------------------------------------------

def test_web_normal_get():
    parsed = parse_webserver(WEB[0], CTX)

    assert parsed.kind == "http_request"
    assert parsed.source_ip == "192.168.1.10"
    assert parsed.timestamp == utc(2025, 7, 3, 10, 0, 1)
    assert parsed.timestamp.isoformat() == "2025-07-03T10:00:01+00:00"
    assert parsed.fields == {
        "method": "GET", "path": "/index.html", "path_decoded": "/index.html",
        "protocol": "HTTP/1.1", "status": "200", "size": "1234", "user": "-",
    }


@pytest.mark.parametrize("line_no, ip, method, path, status", [
    (3, "10.0.0.50", "POST", "/login", "401"),
    (7, "10.0.0.50", "POST", "/login", "200"),
    (12, "203.0.113.5", "GET", "/admin/../../../etc/passwd", "400"),
    (14, "10.0.0.88", "GET", "/search?q=' UNION SELECT * FROM users--", "200"),
    (15, "192.168.1.14", "GET", "/search?q=O'Brien", "200"),
    (16, "10.0.0.88", "GET", "/search?q=1; DROP TABLE users--", "200"),
    (32, "10.0.0.99", "POST", "/api/users", "429"),
])
def test_web_sample_lines(line_no, ip, method, path, status):
    parsed = parse_webserver(WEB[line_no - 1], CTX)

    assert (parsed.source_ip, parsed.fields["method"], parsed.fields["path"], parsed.fields["status"]) == (
        ip, method, path, status)
    assert parsed.fields["protocol"] == "HTTP/1.1"


def test_web_size_dash_becomes_zero():
    parsed = parse_webserver('1.2.3.4 - - [03/Jul/2025:10:00:01 +0000] "GET / HTTP/1.0" 304 -', CTX)

    assert parsed.fields["size"] == "0"
    assert parsed.fields["protocol"] == "HTTP/1.0"


def test_web_path_is_url_decoded_for_rules():
    parsed = parse_webserver(
        '1.2.3.4 - - [03/Jul/2025:10:00:01 +0000] "GET /s?q=%27%20UNION+SELECT HTTP/1.1" 200 1', CTX)

    assert parsed.fields["path"] == "/s?q=%27%20UNION+SELECT"
    assert parsed.fields["path_decoded"] == "/s?q=' UNION SELECT"


def test_web_timezone_offset_is_converted_to_utc():
    assert parse_clf_timestamp("03/Jul/2025:12:00:01 +0200") == utc(2025, 7, 3, 10, 0, 1)
    assert parse_clf_timestamp("03/Jul/2025:05:30:01 -0430") == utc(2025, 7, 3, 10, 0, 1)


@pytest.mark.parametrize("line", [
    "[MALFORMED ENTRY - system restart",
    "",
    "just some text",
    '1.2.3.4 - - [03/Foo/2025:10:00:01 +0000] "GET / HTTP/1.1" 200 1',   # bad month
    '1.2.3.4 - - [32/Jul/2025:10:00:01 +0000] "GET / HTTP/1.1" 200 1',   # bad day
    '1.2.3.4 - - [03/Jul/2025:10:00:01 +0000] "GET / HTTP/1.1" 2000 1',  # bad status
    '1.2.3.4 - - [03/Jul/2025:10:00:01 +0000] "GET / HTTP/1.1"',         # truncated
])
def test_web_rejects_bad_lines(line):
    assert parse_webserver(line, CTX) is None


def test_web_sample_file_counts():
    events, stats = parse_samples("webserver.log")

    assert len(events) == 32
    assert stats.malformed_count == 1
    source_file, line_no, raw = stats.malformed[0]
    assert source_file.endswith("webserver.log")
    assert (line_no, raw) == (26, "[MALFORMED ENTRY - system restart")
    # Parsing continues after the malformed line.
    assert [e.line_no for e in events if e.line_no in (25, 27)] == [25, 27]


# --- Auth log (US-03) ------------------------------------------------------------------------

def test_auth_failed_password_valid_user():
    parsed = parse_auth(AUTH[0], CTX)

    assert parsed.kind == "ssh_failed"
    assert parsed.source_ip == "10.0.0.50"
    assert parsed.timestamp.isoformat() == "2025-07-03T10:00:03+00:00"
    assert parsed.fields["user"] == "admin"
    assert parsed.fields["port"] == "52341"
    assert parsed.fields["method"] == "password"
    assert parsed.fields["invalid_user"] == "false"


def test_auth_failed_password_invalid_user():
    parsed = parse_auth(AUTH[5], CTX)

    assert (parsed.kind, parsed.source_ip) == ("ssh_failed", "203.0.113.5")
    assert parsed.fields["user"] == "test"
    assert parsed.fields["invalid_user"] == "true"


@pytest.mark.parametrize("line_no, method, user, ip", [
    (5, "password", "admin", "10.0.0.50"),
    (10, "publickey", "deploy", "192.168.1.100"),
])
def test_auth_accepted(line_no, method, user, ip):
    parsed = parse_auth(AUTH[line_no - 1], CTX)

    assert parsed.kind == "ssh_accepted"
    assert (parsed.fields["method"], parsed.fields["user"], parsed.source_ip) == (method, user, ip)


def test_auth_sudo():
    parsed = parse_auth(AUTH[8], CTX)

    assert parsed.kind == "sudo"
    assert parsed.source_ip is None
    assert parsed.fields["user"] == "johndoe"
    assert parsed.fields["target_user"] == "root"
    assert parsed.fields["command"] == "/bin/cat /etc/shadow"
    assert parsed.fields["tty"] == "pts/0"
    assert parsed.fields["pwd"] == "/home/johndoe"


def test_auth_sudo_command_keeps_equals_and_semicolons():
    line = "Jul  3 10:00:15 server sudo: bob : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/env A=1 sh -c 'a ; b'"

    parsed = parse_auth(line, CTX)

    assert parsed.fields["command"] == "/usr/bin/env A=1 sh -c 'a ; b'"
    assert parsed.fields["target_user"] == "root"


def test_auth_connection_closed():
    parsed = parse_auth(AUTH[11], CTX)

    assert (parsed.kind, parsed.source_ip) == ("ssh_closed", "10.0.0.50")
    assert parsed.fields["port"] == "52345"
    assert parsed.fields["preauth"] == "true"


@pytest.mark.parametrize("line", [
    "Jul 13 10:00:03 server sshd[99]: Failed password for admin from 1.2.3.4 port 1 ssh2",  # two-digit day
    "Jul  3 10:00:03 server sshd[99]: Failed password for admin from 1.2.3.4 port 1 ssh2",  # padded day
])
def test_auth_day_formats(line):
    assert parse_auth(line, CTX).kind == "ssh_failed"


def test_auth_unknown_sshd_message_is_kept_as_other():
    parsed = parse_auth("Jul  3 10:00:03 server sshd[99]: pam_unix(sshd:session): session opened for user x", CTX)

    assert parsed.kind == "auth_other"
    assert parsed.fields["program"] == "sshd"
    assert parsed.fields["message"].startswith("pam_unix")


def test_auth_uses_year_from_context():
    assert parse_auth(AUTH[0], ParseContext(year=2031)).timestamp.year == 2031


@pytest.mark.parametrize("line", [
    "Feb 30 10:00:03 server sshd[1]: Failed password for a from 1.2.3.4 port 1 ssh2",  # no such date
    "Foo  3 10:00:03 server sshd[1]: Failed password for a from 1.2.3.4 port 1 ssh2",  # bad month
    "Jul  3 25:00:03 server sshd[1]: Failed password for a from 1.2.3.4 port 1 ssh2",  # bad hour
    "[MALFORMED ENTRY - system restart",
])
def test_auth_rejects_bad_lines(line):
    assert parse_auth(line, CTX) is None


def test_auth_sample_file_counts():
    events, stats = parse_samples("auth.log")

    assert len(events) == 12
    assert stats.malformed_count == 0
    assert [e.kind for e in events].count("ssh_failed") == 7


# --- Registry and stream ---------------------------------------------------------------------

def test_format_is_detected_per_line():
    assert parse_line(WEB[0], CTX).kind == "http_request"
    assert parse_line(AUTH[0], CTX).kind == "ssh_failed"
    assert parse_line("garbage", CTX) is None


def test_parse_stream_mixed_input():
    stats = ParseStats()
    lines = [("web.log", 1, WEB[0]), ("auth.log", 1, AUTH[0]), ("web.log", 2, "garbage")]

    events = list(parse_stream(lines, CTX, stats))

    assert [(e.source_file, e.line_no, e.kind) for e in events] == [
        ("web.log", 1, "http_request"), ("auth.log", 1, "ssh_failed")]
    assert events[0].raw == WEB[0]
    assert (stats.total_lines, stats.parsed, stats.malformed_count) == (3, 2, 1)
    assert stats.malformed == [("web.log", 2, "garbage")]


def test_both_sample_files_in_any_order():
    forward, stats = parse_samples("webserver.log", "auth.log")
    backward, _ = parse_samples("auth.log", "webserver.log")

    assert len(forward) == len(backward) == 44
    assert stats.malformed_count == 1


def test_parse_stats_caps_stored_malformed_lines():
    stats = ParseStats()
    for line_no in range(MAX_STORED_MALFORMED + 50):
        stats.record_malformed("x.log", line_no, "bad")

    assert stats.malformed_count == MAX_STORED_MALFORMED + 50
    assert len(stats.malformed) == MAX_STORED_MALFORMED
