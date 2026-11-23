"""Reading and parsing log files.

Each parser takes one raw line and returns a `Parsed` tuple, or None if the line is not in its
format. Parsers never raise on bad input. To support a new log format, write one parser function
and add it to PARSERS.
"""

import re
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import NamedTuple
from urllib.parse import unquote_plus

from loganalyzer.models import (
    AUTH_OTHER,
    HTTP_REQUEST,
    SSH_ACCEPTED,
    SSH_CLOSED,
    SSH_FAILED,
    SUDO,
    Event,
    ParseStats,
)

# Fixed English month names, so parsing does not depend on the machine's locale.
MONTHS = {name: number for number, name in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}


@dataclass(frozen=True)
class ParseContext:
    year: int  # used for syslog timestamps, which carry no year


class Parsed(NamedTuple):
    kind: str
    timestamp: datetime
    source_ip: str | None
    fields: dict[str, str]


Parser = Callable[[str, ParseContext], Parsed | None]


def read_lines(paths: Iterable[str]) -> Iterator[tuple[str, int, str]]:
    """Yield (path, line_number, line) for every non-blank line, one file after another.

    Files are read lazily, line by line, so memory use does not depend on file size.
    Line numbers start at 1 and count blank lines, so they match the file as shown in an editor.
    Invalid UTF-8 bytes are replaced instead of raising.
    """
    for path in paths:
        with open(path, encoding="utf-8", errors="replace") as handle:
            for line_no, line in enumerate(handle, start=1):
                line = line.rstrip("\r\n")
                if line.strip():
                    yield path, line_no, line


# --- Web server access log (Common Log Format) -------------------------------------------------

# The path is everything between the method and the last "HTTP/x.y" before the closing quote,
# so request lines containing spaces (e.g. SQL injection attempts) still parse.
_WEB_RE = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>.*) (?P<protocol>HTTP/\d\.\d)" '
    r'(?P<status>\d{3}) (?P<size>\d+|-)$'
)
_CLF_TS_RE = re.compile(
    r"^(?P<day>\d{2})/(?P<month>[A-Za-z]{3})/(?P<year>\d{4}):"
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2}) (?P<sign>[+-])(?P<tzh>\d{2})(?P<tzm>\d{2})$"
)


def parse_clf_timestamp(value: str) -> datetime | None:
    """Parse '03/Jul/2025:10:00:01 +0000' into an aware UTC datetime."""
    match = _CLF_TS_RE.match(value)
    if not match or match["month"] not in MONTHS:
        return None
    offset = timedelta(hours=int(match["tzh"]), minutes=int(match["tzm"]))
    if match["sign"] == "-":
        offset = -offset
    try:
        local = datetime(
            int(match["year"]), MONTHS[match["month"]], int(match["day"]),
            int(match["hour"]), int(match["minute"]), int(match["second"]),
            tzinfo=timezone(offset),
        )
    except ValueError:
        return None
    return local.astimezone(timezone.utc)


def parse_webserver(line: str, ctx: ParseContext | None = None) -> Parsed | None:
    match = _WEB_RE.match(line)
    if not match:
        return None
    timestamp = parse_clf_timestamp(match["ts"])
    if timestamp is None:
        return None
    path = match["path"]
    fields = {
        "method": match["method"],
        "path": path,
        # Decoded copy, so rules also catch URL-encoded attacks such as %27%20UNION.
        "path_decoded": unquote_plus(path),
        "protocol": match["protocol"],
        "status": match["status"],
        "size": "0" if match["size"] == "-" else match["size"],
        "user": match["user"],
    }
    return Parsed(HTTP_REQUEST, timestamp, match["ip"], fields)


# --- Auth log (syslog) -----------------------------------------------------------------------

# Days below 10 are padded with a space ("Jul  3"), hence " +".
_SYSLOG_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2}) +(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) (?P<program>[\w\-.]+)(?:\[(?P<pid>\d+)\])?: (?P<message>.*)$"
)
_SSH_MESSAGES: list[tuple[str, re.Pattern[str]]] = [
    (SSH_FAILED, re.compile(
        r"^Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>\S+) "
        r"from (?P<ip>\S+) port (?P<port>\d+)")),
    (SSH_ACCEPTED, re.compile(
        r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")),
    (SSH_CLOSED, re.compile(
        r"^Connection closed by (?:(?:invalid |authenticating )?user (?P<user>\S+) )?"
        r"(?P<ip>\S+) port (?P<port>\d+)(?P<preauth> \[preauth\])?")),
]
_SUDO_RE = re.compile(r"^\s*(?P<user>\S+) : (?P<rest>.*)$")
_SUDO_KEYS = {"TTY": "tty", "PWD": "pwd", "USER": "target_user"}


def parse_syslog_timestamp(month: str, day: str, time: str, year: int) -> datetime | None:
    if month not in MONTHS:
        return None
    try:
        hour, minute, second = (int(part) for part in time.split(":"))
        return datetime(year, MONTHS[month], int(day), hour, minute, second, tzinfo=timezone.utc)
    except ValueError:
        return None


def _parse_sshd(message: str) -> tuple[str, str | None, dict[str, str]] | None:
    for kind, pattern in _SSH_MESSAGES:
        match = pattern.match(message)
        if not match:
            continue
        groups = match.groupdict()
        fields = {"port": groups["port"]}
        if groups.get("user"):
            fields["user"] = groups["user"]
        if "method" in groups:
            fields["method"] = groups["method"]
        if kind == SSH_FAILED:
            # Always set, because rule filters treat a missing field as "no match".
            fields["invalid_user"] = "true" if groups["invalid"] else "false"
        if kind == SSH_CLOSED:
            fields["preauth"] = "true" if groups["preauth"] else "false"
        return kind, groups["ip"], fields
    return None


def _parse_sudo(message: str) -> dict[str, str] | None:
    """Parse 'user : TTY=pts/0 ; PWD=/x ; USER=root ; COMMAND=/bin/cat /etc/shadow'."""
    match = _SUDO_RE.match(message)
    if not match:
        return None
    rest = match["rest"]
    fields = {"user": match["user"]}
    # COMMAND runs to the end of the line and may itself contain ";" or "=".
    command_at = rest.find("COMMAND=")
    if command_at != -1:
        fields["command"] = rest[command_at + len("COMMAND="):].strip()
        rest = rest[:command_at]
    for part in rest.split(";"):
        key, sep, value = part.strip().partition("=")
        if sep and key in _SUDO_KEYS:
            fields[_SUDO_KEYS[key]] = value.strip()
    if "command" not in fields:
        return None
    return fields


def parse_auth(line: str, ctx: ParseContext) -> Parsed | None:
    header = _SYSLOG_RE.match(line)
    if not header:
        return None
    timestamp = parse_syslog_timestamp(header["month"], header["day"], header["time"], ctx.year)
    if timestamp is None:
        return None
    base = {"host": header["host"], "program": header["program"]}
    if header["pid"]:
        base["pid"] = header["pid"]
    program, message = header["program"], header["message"]

    if program == "sshd":
        ssh = _parse_sshd(message)
        if ssh:
            kind, ip, fields = ssh
            return Parsed(kind, timestamp, ip, base | fields)
    elif program == "sudo":
        sudo = _parse_sudo(message)
        if sudo:
            return Parsed(SUDO, timestamp, None, base | sudo)
    # A valid syslog line we have no specific parser for: keep it, it is not malformed.
    return Parsed(AUTH_OTHER, timestamp, None, base | {"message": message})


# --- Registry and stream ---------------------------------------------------------------------

PARSERS: list[tuple[str, Parser]] = [
    ("webserver", parse_webserver),
    ("auth", parse_auth),
]


def parse_line(line: str, ctx: ParseContext) -> Parsed | None:
    for _name, parser in PARSERS:
        parsed = parser(line, ctx)
        if parsed is not None:
            return parsed
    return None


def parse_stream(
    lines: Iterable[tuple[str, int, str]], ctx: ParseContext, stats: ParseStats
) -> Iterator[Event]:
    """Turn (file, line_no, raw) items into Events; count malformed lines in `stats`."""
    for source_file, line_no, raw in lines:
        stats.total_lines += 1
        parsed = parse_line(raw, ctx)
        if parsed is None:
            stats.record_malformed(source_file, line_no, raw)
            continue
        stats.parsed += 1
        yield Event(source_file, line_no, parsed.timestamp, parsed.source_ip, parsed.kind, parsed.fields, raw)
