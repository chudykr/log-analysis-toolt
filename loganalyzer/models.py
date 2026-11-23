"""Data shared by parsers, rules, detector and report."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum

# Event kinds produced by the parsers. Rules may only refer to these.
HTTP_REQUEST = "http_request"
SSH_FAILED = "ssh_failed"
SSH_ACCEPTED = "ssh_accepted"
SSH_CLOSED = "ssh_closed"
SUDO = "sudo"
AUTH_OTHER = "auth_other"
KNOWN_KINDS = frozenset({HTTP_REQUEST, SSH_FAILED, SSH_ACCEPTED, SSH_CLOSED, SUDO, AUTH_OTHER})

MAX_STORED_MALFORMED = 100
MAX_EVIDENCE = 20
MAX_CONTEXT = 5  # extra non-finding events kept per incident key


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, value: str) -> "Severity":
        return cls[value.upper()]


@dataclass(frozen=True, slots=True)
class Event:
    source_file: str
    line_no: int
    timestamp: datetime  # always timezone-aware, UTC
    source_ip: str | None
    kind: str
    fields: dict[str, str]
    raw: str

    def get(self, name: str) -> str | None:
        """Value of a field by name; `source_ip` and `kind` are attributes, the rest live in `fields`."""
        if name == "source_ip":
            return self.source_ip
        if name == "kind":
            return self.kind
        return self.fields.get(name)


@dataclass(slots=True)
class ParseStats:
    total_lines: int = 0
    parsed: int = 0
    malformed_count: int = 0
    lines_per_file: dict[str, int] = field(default_factory=dict)  # non-blank lines read per file
    # Only the first MAX_STORED_MALFORMED are kept, so a broken file cannot use up memory.
    malformed: list[tuple[str, int, str]] = field(default_factory=list)

    def record_malformed(self, source_file: str, line_no: int, raw: str) -> None:
        self.malformed_count += 1
        if len(self.malformed) < MAX_STORED_MALFORMED:
            self.malformed.append((source_file, line_no, raw))


@dataclass(slots=True)
class Finding:
    rule_id: str
    title: str
    severity: Severity
    key_field: str  # "source_ip" or e.g. "user": what `key` identifies
    key: str
    source_file: str
    first_seen: datetime
    last_seen: datetime
    action: str
    count: int = 0
    escalated: bool = False
    # Capped at MAX_EVIDENCE; `count` keeps the full number.
    evidence: list[Event] = field(default_factory=list)

    def add(self, event: Event) -> None:
        self.count += 1
        if len(self.evidence) < MAX_EVIDENCE:
            self.evidence.append(event)
        if event.timestamp < self.first_seen:
            self.first_seen = event.timestamp
        if event.timestamp > self.last_seen:
            self.last_seen = event.timestamp


@dataclass(slots=True)
class Incident:
    """All findings about one actor (source IP or local user), possibly across several files."""

    key: str           # "10.0.0.50" or "user:johndoe"
    key_type: str      # "ip" or the key field name, e.g. "user"
    severity: Severity
    findings: list[Finding]
    sources: list[str]  # sorted source files the findings came from
    first_seen: datetime
    last_seen: datetime
    correlated: bool    # findings come from two or more files
    summary: str
    actions: list[str]  # de-duplicated, in finding order
    context: list[Event] = field(default_factory=list)
