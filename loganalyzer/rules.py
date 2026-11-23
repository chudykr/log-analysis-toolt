"""Loading and validating detection rules from TOML.

Two rule types:
    pattern    fires on every event whose `field` matches `regex`
    threshold  fires when `count` matching events (or distinct values of `distinct`)
               from one key fall inside `window_seconds`
See loganalyzer/rules.toml for the default rules and the README for the full schema.
"""

import re
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

from loganalyzer.models import KNOWN_KINDS, Event, Severity

PATTERN = "pattern"
THRESHOLD = "threshold"

_ID_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_COMMON_KEYS = {"id", "title", "type", "severity", "kinds", "where", "action", "enabled", "group_by"}
_TYPE_KEYS = {
    PATTERN: _COMMON_KEYS | {"field", "regex"},
    THRESHOLD: _COMMON_KEYS | {"count", "window_seconds", "distinct", "escalate_on"},
}
_ESCALATION_KEYS = {"kinds", "where", "severity"}


class RulesError(Exception):
    """Raised with every problem found in a rules file, not only the first."""

    def __init__(self, errors: list[str]):
        super().__init__("\n".join(errors))
        self.errors = errors


@dataclass(frozen=True)
class Filter:
    kinds: frozenset[str]
    where: Mapping[str, re.Pattern[str]] = field(default_factory=dict)

    def matches(self, event: Event) -> bool:
        if event.kind not in self.kinds:
            return False
        for name, pattern in self.where.items():
            value = event.get(name)
            if value is None or not pattern.search(value):
                return False
        return True


@dataclass(frozen=True)
class Escalation:
    filter: Filter
    severity: Severity


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    type: str
    severity: Severity
    filter: Filter
    group_by: tuple[str, ...]
    action: str
    enabled: bool = True

    def matches(self, event: Event) -> bool:
        return self.filter.matches(event)

    def key_of(self, event: Event) -> tuple[str, ...]:
        return tuple(event.get(name) or "unknown" for name in self.group_by)


@dataclass(frozen=True)
class PatternRule(Rule):
    field: str = ""
    regex: re.Pattern[str] = re.compile("")

    def hits(self, event: Event) -> bool:
        if not self.matches(event):
            return False
        value = event.get(self.field)
        return value is not None and self.regex.search(value) is not None


@dataclass(frozen=True)
class ThresholdRule(Rule):
    count: int = 1
    window_seconds: float = 60.0
    distinct: str | None = None
    escalate_on: Escalation | None = None


# --- loading ---------------------------------------------------------------------------------

def default_rules_path() -> Path:
    return Path(str(resources.files("loganalyzer") / "rules.toml"))


def load_rules(path: str | Path | None = None) -> list[Rule]:
    """Load and validate rules; return only enabled rules. Raise RulesError listing all problems."""
    path = Path(path) if path is not None else default_rules_path()
    try:
        with open(path, "rb") as handle:
            data = tomllib.load(handle)
    except tomllib.TOMLDecodeError as exc:
        raise RulesError([f"{path}: invalid TOML: {exc}"]) from None
    except OSError as exc:
        raise RulesError([f"{path}: cannot read: {exc.strerror}"]) from None
    rules = parse_rules(data, source=str(path))
    return [rule for rule in rules if rule.enabled]


def parse_rules(data: Mapping[str, Any], source: str = "rules") -> list[Rule]:
    errors: list[str] = []
    unknown_top = set(data) - {"rule"}
    if unknown_top:
        errors.append(f"{source}: unknown top-level key(s): {', '.join(sorted(unknown_top))}")
    tables = data.get("rule", [])
    if not isinstance(tables, list) or not tables:
        errors.append(f"{source}: no rules defined (expected one or more [[rule]] tables)")
        tables = []

    rules: list[Rule] = []
    seen_ids: set[str] = set()
    for index, table in enumerate(tables, start=1):
        label = f"rule #{index}"
        if isinstance(table, Mapping) and isinstance(table.get("id"), str):
            label = f"rule '{table['id']}'"
        rule_errors: list[str] = []
        rule = _build_rule(table, rule_errors)
        if rule is not None and rule.id in seen_ids:
            rule_errors.append(f"duplicate id '{rule.id}'")
        if rule_errors:
            errors.extend(f"{source}: {label}: {message}" for message in rule_errors)
        elif rule is not None:
            seen_ids.add(rule.id)
            rules.append(rule)

    if errors:
        raise RulesError(errors)
    return rules


def _build_rule(table: Any, errors: list[str]) -> Rule | None:
    if not isinstance(table, Mapping):
        errors.append("must be a table")
        return None

    rule_id = _require_str(table, "id", errors)
    if rule_id is not None and not _ID_RE.match(rule_id):
        errors.append(f"'id' must be kebab-case (e.g. 'ssh-bruteforce'), got {rule_id!r}")
    title = _require_str(table, "title", errors)
    action = _require_str(table, "action", errors)
    severity = _severity(table.get("severity"), "severity", errors)

    rule_type = table.get("type")
    if rule_type not in _TYPE_KEYS:
        errors.append(f"'type' must be 'pattern' or 'threshold', got {rule_type!r}")
    else:
        unknown = set(table) - _TYPE_KEYS[rule_type]
        if unknown:
            errors.append(f"unknown key(s) for a {rule_type} rule: {', '.join(sorted(unknown))}")

    rule_filter = _filter(table, "", errors)
    group_by = _group_by(table.get("group_by", "source_ip"), errors)
    enabled = table.get("enabled", True)
    if not isinstance(enabled, bool):
        errors.append("'enabled' must be true or false")

    common = dict(id=rule_id, title=title, type=rule_type, severity=severity, filter=rule_filter,
                  group_by=group_by, action=action, enabled=enabled)

    if rule_type == PATTERN:
        field_name = _require_str(table, "field", errors)
        regex = _regex(table.get("regex"), "regex", errors)
        if errors:
            return None
        return PatternRule(**common, field=field_name, regex=regex)

    if rule_type == THRESHOLD:
        count = table.get("count")
        if isinstance(count, bool) or not isinstance(count, int) or count < 1:
            errors.append(f"'count' must be a positive integer, got {count!r}")
        window = table.get("window_seconds")
        if isinstance(window, bool) or not isinstance(window, (int, float)) or window <= 0:
            errors.append(f"'window_seconds' must be a positive number, got {window!r}")
        distinct = table.get("distinct")
        if distinct is not None and (not isinstance(distinct, str) or not distinct):
            errors.append("'distinct' must be a field name")
        escalation = _escalation(table.get("escalate_on"), errors)
        if errors:
            return None
        return ThresholdRule(**common, count=count, window_seconds=float(window),
                             distinct=distinct, escalate_on=escalation)
    return None


def _require_str(table: Mapping[str, Any], key: str, errors: list[str]) -> str | None:
    value = table.get(key)
    if not isinstance(value, str) or not value.strip():
        errors.append(f"'{key}' is required and must be a non-empty string")
        return None
    return value


def _severity(value: Any, key: str, errors: list[str]) -> Severity | None:
    try:
        return Severity.parse(value)
    except (KeyError, AttributeError):
        errors.append(f"'{key}' must be one of low, medium, high, critical, got {value!r}")
        return None


def _regex(value: Any, key: str, errors: list[str]) -> re.Pattern[str] | None:
    if not isinstance(value, str):
        errors.append(f"'{key}' must be a regex string")
        return None
    try:
        return re.compile(value)
    except re.error as exc:
        errors.append(f"'{key}': invalid regex {value!r}: {exc}")
        return None


def _filter(table: Mapping[str, Any], prefix: str, errors: list[str]) -> Filter | None:
    kinds = table.get("kinds")
    if not isinstance(kinds, list) or not kinds or not all(isinstance(kind, str) for kind in kinds):
        errors.append(f"'{prefix}kinds' must be a non-empty list of event kinds")
        kinds = []
    unknown = sorted(set(kinds) - KNOWN_KINDS)
    if unknown:
        errors.append(f"'{prefix}kinds' has unknown kind(s): {', '.join(unknown)} "
                      f"(known: {', '.join(sorted(KNOWN_KINDS))})")
    where_table = table.get("where", {})
    where: dict[str, re.Pattern[str]] = {}
    if not isinstance(where_table, Mapping):
        errors.append(f"'{prefix}where' must be a table of field = regex")
    else:
        for name, pattern in where_table.items():
            compiled = _regex(pattern, f"{prefix}where.{name}", errors)
            if compiled is not None:
                where[name] = compiled
    return Filter(frozenset(kinds), where)


def _group_by(value: Any, errors: list[str]) -> tuple[str, ...]:
    if isinstance(value, str) and value:
        return (value,)
    if isinstance(value, list) and value and all(isinstance(item, str) and item for item in value):
        return tuple(value)
    errors.append("'group_by' must be a field name or a non-empty list of field names")
    return ("source_ip",)


def _escalation(value: Any, errors: list[str]) -> Escalation | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        errors.append("'escalate_on' must be a table")
        return None
    unknown = set(value) - _ESCALATION_KEYS
    if unknown:
        errors.append(f"unknown key(s) in 'escalate_on': {', '.join(sorted(unknown))}")
    escalation_filter = _filter(value, "escalate_on.", errors)
    severity = _severity(value.get("severity", "critical"), "escalate_on.severity", errors)
    return Escalation(escalation_filter, severity)
