"""Single-pass detection engine.

Pattern rules are checked per event. Threshold rules keep a sliding window per
(rule, key, source file). Each file is assumed to be in time order; files are not merged by time,
so state is kept per file and the correlator links findings across files afterwards.

Memory stays flat: windows only hold events inside `window_seconds`, idle state is swept
regularly, and findings keep at most MAX_EVIDENCE events.
"""

from collections import Counter, defaultdict, deque
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from loganalyzer.models import Event, Finding
from loganalyzer.rules import PatternRule, Rule, ThresholdRule

SWEEP_EVERY = 10_000  # events between sweeps of idle threshold state

StateKey = tuple[str, tuple[str, ...], str]  # (rule id, group key, source file)


@dataclass(slots=True)
class _Window:
    events: deque = field(default_factory=deque)  # (timestamp, distinct value or None, event)
    distinct: Counter = field(default_factory=Counter)
    finding: Finding | None = None  # open finding: still being extended
    escalated: bool = False
    last_seen: datetime | None = None


def _new_finding(rule: Rule, key: tuple[str, ...], event: Event) -> Finding:
    return Finding(
        rule_id=rule.id, title=rule.title, severity=rule.severity,
        key_field=rule.group_by[0], key=key[0], source_file=event.source_file,
        first_seen=event.timestamp, last_seen=event.timestamp, action=rule.action,
    )


class Detector:
    def __init__(self, rules: Iterable[Rule]):
        self.rules = list(rules)
        self.findings: list[Finding] = []
        self._pattern_findings: dict[StateKey, Finding] = {}
        self._windows: dict[StateKey, _Window] = {}
        # Index rules by event kind so each event only meets the rules that can match it.
        self._main_by_kind: dict[str, list[Rule]] = defaultdict(list)
        self._escalation_by_kind: dict[str, list[ThresholdRule]] = defaultdict(list)
        for rule in self.rules:
            for kind in rule.filter.kinds:
                self._main_by_kind[kind].append(rule)
            if isinstance(rule, ThresholdRule) and rule.escalate_on is not None:
                for kind in rule.escalate_on.filter.kinds:
                    self._escalation_by_kind[kind].append(rule)
        self._seen = 0
        self._latest: dict[str, datetime] = {}

    # --- public API --------------------------------------------------------------------------

    def feed(self, event: Event) -> None:
        for rule in self._main_by_kind.get(event.kind, ()):
            if isinstance(rule, PatternRule):
                self._pattern(rule, event)
            elif isinstance(rule, ThresholdRule) and rule.matches(event):
                self._threshold(rule, event)
        for rule in self._escalation_by_kind.get(event.kind, ()):
            self._escalate(rule, event)

        latest = self._latest.get(event.source_file)
        if latest is None or event.timestamp > latest:
            self._latest[event.source_file] = event.timestamp
        self._seen += 1
        if self._seen % SWEEP_EVERY == 0:
            self._sweep()

    def results(self) -> list[Finding]:
        """Findings sorted by severity (highest first), then by first time seen."""
        return sorted(self.findings, key=lambda f: (-f.severity, f.first_seen, f.rule_id, f.key))

    # --- rule types --------------------------------------------------------------------------

    def _pattern(self, rule: PatternRule, event: Event) -> None:
        if not rule.hits(event):
            return
        key = rule.key_of(event)
        state_key = (rule.id, key, event.source_file)
        finding = self._pattern_findings.get(state_key)
        if finding is None:
            finding = _new_finding(rule, key, event)
            self._pattern_findings[state_key] = finding
            self.findings.append(finding)
        finding.add(event)

    def _threshold(self, rule: ThresholdRule, event: Event) -> None:
        key = rule.key_of(event)
        state_key = (rule.id, key, event.source_file)
        window = self._windows.get(state_key)
        if window is None:
            window = self._windows[state_key] = _Window()
        span = timedelta(seconds=rule.window_seconds)

        # An open finding keeps growing while events keep coming within the window.
        if window.finding is not None:
            if event.timestamp - window.finding.last_seen <= span:
                window.finding.add(event)
                window.last_seen = event.timestamp
                return
            window.finding = None  # burst is over; a later burst becomes a new finding
            window.escalated = False

        distinct_value = event.get(rule.distinct) if rule.distinct else None
        if rule.distinct and distinct_value is None:
            return
        self._expire(window, event.timestamp - span)
        window.events.append((event.timestamp, distinct_value, event))
        window.last_seen = event.timestamp
        if rule.distinct:
            window.distinct[distinct_value] += 1

        reached = len(window.distinct) if rule.distinct else len(window.events)
        if reached >= rule.count:
            # The finding starts with the events that led up to the threshold.
            finding = _new_finding(rule, key, window.events[0][2])
            for _, _, item in window.events:
                finding.add(item)
            self.findings.append(finding)
            window.finding = finding
            window.events.clear()
            window.distinct.clear()

    def _escalate(self, rule: ThresholdRule, event: Event) -> None:
        escalation = rule.escalate_on
        if escalation is None or not escalation.filter.matches(event):
            return
        window = self._windows.get((rule.id, rule.key_of(event), event.source_file))
        if window is None or window.finding is None or window.escalated:
            return
        if event.timestamp - window.finding.last_seen > timedelta(seconds=rule.window_seconds):
            return
        window.finding.severity = max(window.finding.severity, escalation.severity)
        window.finding.escalated = True
        window.finding.add(event)
        window.escalated = True

    # --- housekeeping ------------------------------------------------------------------------

    @staticmethod
    def _expire(window: _Window, cutoff: datetime) -> None:
        while window.events and window.events[0][0] < cutoff:
            _, value, _ = window.events.popleft()
            if value is not None:
                window.distinct[value] -= 1
                if window.distinct[value] <= 0:
                    del window.distinct[value]

    def _sweep(self) -> None:
        """Drop threshold state that has been idle for longer than its rule's window."""
        rules = {rule.id: rule for rule in self.rules if isinstance(rule, ThresholdRule)}
        for state_key, window in list(self._windows.items()):
            rule_id, _key, source_file = state_key
            latest = self._latest.get(source_file)
            span = timedelta(seconds=rules[rule_id].window_seconds)
            if latest and window.last_seen and latest - window.last_seen > span:
                del self._windows[state_key]


def detect(events: Iterable[Event], rules: Iterable[Rule]) -> list[Finding]:
    """Run every rule over the events in a single pass and return the findings."""
    detector = Detector(rules)
    for event in events:
        detector.feed(event)
    return detector.results()
