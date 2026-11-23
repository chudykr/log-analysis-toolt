"""Group findings about the same actor into incidents, across log files.

An incident's key is the source IP (most rules) or another actor field such as the local user
(sudo rules, shown as "user:johndoe"). Severity rules:
    1. start with the highest finding severity
    2. findings from two or more files: raise one level (coordinated activity)
    3. any escalated finding (success after an attack): critical
"""

from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime

from loganalyzer.models import Event, Finding, Incident, Severity

IP_FIELD = "source_ip"


def incident_key(finding: Finding) -> tuple[str, str]:
    """Return (key, key_type), e.g. ("10.0.0.50", "ip") or ("user:johndoe", "user")."""
    if finding.key_field == IP_FIELD:
        return finding.key, "ip"
    return f"{finding.key_field}:{finding.key}", finding.key_field


def incident_severity(findings: Sequence[Finding], correlated: bool) -> Severity:
    severity = max(finding.severity for finding in findings)
    if correlated:
        severity = Severity(min(severity + 1, Severity.CRITICAL))
    if any(finding.escalated for finding in findings):
        severity = Severity.CRITICAL
    return severity


def correlate(findings: Iterable[Finding], context: Mapping[str, Iterable[Event]] | None = None) -> list[Incident]:
    """Build incidents, sorted by severity (highest first) then first time seen.

    `context` maps a source IP to extra events (not used by any rule) to show with its incident.
    """
    context = context or {}
    groups: dict[tuple[str, str], list[Finding]] = {}
    for finding in findings:
        groups.setdefault(incident_key(finding), []).append(finding)

    incidents = []
    for (key, key_type), group in groups.items():
        group.sort(key=lambda f: (-f.severity, f.first_seen, f.rule_id))
        sources = sorted({finding.source_file for finding in group})
        correlated = len(sources) >= 2
        first_seen = min(finding.first_seen for finding in group)
        last_seen = max(finding.last_seen for finding in group)
        extra = sorted(context.get(key, ()), key=lambda e: e.timestamp) if key_type == "ip" else []
        incidents.append(Incident(
            key=key,
            key_type=key_type,
            severity=incident_severity(group, correlated),
            findings=group,
            sources=sources,
            first_seen=first_seen,
            last_seen=last_seen,
            correlated=correlated,
            summary=summarize(key, group, len(sources), first_seen, last_seen),
            actions=_unique(finding.action for finding in group),
            context=extra,
        ))
    incidents.sort(key=lambda i: (-i.severity, i.first_seen, i.key))
    return incidents


def summarize(key: str, findings: Sequence[Finding], source_count: int,
              first_seen: datetime, last_seen: datetime) -> str:
    """One sentence from fixed templates, e.g.
    '10.0.0.50: SSH password brute force; Web login brute force, followed by a successful
    attempt (2 sources, 2025-07-03 10:00:03-10:00:07 UTC).'
    Titles are kept as written in the rules (no case changes, so "SSH" stays "SSH").
    """
    what = "; ".join(_unique(finding.title for finding in findings))
    escalated = ", followed by a successful attempt" if any(f.escalated for f in findings) else ""
    plural = "" if source_count == 1 else "s"
    return f"{key}: {what}{escalated} ({source_count} source{plural}, {format_span(first_seen, last_seen)})."


def format_span(start: datetime, end: datetime) -> str:
    if start.date() == end.date():
        if start == end:
            return f"{start:%Y-%m-%d %H:%M:%S} UTC"
        return f"{start:%Y-%m-%d %H:%M:%S}-{end:%H:%M:%S} UTC"
    return f"{start:%Y-%m-%d %H:%M:%S} - {end:%Y-%m-%d %H:%M:%S} UTC"


def _unique(items: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(items))
