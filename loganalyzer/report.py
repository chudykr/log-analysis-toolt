"""Text and JSON reports.

Both renderers return a string, so they are easy to test. The JSON schema is versioned with
`schema_version`; every list in it is sorted so output is stable between runs (only
`generated_at` changes).
"""

import json
from collections.abc import Sequence
from datetime import datetime, timezone

from loganalyzer.models import Event, Finding, Incident, ParseStats, Severity

SCHEMA_VERSION = 1
EVIDENCE_PER_FINDING = 5
MAX_MALFORMED_SHOWN = 10
MAX_LINE_WIDTH = 160

_COLORS = {
    Severity.CRITICAL: "\033[1;31m",  # bold red
    Severity.HIGH: "\033[31m",        # red
    Severity.MEDIUM: "\033[33m",      # yellow
    Severity.LOW: "\033[36m",         # cyan
}
_RESET = "\033[0m"


def severity_counts(incidents: Sequence[Incident]) -> dict[str, int]:
    counts = {str(severity): 0 for severity in sorted(Severity, reverse=True)}
    for incident in incidents:
        counts[str(incident.severity)] += 1
    return counts


# --- text ------------------------------------------------------------------------------------

def render_text(incidents: Sequence[Incident], stats: ParseStats, files: Sequence[str], *,
                color: bool = False) -> str:
    out = ["Security Log Analysis Report"]
    out.append("Files: " + ", ".join(f"{path} ({stats.lines_per_file.get(path, 0)} lines)" for path in files))
    by_severity = ", ".join(f"{name} {count}" for name, count in severity_counts(incidents).items() if count)
    incident_summary = f"Incidents: {len(incidents)}" + (f" ({by_severity})" if by_severity else "")
    out.append(f"Events parsed: {stats.parsed}   Malformed lines: {stats.malformed_count}   {incident_summary}")

    if not incidents:
        out += ["", "No suspicious activity found."]

    for incident in incidents:
        out += [""] + _incident_text(incident, color)

    if stats.malformed_count:
        out += ["", f"Malformed lines ({stats.malformed_count}):"]
        shown = stats.malformed[:MAX_MALFORMED_SHOWN]
        width = max(len(f"{file}:{line_no}") for file, line_no, _ in shown)
        for file, line_no, raw in shown:
            out.append(_clip(f"  {f'{file}:{line_no}':<{width}}  {raw}"))
        if stats.malformed_count > len(shown):
            out.append(f"  ... and {stats.malformed_count - len(shown)} more")
    return "\n".join(out)


def _incident_text(incident: Incident, color: bool) -> list[str]:
    tag = f"[{str(incident.severity).upper()}]"
    if color:
        tag = f"{_COLORS[incident.severity]}{tag}{_RESET}"
    where = (f"correlated across {', '.join(incident.sources)}" if incident.correlated
             else incident.sources[0])
    lines = [f"{tag} {incident.key} - {where}", f"  {incident.summary}", "  Findings:"]

    for finding in incident.findings:
        flag = ", ESCALATED" if finding.escalated else ""
        noun = "event" if finding.count == 1 else "events"
        lines.append(f"    - {finding.rule_id} [{finding.severity}]: {finding.title} ({finding.count} {noun}{flag})")
        lines += _evidence_lines(finding.evidence[:EVIDENCE_PER_FINDING], indent=8)
        hidden = finding.count - min(len(finding.evidence), EVIDENCE_PER_FINDING)
        if hidden > 0:
            lines.append(f"        ... and {hidden} more")

    if incident.context:
        lines.append("  Context:")
        lines += _evidence_lines(incident.context, indent=4)

    lines.append("  Recommended actions:")
    lines += [f"    {number}. {action}" for number, action in enumerate(incident.actions, start=1)]
    return lines


def _evidence_lines(events: Sequence[Event], indent: int) -> list[str]:
    if not events:
        return []
    labels = [f"{event.source_file}:{event.line_no}" for event in events]
    width = max(map(len, labels))
    return [_clip(f"{' ' * indent}{label:<{width}}  {event.raw}") for label, event in zip(labels, events)]


def _clip(line: str) -> str:
    return line if len(line) <= MAX_LINE_WIDTH else line[:MAX_LINE_WIDTH - 1] + "…"


# --- JSON ------------------------------------------------------------------------------------

def render_json(incidents: Sequence[Incident], stats: ParseStats, files: Sequence[str], *,
                generated_at: datetime | None = None) -> str:
    generated_at = generated_at or datetime.now(timezone.utc)
    document = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": _iso(generated_at),
        "files": [{"path": path, "lines": stats.lines_per_file.get(path, 0)} for path in files],
        "stats": {
            "events": stats.parsed,
            "malformed": stats.malformed_count,
            "incidents": len(incidents),
            "by_severity": severity_counts(incidents),
        },
        "incidents": [_incident_json(incident) for incident in incidents],
        "malformed": [{"file": file, "line": line_no, "raw": raw}
                      for file, line_no, raw in sorted(stats.malformed)],
    }
    return json.dumps(document, indent=2, ensure_ascii=False)


def _incident_json(incident: Incident) -> dict:
    return {
        "key": incident.key,
        "key_type": incident.key_type,
        "severity": str(incident.severity),
        "correlated": incident.correlated,
        "sources": incident.sources,
        "first_seen": _iso(incident.first_seen),
        "last_seen": _iso(incident.last_seen),
        "summary": incident.summary,
        "actions": incident.actions,
        "findings": [_finding_json(finding) for finding in incident.findings],
        "context": [_event_json(event) for event in _sorted_events(incident.context)],
    }


def _finding_json(finding: Finding) -> dict:
    return {
        "rule_id": finding.rule_id,
        "title": finding.title,
        "severity": str(finding.severity),
        "escalated": finding.escalated,
        "count": finding.count,
        "source_file": finding.source_file,
        "first_seen": _iso(finding.first_seen),
        "last_seen": _iso(finding.last_seen),
        "action": finding.action,
        "evidence": [_event_json(event) for event in _sorted_events(finding.evidence)],
    }


def _event_json(event: Event) -> dict:
    return {"file": event.source_file, "line": event.line_no, "raw": event.raw}


def _sorted_events(events: Sequence[Event]) -> list[Event]:
    return sorted(events, key=lambda event: (event.source_file, event.line_no))


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat()
