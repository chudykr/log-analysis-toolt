import json
from datetime import datetime, timedelta, timezone

import pytest

from loganalyzer.correlator import correlate
from loganalyzer.detector import run
from loganalyzer.models import Finding, ParseStats, Severity
from loganalyzer.report import (
    EVIDENCE_PER_FINDING,
    MAX_LINE_WIDTH,
    MAX_MALFORMED_SHOWN,
    SCHEMA_VERSION,
    render_json,
    render_text,
)
from loganalyzer.parsers import ParseContext, parse_stream, read_lines
from loganalyzer.rules import load_rules
from tests.conftest import REPO_ROOT, SAMPLE_YEAR, SAMPLES_DIR, T0, make_event

# Relative paths, as a user types them. Absolute paths would make line lengths (and so clipping)
# depend on where the repository is checked out.
FILES = ["samples/webserver.log", "samples/auth.log"]


@pytest.fixture(scope="module")
def sample():
    with pytest.MonkeyPatch.context() as patch:
        patch.chdir(REPO_ROOT)
        stats = ParseStats()
        detector = run(parse_stream(read_lines(FILES), ParseContext(SAMPLE_YEAR), stats), load_rules())
    return correlate(detector.results(), detector.context), stats


@pytest.fixture(scope="module")
def text(sample):
    incidents, stats = sample
    return render_text(incidents, stats, FILES)


@pytest.fixture(scope="module")
def document(sample):
    incidents, stats = sample
    return json.loads(render_json(incidents, stats, FILES))


def one_incident(*, count=1, evidence=1, raw="x", escalated=False):
    events = [make_event(line_no=n + 1, path="/") for n in range(evidence)]
    events = [type(e)(e.source_file, e.line_no, e.timestamp, e.source_ip, e.kind, e.fields, raw) for e in events]
    finding = Finding(rule_id="r", title="Rule", severity=Severity.HIGH, key_field="source_ip", key="10.0.0.1",
                      source_file="test.log", first_seen=T0, last_seen=T0, action="Block the source IP now.",
                      count=count, escalated=escalated, evidence=events)
    return correlate([finding])


def stats_for(files, lines=1, malformed=()):
    stats = ParseStats(parsed=lines)
    stats.lines_per_file = {path: lines for path in files}
    for item in malformed:
        stats.record_malformed(*item)
    return stats


# --- Text report on the samples (US-07 acceptance) -------------------------------------------

def test_text_header(text):
    lines = text.splitlines()

    assert lines[0] == "Security Log Analysis Report"
    assert lines[1] == f"Files: {FILES[0]} (33 lines), {FILES[1]} (12 lines)"
    assert lines[2] == "Events parsed: 44   Malformed lines: 1   Incidents: 6 (critical 2, high 2, medium 2)"


def test_text_incident_order_and_correlation(text):
    headers = [line for line in text.splitlines() if line.startswith("[")]

    assert [h.split(" - ")[0] for h in headers] == [
        "[CRITICAL] 10.0.0.50", "[CRITICAL] 203.0.113.5", "[HIGH] 10.0.0.88",
        "[HIGH] user:johndoe", "[MEDIUM] 172.16.0.20", "[MEDIUM] 10.0.0.99"]
    assert all("correlated across" in h for h in headers[:2])
    assert not any("correlated" in h for h in headers[2:])


def test_text_evidence_points_at_real_lines(text):
    files = {path: (SAMPLES_DIR / path.rsplit("/", 1)[-1]).read_text().splitlines() for path in FILES}
    checked = 0
    for line in text.splitlines():
        stripped = line.strip()
        for path, content in files.items():
            if stripped.startswith(f"{path}:"):
                label, raw = stripped.split(None, 1)
                line_no = int(label.rsplit(":", 1)[1])
                if raw.endswith("…"):  # long lines are clipped to MAX_LINE_WIDTH
                    assert content[line_no - 1].startswith(raw[:-1]), label
                else:
                    assert content[line_no - 1] == raw, label
                checked += 1

    # Evidence shown per incident: 10.0.0.50 10, 203.0.113.5 7, 10.0.0.88 2, johndoe 1,
    # 172.16.0.20 5 (capped), 10.0.0.99 6 = 31; plus 1 context line and 1 malformed line.
    assert checked == 33


def test_text_every_incident_has_actions(text):
    blocks = text.split("\n\n")[1:-1]  # incidents, without header and malformed section

    assert len(blocks) == 6
    assert all("Recommended actions:\n    1. " in block for block in blocks)


def test_text_escalation_and_context(text):
    assert "ssh-bruteforce [critical]: SSH password brute force (5 events, ESCALATED)" in text
    assert "Context:\n    " in text
    assert "Connection closed by 10.0.0.50" in text


def test_text_malformed_section(text):
    assert text.endswith("Malformed lines (1):\n"
                         f"  {FILES[0]}:26  [MALFORMED ENTRY - system restart")


def test_text_evidence_cap(text):
    # sensitive-path-scan has 6 events; only EVIDENCE_PER_FINDING are shown.
    assert EVIDENCE_PER_FINDING == 5
    assert "        ... and 1 more" in text


def test_text_has_no_ansi_codes_without_color(text):
    assert "\033[" not in text


def test_text_color_marks_severity(sample):
    incidents, stats = sample

    colored = render_text(incidents, stats, FILES, color=True)

    assert "\033[1;31m[CRITICAL]\033[0m 10.0.0.50" in colored
    assert "\033[33m[MEDIUM]\033[0m" in colored


# --- Text report edge cases ------------------------------------------------------------------

def test_text_no_incidents():
    text = render_text([], stats_for(["a.log"], lines=2), ["a.log"])

    assert "Incidents: 0\n" in text
    assert text.endswith("No suspicious activity found.")


def test_text_file_with_no_lines_is_listed():
    text = render_text([], stats_for([], lines=0), ["empty.log"])

    assert "Files: empty.log (0 lines)" in text


def test_text_long_lines_are_clipped():
    text = render_text(one_incident(raw="A" * 500), stats_for(["test.log"]), ["test.log"])

    evidence = [line for line in text.splitlines() if "AAAA" in line]
    assert evidence and all(len(line) == MAX_LINE_WIDTH and line.endswith("…") for line in evidence)


def test_text_shows_hidden_count_when_evidence_capped_by_detector():
    # 30 events counted, 20 kept by the detector, 5 shown: "... and 25 more".
    text = render_text(one_incident(count=30, evidence=20), stats_for(["test.log"]), ["test.log"])

    assert "(30 events)" in text
    assert "... and 25 more" in text


def test_text_singular_event():
    text = render_text(one_incident(), stats_for(["test.log"]), ["test.log"])

    assert "(1 event)" in text


def test_text_malformed_lines_are_capped():
    malformed = [("a.log", n, "garbage") for n in range(1, 26)]

    text = render_text([], stats_for(["a.log"], malformed=malformed), ["a.log"])

    assert text.count("garbage") == MAX_MALFORMED_SHOWN
    assert text.endswith("  ... and 15 more")


# --- JSON report -----------------------------------------------------------------------------

def test_json_top_level(document):
    assert document["schema_version"] == SCHEMA_VERSION == 1
    datetime.fromisoformat(document["generated_at"])
    assert document["files"] == [{"path": FILES[0], "lines": 33}, {"path": FILES[1], "lines": 12}]
    assert document["stats"] == {"events": 44, "malformed": 1, "incidents": 6,
                                 "by_severity": {"critical": 2, "high": 2, "medium": 2, "low": 0}}
    assert document["malformed"] == [{"file": FILES[0], "line": 26, "raw": "[MALFORMED ENTRY - system restart"}]


def test_json_matches_text_report(document, text):
    headers = [line.split(" - ")[0] for line in text.splitlines() if line.startswith("[")]

    assert [f"[{i['severity'].upper()}] {i['key']}" for i in document["incidents"]] == headers


def test_json_incident_shape(document):
    incident = document["incidents"][0]

    assert incident["key"] == "10.0.0.50"
    assert incident["key_type"] == "ip"
    assert incident["correlated"] is True
    assert incident["sources"] == sorted(FILES)
    assert incident["first_seen"] == "2025-07-03T10:00:03+00:00"
    assert incident["last_seen"] == "2025-07-03T10:00:07+00:00"
    assert incident["context"] == [{"file": FILES[1], "line": 12, "raw": (SAMPLES_DIR / "auth.log")
                                    .read_text().splitlines()[11]}]
    finding = incident["findings"][0]
    assert set(finding) == {"rule_id", "title", "severity", "escalated", "count", "source_file",
                            "first_seen", "last_seen", "action", "evidence"}
    assert (finding["rule_id"], finding["escalated"], finding["count"]) == ("ssh-bruteforce", True, 5)


def test_json_evidence_is_complete_and_sorted(document):
    for incident in document["incidents"]:
        for finding in incident["findings"]:
            keys = [(e["file"], e["line"]) for e in finding["evidence"]]
            assert keys == sorted(keys)
            assert len(keys) == min(finding["count"], 20)


def test_json_is_stable_apart_from_generated_at(sample):
    incidents, stats = sample
    moment = datetime(2026, 1, 1, tzinfo=timezone.utc)

    first = render_json(incidents, stats, FILES, generated_at=moment)
    second = render_json(incidents, stats, FILES, generated_at=moment + timedelta(hours=1))

    assert json.loads(first) | {"generated_at": None} == json.loads(second) | {"generated_at": None}


def test_json_no_incidents():
    document = json.loads(render_json([], stats_for(["a.log"]), ["a.log"]))

    assert document["incidents"] == []
    assert document["stats"]["incidents"] == 0
