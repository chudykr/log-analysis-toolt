from datetime import timedelta

import pytest

from loganalyzer.correlator import correlate, format_span, incident_key, incident_severity, summarize
from loganalyzer.detector import run
from loganalyzer.models import Finding, Severity
from tests.conftest import T0, make_event, parse_samples


def finding(rule_id="rule", key="10.0.0.1", *, file="web.log", severity=Severity.MEDIUM, seconds=0,
            key_field="source_ip", escalated=False, title=None, action=None, count=1):
    return Finding(
        rule_id=rule_id, title=title or rule_id.replace("-", " ").capitalize(), severity=severity,
        key_field=key_field, key=key, source_file=file,
        first_seen=T0 + timedelta(seconds=seconds), last_seen=T0 + timedelta(seconds=seconds + 4),
        action=action or f"Do something about {rule_id}.", count=count, escalated=escalated,
    )


# --- Grouping --------------------------------------------------------------------------------

def test_findings_with_same_ip_from_two_files_are_one_correlated_incident():
    [incident] = correlate([finding("web-a", file="web.log"), finding("ssh-b", file="auth.log")])

    assert incident.key == "10.0.0.1"
    assert incident.key_type == "ip"
    assert incident.correlated
    assert incident.sources == ["auth.log", "web.log"]


def test_findings_from_one_file_are_not_correlated():
    [incident] = correlate([finding("a"), finding("b")])

    assert not incident.correlated
    assert incident.sources == ["web.log"]


def test_user_key_is_separate_from_ip_key():
    incidents = correlate([finding("sudo", key="johndoe", key_field="user", file="auth.log"),
                           finding("web", key="johndoe", file="web.log")])

    assert sorted((i.key, i.key_type) for i in incidents) == [("johndoe", "ip"), ("user:johndoe", "user")]
    assert not any(i.correlated for i in incidents)


def test_incident_key():
    assert incident_key(finding(key="1.2.3.4")) == ("1.2.3.4", "ip")
    assert incident_key(finding(key="bob", key_field="user")) == ("user:bob", "user")


def test_incident_time_span_covers_all_findings():
    [incident] = correlate([finding("a", seconds=10), finding("b", seconds=0, file="auth.log")])

    assert incident.first_seen == T0
    assert incident.last_seen == T0 + timedelta(seconds=14)


def test_incidents_sorted_by_severity_then_time():
    incidents = correlate([
        finding("late-high", key="1.1.1.1", severity=Severity.HIGH, seconds=50),
        finding("low", key="2.2.2.2", severity=Severity.LOW, seconds=0),
        finding("early-high", key="3.3.3.3", severity=Severity.HIGH, seconds=10),
    ])

    assert [i.key for i in incidents] == ["3.3.3.3", "1.1.1.1", "2.2.2.2"]


def test_findings_inside_incident_sorted_by_severity():
    [incident] = correlate([finding("low", severity=Severity.LOW), finding("high", severity=Severity.HIGH)])

    assert [f.rule_id for f in incident.findings] == ["high", "low"]


def test_actions_are_deduplicated_in_order():
    [incident] = correlate([
        finding("a", severity=Severity.HIGH, action="Block the IP."),
        finding("b", severity=Severity.MEDIUM, action="Reset the password."),
        finding("c", severity=Severity.LOW, action="Block the IP."),
    ])

    assert incident.actions == ["Block the IP.", "Reset the password."]


def test_empty_input():
    assert correlate([]) == []


# --- Severity --------------------------------------------------------------------------------

@pytest.mark.parametrize("severities, correlated, escalated, expected", [
    ([Severity.MEDIUM], False, False, Severity.MEDIUM),                   # rule 1: highest finding
    ([Severity.LOW, Severity.HIGH], False, False, Severity.HIGH),
    ([Severity.MEDIUM, Severity.LOW], True, False, Severity.HIGH),        # rule 2: +1 when correlated
    ([Severity.HIGH, Severity.MEDIUM], True, False, Severity.CRITICAL),
    ([Severity.CRITICAL, Severity.HIGH], True, False, Severity.CRITICAL),  # capped at critical
    ([Severity.LOW], False, True, Severity.CRITICAL),                     # rule 3: escalated is critical
])
def test_incident_severity(severities, correlated, escalated, expected):
    findings = [finding(f"r{i}", severity=s, escalated=escalated and i == 0) for i, s in enumerate(severities)]

    assert incident_severity(findings, correlated) is expected


# --- Context ---------------------------------------------------------------------------------

def test_context_events_attached_to_ip_incident_only():
    closed = make_event("ssh_closed", ip="10.0.0.1")
    [ip_incident, user_incident] = correlate(
        [finding("a", severity=Severity.HIGH), finding("sudo", key="10.0.0.1", key_field="user")],
        {"10.0.0.1": [closed]},
    )

    assert ip_incident.context == [closed]
    assert user_incident.context == []


def test_detector_keeps_unused_context_events_for_flagged_ips(default_rules):
    events = [make_event("ssh_failed", seconds=s, user="admin", invalid_user="false") for s in range(3)]
    events += [make_event("ssh_accepted", seconds=3, user="admin", method="password"),  # escalation: evidence
               make_event("ssh_closed", seconds=4, port="1", preauth="true"),          # context
               make_event("ssh_closed", seconds=5, ip="9.9.9.9", port="1", preauth="true")]  # no finding: dropped

    detector = run(events, default_rules)

    assert [e.kind for e in detector.context["10.0.0.1"]] == ["ssh_closed"]
    assert "9.9.9.9" not in detector.context


def test_context_is_capped(default_rules):
    from loganalyzer.models import MAX_CONTEXT

    events = [make_event("ssh_failed", seconds=s, user="admin", invalid_user="false") for s in range(3)]
    events += [make_event("ssh_closed", seconds=10 + s, line_no=100 + s, port="1", preauth="true")
               for s in range(MAX_CONTEXT + 3)]

    context = run(events, default_rules).context["10.0.0.1"]

    assert len(context) == MAX_CONTEXT
    assert context[-1].line_no == 100 + MAX_CONTEXT + 2  # keeps the most recent


# --- Summary ---------------------------------------------------------------------------------

def test_summary_template():
    findings = [finding("ssh-bf", title="SSH password brute force", escalated=True),
                finding("web-bf", title="Web login brute force", file="auth.log")]

    text = summarize("10.0.0.50", findings, 2, T0, T0 + timedelta(seconds=4))

    assert text == ("10.0.0.50: SSH password brute force; Web login brute force, followed by a successful "
                    "attempt (2 sources, 2025-07-03 10:00:00-10:00:04 UTC).")


@pytest.mark.parametrize("seconds, expected", [
    (0, "2025-07-03 10:00:00 UTC"),
    (59, "2025-07-03 10:00:00-10:00:59 UTC"),
    (86_400, "2025-07-03 10:00:00 - 2025-07-04 10:00:00 UTC"),
])
def test_format_span(seconds, expected):
    assert format_span(T0, T0 + timedelta(seconds=seconds)) == expected


# --- Sample logs (US-06 acceptance) ----------------------------------------------------------

EXPECTED_INCIDENTS = [
    ("10.0.0.50", "critical", True, ["ssh-bruteforce", "web-login-bruteforce"]),
    ("203.0.113.5", "critical", True, ["path-traversal", "admin-probing", "ssh-invalid-users"]),
    ("10.0.0.88", "high", False, ["sql-injection"]),
    ("user:johndoe", "high", False, ["sensitive-sudo"]),
    ("172.16.0.20", "medium", False, ["sensitive-path-scan"]),
    ("10.0.0.99", "medium", False, ["request-flood", "rate-limited"]),
]


@pytest.fixture(scope="module")
def sample_incidents():
    from loganalyzer.rules import load_rules

    events, _ = parse_samples("webserver.log", "auth.log")
    detector = run(events, load_rules())
    return correlate(detector.results(), detector.context)


def test_sample_incidents(sample_incidents):
    actual = [(i.key, str(i.severity), i.correlated, [f.rule_id for f in i.findings]) for i in sample_incidents]

    assert actual == EXPECTED_INCIDENTS


def test_sample_correlated_incidents_name_both_files(sample_incidents):
    for incident in sample_incidents[:2]:
        assert [source.rsplit("/", 1)[-1] for source in incident.sources] == ["auth.log", "webserver.log"]


def test_sample_connection_closed_is_context_for_10_0_0_50(sample_incidents):
    by_key = {i.key: i for i in sample_incidents}

    assert [(e.kind, e.line_no) for e in by_key["10.0.0.50"].context] == [("ssh_closed", 12)]
    assert all(not i.context for key, i in by_key.items() if key != "10.0.0.50")


def test_sample_summary_for_10_0_0_50(sample_incidents):
    assert sample_incidents[0].summary == (
        "10.0.0.50: SSH password brute force; Web login brute force, followed by a successful attempt "
        "(2 sources, 2025-07-03 10:00:03-10:00:07 UTC).")


def test_every_sample_incident_has_an_action(sample_incidents):
    assert all(incident.actions for incident in sample_incidents)
