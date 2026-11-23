import pytest

from loganalyzer import detector as detector_module
from loganalyzer.detector import Detector, detect
from loganalyzer.models import MAX_EVIDENCE, Severity
from loganalyzer.rules import parse_rules
from tests.conftest import make_event, parse_samples


def rules(*tables):
    return parse_rules({"rule": list(tables)})


def ssh_bruteforce(**overrides):
    table = {"id": "ssh-bf", "title": "SSH brute force", "type": "threshold", "severity": "high",
             "kinds": ["ssh_failed"], "count": 3, "window_seconds": 60,
             "escalate_on": {"kinds": ["ssh_accepted"]}, "action": "Block the source IP."}
    table.update(overrides)
    return table


def failed(seconds, ip="10.0.0.1", **fields):
    return make_event("ssh_failed", seconds=seconds, ip=ip, line_no=int(seconds) + 1, user="admin", **fields)


# --- Threshold engine ------------------------------------------------------------------------

def test_below_threshold_no_finding():
    assert detect([failed(0), failed(1)], rules(ssh_bruteforce())) == []


def test_threshold_reached_exactly_within_window():
    [finding] = detect([failed(0), failed(30), failed(60)], rules(ssh_bruteforce()))

    assert (finding.rule_id, finding.key, finding.count) == ("ssh-bf", "10.0.0.1", 3)
    assert finding.severity is Severity.HIGH
    assert [e.line_no for e in finding.evidence] == [1, 31, 61]


def test_events_spread_over_more_than_window_do_not_fire():
    assert detect([failed(0), failed(30), failed(61)], rules(ssh_bruteforce())) == []


def test_old_events_slide_out_of_window():
    # 0 expires by 61, so the threshold is reached at 62 with 30, 61, 62.
    [finding] = detect([failed(0), failed(30), failed(61), failed(62)], rules(ssh_bruteforce()))

    assert [e.line_no for e in finding.evidence] == [31, 62, 63]


def test_keys_are_counted_separately():
    events = [failed(0, ip="1.1.1.1"), failed(1, ip="2.2.2.2"), failed(2, ip="1.1.1.1"), failed(3, ip="2.2.2.2")]

    assert detect(events, rules(ssh_bruteforce())) == []


def test_files_are_counted_separately():
    events = [make_event("ssh_failed", seconds=s, file=f) for s, f in [(0, "a"), (1, "b"), (2, "a"), (3, "b")]]

    assert detect(events, rules(ssh_bruteforce())) == []


def test_burst_extends_one_finding():
    [finding] = detect([failed(s) for s in range(10)], rules(ssh_bruteforce()))

    assert finding.count == 10
    assert finding.last_seen - finding.first_seen == (failed(9).timestamp - failed(0).timestamp)


def test_new_burst_after_quiet_period_is_a_new_finding():
    events = [failed(s) for s in (0, 1, 2)] + [failed(s) for s in (500, 501, 502)]

    findings = detect(events, rules(ssh_bruteforce()))

    assert [f.count for f in findings] == [3, 3]


def test_many_events_keep_capped_evidence():
    [finding] = detect((failed(s / 1000) for s in range(10_000)), rules(ssh_bruteforce()))

    assert finding.count == 10_000
    assert len(finding.evidence) == MAX_EVIDENCE


def test_distinct_counts_values_not_events():
    rule = rules(ssh_bruteforce(distinct="user"))
    same_user = [failed(s) for s in range(5)]
    three_users = [make_event("ssh_failed", seconds=s, user=u) for s, u in enumerate(["a", "a", "b", "c"])]

    assert detect(same_user, rule) == []
    [finding] = detect(three_users, rule)
    assert finding.count == 4


def test_distinct_value_expires_with_window():
    rule = rules(ssh_bruteforce(distinct="user", window_seconds=10))
    events = [make_event("ssh_failed", seconds=s, user=u) for s, u in [(0, "a"), (5, "b"), (20, "c")]]

    assert detect(events, rule) == []


def test_compound_group_by_uses_first_field_as_key():
    rule = rules(ssh_bruteforce(group_by=["source_ip", "user"]))
    mixed = [make_event("ssh_failed", seconds=s, user=u) for s, u in enumerate(["a", "b", "a", "b"])]
    same = [make_event("ssh_failed", seconds=s, user="a") for s in range(3)]

    assert detect(mixed, rule) == []
    [finding] = detect(same, rule)
    assert (finding.key_field, finding.key) == ("source_ip", "10.0.0.1")


# --- Escalation ------------------------------------------------------------------------------

def test_success_after_threshold_escalates():
    accepted = make_event("ssh_accepted", seconds=4, line_no=99, user="admin")

    [finding] = detect([failed(0), failed(1), failed(2), accepted], rules(ssh_bruteforce()))

    assert finding.escalated
    assert finding.severity is Severity.CRITICAL
    assert finding.count == 4
    assert finding.evidence[-1].line_no == 99


def test_success_from_other_ip_does_not_escalate():
    accepted = make_event("ssh_accepted", seconds=4, ip="9.9.9.9")

    [finding] = detect([failed(0), failed(1), failed(2), accepted], rules(ssh_bruteforce()))

    assert not finding.escalated


def test_success_after_window_does_not_escalate():
    accepted = make_event("ssh_accepted", seconds=200)

    [finding] = detect([failed(0), failed(1), failed(2), accepted], rules(ssh_bruteforce()))

    assert not finding.escalated
    assert finding.severity is Severity.HIGH


def test_success_before_threshold_does_not_escalate():
    events = [failed(0), make_event("ssh_accepted", seconds=1), failed(2), failed(3)]

    [finding] = detect(events, rules(ssh_bruteforce()))

    assert not finding.escalated


# --- Pattern engine --------------------------------------------------------------------------

def sqli_rule(**overrides):
    table = {"id": "sqli", "title": "SQLi", "type": "pattern", "severity": "high", "kinds": ["http_request"],
             "field": "path", "regex": "(?i)union.+select", "action": "Block the source IP."}
    table.update(overrides)
    return table


def test_pattern_matches_merge_per_key():
    events = [make_event(seconds=0, path="/?q=union select"), make_event(seconds=5, path="/?q=UNION ALL SELECT"),
              make_event(seconds=6, path="/?q=laptop")]

    [finding] = detect(events, rules(sqli_rule()))

    assert finding.count == 2
    assert (finding.last_seen - finding.first_seen).total_seconds() == 5


def test_pattern_on_missing_field_does_not_match():
    assert detect([make_event(status="200")], rules(sqli_rule())) == []


def test_pattern_group_by_user():
    rule = sqli_rule(kinds=["sudo"], field="command", regex="shadow", group_by="user")
    event = make_event("sudo", ip=None, user="bob", command="cat /etc/shadow")

    [finding] = detect([event], rules(rule))

    assert (finding.key_field, finding.key) == ("user", "bob")


# --- Engine properties -----------------------------------------------------------------------

class OnceOnly:
    """Iterable that fails if iterated twice: proves the detector makes a single pass."""

    def __init__(self, items):
        self.items, self.used = items, False

    def __iter__(self):
        assert not self.used, "events iterated twice"
        self.used = True
        return iter(self.items)


def test_single_pass(default_rules):
    events, _ = parse_samples("webserver.log", "auth.log")

    assert detect(OnceOnly(events), default_rules)


def test_results_sorted_by_severity_then_time():
    table = [sqli_rule(id="low-rule", severity="low"), sqli_rule(id="high-rule", severity="high")]
    events = [make_event(seconds=0, path="union select"), make_event(seconds=1, path="union select", ip="2.2.2.2")]

    findings = detect(events, rules(*table))

    assert [(f.rule_id, f.key) for f in findings] == [
        ("high-rule", "10.0.0.1"), ("high-rule", "2.2.2.2"), ("low-rule", "10.0.0.1"), ("low-rule", "2.2.2.2")]


def test_idle_state_is_swept(monkeypatch):
    monkeypatch.setattr(detector_module, "SWEEP_EVERY", 10)
    det = Detector(rules(ssh_bruteforce()))

    for i in range(10):  # ten different IPs, one failure each, a minute apart
        det.feed(failed(i * 100, ip=f"10.0.0.{i}"))

    assert len(det._windows) == 1  # only the most recent IP is still inside its window


# --- Default rules on the sample logs (US-05 acceptance) -------------------------------------

EXPECTED = {
    ("ssh-bruteforce", "10.0.0.50"): ("critical", 5, True),
    ("web-login-bruteforce", "10.0.0.50"): ("critical", 5, True),
    ("path-traversal", "203.0.113.5"): ("high", 1, False),
    ("sql-injection", "10.0.0.88"): ("high", 2, False),
    ("sensitive-sudo", "johndoe"): ("high", 1, False),
    ("admin-probing", "203.0.113.5"): ("medium", 3, False),
    ("ssh-invalid-users", "203.0.113.5"): ("medium", 3, False),
    ("sensitive-path-scan", "172.16.0.20"): ("medium", 6, False),
    ("request-flood", "10.0.0.99"): ("medium", 5, False),
    ("rate-limited", "10.0.0.99"): ("low", 1, False),
}


@pytest.fixture(scope="module")
def sample_findings():
    from loganalyzer.rules import load_rules

    events, _ = parse_samples("webserver.log", "auth.log")
    return detect(events, load_rules())


def test_sample_findings_match_expected_table(sample_findings):
    actual = {(f.rule_id, f.key): (str(f.severity), f.count, f.escalated) for f in sample_findings}

    assert actual == EXPECTED


def test_sample_findings_order(sample_findings):
    severities = [f.severity for f in sample_findings]

    assert severities == sorted(severities, reverse=True)


@pytest.mark.parametrize("rule_id, key, lines", [
    ("web-login-bruteforce", "10.0.0.50", [3, 4, 5, 6, 7]),  # ends with the successful login
    ("ssh-bruteforce", "10.0.0.50", [1, 2, 3, 4, 5]),        # ends with "Accepted password"
    ("sql-injection", "10.0.0.88", [14, 16]),
    ("path-traversal", "203.0.113.5", [12]),
    ("admin-probing", "203.0.113.5", [9, 10, 11]),
    ("ssh-invalid-users", "203.0.113.5", [6, 7, 8]),
    ("sensitive-path-scan", "172.16.0.20", [19, 20, 21, 22, 23, 24]),
    ("request-flood", "10.0.0.99", [28, 29, 30, 31, 32]),
    ("rate-limited", "10.0.0.99", [32]),
    ("sensitive-sudo", "johndoe", [9]),
])
def test_sample_evidence_lines(sample_findings, rule_id, key, lines):
    [finding] = [f for f in sample_findings if (f.rule_id, f.key) == (rule_id, key)]

    assert [e.line_no for e in finding.evidence] == lines


@pytest.mark.parametrize("innocent", [
    "192.168.1.14",   # q=O'Brien
    "192.168.1.13",   # q=laptop
    "192.168.1.100",  # deploy publickey login
    "deploy",         # sudo systemctl restart nginx
    "192.168.1.10", "192.168.1.11", "192.168.1.12", "192.168.1.15", "192.168.1.16", "192.168.1.17", "192.168.1.18",
])
def test_sample_false_positive_guards(sample_findings, innocent):
    assert [f.rule_id for f in sample_findings if f.key == innocent] == []


@pytest.mark.parametrize("path", [
    "/search?q=O'Brien", "/search?q=it's+a+test", "/search?q=rock+and+roll", "/search?q=union+station",
    "/products?select=all", "/blog/how-to--guide",
])
def test_sql_injection_rule_ignores_normal_queries(default_rules, path):
    event = make_event(method="GET", path=path, path_decoded=path.replace("+", " "), status=200)

    assert detect([event], default_rules) == []


@pytest.mark.parametrize("path", [
    "/search?q=' UNION SELECT * FROM users--",
    "/search?q=1; DROP TABLE users--",
    "/search?q=1' OR '1'='1",
    "/item?id=1 OR 1=1",
    "/login?user=admin'--",
    "/search?q=1; SLEEP(5)",
])
def test_sql_injection_rule_catches_attacks(default_rules, path):
    event = make_event(method="GET", path=path, path_decoded=path, status=200)

    assert [f.rule_id for f in detect([event], default_rules)] == ["sql-injection"]
