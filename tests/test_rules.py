import pytest

from loganalyzer.models import Severity
from loganalyzer.rules import PatternRule, RulesError, ThresholdRule, load_rules, parse_rules
from tests.conftest import make_event

DEFAULT_RULE_IDS = {
    "web-login-bruteforce", "ssh-bruteforce", "ssh-invalid-users", "sql-injection", "path-traversal",
    "admin-probing", "sensitive-path-scan", "request-flood", "rate-limited", "sensitive-sudo",
}


def pattern(**overrides):
    rule = {"id": "test-rule", "title": "Test rule", "type": "pattern", "severity": "high",
            "kinds": ["http_request"], "field": "path", "regex": "evil",
            "action": "Block the source IP and investigate."}
    rule.update(overrides)
    return rule


def threshold(**overrides):
    rule = {"id": "test-threshold", "title": "Test threshold", "type": "threshold", "severity": "medium",
            "kinds": ["ssh_failed"], "count": 3, "window_seconds": 60,
            "action": "Block the source IP and investigate."}
    rule.update(overrides)
    return rule


def errors_for(*tables):
    with pytest.raises(RulesError) as exc:
        parse_rules({"rule": list(tables)})
    return exc.value.errors


# --- Default rules ---------------------------------------------------------------------------

def test_default_rules_load(default_rules):
    assert {rule.id for rule in default_rules} == DEFAULT_RULE_IDS


def test_every_default_rule_has_a_concrete_action(default_rules):
    for rule in default_rules:
        assert len(rule.action) >= 20, rule.id


# --- Valid rules -----------------------------------------------------------------------------

def test_pattern_rule_is_built_with_compiled_regex():
    [rule] = parse_rules({"rule": [pattern(where={"status": "^200$"})]})

    assert isinstance(rule, PatternRule)
    assert rule.severity is Severity.HIGH
    assert rule.group_by == ("source_ip",)
    assert rule.regex.pattern == "evil"
    assert rule.filter.where["status"].pattern == "^200$"


def test_threshold_rule_with_escalation_and_compound_key():
    [rule] = parse_rules({"rule": [threshold(
        group_by=["source_ip", "user"], distinct="user",
        escalate_on={"kinds": ["ssh_accepted"]},
    )]})

    assert isinstance(rule, ThresholdRule)
    assert rule.group_by == ("source_ip", "user")
    assert rule.window_seconds == 60.0
    assert rule.escalate_on.severity is Severity.CRITICAL  # default escalation severity


def test_severity_order():
    assert Severity.LOW < Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL
    assert str(Severity.HIGH) == "high"


def test_disabled_rules_are_dropped(tmp_path):
    path = tmp_path / "rules.toml"
    path.write_text("""
[[rule]]
id = "on"
title = "On"
type = "pattern"
severity = "low"
kinds = ["http_request"]
field = "path"
regex = "x"
action = "Investigate the request."

[[rule]]
id = "off"
title = "Off"
type = "pattern"
severity = "low"
kinds = ["http_request"]
field = "path"
regex = "x"
action = "Investigate the request."
enabled = false
""")

    assert [rule.id for rule in load_rules(path)] == ["on"]


# --- Filter matching -------------------------------------------------------------------------

def test_filter_requires_kind_and_all_where_fields():
    [rule] = parse_rules({"rule": [pattern(where={"method": "^POST$", "status": "^401$"})]})

    assert rule.matches(make_event(method="POST", status=401, path="/login"))
    assert not rule.matches(make_event(method="GET", status=401, path="/login"))
    assert not rule.matches(make_event("ssh_failed", method="POST", status=401))


def test_filter_missing_field_does_not_match():
    [rule] = parse_rules({"rule": [pattern(where={"status": ".*"})]})

    assert not rule.matches(make_event(path="/x"))


def test_where_can_filter_on_source_ip():
    [rule] = parse_rules({"rule": [pattern(where={"source_ip": r"^10\."})]})

    assert rule.matches(make_event(ip="10.1.2.3", path="/"))
    assert not rule.matches(make_event(ip="192.168.1.1", path="/"))


# --- Validation errors -----------------------------------------------------------------------

@pytest.mark.parametrize("overrides, expected", [
    ({"id": None}, "'id' is required"),
    ({"id": "Not Kebab"}, "kebab-case"),
    ({"title": ""}, "'title' is required"),
    ({"action": None}, "'action' is required"),
    ({"type": "magic"}, "'type' must be 'pattern' or 'threshold'"),
    ({"severity": "urgent"}, "'severity' must be one of"),
    ({"kinds": []}, "'kinds' must be a non-empty list"),
    ({"kinds": ["http_reqest"]}, "unknown kind(s): http_reqest"),
    ({"regex": "(unclosed"}, "'regex': invalid regex"),
    ({"where": {"path": "[bad"}}, "'where.path': invalid regex"),
    ({"where": "path"}, "'where' must be a table"),
    ({"enabled": "yes"}, "'enabled' must be true or false"),
    ({"group_by": []}, "'group_by' must be"),
    ({"count": 3}, "unknown key(s) for a pattern rule: count"),
])
def test_pattern_rule_validation(overrides, expected):
    errors = errors_for(pattern(**overrides))

    assert any(expected in message for message in errors), errors


@pytest.mark.parametrize("overrides, expected", [
    ({"count": 0}, "'count' must be a positive integer"),
    ({"count": True}, "'count' must be a positive integer"),
    ({"count": "3"}, "'count' must be a positive integer"),
    ({"window_seconds": -1}, "'window_seconds' must be a positive number"),
    ({"window_seconds": None}, "'window_seconds' must be a positive number"),
    ({"distinct": ""}, "'distinct' must be a field name"),
    ({"escalate_on": "yes"}, "'escalate_on' must be a table"),
    ({"escalate_on": {"kinds": ["nope"]}}, "'escalate_on.kinds' has unknown kind(s)"),
    ({"escalate_on": {"kinds": ["ssh_accepted"], "severity": "max"}}, "'escalate_on.severity' must be one of"),
    ({"escalate_on": {"kinds": ["ssh_accepted"], "level": 1}}, "unknown key(s) in 'escalate_on'"),
])
def test_threshold_rule_validation(overrides, expected):
    errors = errors_for(threshold(**overrides))

    assert any(expected in message for message in errors), errors


def test_all_errors_are_reported_together():
    errors = errors_for(pattern(regex="(bad"), pattern(), pattern(), threshold(count=0))

    # Rule 1 is invalid, so rule 2 is the first valid 'test-rule' and rule 3 is the duplicate.
    assert len(errors) == 3
    assert "rule 'test-rule': 'regex': invalid regex" in errors[0]
    assert "rule 'test-rule': duplicate id 'test-rule'" in errors[1]
    assert "rule 'test-threshold': 'count' must be a positive integer" in errors[2]


def test_errors_name_the_rule_by_position_when_id_missing():
    errors = errors_for(pattern(), pattern(id=None))

    assert any(message.startswith("rules: rule #2: 'id' is required") for message in errors)


def test_empty_rules_file_is_an_error():
    with pytest.raises(RulesError, match="no rules defined"):
        parse_rules({})


def test_unknown_top_level_key_is_an_error():
    with pytest.raises(RulesError, match="unknown top-level key"):
        parse_rules({"rules": [pattern()], "rule": [pattern()]})


def test_invalid_toml_reports_line_number(tmp_path):
    path = tmp_path / "rules.toml"
    path.write_text('[[rule]]\nid = "x"\ntitle = \n')

    with pytest.raises(RulesError) as exc:
        load_rules(path)

    assert "invalid TOML" in exc.value.errors[0]
    assert "line 3" in exc.value.errors[0]
