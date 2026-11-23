"""End-to-end tests: run the real command, `python -m loganalyzer`, as a subprocess.

Every case uses the sample logs from the assessment (samples/) with --year 2025, so results do not
depend on today's date. Case numbers (E1-E14) match development-plan/US-08-test-coverage-and-e2e.md.
"""

import json
import subprocess
import sys

import pytest

from tests.conftest import REPO_ROOT

WEB = "samples/webserver.log"
AUTH = "samples/auth.log"

# Expected incidents on both sample files: key -> (severity, rule ids).
EXPECTED = {
    "10.0.0.50":    ("critical", {"web-login-bruteforce", "ssh-bruteforce"}),
    "203.0.113.5":  ("critical", {"admin-probing", "path-traversal", "ssh-invalid-users"}),
    "10.0.0.88":    ("high",     {"sql-injection"}),
    "user:johndoe": ("high",     {"sensitive-sudo"}),
    "172.16.0.20":  ("medium",   {"sensitive-path-scan"}),
    "10.0.0.99":    ("medium",   {"request-flood", "rate-limited"}),
}

INNOCENT_KEYS = [
    "192.168.1.14",   # q=O'Brien: apostrophe, not SQL injection
    "192.168.1.100",  # deploy: publickey login
    "user:deploy",    # deploy: sudo systemctl restart nginx
    "192.168.1.10", "192.168.1.11", "192.168.1.12", "192.168.1.13",
    "192.168.1.15", "192.168.1.16", "192.168.1.17", "192.168.1.18",
]


def run_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "loganalyzer", *args],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=30,
    )


def run_json(*args: str) -> tuple[int, dict]:
    result = run_cli(*args, "--year", "2025", "--json")
    assert result.stderr == ""
    return result.returncode, json.loads(result.stdout)


def by_key(document: dict) -> dict[str, dict]:
    return {incident["key"]: incident for incident in document["incidents"]}


@pytest.fixture(scope="module")
def both() -> tuple[int, dict]:
    return run_json(WEB, AUTH)


# --- E1-E8: both sample files ----------------------------------------------------------------

def test_e1_text_report_on_both_files():
    result = run_cli(WEB, AUTH, "--year", "2025")

    assert result.returncode == 1, result.stderr
    assert result.stderr == ""
    lines = result.stdout.splitlines()
    assert lines[0] == "Security Log Analysis Report"
    assert lines[1] == f"Files: {WEB} (33 lines), {AUTH} (12 lines)"
    assert lines[2] == "Events parsed: 44   Malformed lines: 1   Incidents: 6 (critical 2, high 2, medium 2)"


def test_e2_json_incidents_match_expected_table(both):
    code, document = both

    assert code == 1
    assert document["schema_version"] == 1
    actual = {i["key"]: (i["severity"], {f["rule_id"] for f in i["findings"]}) for i in document["incidents"]}
    assert actual == EXPECTED
    # Order: by severity, then first time seen.
    assert [i["key"] for i in document["incidents"]] == list(EXPECTED)


def test_e3_correlation_across_files(both):
    _, document = both
    incidents = by_key(document)

    for key in ("10.0.0.50", "203.0.113.5"):
        assert incidents[key]["correlated"] is True
        assert incidents[key]["sources"] == [AUTH, WEB]
    for key in ("10.0.0.88", "user:johndoe", "172.16.0.20", "10.0.0.99"):
        assert incidents[key]["correlated"] is False
        assert len(incidents[key]["sources"]) == 1


def test_e4_brute_force_followed_by_success_is_escalated(both):
    _, document = both
    findings = {f["rule_id"]: f for f in by_key(document)["10.0.0.50"]["findings"]}

    for rule_id, success in (("web-login-bruteforce", (WEB, 7)), ("ssh-bruteforce", (AUTH, 5))):
        assert findings[rule_id]["escalated"] is True
        assert findings[rule_id]["severity"] == "critical"
        assert success in [(e["file"], e["line"]) for e in findings[rule_id]["evidence"]]


def test_e5_every_default_rule_fires_on_the_right_source(both):
    _, document = both
    fired = {(f["rule_id"], i["key"]) for i in document["incidents"] for f in i["findings"]}

    assert fired == {(rule_id, key) for key, (_, rule_ids) in EXPECTED.items() for rule_id in rule_ids}
    assert len({rule_id for rule_id, _ in fired}) == 10  # all ten default rules


@pytest.mark.parametrize("key", INNOCENT_KEYS)
def test_e6_false_positive_guards(both, key):
    _, document = both

    assert key not in by_key(document)


def test_e7_malformed_line_is_reported_not_fatal(both):
    _, document = both

    assert document["stats"]["malformed"] == 1
    assert document["malformed"] == [{"file": WEB, "line": 26, "raw": "[MALFORMED ENTRY - system restart"}]
    assert document["stats"]["events"] == 44  # parsing continued after line 26


def test_e8_every_evidence_line_is_the_real_log_line(both):
    _, document = both
    files = {path: (REPO_ROOT / path).read_text().splitlines() for path in (WEB, AUTH)}
    entries = [e for i in document["incidents"] for f in i["findings"] for e in f["evidence"]]
    entries += [e for i in document["incidents"] for e in i["context"]]

    assert len(entries) == 33  # 32 evidence entries + 1 context line
    for entry in entries:
        assert files[entry["file"]][entry["line"] - 1] == entry["raw"]


# --- E9-E14: other inputs --------------------------------------------------------------------

def test_e9_file_order_does_not_change_results(both):
    _, forward = both
    _, backward = run_json(AUTH, WEB)

    for key in ("stats", "incidents", "malformed"):
        assert backward[key] == forward[key], key


def test_e10_single_file_has_no_correlation():
    code, document = run_json(AUTH)
    incidents = by_key(document)

    assert code == 1
    assert set(incidents) == {"10.0.0.50", "203.0.113.5", "user:johndoe"}
    assert not any(i["correlated"] for i in incidents.values())
    assert incidents["10.0.0.50"]["severity"] == "critical"   # still escalated
    assert incidents["203.0.113.5"]["severity"] == "medium"   # no cross-file boost


def test_e11_clean_log_exits_zero(tmp_path):
    clean = tmp_path / "clean.log"
    clean.write_text("".join(line + "\n" for line in (REPO_ROOT / WEB).read_text().splitlines()
                             if line.startswith(("192.168.1.10 ", "192.168.1.11 ", "192.168.1.12 ",
                                                 "192.168.1.13 "))))

    result = run_cli(str(clean), "--year", "2025")

    assert result.returncode == 0, result.stdout
    assert "Events parsed: 4   Malformed lines: 0   Incidents: 0" in result.stdout
    assert result.stdout.rstrip().endswith("No suspicious activity found.")


def test_e12_missing_file_is_an_input_error():
    result = run_cli(WEB, "samples/missing.log")

    assert result.returncode == 2
    assert result.stdout == ""
    assert "error: file not found: samples/missing.log" in result.stderr


def test_e13_custom_rules_replace_the_defaults(tmp_path):
    rules = tmp_path / "only-sqli.toml"
    rules.write_text("""
[[rule]]
id = "sql-injection"
title = "SQL injection attempt"
type = "pattern"
severity = "high"
kinds = ["http_request"]
field = "path_decoded"
regex = '(?i)(union.+select|;\\s*drop\\s+table)'
action = "Block the IP and review the database logs."
""")

    code, document = run_json(WEB, AUTH, "--rules", str(rules))

    assert code == 1
    assert [(i["key"], [f["rule_id"] for f in i["findings"]]) for i in document["incidents"]] == [
        ("10.0.0.88", ["sql-injection"])]
    assert document["incidents"][0]["findings"][0]["count"] == 2


def test_e14_invalid_rules_file_names_the_rule(tmp_path):
    rules = tmp_path / "bad.toml"
    rules.write_text("""
[[rule]]
id = "broken-regex"
title = "Broken"
type = "pattern"
severity = "high"
kinds = ["http_request"]
field = "path"
regex = '(unclosed'
action = "Nothing to do here."
""")

    result = run_cli(WEB, "--rules", str(rules))

    assert result.returncode == 2
    assert result.stdout == ""
    assert "rule 'broken-regex'" in result.stderr
    assert "invalid regex" in result.stderr
