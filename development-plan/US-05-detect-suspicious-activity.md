# US-05: Detect suspicious activity

**Estimate:** L · **Depends on:** US-02, US-03, US-04 · **Decisions:** D5, D6

## Story

As a **security analyst**
I want **every event checked against the rules, with matches turned into findings**
so that **attacks such as brute force, injection and scanning are spotted without reading logs by hand**.

## Description

The detector reads the event stream once and passes each event to every enabled rule whose `kinds` and `where` filters match.

- **Pattern rules** test one field with a regex and emit a `Finding` immediately.
- **Threshold rules** keep a sliding window per `group_by` key: a `deque` of `(timestamp, event)` from which events older than `window_seconds` are dropped on each new event. When the count (or the number of distinct values) reaches `count`, the rule emits one `Finding` for that key. Further matching events from the same key are added to the same finding as evidence instead of creating new findings. After a threshold finding, the rule watches for `escalate_on` events from the same key within the window; if one arrives, the finding's severity is raised and the event is added as evidence.

Memory stays flat because only events inside each window are kept (D6). Keys with an empty window are removed from the dict so idle IPs do not pile up.

**Ordering:** each file is in time order, but files are read one after another. To keep thresholds correct across interleaved sources, the detector keeps a separate window state per `(rule, key, source_file)` and assumes order only within a file. The correlator (US-06) does the cross-file linking.

```python
@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    key: str                  # source IP or user
    source_file: str
    first_seen: datetime
    last_seen: datetime
    evidence: list[Event]     # capped at 20 events, full count in `count`
    count: int
    action: str
    escalated: bool = False
```

### Default rules (shipped in `rules.toml`)

| Rule ID | Type | Logic | Severity | Fires on sample |
|---|---|---|---|---|
| `web-login-bruteforce` | threshold | `http_request`, `method=POST`, `path=^/login`, `status=401`; ≥3 per IP in 60 s; escalate on `status=2..` for the same path → critical | high | `10.0.0.50` (4 × 401, then 200 → critical) |
| `ssh-bruteforce` | threshold | `ssh_failed`, valid user; ≥3 per IP in 60 s; escalate on `ssh_accepted` → critical | high | `10.0.0.50` (4 failed, then accepted → critical) |
| `ssh-invalid-users` | threshold | `ssh_failed`, `invalid_user=true`; ≥3 **distinct** `user` per IP in 300 s | medium | `203.0.113.5` (`test`, `root`, `ubuntu`) |
| `admin-probing` | threshold | `http_request`, `path=^/admin`, `status=403`; ≥3 per IP in 60 s | medium | `203.0.113.5` |
| `sensitive-path-scan` | threshold | `http_request`, path matches `^/(admin\|phpmyadmin\|wp-admin\|administrator\|\.env\|config\.php\|\.git)`; ≥5 **distinct** `path` per IP in 10 s | medium | `172.16.0.20` (6 distinct). `203.0.113.5` hits 4 distinct `/admin…` paths, so it stays below the threshold and is covered by `admin-probing` |
| `request-flood` | threshold | `http_request`; ≥5 per IP + same `method` and `path` in 2 s (`group_by = ["source_ip","method","path"]`) | medium | `10.0.0.99` (5 × `POST /api/users`). `172.16.0.20` uses different paths, so it does not fire |
| `rate-limited` | pattern | `http_request`, `status=^429$` | low | `10.0.0.99`; merged into the same incident by US-06 |
| `sql-injection` | pattern | `path` matches `(?i)(\bunion\b.+\bselect\b\|;\s*drop\s+table\|\bor\b\s+'?\d+'?\s*=\s*'?\d+\|'\s*--\|\bsleep\s*\()` | high | `10.0.0.88` ×2. **Not** `O'Brien` |
| `path-traversal` | pattern | `path` matches `(\.\./\|\.\.%2[fF]\|%2[eE]%2[eE]/)` | high | `203.0.113.5` |
| `sensitive-sudo` | pattern | `sudo`, `target_user=root`, `command` matches `(/etc/shadow\|/etc/sudoers\|/etc/gshadow\|\bvisudo\b\|\bpasswd\b\|chmod\s+[0-7]*7[0-7]*\s+/)` | high | `johndoe`. **Not** `deploy systemctl restart nginx` |

**False-positive guards** are part of the definition of done: `O'Brien`, `/search?q=laptop`, and the `deploy` sudo and publickey lines must stay clean. Each guard gets its own test case.

## Acceptance criteria

1. **Given** the sample files and default rules, **then** the detector produces exactly the findings listed in the table above. Each finding has the right `rule_id`, `key`, `severity` and `count`.
2. **Given** `10.0.0.50`, **then** both brute-force findings are `critical` with `escalated=True`, and the success event (web line 7, auth line 5) is in the evidence.
3. **Given** 3 failed SSH logins spread over 61 seconds, **then** `ssh-bruteforce` does not fire (window boundary).
4. **Given** exactly 3 failed logins within 60 seconds, **then** it fires (inclusive threshold).
5. **Given** 10,000 failed logins from one IP, **then** one finding is produced with `count=10000` and at most 20 evidence events stored.
6. **Given** `q=O'Brien`, `q=laptop`, the `deploy` sudo line and the publickey login, **then** no findings.
7. The detector reads the event stream once (single pass); `tests/test_detector.py` checks this with a generator that fails if iterated twice.

## Tasks

### T-05.1 Finding model and filter matching
Add `Finding` to `models.py`. Implement `rule.matches(event)`: kind in `kinds` and every `where` regex matches the field (a missing field counts as no match).
*Files:* `loganalyzer/models.py`, `loganalyzer/rules.py`
*Test:* `where` with a missing field, a numeric status as a string, multiple filters.

### T-05.2 Pattern rule engine
Evaluate pattern rules per event and emit a `Finding` with one evidence event. Findings with the same `(rule_id, key, source_file)` merge (count goes up, evidence is appended up to the cap, `last_seen` moves forward), so the two SQL injection lines from `10.0.0.88` become one finding with `count=2`.
*Files:* `loganalyzer/detector.py`
*Test:* single match, two matches merged, evidence cap, non-matching field.

### T-05.3 Threshold rule engine with sliding window
Per `(rule, key, file)` keep a `deque` plus an optional `set`/`Counter` for `distinct`. On each event: drop expired items, append, check the threshold, emit or extend the finding. Remove empty keys. Handle `escalate_on`.
*Files:* `loganalyzer/detector.py`
*Test:* `tests/test_detector.py` with hand-built events: below threshold, at threshold, window expiry, distinct counting, escalation inside the window, escalation after the window (no escalation), compound `group_by`.

### T-05.4 Default rules content
Write the ten rules above into `rules.toml`, with a comment per rule.
*Files:* `loganalyzer/rules.toml`
*Test:* one test per rule, fed only the relevant sample lines, asserting it fires; one test per false-positive guard asserting it does not.

### T-05.5 Detector entry point
`detect(events, rules) -> list[Finding]`: single pass, returns findings sorted by `(severity desc, first_seen)`.
*Files:* `loganalyzer/detector.py`
*Test:* the single-pass generator test; sort order.

## Out of scope

- Allow-lists for internal IP ranges (worth adding later as a `where_not` filter)
- Global time-ordering across files (handled by per-file state plus correlation)
