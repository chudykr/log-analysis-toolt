# US-06: Correlate findings across files

**Estimate:** M · **Depends on:** US-05

## Story

As a **security analyst**
I want **findings about the same attacker grouped into one incident, even when they come from different log files**
so that **I see the whole attack (for example web and SSH brute force from one IP) instead of separate alerts**.

## Description

The correlator takes the list of findings and returns **incidents**. An incident groups every finding that shares the same key (source IP, or user for sudo findings).

```python
@dataclass
class Incident:
    key: str                     # "10.0.0.50" or "user:johndoe"
    key_type: str                # "ip" or "user"
    severity: Severity           # final severity after correlation boosts
    findings: list[Finding]
    sources: set[str]            # {"webserver.log", "auth.log"}
    first_seen: datetime
    last_seen: datetime
    correlated: bool             # True if sources has 2 or more entries
    context: list[Event]         # extra non-finding events for this key (e.g. "Connection closed")
    summary: str                 # one sentence, built from the findings
    actions: list[str]           # de-duplicated actions from the findings
```

### Severity rules

1. Start with the highest finding severity in the incident.
2. If `correlated` (the key appears in findings from two or more files), raise severity by one level (max `critical`).
3. If any finding is `escalated` (a success after brute force), the incident is `critical`.

On the sample:

| Incident | Findings | Correlated | Final severity |
|---|---|---|---|
| `10.0.0.50` | `web-login-bruteforce` (critical), `ssh-bruteforce` (critical) | yes | critical |
| `203.0.113.5` | `path-traversal` (high), `admin-probing` (medium), `ssh-invalid-users` (medium) | yes | high → **critical** (boost) |
| `10.0.0.88` | `sql-injection` (high) | no | high |
| `user:johndoe` | `sensitive-sudo` (high) | no | high |
| `172.16.0.20` | `sensitive-path-scan` (medium) | no | medium |
| `10.0.0.99` | `request-flood` (medium), `rate-limited` (low) | no | medium |

The boost raising `203.0.113.5` to **critical** is intended: someone probing admin paths and trying SSH logins from the same IP at the same time is a coordinated attack.

### Context events

For each incident key, the correlator also keeps up to 5 non-finding events from that key in time order. These come from a small `context_kinds` list (`ssh_accepted`, `ssh_closed`), so `Connection closed by 10.0.0.50 port 52345 [preauth]` appears under the `10.0.0.50` incident. To make this possible without a second pass, the detector forwards events of those kinds for keys that have findings. It buffers at most 5 per key, which keeps memory flat.

### Summary sentence

Built from templates, never free text, so it can be tested:
`"10.0.0.50: login brute force on web and SSH, followed by successful login (2 sources, 10:00:03–10:00:07)."`

## Acceptance criteria

1. **Given** the sample findings, **then** 6 incidents are produced, as in the table above.
2. **Given** `10.0.0.50`, **then** `correlated=True`, `sources={"webserver.log","auth.log"}`, severity `critical`, and the `ssh_closed` event is in `context`.
3. **Given** `203.0.113.5`, **then** `correlated=True` and severity `critical`.
4. **Given** findings from one file only, **then** `correlated=False` and no boost.
5. **Given** sudo findings, **then** they group under `user:<name>` and never merge with IP incidents.
6. Incidents are sorted by severity (desc), then `first_seen` (asc).
7. `actions` contains no duplicates.

## Tasks

### T-06.1 Incident model and grouping
Add `Incident` to `models.py`. Implement `correlate(findings, context_events) -> list[Incident]` with grouping by key, `sources`, `first_seen`/`last_seen`, and sorting.
*Files:* `loganalyzer/models.py`, `loganalyzer/correlator.py`
*Test:* `tests/test_correlator.py`: two files, one file, user key separate from IP key.

### T-06.2 Severity boosts
Implement the three severity rules above as a separate pure function, `incident_severity(findings, correlated) -> Severity`, so it can be unit-tested on its own.
*Files:* `loganalyzer/correlator.py`
*Test:* a table-driven test covering each rule and the cap at `critical`.

### T-06.3 Context events
Add the bounded context buffer in the detector (`context_kinds`, max 5 per key) and attach it to incidents.
*Files:* `loganalyzer/detector.py`, `loganalyzer/correlator.py`
*Test:* the `ssh_closed` line appears under `10.0.0.50`; the buffer cap holds.

### T-06.4 Summary and actions
Build the template summary from rule titles, source count and time span; de-duplicate actions while keeping their order.
*Files:* `loganalyzer/correlator.py`
*Test:* the exact summary string for `10.0.0.50` on the sample data.

## Out of scope

- Correlation by anything other than IP or user (sessions, user agents)
- Correlation across separate runs (no state is stored between runs)
