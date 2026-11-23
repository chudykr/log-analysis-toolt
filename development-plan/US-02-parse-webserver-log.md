# US-02: Parse the web server access log

**Estimate:** M · **Depends on:** US-01 · **Decisions:** D3, D6, D7, D11

## Story

As a **security analyst**
I want **web server access log lines turned into structured events**
so that **rules can check IPs, paths, methods and status codes reliably**.

## Description

`webserver.log` uses the Common Log Format:

```
192.168.1.10 - - [03/Jul/2025:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 1234
```

The parser turns each line into an `Event` (shared model, also used by US-03):

```python
@dataclass(frozen=True, slots=True)
class Event:
    source_file: str        # "webserver.log"
    line_no: int            # 1-based
    timestamp: datetime     # timezone-aware
    source_ip: str | None
    kind: str               # "http_request" for this parser
    fields: dict[str, str]  # method, path, protocol, status, size, user
    raw: str                # original line, kept for evidence in the report
```

**Watch out for:** attack lines contain spaces inside the request, for example
`"GET /search?q=' UNION SELECT * FROM users-- HTTP/1.1"`. A naive split on spaces breaks here. The regex must take the method as the first token and the protocol as the last `HTTP/x.y` token before the closing quote, with everything in between as the path:

```
^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>.*) (?P<protocol>HTTP/\d\.\d)" (?P<status>\d{3}) (?P<size>\d+|-)$
```

Timestamps such as `03/Jul/2025:10:00:01 +0000` are parsed with `%d/%b/%Y:%H:%M:%S %z`. Always parse month names with a fixed English table, not `strptime`'s locale-dependent `%b`, so the tool works the same on any machine.

**Malformed lines** (for example `[MALFORMED ENTRY - system restart` at line 26) do not match any parser. The registry (T-02.3) returns `None` for them, and the caller records `(file, line_no, raw)` in a `ParseStats` object instead of raising. The run continues.

## Acceptance criteria

1. **Given** line 1 of the sample, **then** the event has `source_ip=192.168.1.10`, `method=GET`, `path=/index.html`, `status=200`, `size=1234`, timestamp `2025-07-03T10:00:01+00:00`.
2. **Given** line 14 (`' UNION SELECT * FROM users--`), **then** `path` equals `/search?q=' UNION SELECT * FROM users--` exactly and `protocol=HTTP/1.1`.
3. **Given** line 15 (`q=O'Brien`), **then** it parses normally.
4. **Given** line 26 (`[MALFORMED ENTRY - system restart`), **then** no event is produced, `ParseStats.malformed` contains `("webserver.log", 26, ...)`, and parsing continues with line 27.
5. **Given** the full sample file, **then** 32 events are produced and 1 line is counted as malformed.
6. **Given** a size of `-` (allowed in CLF), **then** the line parses with `size="0"`.
7. Parsing a 1,000,000-line generated file uses flat memory (generator-based, no list of all events).

## Tasks

### T-02.1 Shared models
Create `models.py` with `Event` (above) and `ParseStats` (`total_lines`, `parsed`, `malformed: list[tuple[str, int, str]]`). Store at most the first 100 malformed lines in the list but always keep the full count, so a broken file cannot use up memory.
*Files:* `loganalyzer/models.py`
*Test:* `ParseStats` caps the stored list at 100 while the counter keeps going.

### T-02.2 Web server parser
Implement `parse_webserver(line) -> dict | None` with the regex above (compiled once at module level) and the locale-independent timestamp parsing. Return `None` on no match or an invalid timestamp; never raise.
*Files:* `loganalyzer/parsers.py`
*Test:* `tests/test_parsers.py`, parametrised over: a normal GET, a POST with 401, a SQL-injection path with spaces, a traversal path, an apostrophe in a query, size `-`, the malformed line, an empty string, a line with a bad month (`03/Foo/2025`).

### T-02.3 Parser registry and format detection
Create `PARSERS = [("http_request", parse_webserver), ...]` and `parse_stream(lines) -> Iterator[Event]`, which tries each parser in order for each line, builds the `Event`, and updates `ParseStats`. US-03 adds the auth parsers to the same list. Adding a new format later means one function and one entry (D11).
*Files:* `loganalyzer/parsers.py`
*Test:* a mixed stream (web line, auth line, garbage) gives two events and one malformed entry, with correct `source_file` and `line_no`.

### T-02.4 Sample fixture
Copy the `webserver.log` block from `qa-assessment.md` into `samples/webserver.log` exactly as written (33 lines, final newline). Add a test that checks the line count, so an accidental edit is caught.
*Files:* `samples/webserver.log`
*Test:* the fixture has 33 lines, and line 26 starts with `[MALFORMED`.

## Out of scope

- Combined Log Format extras (referrer, user agent). The regex should be easy to extend, but this is not needed now.
- IPv6-specific validation (the IP is kept as a string).
