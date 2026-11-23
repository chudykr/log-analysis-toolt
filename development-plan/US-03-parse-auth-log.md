# US-03: Parse the auth log

**Estimate:** M · **Depends on:** US-01 (uses `Event` and the registry from US-02 if done first; otherwise create them here) · **Decisions:** D3, D7, D11

## Story

As a **security analyst**
I want **SSH and sudo entries from `auth.log` turned into structured events**
so that **login attacks and privilege use can be detected and matched with web activity**.

## Description

`auth.log` uses the syslog format, where the message part differs by program. The sample contains these message shapes:

| Shape | Example | Event `kind` | Fields |
|---|---|---|---|
| SSH failed, valid user | `sshd[1234]: Failed password for admin from 10.0.0.50 port 52341 ssh2` | `ssh_failed` | `user=admin`, `port`, `method=password`, `invalid_user=false` |
| SSH failed, invalid user | `sshd[1235]: Failed password for invalid user test from 203.0.113.5 port 44123 ssh2` | `ssh_failed` | `user=test`, `invalid_user=true` |
| SSH accepted | `sshd[1234]: Accepted password for admin from 10.0.0.50 port 52345 ssh2` | `ssh_accepted` | `user`, `port`, `method=password` or `publickey` |
| SSH connection closed | `sshd[1245]: Connection closed by 10.0.0.50 port 52345 [preauth]` | `ssh_closed` | `port`, `preauth=true` |
| sudo | `sudo: johndoe : TTY=pts/0 ; PWD=/home/johndoe ; USER=root ; COMMAND=/bin/cat /etc/shadow` | `sudo` | `user=johndoe`, `target_user=root`, `tty`, `pwd`, `command` |

Common header regex:

```
^(?P<month>[A-Z][a-z]{2}) +(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) (?P<host>\S+) (?P<program>[\w\-]+)(?:\[(?P<pid>\d+)\])?: (?P<message>.*)$
```

Note the **double space** in `Jul  3`: days below 10 are padded with a space, so the regex uses ` +`.

**No year, no timezone.** Syslog lines have neither. The parser takes the year from `--year` (default: current year) and assumes UTC. With `--year 2025` the sample lines up with `webserver.log`. Test fixtures always pass the year explicitly so tests do not depend on today's date.

Sudo lines have no source IP (`source_ip=None`). Their actor is the local user, so rules for them key on `user` instead of the IP (see US-05).

Lines from known programs whose message matches none of the shapes (for example `sshd: pam_unix(...)`) become an event with `kind="auth_other"`, so no information is lost and they do not count as malformed. Only lines whose header does not match count as malformed.

## Acceptance criteria

1. **Given** auth line 1 and `--year 2025`, **then** the event is `kind=ssh_failed`, `source_ip=10.0.0.50`, `user=admin`, `port=52341`, `invalid_user=false`, timestamp `2025-07-03T10:00:03+00:00`. (`invalid_user` is always set on `ssh_failed`, because rule filters treat a missing field as no match.)
2. **Given** auth line 6, **then** `user=test`, `invalid_user=true`, `source_ip=203.0.113.5`.
3. **Given** auth line 5, **then** `kind=ssh_accepted`, `method=password`; line 10 gives `method=publickey`, `user=deploy`.
4. **Given** auth line 9, **then** `kind=sudo`, `user=johndoe`, `target_user=root`, `command=/bin/cat /etc/shadow`, `source_ip=None`.
5. **Given** auth line 12, **then** `kind=ssh_closed`, `source_ip=10.0.0.50`, `preauth=true`.
6. **Given** the full sample, **then** 12 events and 0 malformed lines.
7. **Given** a mixed call with both sample files, **then** each line goes to the right parser with no `--format` flag.

## Tasks

### T-03.1 Syslog header parser and timestamp
Implement header matching, a fixed English month table, and timestamp building from `year` + month + day + time in UTC. The year is passed in through a parser context object set by the CLI, not read from a global.
*Files:* `loganalyzer/parsers.py`
*Test:* `Jul  3` (two spaces) and `Jul 13` both parse; an invalid date such as `Feb 30` returns `None`.

### T-03.2 sshd message parsers
One compiled regex per sshd shape from the table. Keep them in a small ordered list so new shapes (for example `Invalid user X from IP`) can be added in one line.
*Files:* `loganalyzer/parsers.py`
*Test:* parametrised over every sshd line in the sample plus an unknown sshd message (gives `auth_other`).

### T-03.3 sudo message parser
Parse `user : KEY=VALUE ; KEY=VALUE ; ... COMMAND=...`. Split on ` ; ` and treat `COMMAND` as running to the end of the line, since commands can contain `;` or `=`.
*Files:* `loganalyzer/parsers.py`
*Test:* both sample sudo lines; a command containing `=` (`COMMAND=/usr/bin/env A=1 ls`) keeps the full command.

### T-03.4 Register auth parsers and add the fixture
Add the auth parser to `PARSERS` after the web parser. Copy `auth.log` from `qa-assessment.md` into `samples/auth.log` exactly as written (12 lines).
*Files:* `loganalyzer/parsers.py`, `samples/auth.log`
*Test:* the fixture has 12 lines; parsing both sample files gives 32 + 12 = 44 events and 1 malformed line.

## Out of scope

- Other syslog programs (cron, systemd) beyond `auth_other`
- RFC 5424 syslog or journald JSON (future parsers via D11)
- Guessing the year rollover for logs that cross New Year
