# US-09: Understand and submit the tool

**Estimate:** S · **Depends on:** US-07 (README sections from US-04 and US-08 are merged here)

## Story

As a **reviewer of the assessment**
I want **a README that gets me running in under a minute and explains the design, and the AI conversation history included in the repo**
so that **I can check the tool, the testing approach and how AI was used without asking the author**.

## Description

The assessment requires a public GitHub repo with (1) the solution and a README explaining how to run it, and (2) the AI conversation history. This story finishes both and checks the repo from a clean clone.

### README structure

1. **One-line description**
2. **Quick start**, three commands:
   ```bash
   git clone <repo> && cd log-analysis-tool
   python -m loganalyzer samples/webserver.log samples/auth.log --year 2025
   pip install -e .[dev] && pytest
   ```
   Note that running needs only Python 3.11+, and testing needs `pip install -e .[dev]`.
3. **Example output**: the real text report on the sample files, pasted from an actual run (not written by hand)
4. **Options**: the flag table and the exit codes
5. **What it detects**: the default rules table (from US-05) with one line each
6. **Writing your own rules**: the schema and examples (from T-04.4)
7. **How it works**: a short pipeline diagram `read → parse → detect → correlate → report` with one sentence per stage, plus the design decisions D1–D12 in brief
8. **Testing approach**: test levels, how to run them (`pytest`, `pytest -m "not slow"`, coverage), the e2e cases, and the false-positive guards (from US-08)
9. **Production notes**: streaming and flat memory, bounded buffers, exit codes and JSON for automation, continuous use through scheduled runs (live mode planned in US-10, not implemented yet), adding a parser for a new format, and how to scale beyond one machine
10. **Limitations and future work**: no year or timezone in syslog, no state saved between restarts, no strict time-merge of live files, allow-lists, Hypothesis and mutation testing, more formats (nginx combined, journald JSON)
11. **AI usage**: where the transcript is and a short note on how AI was used (planning with user stories, implementation, test design) and what was checked by hand

### AI conversation history

Export the Claude Code session(s) used for planning and implementation and commit them as `ai-transcript/` (Markdown or text). Before committing, remove personal data such as email addresses and local home paths. Link the folder from the README.

## Acceptance criteria

1. Following only the README Quick start on a fresh clone with Python 3.11, the report runs and the tests pass.
2. The example output in the README matches a real run on the sample files (checked by re-running before submission).
3. Every CLI flag and every default rule is documented.
4. `ai-transcript/` exists, is linked from the README, and contains no email addresses or absolute home-directory paths (`grep -rE "@|/Users/" ai-transcript/` finds nothing unexpected).
5. The repository is public, and the submission link opens without a login.

## Tasks

### T-09.1 Write the README
Write the sections above. Generate the example output with the actual command and paste it in.
*Files:* `README.md`

### T-09.2 Add the AI transcript
Export, clean and commit the transcript; link it from the README.
*Files:* `ai-transcript/*.md`, `README.md`

### T-09.3 Clean-clone check
In a temp directory: `git clone`, create a fresh venv with Python 3.11, follow the README exactly, and run `pytest`. Fix any step that does not work as written.
*Test:* manual, recorded as a checklist in the final PR.

### T-09.4 Submission
Run `pytest --cov` locally on the final commit and confirm it passes, merge to the default branch, make the repo public, and send the link.

## Out of scope

- Packaging to PyPI
- A docs site
