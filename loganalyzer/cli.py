"""Command-line entry point.

Exit codes:
    0  ran successfully, no findings
    1  ran successfully, findings reported
    2  usage error, missing or unreadable input
"""

import argparse
import datetime
import json
import os
import sys
from collections.abc import Sequence

from loganalyzer import __version__
from loganalyzer.detector import detect
from loganalyzer.models import Finding, ParseStats
from loganalyzer.parsers import ParseContext, parse_stream, read_lines
from loganalyzer.rules import RulesError, load_rules

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

MIN_YEAR, MAX_YEAR = 1970, 2100


def _year(value: str) -> int:
    try:
        year = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid year: {value!r}") from None
    if not MIN_YEAR <= year <= MAX_YEAR:
        raise argparse.ArgumentTypeError(f"year must be between {MIN_YEAR} and {MAX_YEAR}: {year}")
    return year


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="loganalyzer",
        description="Find security incidents in web server and auth logs.",
        epilog="Exit codes: 0 no findings, 1 findings reported, 2 usage or input error.",
    )
    parser.add_argument("files", nargs="+", metavar="FILE", help="log file(s) to analyse, in any format and order")
    parser.add_argument("--rules", metavar="PATH", help="rules file to use instead of the bundled rules.toml")
    parser.add_argument("--json", action="store_true", help="print the report as JSON instead of text")
    parser.add_argument(
        "--year",
        type=_year,
        default=datetime.date.today().year,
        help="year assumed for syslog timestamps that have no year (default: current year)",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def check_inputs(paths: Sequence[str]) -> list[str]:
    """Return one error message per path that is missing, not a file, or not readable."""
    errors = []
    for path in paths:
        if not os.path.exists(path):
            errors.append(f"file not found: {path}")
        elif not os.path.isfile(path):
            errors.append(f"not a file: {path}")
        elif not os.access(path, os.R_OK):
            errors.append(f"file not readable: {path}")
    return errors


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:  # argparse exits with 0 for --help/--version and 2 for usage errors
        return int(exc.code or 0)

    errors = check_inputs(args.files)
    if args.rules is not None:
        errors += [f"rules {msg}" for msg in check_inputs([args.rules])]
    if errors:
        for message in errors:
            print(f"error: {message}", file=sys.stderr)
        return EXIT_ERROR

    try:
        rules = load_rules(args.rules)
    except RulesError as exc:
        for message in exc.errors:
            print(f"error: {message}", file=sys.stderr)
        return EXIT_ERROR

    stats = ParseStats()
    try:
        events = parse_stream(read_lines(args.files), ParseContext(year=args.year), stats)
        findings = detect(events, rules)
    except OSError as exc:
        print(f"error: cannot read {exc.filename}: {exc.strerror}", file=sys.stderr)
        return EXIT_ERROR

    # Correlation (US-06) and the full report (US-07) replace this simple output.
    print(_render_json(findings, stats) if args.json else _render_text(findings, stats))
    return EXIT_FINDINGS if findings else EXIT_OK


def _render_text(findings: list[Finding], stats: ParseStats) -> str:
    lines = [f"Events parsed: {stats.parsed}   Malformed lines: {stats.malformed_count}   Findings: {len(findings)}"]
    if not findings:
        lines.append("No suspicious activity found.")
    for finding in findings:
        where = ", ".join(f"{event.source_file}:{event.line_no}" for event in finding.evidence)
        escalated = "  ESCALATED" if finding.escalated else ""
        lines.append(f"[{str(finding.severity).upper()}] {finding.rule_id} {finding.key_field}={finding.key} "
                     f"({finding.count} events){escalated}  {where}")
    for source_file, line_no, raw in stats.malformed:
        lines.append(f"Malformed: {source_file}:{line_no}  {raw}")
    return "\n".join(lines)


def _render_json(findings: list[Finding], stats: ParseStats) -> str:
    return json.dumps({
        "stats": {"events": stats.parsed, "malformed": stats.malformed_count, "findings": len(findings)},
        "findings": [{
            "rule_id": f.rule_id, "severity": str(f.severity), "key_field": f.key_field, "key": f.key,
            "source_file": f.source_file, "count": f.count, "escalated": f.escalated,
            "first_seen": f.first_seen.isoformat(), "last_seen": f.last_seen.isoformat(),
            "evidence": [{"file": e.source_file, "line": e.line_no, "raw": e.raw} for e in f.evidence],
        } for f in findings],
        "malformed": [{"file": file, "line": line_no, "raw": raw} for file, line_no, raw in stats.malformed],
    }, indent=2)
