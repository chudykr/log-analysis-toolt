"""Command-line entry point.

Exit codes:
    0  ran successfully, no findings
    1  ran successfully, findings reported
    2  usage error, missing or unreadable input
"""

import argparse
import datetime
import os
import sys
from collections.abc import Sequence

from loganalyzer import __version__
from loganalyzer.parsers import read_lines

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
        line_count = sum(1 for _ in read_lines(args.files))
    except OSError as exc:
        print(f"error: cannot read {exc.filename}: {exc.strerror}", file=sys.stderr)
        return EXIT_ERROR

    # Parsing (US-02, US-03), detection (US-05), correlation (US-06) and the report (US-07)
    # plug in here. Until then the tool only reads the input and reports what it read.
    print(f"Read {line_count} lines from {len(args.files)} file(s).")
    return EXIT_OK
