"""Reading and parsing log files."""

from collections.abc import Iterable, Iterator


def read_lines(paths: Iterable[str]) -> Iterator[tuple[str, int, str]]:
    """Yield (path, line_number, line) for every non-blank line, one file after another.

    Files are read lazily, line by line, so memory use does not depend on file size.
    Line numbers start at 1 and count blank lines, so they match the file as shown in an editor.
    Invalid UTF-8 bytes are replaced instead of raising.
    """
    for path in paths:
        with open(path, encoding="utf-8", errors="replace") as handle:
            for line_no, line in enumerate(handle, start=1):
                line = line.rstrip("\r\n")
                if line.strip():
                    yield path, line_no, line
