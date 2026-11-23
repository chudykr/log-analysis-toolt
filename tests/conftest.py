from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from loganalyzer.models import Event, ParseStats
from loganalyzer.parsers import ParseContext, parse_stream, read_lines
from loganalyzer.rules import load_rules

REPO_ROOT = Path(__file__).resolve().parent.parent
SAMPLES_DIR = REPO_ROOT / "samples"
SAMPLE_YEAR = 2025
T0 = datetime(2025, 7, 3, 10, 0, 0, tzinfo=timezone.utc)


def make_event(kind="http_request", *, seconds=0, ip="10.0.0.1", file="test.log", line_no=1, **fields) -> Event:
    """Build an Event at T0 + seconds. Keyword arguments become event fields (values as strings)."""
    return Event(
        source_file=file, line_no=line_no, timestamp=T0 + timedelta(seconds=seconds),
        source_ip=ip, kind=kind, fields={k: str(v) for k, v in fields.items()}, raw=f"{kind} {fields}",
    )


def sample_lines(name: str) -> list[str]:
    return (SAMPLES_DIR / name).read_text().splitlines()


def parse_samples(*names: str) -> tuple[list[Event], ParseStats]:
    stats = ParseStats()
    paths = [str(SAMPLES_DIR / name) for name in names]
    events = list(parse_stream(read_lines(paths), ParseContext(SAMPLE_YEAR), stats))
    return events, stats


@pytest.fixture(scope="session")
def default_rules():
    return load_rules()


@pytest.fixture
def samples_dir() -> Path:
    return SAMPLES_DIR


@pytest.fixture
def write_log(tmp_path):
    """Write lines to a temp log file and return its path as a string."""

    def _write(name: str, lines: list[str] | str, *, encoding: str = "utf-8") -> str:
        path = tmp_path / name
        content = lines if isinstance(lines, str) else "".join(f"{line}\n" for line in lines)
        path.write_bytes(content.encode(encoding) if isinstance(content, str) else content)
        return str(path)

    return _write
