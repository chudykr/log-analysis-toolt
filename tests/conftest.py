from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SAMPLES_DIR = REPO_ROOT / "samples"


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
