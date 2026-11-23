"""Volume smoke test: large generated logs, real command, time and memory limits.

Marked `slow`; skip locally with `pytest -m "not slow"`. CI runs it.
"""

import json
import random
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone

import pytest

from tests.conftest import REPO_ROOT

pytestmark = pytest.mark.slow

try:
    import resource
except ImportError:  # Windows
    resource = None

LINES = 200_000
MAX_SECONDS = 10
MAX_PEAK_MB = 150
MAX_GROWTH_MB = 10  # peak memory for 200k lines vs 20k lines; normal growth is about 0

ATTACKER = "198.51.100.7"
PATHS = ["/", "/index.html", "/products", "/about.html", "/search?q=laptop", "/api/users/me", "/dashboard"]

# Runs the CLI in-process and prints its own peak memory (in bytes) to stderr as the last line.
_MEASURE = """
import resource, runpy, sys
sys.argv = ["loganalyzer", *sys.argv[1:]]
code = 0
try:
    runpy.run_module("loganalyzer", run_name="__main__")
except SystemExit as exc:
    code = exc.code
peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
print(peak if sys.platform == "darwin" else peak * 1024, file=sys.stderr)
sys.exit(code)
"""


def write_traffic(path, lines: int) -> None:
    """Normal traffic from many IPs over about an hour, with one brute force in the middle."""
    rng = random.Random(42)
    start = datetime(2025, 7, 3, 10, 0, 0, tzinfo=timezone.utc)
    attack_at = lines // 2
    with open(path, "w") as handle:
        for n in range(lines):
            moment = start + timedelta(seconds=n * 3600 / lines)
            stamp = moment.strftime("%d/%b/%Y:%H:%M:%S +0000")
            if attack_at <= n < attack_at + 6:
                status = "200" if n == attack_at + 5 else "401"
                handle.write(f'{ATTACKER} - - [{stamp}] "POST /login HTTP/1.1" {status} 54\n')
                continue
            ip = f"10.{rng.randrange(256)}.{rng.randrange(256)}.{rng.randrange(1, 255)}"
            path_ = rng.choice(PATHS)
            handle.write(f'{ip} - - [{stamp}] "GET {path_} HTTP/1.1" 200 {rng.randrange(100, 9000)}\n')
            if n % 997 == 0:
                handle.write("garbage line from a log rotation\n")


def run_measured(log_path) -> tuple[subprocess.CompletedProcess, float, float]:
    started = time.perf_counter()
    result = subprocess.run(
        [sys.executable, "-c", _MEASURE, str(log_path), "--json", "--year", "2025"],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=120,
    )
    elapsed = time.perf_counter() - started
    peak_mb = int(result.stderr.strip().splitlines()[-1]) / 1024 / 1024
    return result, elapsed, peak_mb


@pytest.mark.skipif(resource is None, reason="memory measurement needs the resource module (POSIX)")
def test_large_log_is_fast_finds_the_attack_and_memory_stays_flat(tmp_path):
    small, large = tmp_path / "small.log", tmp_path / "large.log"
    write_traffic(small, LINES // 10)
    write_traffic(large, LINES)

    _, _, small_peak = run_measured(small)
    result, elapsed, large_peak = run_measured(large)

    assert result.returncode == 1, result.stderr
    document = json.loads(result.stdout)
    incidents = {i["key"]: i for i in document["incidents"]}
    assert ATTACKER in incidents
    assert incidents[ATTACKER]["severity"] == "critical"  # brute force followed by a success
    assert document["stats"]["events"] == LINES
    assert document["stats"]["malformed"] == len(range(0, LINES, 997))

    print(f"\n{LINES} lines in {elapsed:.2f}s ({LINES / elapsed:,.0f} lines/s), "
          f"peak {large_peak:.0f} MB (20k lines: {small_peak:.0f} MB)")
    assert elapsed < MAX_SECONDS
    assert large_peak < MAX_PEAK_MB
    assert large_peak - small_peak < MAX_GROWTH_MB
