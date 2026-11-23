"""The example output in README.md must be the real output of the tool."""

import re
import subprocess
import sys

from tests.conftest import REPO_ROOT

COMMAND = ["samples/webserver.log", "samples/auth.log", "--year", "2025"]
BLOCK = re.compile(r"<!-- example-output:start -->\n```text\n\$ python3 -m loganalyzer (?P<args>[^\n]*)\n"
                   r"(?P<output>.*?)\n```\n<!-- example-output:end -->", re.S)


def test_readme_example_output_matches_real_output():
    readme = (REPO_ROOT / "README.md").read_text()
    match = BLOCK.search(readme)
    assert match, "example output block not found in README.md"
    assert match["args"].split() == COMMAND

    result = subprocess.run([sys.executable, "-m", "loganalyzer", *COMMAND],
                            cwd=REPO_ROOT, capture_output=True, text=True, timeout=30)

    assert result.returncode == 1
    assert match["output"] == result.stdout.rstrip("\n"), (
        "README example output is out of date; regenerate it from the command above")
