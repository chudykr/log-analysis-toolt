"""Security log analysis tool."""

import sys

__version__ = "0.1.0"

MIN_PYTHON = (3, 11)


def python_supported(version_info=sys.version_info):
    return tuple(version_info[:2]) >= MIN_PYTHON


# Checked before any other module is imported, so an old interpreter (e.g. macOS's default
# python3 3.9) gets a clear message instead of a traceback. Keep this file 3.6-compatible.
# Exit code 2, like every other usage/environment error (1 means "findings reported").
if not python_supported():
    sys.stderr.write(
        "loganalyzer needs Python {}.{} or newer; this is Python {}.{} ({}).\n"
        "Install a newer Python (e.g. `brew install python@3.12` or pyenv) and run it with that interpreter.\n"
        .format(*MIN_PYTHON, *sys.version_info[:2], sys.executable)
    )
    sys.exit(2)
