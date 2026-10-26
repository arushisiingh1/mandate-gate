"""Test package.

Puts ``src/`` on the path so the suite runs from a fresh clone with no install:

    python -m unittest discover -s tests -t . -v     # standard library only
    python -m pytest -q                              # also works

The tests are plain ``unittest.TestCase`` classes on purpose: they need no test
framework to be installed, and pytest collects them unchanged.
"""

import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))
