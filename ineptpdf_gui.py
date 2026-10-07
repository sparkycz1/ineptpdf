#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.13"
# dependencies = ["cryptography>=44"]
# ///
"""Starts the ineptpdf window. Run it with:  uv run ineptpdf_gui.py

Given arguments, it behaves like the ``ineptpdf`` command instead.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from ineptpdf.cli import main  # noqa: E402
from ineptpdf.gui import run  # noqa: E402

if __name__ == "__main__":
    sys.exit(main() if len(sys.argv) > 1 else run())
