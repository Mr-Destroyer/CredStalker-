#!/usr/bin/env python3
"""Backward-compatible entry point.

Old usage keeps working:
    python credential_scanner.py http://example.com --depth 3 --verbose --export findings.json

New canonical usage:
    credstalker http://example.com ...
    python -m credstalker http://example.com ...
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from credstalker.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
