"""Allow `python -m credstalker https://example.com`."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
