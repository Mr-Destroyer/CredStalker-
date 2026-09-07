"""argparse CLI — `credstalker` entry point."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .banner import print_banner
from .reporter import print_results
from .scanner import CredentialScanner


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="credstalker",
        description="CredStalker — crawl a site and hunt exposed credentials.",
        epilog="Example: credstalker https://example.com --depth 5 --verbose --export findings.json",
    )
    p.add_argument("url", nargs="?", help="Target website URL (e.g. https://example.com)")
    p.add_argument("--depth", type=int, default=3, help="Maximum crawl depth (default: 3)")
    p.add_argument("--verbose", action="store_true", help="Show every URL crawled + live hits")
    p.add_argument("--export", metavar="FILE", default=None, help="Export findings to JSON file")
    p.add_argument("--timeout", type=int, default=8, help="Per-request timeout in seconds (default: 8)")
    p.add_argument("--max-urls", type=int, default=200, help="Max pages+assets to fetch (default: 200)")
    p.add_argument("--delay", type=float, default=0.0, help="Delay between requests in seconds (default: 0)")
    p.add_argument("--user-agent", default=None, help="Custom User-Agent string")
    p.add_argument(
        "--include-subdomains",
        action="store_true",
        help="Also crawl subdomains of the target (default: only exact domain)",
    )
    p.add_argument("--silent", action="store_true", help="Only output the export file, no console report")
    p.add_argument("--no-color", action="store_true", help="Disable colors / Rich output")
    p.add_argument("--version", action="store_true", help="Show version and exit")
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.version:
        print(f"credstalker {__version__}")
        return 0

    if not args.url:
        print_banner(no_color=args.no_color)
        parser.print_help()
        return 1

    url = args.url
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    if not args.silent:
        print_banner(no_color=args.no_color)

    from .scanner import DEFAULT_UA

    scanner = CredentialScanner(
        url,
        max_depth=args.depth,
        verbose=args.verbose,
        timeout=args.timeout,
        max_urls=args.max_urls,
        delay=args.delay,
        user_agent=args.user_agent or DEFAULT_UA,
        include_subdomains=args.include_subdomains,
        silent=args.silent,
    )
    findings = scanner.scan()
    print_results(findings, silent=args.silent, no_color=args.no_color)

    if args.export:
        scanner.export_json(args.export)
    return 0


if __name__ == "__main__":
    sys.exit(main())
