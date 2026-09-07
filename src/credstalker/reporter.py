"""Pretty console reporting + JSON export."""

from __future__ import annotations

from typing import Dict, List

from .patterns import PATTERN_META


def _severity_style(sev: str) -> str:
    return {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "dim",
    }.get(sev, "white")


def print_results(findings: Dict[str, List[dict]], silent: bool = False, no_color: bool = False) -> int:
    """Print findings summary. Returns total count."""
    total = sum(len(v) for v in findings.values())
    if silent:
        return total

    if not findings or total == 0:
        try:
            from rich.console import Console

            if not no_color:
                Console().print("[bold green]✅ No sensitive data found![/bold green]\n")
                return 0
        except Exception:
            pass
        print("\n✅ No sensitive data found!\n")
        return 0

    # Rich table path
    if not no_color:
        try:
            from rich.console import Console
            from rich.table import Table

            console = Console()
            console.print("\n[bold red]🚨 FINDINGS SUMMARY[/bold red]")
            table = Table(show_header=True, header_style="bold cyan")
            table.add_column("#", width=4)
            table.add_column("Type", style="bold")
            table.add_column("Severity")
            table.add_column("Source")
            table.add_column("URL", overflow="fold")
            table.add_column("Match", overflow="fold")

            n = 0
            for kind, items in findings.items():
                meta = PATTERN_META.get(kind, {})
                label = meta.get("label", kind.upper())
                sev = meta.get("severity", "-")
                for f in items:
                    n += 1
                    table.add_row(
                        str(n),
                        label,
                        f"[{_severity_style(sev)}]{sev}[/{_severity_style(sev)}]",
                        f.get("source", "-"),
                        f.get("url", "-"),
                        (f.get("match", "")[:120]),
                    )
            console.print(table)
            console.print(f"[bold]📊 Total findings: {total}[/bold]\n")
            return total
        except Exception:
            pass

    # Plain fallback
    print(f"\n{'=' * 60}")
    print("🚨 FINDINGS SUMMARY")
    print(f"{'=' * 60}\n")
    n = 0
    for kind, items in findings.items():
        if not items:
            continue
        print(f"\n📌 {kind.upper()} ({len(items)} found):")
        print(f"   {'-' * 56}")
        for i, f in enumerate(items, 1):
            n += 1
            print(f"\n   [{n}] URL: {f['url']}")
            print(f"       Source: {f['source']}")
            print(f"       Match: {f['match'][:120]}")
    print(f"\n{'=' * 60}")
    print(f"📊 Total findings: {total}")
    print(f"{'=' * 60}\n")
    return total
