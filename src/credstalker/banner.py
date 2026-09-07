"""CredStalker banner — Rich-first with ANSI fallback."""

from __future__ import annotations

VERSION = "2.0.0"

ASCII_LOGO = r"""
   ____              _ ____  _        _ _
  / ___|_ __ ___  __| / ___|| |_ __ _| | | _____ _ __
 | |   | '__/ _ \/ _` \___ \| __/ _` | | |/ / _ \ '__|
 | |___| | |  __/ (_| |___) | || (_| | |   <  __/ |
  \____|_|  \___|\__,_|____/ \__\__,_|_|_|\_\___|_|
""".rstrip("\n")

TAGLINE = "Hunt exposed credentials before attackers do."
FIND_LINE = "API Keys  •  Passwords  •  Tokens  •  Private Keys  •  DB URLs  •  Webhooks"
AUTHOR_LINE = "by Mr-Destroyer  •  github.com/Mr-Destroyer  •  v{version}".format(version=VERSION)


def _plain_banner() -> str:
    bar = "═" * 68
    return (
        f"{ASCII_LOGO}\n"
        f"  {TAGLINE}\n"
        f"  {FIND_LINE}\n"
        f"  {bar}\n"
        f"  {AUTHOR_LINE}\n"
    )


def print_banner(no_color: bool = False) -> None:
    """Print the CredStalker banner.

    Uses Rich Panel when available, otherwise plain ANSI.
    Never raises — banner must never crash a scan.
    """
    try:
        if no_color:
            print(_plain_banner())
            return

        try:
            from rich.console import Console
            from rich.panel import Panel
            from rich.text import Text

            console = Console()
            body = Text()
            body.append(ASCII_LOGO + "\n", style="bold cyan")
            body.append(TAGLINE + "\n", style="bold white")
            body.append(FIND_LINE + "\n", style="magenta")
            body.append(AUTHOR_LINE, style="dim")
            console.print(
                Panel(
                    body,
                    title="[bold red]◉ CredStalker[/bold red]",
                    subtitle=f"[dim]v{VERSION}[/dim]",
                    border_style="cyan",
                    expand=False,
                )
            )
            return
        except Exception:
            pass

        # ANSI fallback
        CYAN = "\033[96m"
        MAGENTA = "\033[95m"
        DIM = "\033[2m"
        BOLD = "\033[1m"
        RESET = "\033[0m"
        print(f"{CYAN}{BOLD}{ASCII_LOGO}{RESET}")
        print(f"  {BOLD}{TAGLINE}{RESET}")
        print(f"  {MAGENTA}{FIND_LINE}{RESET}")
        print(f"  {DIM}{AUTHOR_LINE}{RESET}")
    except Exception:
        # absolute last resort
        print("CredStalker v%s" % VERSION)
