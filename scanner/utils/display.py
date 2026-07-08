from __future__ import annotations
"""
scanner/utils/display.py
-------------------------
All terminal output lives here — keeps every other module clean.

Uses the `rich` library for:
  - Coloured, severity-coded finding banners
  - A live progress bar during crawling / testing
  - A clean summary table at scan end
  - Status spinners during long operations

Import pattern:
    from scanner.utils.display import console, print_finding, print_banner, ...
"""

import threading
import time

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.progress import (
    Progress,
    SpinnerColumn,
    BarColumn,
    TextColumn,
    TimeElapsedColumn,
    TaskProgressColumn,
)
from rich.rule import Rule
from rich.style import Style
from rich import box

from scanner.reporting.models import Finding, ScanSummary, Severity

# ---------------------------------------------------------------------------
# Shared console — import this everywhere that needs to print
# ---------------------------------------------------------------------------
console = Console(highlight=False)

# ---------------------------------------------------------------------------
# Severity → Rich style mapping
# ---------------------------------------------------------------------------
_SEV_STYLE: dict[str, str] = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH:     "bold red",
    Severity.MEDIUM:   "bold yellow",
    Severity.LOW:      "bold cyan",
}

_SEV_ICON: dict[str, str] = {
    Severity.CRITICAL: "!!",
    Severity.HIGH:     " !",
    Severity.MEDIUM:   " ~",
    Severity.LOW:      " i",
}


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

BANNER = r"""

        ██╗    ██╗ ██████╗ ██████╗ ███████╗██████╗  ██╗██████╗ ██████╗ ██████╗
        ██║    ██║ ╚════██╗██╔══██╗██╔════╝██╔══██╗███║██╔══██╗╚════██╗██╔══██╗
        ██║ █╗ ██║  █████╔╝██████╔╝███████╗██████╔╝╚██║██║  ██║ █████╔╝██████╔╝
        ██║███╗██║  ╚═══██╗██╔══██╗╚════██║██╔═══╝  ██║██║  ██║ ╚═══██╗██╔══██╗
        ╚███╔███╔╝ ██████╔╝██████╔╝███████║██║      ██║██████╔╝██████╔╝██║  ██║
         ╚══╝╚══╝  ╚═════╝ ╚═════╝ ╚══════╝╚═╝      ╚═╝╚═════╝ ╚═════╝ ╚═╝  ╚═╝

                    ─── Web Vulnerability Scanner ───
"""

def print_banner(version: str = "3.0.0-beta") -> None:
    """Print the scanner ASCII banner and ethical warning."""
    console.print(BANNER, style="bold red")
    console.print(
        Panel(
            "[bold red]AUTHORISED TESTING ONLY[/bold red]\n"
            "This tool is for [bold]educational use only[/bold] against applications "
            "you [underline]own or have explicit written permission[/underline] to test.\n"
            "Unauthorised scanning is [bold red]illegal[/bold red] under the Computer "
            "Fraud and Abuse Act (CFAA) and equivalent laws worldwide.\n"
            "[dim]I AM NOT RESPONSIBLE FOR ANYONE USING THIS APP. "
            "by S1YOL.[/dim]",
            title=f"[bold red]W3BSP1D3R[/bold red] [white]v{version}[/white]",
            border_style="red",
            expand=False,
        )
    )
    console.print()


# ---------------------------------------------------------------------------
# Scan lifecycle messages
# ---------------------------------------------------------------------------

def print_scan_start(url: str, scan_type: str, authenticated: bool) -> None:
    console.print(Rule(f"[bold]Starting {scan_type.upper()} scan", style="red"))
    console.print(f"  [bold]Target:[/bold]        {url}")
    console.print(f"  [bold]Scan type:[/bold]     {scan_type}")
    console.print(f"  [bold]Authenticated:[/bold] {'[green]Yes[/green]' if authenticated else '[yellow]No[/yellow]'}")
    console.print()


def print_phase(phase_name: str) -> None:
    """Announce a new scan phase (crawl, SQLi, XSS, etc.)."""
    console.print(Rule(f"[bold white]{phase_name}[/bold white]", style="red"))


def print_status(msg: str) -> None:
    console.print(f"  [dim]→[/dim] {msg}")


def print_info(msg: str) -> None:
    console.print(f"  [bold white][INFO][/bold white] {msg}")


def print_success(msg: str) -> None:
    console.print(f"  [bold green][OK][/bold green]  {msg}")


def print_warning(msg: str) -> None:
    console.print(f"  [bold yellow][WARN][/bold yellow] {msg}")


def print_error(msg: str) -> None:
    console.print(f"  [bold red][ERR][/bold red]  {msg}")


# ---------------------------------------------------------------------------
# Finding display
# ---------------------------------------------------------------------------

def print_finding(finding: Finding) -> None:
    """
    Print a colour-coded vulnerability finding panel to the terminal.

    Structured so the reader sees: WHAT → WHERE → PROOF → FIX
    """
    style = _SEV_STYLE.get(finding.severity, "white")
    icon  = _SEV_ICON.get(finding.severity, " ?")

    title = Text()
    title.append(f"[{icon}] ", style=style)
    title.append(finding.vuln_type, style="bold")
    title.append(f" — {finding.severity}", style=style)

    body = (
        f"[bold]URL:[/bold]         {finding.url}\n"
        f"[bold]Parameter:[/bold]   {finding.parameter}\n"
        f"[bold]Method:[/bold]      {finding.method}\n"
        f"[bold]Payload:[/bold]     [italic yellow]{finding.payload}[/italic yellow]\n"
        f"[bold]Evidence:[/bold]    [dim]{finding.evidence[:200]}[/dim]\n"
        f"[bold]Remediation:[/bold] [green]{finding.remediation}[/green]"
    )

    console.print(
        Panel(
            body,
            title=title,
            border_style=_SEV_STYLE.get(finding.severity, "white").split()[-1],
            expand=False,
            padding=(0, 1),
        )
    )


# ---------------------------------------------------------------------------
# Summary table
# ---------------------------------------------------------------------------

def print_summary(summary: ScanSummary) -> None:
    """Print the final scan summary table."""
    console.print()
    console.print(Rule("[bold]Scan Complete — Summary[/bold]", style="red"))
    console.print()

    # Stats grid
    stats = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    stats.add_column("Key",   style="bold")
    stats.add_column("Value", style="white")

    stats.add_row("Target URL",    summary.target_url)
    stats.add_row("Scan Type",     summary.scan_type)
    stats.add_row("Started",       summary.started_at)
    stats.add_row("Finished",      summary.finished_at)
    stats.add_row("Pages Crawled", str(summary.pages_crawled))
    stats.add_row("Forms Found",   str(summary.forms_found))
    stats.add_row("Params Tested", str(summary.params_tested))
    console.print(stats)

    # Findings breakdown
    findings_table = Table(
        title="Vulnerability Findings",
        box=box.ROUNDED,
        show_lines=True,
        title_style="bold",
    )
    findings_table.add_column("Severity",   style="bold", width=10)
    findings_table.add_column("Count",      justify="center", width=7)
    findings_table.add_column("Bar",        width=30)

    breakdown = [
        (Severity.CRITICAL, summary.critical_count, "bold white on red"),
        (Severity.HIGH,     summary.high_count,     "bold red"),
        (Severity.MEDIUM,   summary.medium_count,   "bold yellow"),
        (Severity.LOW,      summary.low_count,      "bold cyan"),
    ]
    for sev, count, style in breakdown:
        bar = "█" * min(count * 3, 30)
        findings_table.add_row(
            Text(sev, style=style),
            Text(str(count), style=style, justify="center"),
            Text(bar, style=style),
        )
    console.print(findings_table)
    console.print()

    if summary.total_findings == 0:
        console.print("  [bold green]No vulnerabilities found.[/bold green]")
    else:
        console.print(
            f"  [bold]Total findings:[/bold] "
            f"[bold red]{summary.total_findings}[/bold red] "
            f"(Critical: {summary.critical_count}, "
            f"High: {summary.high_count}, "
            f"Medium: {summary.medium_count}, "
            f"Low: {summary.low_count})"
        )
    console.print()


# ---------------------------------------------------------------------------
# Progress bar factory
# ---------------------------------------------------------------------------

def make_progress() -> Progress:
    """
    Create a reusable Rich Progress bar for crawling / testing loops.

    Usage:
        with make_progress() as progress:
            task = progress.add_task("Crawling...", total=100)
            for item in items:
                progress.advance(task)
    """
    return Progress(
        SpinnerColumn(),
        TextColumn("[bold red]{task.description}[/bold red]"),
        BarColumn(bar_width=40),
        TaskProgressColumn(),
        TextColumn("[dim]{task.fields[status]}[/dim]"),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    )


# ---------------------------------------------------------------------------
# Rate limit dashboard — live terminal UI showing HTTP metrics
# ---------------------------------------------------------------------------

class RateLimitDashboard:
    """
    Live terminal dashboard showing real-time HTTP request metrics.

    Displays:
      - Total / successful / failed / retried request counts
      - Current adaptive delay and effective throughput
      - Rate-limited (429) count
      - Bytes transferred
      - Average response time
      - Visual throughput bar

    Usage:
        dashboard = RateLimitDashboard()
        dashboard.start()
        # ... scan runs ...
        dashboard.stop()

    Or as a context manager:
        with RateLimitDashboard():
            # ... scan runs ...
    """

    def __init__(self, refresh_rate: float = 0.5) -> None:
        self._refresh_rate = refresh_rate
        self._live: Live | None = None
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._start_time = 0.0
        self._extra_info: dict[str, str] = {}

    def start(self) -> None:
        """Start the live dashboard in a background thread."""
        self._start_time = time.monotonic()
        self._stop_event.clear()
        self._live = Live(
            self._build_display(),
            console=console,
            refresh_per_second=2,
            transient=True,
        )
        self._live.start()
        self._thread = threading.Thread(target=self._update_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop the dashboard and print a final static snapshot."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=2)
        if self._live:
            self._live.stop()
            self._live = None
        # Print final snapshot
        console.print(self._build_display())

    def set_info(self, key: str, value: str) -> None:
        """Set extra info to display (e.g. current phase, active testers)."""
        self._extra_info[key] = value

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *args):
        self.stop()

    def _update_loop(self) -> None:
        while not self._stop_event.is_set():
            if self._live:
                try:
                    self._live.update(self._build_display())
                except Exception:
                    pass
            time.sleep(self._refresh_rate)

    def _build_display(self) -> Panel:
        from scanner.utils.http import get_metrics, _get_effective_delay, _delay, _adaptive_delay

        m = get_metrics()
        elapsed = time.monotonic() - self._start_time if self._start_time else 0
        rps = m["total_requests"] / max(elapsed, 0.01)

        # Main metrics table
        tbl = Table(box=box.SIMPLE, show_header=False, padding=(0, 2), expand=True)
        tbl.add_column("Metric", style="bold", width=20)
        tbl.add_column("Value", width=15)
        tbl.add_column("Metric", style="bold", width=20)
        tbl.add_column("Value", width=15)

        tbl.add_row(
            "Requests",  f"[white]{m['total_requests']}[/white]",
            "Successful", f"[green]{m['successful']}[/green]",
        )
        tbl.add_row(
            "Failed",    f"[red]{m['failed']}[/red]",
            "Retried",   f"[yellow]{m['retried']}[/yellow]",
        )
        tbl.add_row(
            "Rate Limited", f"[bold yellow]{m['rate_limited']}[/bold yellow]",
            "Avg Response",  f"[cyan]{m['avg_response_time']:.3f}s[/cyan]",
        )

        # Throughput and delay row
        try:
            effective = _get_effective_delay()
            adapt = _adaptive_delay
        except Exception:
            effective = 0
            adapt = 0

        tbl.add_row(
            "Throughput",   f"[bold white]{rps:.1f} req/s[/bold white]",
            "Data Received", _format_bytes(m["total_bytes"]),
        )
        tbl.add_row(
            "Base Delay",   f"[dim]{_delay:.2f}s[/dim]",
            "Adaptive +",    f"[{'bold yellow' if adapt > 0 else 'dim'}]{adapt:.2f}s[/{'bold yellow' if adapt > 0 else 'dim'}]",
        )

        # Throughput bar
        bar_width = 40
        bar_fill = min(int(rps * 4), bar_width)  # Scale: 10 rps = full bar
        bar = "[green]" + "█" * bar_fill + "[/green]" + "[dim]░[/dim]" * (bar_width - bar_fill)
        throughput_line = f"  Throughput  {bar}  {rps:.1f}/s"

        # Extra info
        extra_lines = ""
        for key, val in self._extra_info.items():
            extra_lines += f"\n  [dim]{key}:[/dim] {val}"

        content = Text.from_markup(f"{throughput_line}{extra_lines}")

        inner = Table.grid(expand=True)
        inner.add_row(tbl)
        inner.add_row(content)

        return Panel(
            inner,
            title="[bold red]HTTP Rate Limit Dashboard[/bold red]",
            border_style="red",
            expand=True,
            padding=(0, 1),
        )


def _format_bytes(n: int) -> str:
    """Format bytes into human-readable string."""
    for unit in ("B", "KB", "MB", "GB"):
        if abs(n) < 1024:
            return f"[cyan]{n:.1f} {unit}[/cyan]"
        n /= 1024
    return f"[cyan]{n:.1f} TB[/cyan]"
