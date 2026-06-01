"""
Terminal Dashboard — live threat display using Rich.
Shows a running table of every scan with colour-coded risk levels.
"""

from __future__ import annotations
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.panel import Panel
from rich import box

from guardlayer.models import RiskLevel, ScanResult, SessionRecord

console = Console()

# Colour mapping for each risk level
RISK_COLOURS: dict[RiskLevel, str] = {
    RiskLevel.SAFE: "green",
    RiskLevel.SUSPICIOUS: "yellow",
    RiskLevel.BLOCKED: "red",
}


def _risk_text(level: RiskLevel, score: int) -> Text:
    """Build a coloured Rich Text object showing risk level and score."""
    colour = RISK_COLOURS[level]
    return Text(f"{level.value} ({score})", style=f"bold {colour}")


def print_banner() -> None:
    """Print the GuardLayer startup banner."""
    console.print(Panel(
        "[bold cyan]GuardLayer[/bold cyan] — AI Security Firewall\n"
        "[dim]Scanning all prompts and responses in real time[/dim]",
        box=box.DOUBLE_EDGE,
        border_style="cyan",
    ))


def print_scan_result(record: SessionRecord) -> None:
    """Print a single scan result row to the terminal."""
    req_scan = record.request_scan
    timestamp = record.timestamp.strftime("%H:%M:%S")

    # Build the threat summary string
    if req_scan.findings:
        threat_names = ", ".join(f.category.value for f in req_scan.findings[:2])
        if len(req_scan.findings) > 2:
            threat_names += f" +{len(req_scan.findings) - 2} more"
    else:
        threat_names = "—"

    status_icon = "🚫" if record.was_blocked else ("⚠️ " if req_scan.highest_score > 30 else "✅")

    console.print(
        f"[dim]{timestamp}[/dim]  "
        f"{status_icon}  "
        f"{_risk_text(req_scan.overall_risk_level, req_scan.highest_score)}  "
        f"[dim]{threat_names}[/dim]"
    )

    # Print each finding's explanation on a new line
    for finding in req_scan.findings:
        colour = RISK_COLOURS[finding.risk_level]
        console.print(
            f"  [dim]↳[/dim] [{colour}]{finding.category.value}[/{colour}]: "
            f"[dim]{finding.explanation[:120]}[/dim]"
        )


def print_session_summary(total: int, blocked: int) -> None:
    """Print end-of-session stats."""
    safe = total - blocked
    console.print()
    console.print(Panel(
        f"[bold]Session complete[/bold]\n"
        f"Total requests: [cyan]{total}[/cyan]  |  "
        f"Blocked: [red]{blocked}[/red]  |  "
        f"Passed: [green]{safe}[/green]",
        border_style="dim",
    ))


def build_summary_table(records: list[SessionRecord]) -> Table:
    """Build a Rich Table summarising all session records."""
    table = Table(
        title="GuardLayer — Session Threat Log",
        box=box.ROUNDED,
        show_lines=True,
        header_style="bold cyan",
    )
    table.add_column("Time", style="dim", width=10)
    table.add_column("Status", width=10)
    table.add_column("Score", justify="right", width=7)
    table.add_column("Threats Detected", min_width=30)
    table.add_column("Target URL", style="dim", min_width=20)

    for record in records:
        req = record.request_scan
        status = Text("BLOCKED", style="bold red") if record.was_blocked else (
            Text("WARN", style="bold yellow") if req.highest_score > 30 else
            Text("SAFE", style="bold green")
        )
        threat_list = "\n".join(f.category.value for f in req.findings) or "—"
        table.add_row(
            record.timestamp.strftime("%H:%M:%S"),
            status,
            str(req.highest_score),
            threat_list,
            record.target_url,
        )

    return table
