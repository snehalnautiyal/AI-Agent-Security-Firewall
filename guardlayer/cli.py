"""
CLI entry points for GuardLayer.
  guardlayer start  — launch the proxy server
  guardlayer report — generate the HTML security report
  guardlayer scan   — scan a single string from the command line
"""

from __future__ import annotations
from pathlib import Path

import typer
import uvicorn

from guardlayer.dashboard import console, print_banner, build_summary_table

app = typer.Typer(
    name="guardlayer",
    help="AI security firewall proxy — scan every prompt and response for threats.",
    add_completion=False,
)


@app.command()
def start(
    host: str = typer.Option("0.0.0.0", help="Host to bind the proxy server to"),
    port: int = typer.Option(8080, help="Port to listen on"),
    target: str = typer.Option(
        "https://api.openai.com",
        envvar="GUARDLAYER_TARGET",
        help="LLM API base URL to forward requests to",
    ),
    no_claude: bool = typer.Option(False, "--no-claude", help="Disable Claude deep analysis (regex only)"),
) -> None:
    """Start the GuardLayer proxy server."""
    import os
    os.environ["GUARDLAYER_TARGET"] = target

    if no_claude:
        os.environ["GUARDLAYER_NO_CLAUDE"] = "1"

    print_banner()
    console.print(f"[dim]Target LLM API: {target}[/dim]")
    console.print(f"[dim]Claude analysis: {'disabled' if no_claude else 'enabled (set ANTHROPIC_API_KEY)'}[/dim]\n")

    uvicorn.run(
        "guardlayer.proxy:app",
        host=host,
        port=port,
        log_level="warning",  # suppress uvicorn noise; GuardLayer has its own output
    )


@app.command()
def report(
    output: Path = typer.Option(
        Path("guardlayer-report.html"),
        "--output", "-o",
        help="Path to write the HTML report",
    ),
) -> None:
    """Generate an HTML security report from the current session."""
    from guardlayer.report import generate_report
    from guardlayer.session_store import store

    records = store.all_records()
    if not records:
        console.print("[yellow]No session data found. Start the proxy and send some requests first.[/yellow]")
        raise typer.Exit(1)

    output_path = generate_report(store, output)
    console.print(f"[green]✓[/green] Report written to [cyan]{output_path}[/cyan]")
    console.print(f"  {len(records)} requests  ·  {store.blocked_count()} blocked")


@app.command()
def scan_text(
    text: str = typer.Argument(..., help="Text to scan for threats"),
    no_claude: bool = typer.Option(False, "--no-claude", help="Regex only, no Claude API call"),
) -> None:
    """Scan a single piece of text for threats (useful for testing)."""
    from guardlayer.scanner import scan
    from guardlayer.dashboard import RISK_COLOURS
    from rich.panel import Panel

    result = scan(text, use_claude=not no_claude)

    if not result.findings:
        console.print("[green]✓ No threats detected[/green]")
        return

    for finding in result.findings:
        colour = RISK_COLOURS[finding.risk_level]
        console.print(Panel(
            f"[bold]{finding.explanation}[/bold]\n\n"
            f"[dim]Recommendation:[/dim] {finding.recommendation}",
            title=f"[{colour}]{finding.category.value} — score {finding.risk_score}[/{colour}]",
            border_style=colour,
        ))


if __name__ == "__main__":
    app()
