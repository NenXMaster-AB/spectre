"""
SPECTRE CLI Main Entry Point

The main Typer application that assembles all command groups.
"""

import asyncio
from typing import Annotated

import structlog
import typer
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from spectre import __version__

# Configure structlog
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.dev.ConsoleRenderer(colors=True),
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger(__name__)
console = Console()

# Create the main app
app = typer.Typer(
    name="spectre",
    help="SPECTRE - Security Platform for Enrichment, Collection, Threat Research & Evaluation",
    no_args_is_help=True,
    rich_markup_mode="rich",
)


def version_callback(value: bool) -> None:
    """Print version and exit."""
    if value:
        console.print(
            Panel(
                Text.from_markup(
                    f"[bold cyan]SPECTRE[/bold cyan] v{__version__}\n"
                    "[dim]Security Platform for Enrichment, Collection, "
                    "Threat Research & Evaluation[/dim]"
                ),
                title="Version",
                border_style="cyan",
            )
        )
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            "-V",
            help="Show version and exit.",
            callback=version_callback,
            is_eager=True,
        ),
    ] = False,
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose",
            "-v",
            help="Enable verbose output.",
        ),
    ] = False,
) -> None:
    """
    SPECTRE - An Agentic OSINT & Cyber Threat Intelligence Platform

    Use natural language to investigate domains, IPs, and threats.
    SPECTRE autonomously plans and executes multi-step investigations.
    """
    if verbose:
        import logging

        logging.basicConfig(level=logging.DEBUG)


# Import and register sub-commands
from spectre.cli.investigate import app as investigate_app
from spectre.cli.plugins_cmd import app as plugins_app
from spectre.cli.monitor import app as monitor_app

app.add_typer(investigate_app, name="investigate", help="Run OSINT investigations")
app.add_typer(plugins_app, name="plugins", help="Manage plugins")
app.add_typer(monitor_app, name="watch", help="Continuous monitoring with proactive alerts")


# Quick shortcuts for common commands
@app.command()
def scan(
    target: Annotated[str, typer.Argument(help="Target to scan (domain, IP, etc.)")],
    depth: Annotated[
        str,
        typer.Option(
            "--depth",
            "-d",
            help="Scan depth: quick, standard, or full",
        ),
    ] = "standard",
) -> None:
    """
    Quick scan shortcut - alias for 'investigate domain'.

    Example: spectre scan example.com
    """
    from spectre.cli.investigate import domain as investigate_domain

    # Run the async command
    asyncio.run(
        investigate_domain(
            target=target,
            plugins=None,
            output=None,
            json_output=False,
        )
    )


@app.command()
def info() -> None:
    """Show information about SPECTRE."""
    from rich.table import Table

    from spectre.plugins.registry import get_registry

    registry = get_registry()
    plugin_count = len(registry)

    table = Table(title="SPECTRE Information", show_header=False, border_style="cyan")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("Version", __version__)
    table.add_row("Plugins Loaded", str(plugin_count))
    table.add_row("Python", "3.12+")

    console.print(table)


if __name__ == "__main__":
    app()
