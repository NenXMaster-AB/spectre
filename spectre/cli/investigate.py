"""
Investigation CLI Commands

Commands for running OSINT investigations against targets.
"""

import asyncio
import json
import time
from pathlib import Path
from typing import Annotated

import structlog
import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from spectre.models.entities import Domain, IPAddress
from spectre.plugins.base import EntityType, PluginConfig, PluginResult
from spectre.plugins.registry import PluginNotFoundError, get_registry

logger = structlog.get_logger(__name__)
console = Console()

app = typer.Typer(
    name="investigate",
    help="Run OSINT investigations against targets",
    no_args_is_help=True,
)


def detect_entity_type(target: str) -> EntityType:
    """Detect the entity type from the target string."""
    import re
    from ipaddress import IPv4Address, IPv6Address

    # Check if it's an IP address
    try:
        IPv4Address(target)
        return EntityType.IP_ADDRESS
    except ValueError:
        pass

    try:
        IPv6Address(target)
        return EntityType.IP_ADDRESS
    except ValueError:
        pass

    # Check if it's an email
    if re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", target):
        return EntityType.EMAIL

    # Check if it looks like a hash
    if re.match(r"^[a-fA-F0-9]{32}$", target):  # MD5
        return EntityType.HASH
    if re.match(r"^[a-fA-F0-9]{40}$", target):  # SHA1
        return EntityType.HASH
    if re.match(r"^[a-fA-F0-9]{64}$", target):  # SHA256
        return EntityType.HASH

    # Default to domain
    return EntityType.DOMAIN


def display_result(result: PluginResult) -> None:
    """Display a plugin result in a formatted way."""
    if result.success:
        status = "[green]SUCCESS[/green]"
    else:
        status = "[red]FAILED[/red]"

    console.print(
        Panel(
            f"Plugin: [cyan]{result.plugin_name}[/cyan]\n"
            f"Status: {status}\n"
            f"Execution Time: {result.execution_time_ms:.2f}ms\n"
            f"Findings: {len(result.findings)}\n"
            f"Entities Discovered: {len(result.entities_discovered)}",
            title=f"Result: {result.plugin_name}",
            border_style="green" if result.success else "red",
        )
    )

    if result.error:
        console.print(f"[red]Error:[/red] {result.error}")

    # Display findings
    if result.findings:
        table = Table(title="Findings", show_header=True, header_style="bold cyan")
        table.add_column("Type", style="cyan")
        table.add_column("Data", style="white")
        table.add_column("Confidence", style="yellow")

        for finding in result.findings:
            # Format data for display
            data_str = json.dumps(finding.data, indent=2, default=str)
            if len(data_str) > 100:
                data_str = data_str[:100] + "..."
            table.add_row(
                finding.type,
                data_str,
                f"{finding.confidence:.2f}",
            )

        console.print(table)

    # Display discovered entities
    if result.entities_discovered:
        console.print("\n[bold]Discovered Entities:[/bold]")
        for entity in result.entities_discovered:
            entity_type = entity.get("type", "unknown")
            entity_value = entity.get("value", str(entity))
            console.print(f"  - [{entity_type}] {entity_value}")


async def run_investigation(
    target: str,
    entity_type: EntityType,
    plugin_names: list[str] | None = None,
    config: PluginConfig | None = None,
) -> list[PluginResult]:
    """Run an investigation against a target."""
    registry = get_registry()
    results: list[PluginResult] = []

    # Build the entity dict
    entity = {"type": entity_type.value, "value": target}

    # Get plugins to run
    if plugin_names:
        plugins_to_run = []
        for name in plugin_names:
            try:
                plugin = registry.get_plugin(name)
                plugins_to_run.append(plugin)
            except PluginNotFoundError:
                console.print(f"[yellow]Warning:[/yellow] Plugin '{name}' not found, skipping")
    else:
        # Get all plugins that accept this entity type
        plugins_to_run = registry.get_plugins_for_entity(entity_type)

    if not plugins_to_run:
        console.print("[yellow]No plugins available for this entity type[/yellow]")
        return results

    # Run plugins
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        for plugin in plugins_to_run:
            task_id = progress.add_task(f"Running {plugin.name}...", total=None)

            try:
                start_time = time.time()
                result = await plugin.execute(entity, config)
                result.execution_time_ms = (time.time() - start_time) * 1000
                results.append(result)
            except Exception as e:
                logger.error("Plugin execution failed", plugin=plugin.name, error=str(e))
                results.append(
                    PluginResult(
                        success=False,
                        plugin_name=plugin.name,
                        input_entity=entity,
                        error=str(e),
                    )
                )

            progress.remove_task(task_id)

    return results


@app.command()
def domain(
    target: Annotated[str, typer.Argument(help="Domain to investigate")],
    plugins: Annotated[
        str | None,
        typer.Option(
            "--plugins",
            "-p",
            help="Comma-separated list of plugins to run (default: all applicable)",
        ),
    ] = None,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Output file path for results",
        ),
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option(
            "--json",
            "-j",
            help="Output results as JSON",
        ),
    ] = False,
) -> None:
    """
    Investigate a domain.

    Runs OSINT reconnaissance including DNS enumeration, WHOIS lookup,
    and other applicable plugins.

    Example:
        spectre investigate domain example.com
        spectre investigate domain example.com --plugins dns_recon,whois_lookup
    """
    console.print(
        Panel(
            f"[bold]Investigating domain:[/bold] [cyan]{target}[/cyan]",
            title="SPECTRE Investigation",
            border_style="cyan",
        )
    )

    # Parse plugin list
    plugin_list = None
    if plugins:
        plugin_list = [p.strip() for p in plugins.split(",")]

    # Run the investigation
    results = asyncio.run(
        run_investigation(
            target=target,
            entity_type=EntityType.DOMAIN,
            plugin_names=plugin_list,
        )
    )

    # Display results
    if json_output:
        output_data = [
            {
                "plugin": r.plugin_name,
                "success": r.success,
                "findings": [f.model_dump() for f in r.findings],
                "entities_discovered": r.entities_discovered,
                "error": r.error,
                "execution_time_ms": r.execution_time_ms,
            }
            for r in results
        ]
        if output:
            output.write_text(json.dumps(output_data, indent=2, default=str))
            console.print(f"[green]Results saved to {output}[/green]")
        else:
            console.print_json(json.dumps(output_data, default=str))
    else:
        for result in results:
            display_result(result)
            console.print()

        # Summary
        successful = sum(1 for r in results if r.success)
        total_findings = sum(len(r.findings) for r in results)
        total_entities = sum(len(r.entities_discovered) for r in results)

        console.print(
            Panel(
                f"Plugins Run: {len(results)} ({successful} successful)\n"
                f"Total Findings: {total_findings}\n"
                f"Entities Discovered: {total_entities}",
                title="Investigation Summary",
                border_style="cyan",
            )
        )

        if output:
            output_data = [r.model_dump() for r in results]
            output.write_text(json.dumps(output_data, indent=2, default=str))
            console.print(f"[green]Results saved to {output}[/green]")


@app.command()
def ip(
    target: Annotated[str, typer.Argument(help="IP address to investigate")],
    plugins: Annotated[
        str | None,
        typer.Option(
            "--plugins",
            "-p",
            help="Comma-separated list of plugins to run",
        ),
    ] = None,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Output file path for results",
        ),
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option(
            "--json",
            "-j",
            help="Output results as JSON",
        ),
    ] = False,
) -> None:
    """
    Investigate an IP address.

    Example:
        spectre investigate ip 8.8.8.8
    """
    console.print(
        Panel(
            f"[bold]Investigating IP:[/bold] [cyan]{target}[/cyan]",
            title="SPECTRE Investigation",
            border_style="cyan",
        )
    )

    plugin_list = None
    if plugins:
        plugin_list = [p.strip() for p in plugins.split(",")]

    results = asyncio.run(
        run_investigation(
            target=target,
            entity_type=EntityType.IP_ADDRESS,
            plugin_names=plugin_list,
        )
    )

    # Display results (same as domain)
    for result in results:
        display_result(result)
        console.print()


@app.command()
def auto(
    target: Annotated[str, typer.Argument(help="Target to investigate (auto-detected)")],
    plugins: Annotated[
        str | None,
        typer.Option(
            "--plugins",
            "-p",
            help="Comma-separated list of plugins to run",
        ),
    ] = None,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Output file path for results",
        ),
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option(
            "--json",
            "-j",
            help="Output results as JSON",
        ),
    ] = False,
) -> None:
    """
    Auto-detect target type and investigate.

    SPECTRE will automatically determine if the target is a domain,
    IP address, email, or hash.

    Example:
        spectre investigate auto example.com
        spectre investigate auto 8.8.8.8
        spectre investigate auto user@example.com
    """
    entity_type = detect_entity_type(target)
    console.print(f"[dim]Detected entity type: {entity_type.value}[/dim]")

    plugin_list = None
    if plugins:
        plugin_list = [p.strip() for p in plugins.split(",")]

    console.print(
        Panel(
            f"[bold]Investigating:[/bold] [cyan]{target}[/cyan]\n"
            f"[dim]Type: {entity_type.value}[/dim]",
            title="SPECTRE Investigation",
            border_style="cyan",
        )
    )

    results = asyncio.run(
        run_investigation(
            target=target,
            entity_type=entity_type,
            plugin_names=plugin_list,
        )
    )

    for result in results:
        display_result(result)
        console.print()
