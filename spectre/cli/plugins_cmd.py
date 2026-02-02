"""
Plugin Management CLI Commands

Commands for listing, inspecting, and managing plugins.
"""

import asyncio
from typing import Annotated

import structlog
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from spectre.plugins.base import PluginCategory
from spectre.plugins.registry import PluginNotFoundError, get_registry

logger = structlog.get_logger(__name__)
console = Console()

app = typer.Typer(
    name="plugins",
    help="Manage SPECTRE plugins",
    no_args_is_help=True,
)


@app.command("list")
def list_plugins(
    category: Annotated[
        str | None,
        typer.Option(
            "--category",
            "-c",
            help="Filter by category: osint, threat_intel, adversary, custom",
        ),
    ] = None,
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose",
            "-v",
            help="Show detailed plugin information",
        ),
    ] = False,
) -> None:
    """
    List all available plugins.

    Example:
        spectre plugins list
        spectre plugins list --category osint
        spectre plugins list -v
    """
    registry = get_registry()

    # Filter by category if specified
    if category:
        try:
            cat_enum = PluginCategory(category.lower())
            plugins = registry.get_plugins_by_category(cat_enum)
        except ValueError:
            console.print(f"[red]Invalid category:[/red] {category}")
            console.print("Valid categories: osint, threat_intel, adversary, custom")
            raise typer.Exit(1)
    else:
        plugins = registry.list_plugins()

    if not plugins:
        console.print("[yellow]No plugins found[/yellow]")
        if category:
            console.print(f"[dim]Try running without --category filter[/dim]")
        return

    # Create table
    table = Table(
        title=f"SPECTRE Plugins ({len(plugins)} total)",
        show_header=True,
        header_style="bold cyan",
    )

    table.add_column("Name", style="cyan", no_wrap=True)
    table.add_column("Category", style="magenta")
    table.add_column("Description", style="white")

    if verbose:
        table.add_column("Input Types", style="green")
        table.add_column("Output Types", style="yellow")

    for plugin in plugins:
        row = [
            plugin.name,
            plugin.category.value,
            plugin.description[:50] + "..." if len(plugin.description) > 50 else plugin.description,
        ]

        if verbose:
            row.append(", ".join(t.value for t in plugin.input_types))
            row.append(", ".join(t.value for t in plugin.output_types))

        table.add_row(*row)

    console.print(table)


@app.command("info")
def plugin_info(
    name: Annotated[str, typer.Argument(help="Plugin name to inspect")],
) -> None:
    """
    Show detailed information about a plugin.

    Example:
        spectre plugins info dns_recon
    """
    registry = get_registry()

    try:
        plugin = registry.get_plugin(name)
    except PluginNotFoundError:
        console.print(f"[red]Plugin not found:[/red] {name}")
        console.print("\n[dim]Available plugins:[/dim]")
        for p in registry.list_plugins():
            console.print(f"  - {p.name}")
        raise typer.Exit(1)

    info = plugin.get_info()

    # Build info panel
    info_text = (
        f"[bold cyan]Name:[/bold cyan] {info['name']}\n"
        f"[bold cyan]Category:[/bold cyan] {info['category']}\n"
        f"[bold cyan]Description:[/bold cyan] {info['description']}\n\n"
        f"[bold green]Input Types:[/bold green] {', '.join(info['input_types'])}\n"
        f"[bold yellow]Output Types:[/bold yellow] {', '.join(info['output_types'])}\n"
    )

    if info.get("required_config"):
        info_text += f"\n[bold red]Required Config:[/bold red] {', '.join(info['required_config'])}"

    if info.get("rate_limit"):
        rl = info["rate_limit"]
        info_text += (
            f"\n\n[bold]Rate Limits:[/bold]\n"
            f"  Requests/minute: {rl['requests_per_minute']}\n"
            f"  Requests/day: {rl['requests_per_day'] or 'unlimited'}\n"
            f"  Concurrent: {rl['concurrent_requests']}"
        )

    console.print(
        Panel(
            info_text,
            title=f"Plugin: {name}",
            border_style="cyan",
        )
    )


@app.command("health")
def check_health(
    name: Annotated[
        str | None,
        typer.Argument(help="Plugin name to check (default: all)"),
    ] = None,
) -> None:
    """
    Check plugin health status.

    Example:
        spectre plugins health
        spectre plugins health dns_recon
    """
    registry = get_registry()

    async def _check_health() -> dict[str, bool]:
        if name:
            try:
                result = await registry.check_plugin_health(name)
                return {name: result}
            except PluginNotFoundError:
                console.print(f"[red]Plugin not found:[/red] {name}")
                raise typer.Exit(1)
        else:
            return await registry.check_all_health()

    results = asyncio.run(_check_health())

    # Create table
    table = Table(
        title="Plugin Health Status",
        show_header=True,
        header_style="bold cyan",
    )

    table.add_column("Plugin", style="cyan")
    table.add_column("Status", style="white")

    for plugin_name, healthy in results.items():
        status = "[green]Healthy[/green]" if healthy else "[red]Unhealthy[/red]"
        table.add_row(plugin_name, status)

    console.print(table)

    # Summary
    healthy_count = sum(1 for h in results.values() if h)
    total_count = len(results)

    if healthy_count == total_count:
        console.print(f"\n[green]All {total_count} plugins healthy[/green]")
    else:
        console.print(
            f"\n[yellow]{healthy_count}/{total_count} plugins healthy[/yellow]"
        )


@app.command("run")
def run_plugin(
    name: Annotated[str, typer.Argument(help="Plugin name to run")],
    target: Annotated[str, typer.Argument(help="Target to process")],
    target_type: Annotated[
        str,
        typer.Option(
            "--type",
            "-t",
            help="Entity type: domain, ip_address, email, hash",
        ),
    ] = "domain",
) -> None:
    """
    Run a single plugin against a target.

    Example:
        spectre plugins run dns_recon example.com
        spectre plugins run dns_recon example.com --type domain
    """
    from spectre.cli.investigate import display_result, run_investigation
    from spectre.plugins.base import EntityType

    try:
        entity_type = EntityType(target_type)
    except ValueError:
        console.print(f"[red]Invalid entity type:[/red] {target_type}")
        console.print("Valid types: domain, ip_address, email, hash")
        raise typer.Exit(1)

    console.print(
        Panel(
            f"[bold]Running plugin:[/bold] [cyan]{name}[/cyan]\n"
            f"[bold]Target:[/bold] {target}\n"
            f"[bold]Type:[/bold] {target_type}",
            title="Plugin Execution",
            border_style="cyan",
        )
    )

    results = asyncio.run(
        run_investigation(
            target=target,
            entity_type=entity_type,
            plugin_names=[name],
        )
    )

    for result in results:
        display_result(result)
