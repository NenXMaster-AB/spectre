"""
Campaign CLI Commands

Commands for tracking and managing threat campaigns.
"""

from __future__ import annotations

import asyncio
from typing import Annotated

import structlog
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from spectre.adversary.campaign_tracker import (
    Campaign,
    CampaignStatus,
    CampaignSource,
    CampaignIOC,
    get_campaign_tracker,
)

logger = structlog.get_logger(__name__)
console = Console()

app = typer.Typer(
    name="campaign",
    help="Track and monitor threat campaigns",
    no_args_is_help=True,
)


@app.command("list")
def list_campaigns(
    status: Annotated[
        str,
        typer.Option("--status", "-s", help="Filter by status: active, dormant, concluded"),
    ] = "",
    tracked: Annotated[
        bool,
        typer.Option("--tracked", "-t", help="Show only tracked campaigns"),
    ] = False,
    actor: Annotated[
        str,
        typer.Option("--actor", "-a", help="Filter by attributed actor"),
    ] = "",
) -> None:
    """
    List known threat campaigns.

    Example:
        spectre campaign list
        spectre campaign list --status active
        spectre campaign list --actor APT29
    """
    tracker = get_campaign_tracker()

    # Parse status filter
    status_filter = None
    if status:
        try:
            status_filter = CampaignStatus(status)
        except ValueError:
            console.print(f"[red]Invalid status: {status}[/red]")
            console.print(f"Valid: {', '.join(s.value for s in CampaignStatus)}")
            raise typer.Exit(1)

    campaigns = tracker.list_campaigns(
        status=status_filter,
        tracked_only=tracked,
        actor=actor if actor else None,
    )

    if not campaigns:
        console.print("[dim]No campaigns found.[/dim]")
        console.print("[dim]Use 'spectre campaign add' to add campaigns or import from threat intel.[/dim]")
        return

    # Build table
    table = Table(title="Threat Campaigns", border_style="cyan")
    table.add_column("Name", style="cyan", width=25)
    table.add_column("Status", justify="center", width=10)
    table.add_column("Actors", width=20)
    table.add_column("IOCs", justify="right", width=6)
    table.add_column("TTPs", justify="right", width=6)
    table.add_column("Tracked", justify="center", width=8)

    for campaign in campaigns:
        status_style = {
            CampaignStatus.ACTIVE: "[green]● active[/green]",
            CampaignStatus.DORMANT: "[yellow]◐ dormant[/yellow]",
            CampaignStatus.CONCLUDED: "[dim]○ ended[/dim]",
            CampaignStatus.UNKNOWN: "[dim]? unknown[/dim]",
        }.get(campaign.status, campaign.status.value)

        tracked_str = "[green]✓[/green]" if campaign.is_tracked else "[dim]-[/dim]"
        actors = ", ".join(campaign.attributed_actors[:2]) or "[dim]unknown[/dim]"
        if len(campaign.attributed_actors) > 2:
            actors += f" +{len(campaign.attributed_actors) - 2}"

        table.add_row(
            campaign.name[:25],
            status_style,
            actors,
            str(campaign.ioc_count),
            str(campaign.ttp_count),
            tracked_str,
        )

    console.print(table)
    console.print(f"\n[dim]Total: {len(campaigns)} campaigns[/dim]")


@app.command("show")
def show_campaign(
    name: Annotated[str, typer.Argument(help="Campaign name or ID")],
) -> None:
    """
    Show details of a specific campaign.

    Example:
        spectre campaign show SolarWinds
        spectre campaign show "Operation Dream Job"
    """
    tracker = get_campaign_tracker()

    # Try by name first, then by ID
    campaign = tracker.get_campaign_by_name(name)
    if not campaign:
        campaign = tracker.get_campaign(name)

    if not campaign:
        console.print(f"[red]Campaign not found: {name}[/red]")
        raise typer.Exit(1)

    # Build display
    status_color = {
        CampaignStatus.ACTIVE: "green",
        CampaignStatus.DORMANT: "yellow",
        CampaignStatus.CONCLUDED: "dim",
    }.get(campaign.status, "white")

    content = Text()
    content.append(f"Name: ", style="cyan")
    content.append(f"{campaign.name}\n")

    if campaign.aliases:
        content.append(f"Aliases: ", style="cyan")
        content.append(f"{', '.join(campaign.aliases)}\n")

    content.append(f"Status: ", style="cyan")
    content.append(f"{campaign.status.value}\n", style=status_color)

    if campaign.attributed_actors:
        content.append(f"\nAttributed Actors: ", style="cyan")
        content.append(f"{', '.join(campaign.attributed_actors)}\n")
        content.append(f"Attribution Confidence: ", style="cyan")
        content.append(f"{campaign.attribution_confidence * 100:.0f}%\n")

    content.append(f"\nIOCs: ", style="cyan")
    content.append(f"{campaign.ioc_count} ({len(campaign.active_iocs)} active)\n")
    content.append(f"TTPs: ", style="cyan")
    content.append(f"{campaign.ttp_count}\n")

    if campaign.target_sectors:
        content.append(f"\nTarget Sectors: ", style="cyan")
        content.append(f"{', '.join(campaign.target_sectors)}\n")

    if campaign.target_regions:
        content.append(f"Target Regions: ", style="cyan")
        content.append(f"{', '.join(campaign.target_regions)}\n")

    if campaign.malware_families:
        content.append(f"\nMalware: ", style="cyan")
        content.append(f"{', '.join(campaign.malware_families)}\n")

    if campaign.tools:
        content.append(f"Tools: ", style="cyan")
        content.append(f"{', '.join(campaign.tools)}\n")

    if campaign.first_seen:
        content.append(f"\nFirst Seen: ", style="cyan")
        content.append(f"{campaign.first_seen.strftime('%Y-%m-%d')}\n")

    if campaign.last_seen:
        content.append(f"Last Seen: ", style="cyan")
        content.append(f"{campaign.last_seen.strftime('%Y-%m-%d')}\n")

    content.append(f"\nSource: ", style="dim")
    content.append(f"{campaign.source.value}\n")
    content.append(f"Tracked: ", style="dim")
    content.append("Yes" if campaign.is_tracked else "No")

    console.print(Panel(
        content,
        title=f"Campaign: {campaign.name}",
        border_style="cyan",
    ))

    # Show description if available
    if campaign.description:
        console.print(Panel(
            campaign.description,
            title="Description",
            border_style="dim",
        ))


@app.command("track")
def track_campaign(
    name: Annotated[str, typer.Argument(help="Campaign name to track")],
) -> None:
    """
    Start tracking a campaign for updates.

    Example:
        spectre campaign track SolarWinds
    """
    tracker = get_campaign_tracker()

    campaign = tracker.get_campaign_by_name(name)
    if not campaign:
        console.print(f"[red]Campaign not found: {name}[/red]")
        raise typer.Exit(1)

    if campaign.is_tracked:
        console.print(f"[yellow]Campaign already being tracked: {campaign.name}[/yellow]")
        return

    tracker.start_tracking(campaign.id)
    console.print(f"[green]Now tracking campaign: {campaign.name}[/green]")
    console.print("[dim]Use 'spectre watch start-daemon' to enable continuous monitoring.[/dim]")


@app.command("untrack")
def untrack_campaign(
    name: Annotated[str, typer.Argument(help="Campaign name to stop tracking")],
) -> None:
    """
    Stop tracking a campaign.

    Example:
        spectre campaign untrack SolarWinds
    """
    tracker = get_campaign_tracker()

    campaign = tracker.get_campaign_by_name(name)
    if not campaign:
        console.print(f"[red]Campaign not found: {name}[/red]")
        raise typer.Exit(1)

    tracker.stop_tracking(campaign.id)
    console.print(f"[yellow]Stopped tracking: {campaign.name}[/yellow]")


@app.command("iocs")
def show_campaign_iocs(
    name: Annotated[str, typer.Argument(help="Campaign name")],
    active_only: Annotated[
        bool,
        typer.Option("--active", "-a", help="Show only active IOCs"),
    ] = False,
    ioc_type: Annotated[
        str,
        typer.Option("--type", "-t", help="Filter by IOC type"),
    ] = "",
) -> None:
    """
    Show IOCs associated with a campaign.

    Example:
        spectre campaign iocs SolarWinds
        spectre campaign iocs SolarWinds --active --type domain
    """
    tracker = get_campaign_tracker()

    campaign = tracker.get_campaign_by_name(name)
    if not campaign:
        console.print(f"[red]Campaign not found: {name}[/red]")
        raise typer.Exit(1)

    iocs = campaign.active_iocs if active_only else campaign.iocs

    if ioc_type:
        iocs = [i for i in iocs if i.type.lower() == ioc_type.lower()]

    if not iocs:
        console.print(f"[dim]No IOCs found for {campaign.name}[/dim]")
        return

    table = Table(title=f"IOCs: {campaign.name}", border_style="cyan")
    table.add_column("Type", width=10)
    table.add_column("Value", style="white")
    table.add_column("Confidence", justify="right", width=10)
    table.add_column("Last Seen", width=12)

    for ioc in iocs[:50]:  # Limit display
        last_seen = ioc.last_seen.strftime("%Y-%m-%d") if ioc.last_seen else "[dim]-[/dim]"
        table.add_row(
            ioc.type,
            ioc.value[:60],
            f"{ioc.confidence * 100:.0f}%",
            last_seen,
        )

    console.print(table)

    if len(campaign.iocs) > 50:
        console.print(f"[dim]Showing 50 of {len(campaign.iocs)} IOCs[/dim]")


@app.command("search")
def search_campaigns(
    query: Annotated[str, typer.Argument(help="Search query")],
) -> None:
    """
    Search campaigns by name, alias, or description.

    Example:
        spectre campaign search SolarWinds
        spectre campaign search "supply chain"
    """
    tracker = get_campaign_tracker()
    results = tracker.search_campaigns(query)

    if not results:
        console.print(f"[dim]No campaigns match: {query}[/dim]")
        return

    console.print(f"[cyan]Found {len(results)} campaign(s):[/cyan]\n")

    for campaign in results:
        status = {
            CampaignStatus.ACTIVE: "[green]●[/green]",
            CampaignStatus.DORMANT: "[yellow]◐[/yellow]",
            CampaignStatus.CONCLUDED: "[dim]○[/dim]",
        }.get(campaign.status, "")

        console.print(f"  {status} [cyan]{campaign.name}[/cyan]")
        if campaign.aliases:
            console.print(f"    [dim]Aliases: {', '.join(campaign.aliases[:3])}[/dim]")
        if campaign.attributed_actors:
            console.print(f"    [dim]Actors: {', '.join(campaign.attributed_actors[:3])}[/dim]")
