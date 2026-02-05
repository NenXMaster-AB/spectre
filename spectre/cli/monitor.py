"""
Monitor CLI Commands

Commands for managing watches and continuous monitoring.
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

from spectre.heartbeat import (
    Watch,
    WatchType,
    WatchStatus,
    WatchCondition,
    AlertChannel,
    AlertConfig,
    AlertSeverity,
    get_scheduler,
    get_watch_store,
    get_watch_executor,
)
from spectre.plugins.base import EntityType

logger = structlog.get_logger(__name__)
console = Console()

app = typer.Typer(
    name="watch",
    help="Continuous monitoring with proactive alerts",
    no_args_is_help=True,
)


def _parse_interval(interval: str) -> int:
    """Parse interval string (e.g., '6h', '30m', '1d') to minutes."""
    interval = interval.lower().strip()

    if interval.endswith("m"):
        return int(interval[:-1])
    elif interval.endswith("h"):
        return int(interval[:-1]) * 60
    elif interval.endswith("d"):
        return int(interval[:-1]) * 60 * 24
    else:
        # Assume minutes
        return int(interval)


def _format_interval(minutes: int) -> str:
    """Format minutes as human-readable interval."""
    if minutes < 60:
        return f"{minutes}m"
    elif minutes < 1440:
        hours = minutes // 60
        remaining = minutes % 60
        if remaining:
            return f"{hours}h {remaining}m"
        return f"{hours}h"
    else:
        days = minutes // 1440
        remaining = (minutes % 1440) // 60
        if remaining:
            return f"{days}d {remaining}h"
        return f"{days}d"


@app.command("create")
def create_watch(
    target: Annotated[str, typer.Argument(help="Target to monitor (domain, IP, etc.)")],
    name: Annotated[str, typer.Option("--name", "-n", help="Watch name")] = "",
    watch_type: Annotated[
        str,
        typer.Option(
            "--type",
            "-t",
            help="Watch type: domain, ip, subdomain, certificate, threat_feed",
        ),
    ] = "domain",
    interval: Annotated[
        str,
        typer.Option(
            "--interval",
            "-i",
            help="Check interval (e.g., 6h, 30m, 1d)",
        ),
    ] = "6h",
    alert: Annotated[
        list[str],
        typer.Option(
            "--alert",
            "-a",
            help="Alert channel: cli, slack, discord, telegram, webhook",
        ),
    ] = ["cli"],
    slack_webhook: Annotated[str, typer.Option(help="Slack webhook URL")] = "",
    discord_webhook: Annotated[str, typer.Option(help="Discord webhook URL")] = "",
    run_now: Annotated[
        bool,
        typer.Option("--run-now", help="Run the watch immediately after creating"),
    ] = False,
) -> None:
    """
    Create a new watch for continuous monitoring.

    Examples:
        spectre watch create example.com
        spectre watch create example.com -t subdomain -i 1h
        spectre watch create 192.168.1.1 -t ip -a slack --slack-webhook https://...
    """
    # Parse watch type
    try:
        wtype = WatchType(watch_type)
    except ValueError:
        console.print(f"[red]Invalid watch type: {watch_type}[/red]")
        console.print(f"Valid types: {', '.join(t.value for t in WatchType)}")
        raise typer.Exit(1)

    # Parse channels
    channels = []
    for ch in alert:
        try:
            channels.append(AlertChannel(ch))
        except ValueError:
            console.print(f"[red]Invalid alert channel: {ch}[/red]")
            console.print(f"Valid channels: {', '.join(c.value for c in AlertChannel)}")
            raise typer.Exit(1)

    # Parse interval
    try:
        interval_minutes = _parse_interval(interval)
    except ValueError:
        console.print(f"[red]Invalid interval: {interval}[/red]")
        raise typer.Exit(1)

    # Create watch name if not provided
    if not name:
        name = f"Watch {target}"

    # Create alert config
    alert_config = AlertConfig(
        channels=channels,
        slack_webhook_url=slack_webhook if slack_webhook else None,
        discord_webhook_url=discord_webhook if discord_webhook else None,
    )

    # Create watch
    watch = Watch(
        name=name,
        watch_type=wtype,
        target=target,
        interval_minutes=interval_minutes,
        alert_config=alert_config,
    )

    # Save watch
    async def _create():
        store = get_watch_store()
        await store.save_watch(watch)

        # Optionally run immediately
        if run_now:
            executor = get_watch_executor()
            console.print("[cyan]Running initial check...[/cyan]")
            result = await executor.execute(watch)
            if result.success:
                console.print(f"[green]✓ Initial check complete. {len(result.changes)} changes detected.[/green]")
            else:
                console.print(f"[yellow]Initial check failed: {result.error}[/yellow]")

    asyncio.run(_create())

    # Display confirmation
    console.print(Panel(
        f"[green]✓ Watch created successfully[/green]\n\n"
        f"[cyan]ID:[/cyan] {watch.id}\n"
        f"[cyan]Target:[/cyan] {target}\n"
        f"[cyan]Type:[/cyan] {wtype.value}\n"
        f"[cyan]Interval:[/cyan] {_format_interval(interval_minutes)}\n"
        f"[cyan]Alerts:[/cyan] {', '.join(c.value for c in channels)}",
        title="New Watch",
        border_style="green",
    ))


@app.command("list")
def list_watches(
    status: Annotated[
        str,
        typer.Option("--status", "-s", help="Filter by status: active, paused, all"),
    ] = "all",
    watch_type: Annotated[
        str,
        typer.Option("--type", "-t", help="Filter by watch type"),
    ] = "",
) -> None:
    """
    List all watches.

    Example:
        spectre watch list
        spectre watch list --status active
        spectre watch list -t domain
    """
    async def _list():
        store = get_watch_store()

        # Parse status filter
        status_filter = None
        if status != "all":
            try:
                status_filter = WatchStatus(status)
            except ValueError:
                console.print(f"[red]Invalid status: {status}[/red]")
                raise typer.Exit(1)

        watches = await store.list_watches(
            status=status_filter,
            watch_type=watch_type if watch_type else None,
        )

        if not watches:
            console.print("[dim]No watches found.[/dim]")
            return

        # Build table
        table = Table(title="Watches", border_style="cyan")
        table.add_column("ID", style="dim", width=12)
        table.add_column("Name", style="cyan")
        table.add_column("Target", style="white")
        table.add_column("Type", style="dim")
        table.add_column("Status", justify="center")
        table.add_column("Interval")
        table.add_column("Runs", justify="right")
        table.add_column("Alerts", justify="right")

        for watch in watches:
            # Status styling
            status_style = {
                WatchStatus.ACTIVE: "[green]●[/green] active",
                WatchStatus.PAUSED: "[yellow]◐[/yellow] paused",
                WatchStatus.FAILED: "[red]✗[/red] failed",
                WatchStatus.DISABLED: "[dim]○[/dim] disabled",
            }.get(watch.status, watch.status.value)

            table.add_row(
                watch.id[:12],
                watch.name[:30],
                watch.target[:30],
                watch.watch_type.value,
                status_style,
                _format_interval(watch.interval_minutes),
                str(watch.run_count),
                str(watch.alert_count),
            )

        console.print(table)
        console.print(f"\n[dim]Total: {len(watches)} watches[/dim]")

    asyncio.run(_list())


@app.command("show")
def show_watch(
    watch_id: Annotated[str, typer.Argument(help="Watch ID (or partial ID)")],
) -> None:
    """
    Show details of a specific watch.

    Example:
        spectre watch show abc123
    """
    async def _show():
        store = get_watch_store()

        # Find watch by ID (supports partial match)
        watches = await store.list_watches()
        watch = None
        for w in watches:
            if w.id.startswith(watch_id):
                watch = w
                break

        if not watch:
            console.print(f"[red]Watch not found: {watch_id}[/red]")
            raise typer.Exit(1)

        # Display watch details
        status_color = {
            WatchStatus.ACTIVE: "green",
            WatchStatus.PAUSED: "yellow",
            WatchStatus.FAILED: "red",
        }.get(watch.status, "dim")

        content = Text()
        content.append(f"ID: ", style="cyan")
        content.append(f"{watch.id}\n")
        content.append(f"Name: ", style="cyan")
        content.append(f"{watch.name}\n")
        content.append(f"Target: ", style="cyan")
        content.append(f"{watch.target}\n")
        content.append(f"Type: ", style="cyan")
        content.append(f"{watch.watch_type.value}\n")
        content.append(f"Status: ", style="cyan")
        content.append(f"{watch.status.value}\n", style=status_color)
        content.append(f"Interval: ", style="cyan")
        content.append(f"{_format_interval(watch.interval_minutes)}\n")
        content.append(f"\nRuns: ", style="cyan")
        content.append(f"{watch.run_count}\n")
        content.append(f"Alerts: ", style="cyan")
        content.append(f"{watch.alert_count}\n")
        content.append(f"Errors: ", style="cyan")
        content.append(f"{watch.error_count}\n")

        if watch.last_run:
            content.append(f"\nLast Run: ", style="cyan")
            content.append(f"{watch.last_run.strftime('%Y-%m-%d %H:%M:%S UTC')}\n")

        if watch.next_run:
            content.append(f"Next Run: ", style="cyan")
            content.append(f"{watch.next_run.strftime('%Y-%m-%d %H:%M:%S UTC')}\n")

        if watch.last_error:
            content.append(f"\nLast Error: ", style="red")
            content.append(f"{watch.last_error}\n")

        console.print(Panel(content, title="Watch Details", border_style="cyan"))

        # Show recent results
        results = await store.get_results(watch.id, limit=5)
        if results:
            result_table = Table(title="Recent Results", border_style="dim")
            result_table.add_column("Time", style="dim")
            result_table.add_column("Status")
            result_table.add_column("Changes", justify="right")
            result_table.add_column("Duration")

            for r in results:
                status = "[green]✓[/green]" if r.success else f"[red]✗[/red] {r.error}"
                result_table.add_row(
                    r.timestamp.strftime("%Y-%m-%d %H:%M"),
                    status,
                    str(r.change_count),
                    f"{r.duration_seconds:.1f}s",
                )

            console.print(result_table)

    asyncio.run(_show())


@app.command("run")
def run_watch(
    watch_id: Annotated[str, typer.Argument(help="Watch ID to run")],
) -> None:
    """
    Manually trigger a watch to run immediately.

    Example:
        spectre watch run abc123
    """
    async def _run():
        store = get_watch_store()
        executor = get_watch_executor()

        # Find watch
        watches = await store.list_watches()
        watch = None
        for w in watches:
            if w.id.startswith(watch_id):
                watch = w
                break

        if not watch:
            console.print(f"[red]Watch not found: {watch_id}[/red]")
            raise typer.Exit(1)

        console.print(f"[cyan]Running watch: {watch.name}...[/cyan]")

        result = await executor.execute(watch)

        if result.success:
            console.print(f"[green]✓ Check complete[/green]")
            console.print(f"[dim]Duration: {result.duration_seconds:.2f}s[/dim]")

            if result.changes:
                console.print(f"\n[yellow]Changes detected ({len(result.changes)}):[/yellow]")
                for change in result.changes[:10]:
                    console.print(f"  • {change.field}: {change.change_type}")
                if len(result.changes) > 10:
                    console.print(f"  [dim]...and {len(result.changes) - 10} more[/dim]")
            else:
                console.print("[dim]No changes detected.[/dim]")
        else:
            console.print(f"[red]✗ Check failed: {result.error}[/red]")

    asyncio.run(_run())


@app.command("pause")
def pause_watch(
    watch_id: Annotated[str, typer.Argument(help="Watch ID to pause")],
) -> None:
    """Pause a watch."""
    async def _pause():
        store = get_watch_store()

        watches = await store.list_watches()
        watch = None
        for w in watches:
            if w.id.startswith(watch_id):
                watch = w
                break

        if not watch:
            console.print(f"[red]Watch not found: {watch_id}[/red]")
            raise typer.Exit(1)

        watch.pause()
        await store.save_watch(watch)
        console.print(f"[yellow]Watch paused: {watch.name}[/yellow]")

    asyncio.run(_pause())


@app.command("resume")
def resume_watch(
    watch_id: Annotated[str, typer.Argument(help="Watch ID to resume")],
) -> None:
    """Resume a paused watch."""
    async def _resume():
        store = get_watch_store()

        watches = await store.list_watches()
        watch = None
        for w in watches:
            if w.id.startswith(watch_id):
                watch = w
                break

        if not watch:
            console.print(f"[red]Watch not found: {watch_id}[/red]")
            raise typer.Exit(1)

        watch.resume()
        await store.save_watch(watch)
        console.print(f"[green]Watch resumed: {watch.name}[/green]")

    asyncio.run(_resume())


@app.command("delete")
def delete_watch(
    watch_id: Annotated[str, typer.Argument(help="Watch ID to delete")],
    force: Annotated[
        bool,
        typer.Option("--force", "-f", help="Skip confirmation"),
    ] = False,
) -> None:
    """Delete a watch."""
    async def _delete():
        store = get_watch_store()

        watches = await store.list_watches()
        watch = None
        for w in watches:
            if w.id.startswith(watch_id):
                watch = w
                break

        if not watch:
            console.print(f"[red]Watch not found: {watch_id}[/red]")
            raise typer.Exit(1)

        if not force:
            confirm = typer.confirm(f"Delete watch '{watch.name}'?")
            if not confirm:
                raise typer.Abort()

        await store.delete_watch(watch.id)
        console.print(f"[red]Watch deleted: {watch.name}[/red]")

    asyncio.run(_delete())


@app.command("start-daemon")
def start_daemon(
    persist: Annotated[
        str,
        typer.Option("--persist", "-p", help="Path to persist watches"),
    ] = "",
) -> None:
    """
    Start the heartbeat daemon to run scheduled watches.

    This runs in the foreground and executes watches on their schedules.
    Use Ctrl+C to stop.

    Example:
        spectre watch start-daemon
        spectre watch start-daemon --persist ~/.spectre/watches.json
    """
    async def _daemon():
        from pathlib import Path

        persist_path = Path(persist) if persist else None

        # Initialize components
        store = get_watch_store(persist_path=persist_path)
        executor = get_watch_executor()
        scheduler = get_scheduler()

        # Set up executor callback
        scheduler.set_executor(executor.execute)

        # Load existing watches
        watches = await store.list_watches(status=WatchStatus.ACTIVE)
        for watch in watches:
            scheduler.add_watch(watch)

        console.print(Panel(
            f"[green]Heartbeat daemon started[/green]\n\n"
            f"[cyan]Active watches:[/cyan] {len(watches)}\n"
            f"[dim]Press Ctrl+C to stop[/dim]",
            title="SPECTRE Heartbeat",
            border_style="green",
        ))

        # Start scheduler
        await scheduler.start()

        try:
            # Run forever
            while True:
                await asyncio.sleep(1)
        except asyncio.CancelledError:
            pass
        finally:
            await scheduler.stop()
            console.print("[yellow]Heartbeat daemon stopped[/yellow]")

    try:
        asyncio.run(_daemon())
    except KeyboardInterrupt:
        console.print("\n[yellow]Shutting down...[/yellow]")
