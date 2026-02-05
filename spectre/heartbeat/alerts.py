"""
Alert Routing

Routes alerts to configured channels (CLI, Slack, Discord, etc.).
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import httpx
import structlog

from spectre.heartbeat.models import (
    Alert,
    AlertChannel,
    AlertSeverity,
    WatchResultChange,
)

logger = structlog.get_logger(__name__)


class AlertRouter:
    """
    Routes alerts to configured channels.

    Supports:
    - CLI (console output)
    - Slack (via webhook)
    - Discord (via webhook)
    - Telegram (via bot API)
    - Generic webhooks
    """

    def __init__(
        self,
        slack_webhook_url: str | None = None,
        discord_webhook_url: str | None = None,
        telegram_bot_token: str | None = None,
        telegram_chat_id: str | None = None,
    ) -> None:
        """
        Initialize the alert router.

        Args:
            slack_webhook_url: Default Slack webhook URL
            discord_webhook_url: Default Discord webhook URL
            telegram_bot_token: Telegram bot token
            telegram_chat_id: Default Telegram chat ID
        """
        self._slack_webhook = slack_webhook_url
        self._discord_webhook = discord_webhook_url
        self._telegram_token = telegram_bot_token
        self._telegram_chat = telegram_chat_id
        self._http_client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(timeout=30.0)
        return self._http_client

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None

    async def send_alert(
        self,
        alert: Alert,
        channel_overrides: dict[str, str] | None = None,
    ) -> None:
        """
        Send an alert to all configured channels.

        Args:
            alert: The alert to send
            channel_overrides: Override URLs/IDs for specific channels
        """
        overrides = channel_overrides or {}
        tasks = []

        for channel in alert.channels:
            task = self._send_to_channel(alert, channel, overrides)
            tasks.append(task)

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _send_to_channel(
        self,
        alert: Alert,
        channel: AlertChannel,
        overrides: dict[str, str],
    ) -> None:
        """Send alert to a specific channel."""
        try:
            if channel == AlertChannel.CLI:
                await self._send_cli(alert)
            elif channel == AlertChannel.SLACK:
                webhook = overrides.get("slack_webhook") or self._slack_webhook
                if webhook:
                    await self._send_slack(alert, webhook)
                else:
                    logger.warning("No Slack webhook configured")
            elif channel == AlertChannel.DISCORD:
                webhook = overrides.get("discord_webhook") or self._discord_webhook
                if webhook:
                    await self._send_discord(alert, webhook)
                else:
                    logger.warning("No Discord webhook configured")
            elif channel == AlertChannel.TELEGRAM:
                chat_id = overrides.get("telegram_chat_id") or self._telegram_chat
                if self._telegram_token and chat_id:
                    await self._send_telegram(alert, chat_id)
                else:
                    logger.warning("Telegram not configured")
            elif channel == AlertChannel.WEBHOOK:
                webhook = overrides.get("webhook_url")
                if webhook:
                    await self._send_webhook(alert, webhook)

            alert.mark_delivered(channel.value)

        except Exception as e:
            logger.error(
                "Failed to send alert",
                channel=channel.value,
                error=str(e),
            )
            alert.mark_delivery_failed(channel.value, str(e))

    async def _send_cli(self, alert: Alert) -> None:
        """Send alert to CLI (console output)."""
        from rich.console import Console
        from rich.panel import Panel
        from rich.text import Text

        console = Console()

        # Color based on severity
        severity_colors = {
            AlertSeverity.CRITICAL: "red",
            AlertSeverity.HIGH: "red",
            AlertSeverity.MEDIUM: "yellow",
            AlertSeverity.LOW: "cyan",
            AlertSeverity.INFO: "white",
        }
        color = severity_colors.get(alert.severity, "white")

        # Build content
        content = Text()
        content.append(f"{alert.message}\n\n", style="white")
        content.append(f"Target: ", style="dim")
        content.append(f"{alert.target}\n", style="cyan")
        content.append(f"Type: ", style="dim")
        content.append(f"{alert.watch_type.value}\n", style="cyan")

        if alert.changes:
            content.append(f"\nChanges ({len(alert.changes)}):\n", style="dim")
            for change in alert.changes[:5]:  # Limit to first 5
                content.append(f"  • {change.field}: ", style="dim")
                content.append(f"{change.change_type}", style=color)
                if change.new_value:
                    content.append(f" → {_truncate(str(change.new_value), 50)}", style="white")
                content.append("\n")

        console.print(Panel(
            content,
            title=f"[bold {color}]⚠ {alert.title}[/bold {color}]",
            subtitle=f"[dim]{alert.severity.value.upper()}[/dim]",
            border_style=color,
        ))

    async def _send_slack(self, alert: Alert, webhook_url: str) -> None:
        """Send alert to Slack via webhook."""
        client = await self._get_client()

        # Build Slack blocks
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"🚨 {alert.title}",
                    "emoji": True,
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": alert.message,
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Target:*\n`{alert.target}`",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Severity:*\n{_severity_emoji(alert.severity)} {alert.severity.value.upper()}",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Type:*\n{alert.watch_type.value}",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Changes:*\n{len(alert.changes)}",
                    },
                ]
            },
        ]

        # Add changes if present
        if alert.changes:
            changes_text = "\n".join(
                f"• `{c.field}`: {c.change_type}"
                for c in alert.changes[:5]
            )
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Changes:*\n{changes_text}",
                }
            })

        payload = {
            "blocks": blocks,
            "text": f"{alert.title} - {alert.message}",  # Fallback
        }

        response = await client.post(webhook_url, json=payload)
        response.raise_for_status()

    async def _send_discord(self, alert: Alert, webhook_url: str) -> None:
        """Send alert to Discord via webhook."""
        client = await self._get_client()

        # Build Discord embed
        color = {
            AlertSeverity.CRITICAL: 0xFF0000,
            AlertSeverity.HIGH: 0xFF4500,
            AlertSeverity.MEDIUM: 0xFFB000,
            AlertSeverity.LOW: 0x00BFFF,
            AlertSeverity.INFO: 0x808080,
        }.get(alert.severity, 0x808080)

        embed = {
            "title": f"🚨 {alert.title}",
            "description": alert.message,
            "color": color,
            "fields": [
                {
                    "name": "Target",
                    "value": f"`{alert.target}`",
                    "inline": True,
                },
                {
                    "name": "Severity",
                    "value": f"{_severity_emoji(alert.severity)} {alert.severity.value.upper()}",
                    "inline": True,
                },
                {
                    "name": "Type",
                    "value": alert.watch_type.value,
                    "inline": True,
                },
            ],
            "timestamp": alert.created_at.isoformat(),
        }

        if alert.changes:
            changes_text = "\n".join(
                f"• `{c.field}`: {c.change_type}"
                for c in alert.changes[:5]
            )
            embed["fields"].append({
                "name": f"Changes ({len(alert.changes)})",
                "value": changes_text,
                "inline": False,
            })

        payload = {"embeds": [embed]}

        response = await client.post(webhook_url, json=payload)
        response.raise_for_status()

    async def _send_telegram(self, alert: Alert, chat_id: str) -> None:
        """Send alert to Telegram via bot API."""
        client = await self._get_client()

        # Build message text (Telegram uses HTML or Markdown)
        message = (
            f"🚨 <b>{_escape_html(alert.title)}</b>\n\n"
            f"{_escape_html(alert.message)}\n\n"
            f"<b>Target:</b> <code>{_escape_html(alert.target)}</code>\n"
            f"<b>Severity:</b> {_severity_emoji(alert.severity)} {alert.severity.value.upper()}\n"
            f"<b>Type:</b> {alert.watch_type.value}\n"
        )

        if alert.changes:
            message += f"\n<b>Changes ({len(alert.changes)}):</b>\n"
            for change in alert.changes[:5]:
                message += f"• <code>{_escape_html(change.field)}</code>: {change.change_type}\n"

        url = f"https://api.telegram.org/bot{self._telegram_token}/sendMessage"
        payload = {
            "chat_id": chat_id,
            "text": message,
            "parse_mode": "HTML",
        }

        response = await client.post(url, json=payload)
        response.raise_for_status()

    async def _send_webhook(self, alert: Alert, webhook_url: str) -> None:
        """Send alert to a generic webhook."""
        client = await self._get_client()

        payload = {
            "id": alert.id,
            "watch_id": alert.watch_id,
            "watch_name": alert.watch_name,
            "title": alert.title,
            "message": alert.message,
            "severity": alert.severity.value,
            "target": alert.target,
            "watch_type": alert.watch_type.value,
            "changes": [c.model_dump() for c in alert.changes],
            "created_at": alert.created_at.isoformat(),
        }

        response = await client.post(
            webhook_url,
            json=payload,
            headers={"Content-Type": "application/json"},
        )
        response.raise_for_status()


def _severity_emoji(severity: AlertSeverity) -> str:
    """Get emoji for severity level."""
    return {
        AlertSeverity.CRITICAL: "🔴",
        AlertSeverity.HIGH: "🟠",
        AlertSeverity.MEDIUM: "🟡",
        AlertSeverity.LOW: "🔵",
        AlertSeverity.INFO: "⚪",
    }.get(severity, "⚪")


def _truncate(text: str, max_len: int) -> str:
    """Truncate text to max length."""
    if len(text) <= max_len:
        return text
    return text[:max_len - 3] + "..."


def _escape_html(text: str) -> str:
    """Escape HTML special characters for Telegram."""
    return (
        text
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


# Global router instance
_router: AlertRouter | None = None


def get_alert_router(**kwargs: Any) -> AlertRouter:
    """Get the global alert router instance."""
    global _router
    if _router is None:
        _router = AlertRouter(**kwargs)
    return _router
