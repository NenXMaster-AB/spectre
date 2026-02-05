"""
Watchers

Watch execution and result processing.
"""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone
from typing import Any

import structlog

from spectre.heartbeat.models import (
    Watch,
    WatchType,
    WatchResult,
    WatchResultChange,
    Alert,
    AlertSeverity,
)
from spectre.heartbeat.diff import compute_diff, check_conditions
from spectre.heartbeat.store import WatchStore, get_watch_store
from spectre.heartbeat.alerts import AlertRouter, get_alert_router
from spectre.plugins.base import EntityType, PluginConfig
from spectre.plugins.registry import PluginRegistry, get_registry

logger = structlog.get_logger(__name__)


class WatchExecutor:
    """
    Executes watches and processes results.

    Coordinates:
    - Running plugins to gather current data
    - Comparing with previous results (diff detection)
    - Evaluating conditions
    - Generating and routing alerts
    """

    def __init__(
        self,
        registry: PluginRegistry | None = None,
        store: WatchStore | None = None,
        alert_router: AlertRouter | None = None,
        api_keys: dict[str, str] | None = None,
    ) -> None:
        """
        Initialize the watch executor.

        Args:
            registry: Plugin registry
            store: Watch/result store
            alert_router: Alert routing
            api_keys: API keys for plugins
        """
        self.registry = registry or get_registry()
        self.store = store or get_watch_store()
        self.alert_router = alert_router or get_alert_router()
        self.api_keys = api_keys or {}

    async def execute(self, watch: Watch) -> WatchResult:
        """
        Execute a watch and process results.

        Args:
            watch: The watch to execute

        Returns:
            WatchResult with data and detected changes
        """
        start_time = time.time()
        logger.info(
            "Executing watch",
            watch_id=watch.id,
            watch_name=watch.name,
            target=watch.target,
        )

        result = WatchResult(
            watch_id=watch.id,
        )

        try:
            # Get current data
            current_data = await self._gather_data(watch)
            result.data = current_data

            # Get previous result for comparison
            previous = await self.store.get_latest_result(watch.id)

            # Compute diff if we have previous data
            if previous and previous.data:
                changes = compute_diff(
                    previous.data,
                    current_data,
                    tracked_fields=self._get_tracked_fields(watch),
                )
                result.changes = changes
                result.has_changes = len(changes) > 0

            # Check explicit conditions
            if watch.conditions:
                condition_results = check_conditions(
                    current_data,
                    [c.model_dump() for c in watch.conditions],
                )

                for condition, matched, actual in condition_results:
                    if matched:
                        result.changes.append(WatchResultChange(
                            field=condition["field"],
                            change_type="condition_met",
                            old_value=condition.get("value"),
                            new_value=actual,
                            severity=AlertSeverity(condition.get("severity", "medium")),
                        ))
                        result.has_changes = True

            result.duration_seconds = time.time() - start_time
            result.success = True

            # Save result
            await self.store.save_result(result)

            # Update watch
            watch.mark_run_completed(result.id)
            await self.store.save_watch(watch)

            # Generate alerts if changes detected
            if result.has_changes:
                await self._generate_alerts(watch, result)

            logger.info(
                "Watch execution completed",
                watch_id=watch.id,
                changes=len(result.changes),
                duration=f"{result.duration_seconds:.2f}s",
            )

        except Exception as e:
            logger.error("Watch execution failed", watch_id=watch.id, error=str(e))
            result.success = False
            result.error = str(e)
            result.duration_seconds = time.time() - start_time

            watch.mark_run_failed(str(e))
            await self.store.save_watch(watch)
            await self.store.save_result(result)

        return result

    async def _gather_data(self, watch: Watch) -> dict[str, Any]:
        """Gather current data for a watch."""
        data: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target": watch.target,
        }

        # Determine which plugins to run based on watch type
        plugins = self._get_plugins_for_watch(watch)

        if not plugins:
            logger.warning("No plugins available for watch type", watch_type=watch.watch_type)
            return data

        # Build plugin config
        config = PluginConfig()
        for key, value in self.api_keys.items():
            setattr(config, f"{key}_api_key", value)

        # Build entity input
        entity_input = {
            "type": self._get_entity_type(watch).value,
            "value": watch.target,
        }

        # Run plugins
        for plugin_name in plugins:
            try:
                if not self.registry.has_plugin(plugin_name):
                    continue

                plugin = self.registry.get_plugin(plugin_name)
                result = await plugin.execute(entity_input, config)

                # Merge findings into data
                for finding in result.findings:
                    key = f"{plugin_name}_{finding.type}"
                    data[key] = finding.data

                # Store discovered entities
                if result.entities_discovered:
                    data[f"{plugin_name}_entities"] = result.entities_discovered

            except Exception as e:
                logger.warning(
                    "Plugin failed during watch",
                    plugin=plugin_name,
                    error=str(e),
                )
                data[f"{plugin_name}_error"] = str(e)

        return data

    def _get_plugins_for_watch(self, watch: Watch) -> list[str]:
        """Get applicable plugin names for a watch type."""
        # Map watch types to plugins
        plugin_map: dict[WatchType, list[str]] = {
            WatchType.DOMAIN: ["dns_recon", "whois_lookup", "cert_transparency"],
            WatchType.IP: ["dns_recon", "shodan_lookup"],
            WatchType.SUBDOMAIN: ["subdomain_enum", "cert_transparency"],
            WatchType.CERTIFICATE: ["cert_transparency"],
            WatchType.THREAT_FEED: ["abuse_ch", "virustotal", "alienvault_otx"],
            WatchType.CVE: [],  # Would need a CVE plugin
        }

        plugins = plugin_map.get(watch.watch_type, [])

        # Filter to available plugins
        available = []
        for p in plugins:
            if self.registry.has_plugin(p):
                available.append(p)

        return available

    def _get_entity_type(self, watch: Watch) -> EntityType:
        """Get the entity type for a watch."""
        if watch.target_type:
            return watch.target_type

        type_map: dict[WatchType, EntityType] = {
            WatchType.DOMAIN: EntityType.DOMAIN,
            WatchType.IP: EntityType.IP_ADDRESS,
            WatchType.SUBDOMAIN: EntityType.DOMAIN,
            WatchType.CERTIFICATE: EntityType.DOMAIN,
            WatchType.THREAT_FEED: EntityType.DOMAIN,  # Could be IP or hash too
            WatchType.CVE: EntityType.DOMAIN,
        }

        return type_map.get(watch.watch_type, EntityType.DOMAIN)

    def _get_tracked_fields(self, watch: Watch) -> list[str] | None:
        """Get fields to track for diff detection."""
        # If watch has explicit conditions, track those fields
        if watch.conditions:
            return [c.field for c in watch.conditions]
        return None  # Track all fields

    async def _generate_alerts(
        self,
        watch: Watch,
        result: WatchResult,
    ) -> None:
        """Generate and send alerts for detected changes."""
        # Determine max severity of changes
        max_severity = AlertSeverity.INFO
        severity_order = [
            AlertSeverity.INFO,
            AlertSeverity.LOW,
            AlertSeverity.MEDIUM,
            AlertSeverity.HIGH,
            AlertSeverity.CRITICAL,
        ]

        for change in result.changes:
            if severity_order.index(change.severity) > severity_order.index(max_severity):
                max_severity = change.severity

        # Check if severity meets minimum threshold
        min_severity = watch.alert_config.min_severity
        if severity_order.index(max_severity) < severity_order.index(min_severity):
            logger.debug(
                "Skipping alert - below severity threshold",
                max_severity=max_severity.value,
                min_severity=min_severity.value,
            )
            return

        # Build alert
        alert = Alert(
            watch_id=watch.id,
            watch_name=watch.name,
            result_id=result.id,
            title=f"Changes detected: {watch.name}",
            message=self._build_alert_message(watch, result),
            severity=max_severity,
            target=watch.target,
            watch_type=watch.watch_type,
            changes=result.changes,
            channels=watch.alert_config.channels,
        )

        # Save alert
        await self.store.save_alert(alert)

        # Update watch stats
        watch.alert_count += 1
        await self.store.save_watch(watch)

        # Route alert
        overrides = {}
        if watch.alert_config.slack_webhook_url:
            overrides["slack_webhook"] = watch.alert_config.slack_webhook_url
        if watch.alert_config.discord_webhook_url:
            overrides["discord_webhook"] = watch.alert_config.discord_webhook_url
        if watch.alert_config.telegram_chat_id:
            overrides["telegram_chat_id"] = watch.alert_config.telegram_chat_id
        if watch.alert_config.webhook_url:
            overrides["webhook_url"] = watch.alert_config.webhook_url

        await self.alert_router.send_alert(alert, overrides)

        result.alerts_triggered += 1
        logger.info(
            "Alert generated",
            watch_id=watch.id,
            alert_id=alert.id,
            severity=max_severity.value,
        )

    def _build_alert_message(self, watch: Watch, result: WatchResult) -> str:
        """Build the alert message body."""
        changes_summary = []

        for change in result.changes[:5]:
            if change.change_type == "added":
                changes_summary.append(f"New {change.field}: {_truncate(str(change.new_value), 50)}")
            elif change.change_type == "removed":
                changes_summary.append(f"Removed {change.field}")
            elif change.change_type == "modified":
                changes_summary.append(f"Changed {change.field}")
            elif change.change_type == "condition_met":
                changes_summary.append(f"Condition met: {change.field}")

        if len(result.changes) > 5:
            changes_summary.append(f"...and {len(result.changes) - 5} more changes")

        return f"Monitoring {watch.target} detected {len(result.changes)} change(s):\n" + "\n".join(
            f"• {s}" for s in changes_summary
        )


def _truncate(text: str, max_len: int) -> str:
    """Truncate text to max length."""
    if len(text) <= max_len:
        return text
    return text[:max_len - 3] + "..."


# Global executor instance
_executor: WatchExecutor | None = None


def get_watch_executor(**kwargs: Any) -> WatchExecutor:
    """Get the global watch executor instance."""
    global _executor
    if _executor is None:
        _executor = WatchExecutor(**kwargs)
    return _executor
