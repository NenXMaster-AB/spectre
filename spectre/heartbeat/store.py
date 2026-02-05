"""
Heartbeat Store

Persistence layer for watches, results, and alerts.
Uses in-memory storage with optional SQLite persistence.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

import structlog

from spectre.heartbeat.models import (
    Watch,
    WatchResult,
    Alert,
    WatchStatus,
    AlertSeverity,
)

logger = structlog.get_logger(__name__)


class WatchStore:
    """
    Stores watches, results, and alerts.

    Provides in-memory storage with optional file-based persistence.
    """

    def __init__(
        self,
        persist_path: Path | str | None = None,
        result_retention_days: int = 30,
        alert_retention_days: int = 90,
    ) -> None:
        """
        Initialize the store.

        Args:
            persist_path: Path to persist watches (None for memory-only)
            result_retention_days: How long to keep results
            alert_retention_days: How long to keep alerts
        """
        self._persist_path = Path(persist_path) if persist_path else None
        self._result_retention = timedelta(days=result_retention_days)
        self._alert_retention = timedelta(days=alert_retention_days)

        self._watches: dict[str, Watch] = {}
        self._results: dict[str, list[WatchResult]] = {}  # watch_id -> results
        self._alerts: dict[str, Alert] = {}
        self._lock = asyncio.Lock()

        # Load persisted data if available
        if self._persist_path and self._persist_path.exists():
            self._load_from_file()

    def _load_from_file(self) -> None:
        """Load watches from persistence file."""
        if not self._persist_path:
            return

        try:
            with open(self._persist_path, "r") as f:
                data = json.load(f)

            for watch_data in data.get("watches", []):
                watch = Watch.model_validate(watch_data)
                self._watches[watch.id] = watch

            logger.info("Loaded watches from file", count=len(self._watches))

        except Exception as e:
            logger.error("Failed to load watches from file", error=str(e))

    def _save_to_file(self) -> None:
        """Save watches to persistence file."""
        if not self._persist_path:
            return

        try:
            self._persist_path.parent.mkdir(parents=True, exist_ok=True)

            data = {
                "watches": [w.model_dump(mode="json") for w in self._watches.values()],
                "saved_at": datetime.now(timezone.utc).isoformat(),
            }

            with open(self._persist_path, "w") as f:
                json.dump(data, f, indent=2, default=str)

        except Exception as e:
            logger.error("Failed to save watches to file", error=str(e))

    # Watch operations

    async def save_watch(self, watch: Watch) -> None:
        """Save or update a watch."""
        async with self._lock:
            self._watches[watch.id] = watch
            self._save_to_file()

    async def get_watch(self, watch_id: str) -> Watch | None:
        """Get a watch by ID."""
        return self._watches.get(watch_id)

    async def delete_watch(self, watch_id: str) -> bool:
        """Delete a watch and its results."""
        async with self._lock:
            if watch_id not in self._watches:
                return False

            del self._watches[watch_id]

            # Clean up results
            if watch_id in self._results:
                del self._results[watch_id]

            self._save_to_file()
            return True

    async def list_watches(
        self,
        status: WatchStatus | None = None,
        watch_type: str | None = None,
        owner: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Watch]:
        """List watches with optional filtering."""
        watches = list(self._watches.values())

        # Apply filters
        if status:
            watches = [w for w in watches if w.status == status]
        if watch_type:
            watches = [w for w in watches if w.watch_type.value == watch_type]
        if owner:
            watches = [w for w in watches if w.owner == owner]

        # Sort by creation date (newest first)
        watches.sort(key=lambda w: w.created_at, reverse=True)

        # Paginate
        return watches[offset : offset + limit]

    async def count_watches(
        self,
        status: WatchStatus | None = None,
    ) -> int:
        """Count watches with optional status filter."""
        if status:
            return sum(1 for w in self._watches.values() if w.status == status)
        return len(self._watches)

    async def get_due_watches(self) -> list[Watch]:
        """Get all watches that are due to run."""
        now = datetime.now(timezone.utc)
        return [
            w for w in self._watches.values()
            if w.status == WatchStatus.ACTIVE and (w.next_run is None or w.next_run <= now)
        ]

    # Result operations

    async def save_result(self, result: WatchResult) -> None:
        """Save a watch result."""
        async with self._lock:
            if result.watch_id not in self._results:
                self._results[result.watch_id] = []
            self._results[result.watch_id].append(result)

            # Clean up old results
            await self._cleanup_old_results(result.watch_id)

    async def get_result(self, result_id: str) -> WatchResult | None:
        """Get a specific result by ID."""
        for results in self._results.values():
            for result in results:
                if result.id == result_id:
                    return result
        return None

    async def get_latest_result(self, watch_id: str) -> WatchResult | None:
        """Get the most recent result for a watch."""
        results = self._results.get(watch_id, [])
        if not results:
            return None
        return max(results, key=lambda r: r.timestamp)

    async def get_results(
        self,
        watch_id: str,
        limit: int = 50,
        since: datetime | None = None,
    ) -> list[WatchResult]:
        """Get results for a watch."""
        results = self._results.get(watch_id, [])

        if since:
            results = [r for r in results if r.timestamp >= since]

        # Sort by timestamp (newest first)
        results.sort(key=lambda r: r.timestamp, reverse=True)

        return results[:limit]

    async def _cleanup_old_results(self, watch_id: str) -> None:
        """Remove results older than retention period."""
        cutoff = datetime.now(timezone.utc) - self._result_retention
        if watch_id in self._results:
            self._results[watch_id] = [
                r for r in self._results[watch_id]
                if r.timestamp >= cutoff
            ]

    # Alert operations

    async def save_alert(self, alert: Alert) -> None:
        """Save an alert."""
        async with self._lock:
            self._alerts[alert.id] = alert

    async def get_alert(self, alert_id: str) -> Alert | None:
        """Get an alert by ID."""
        return self._alerts.get(alert_id)

    async def list_alerts(
        self,
        watch_id: str | None = None,
        severity: AlertSeverity | None = None,
        acknowledged: bool | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Alert]:
        """List alerts with optional filtering."""
        alerts = list(self._alerts.values())

        if watch_id:
            alerts = [a for a in alerts if a.watch_id == watch_id]
        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        if acknowledged is not None:
            if acknowledged:
                alerts = [a for a in alerts if a.acknowledged_at is not None]
            else:
                alerts = [a for a in alerts if a.acknowledged_at is None]

        # Sort by creation date (newest first)
        alerts.sort(key=lambda a: a.created_at, reverse=True)

        return alerts[offset : offset + limit]

    async def count_unacknowledged_alerts(self) -> int:
        """Count unacknowledged alerts."""
        return sum(1 for a in self._alerts.values() if a.acknowledged_at is None)

    async def acknowledge_alert(self, alert_id: str, by: str) -> bool:
        """Acknowledge an alert."""
        alert = self._alerts.get(alert_id)
        if not alert:
            return False
        alert.acknowledge(by)
        return True

    async def cleanup_old_alerts(self) -> int:
        """Remove alerts older than retention period."""
        cutoff = datetime.now(timezone.utc) - self._alert_retention
        old_count = len(self._alerts)

        async with self._lock:
            self._alerts = {
                aid: a for aid, a in self._alerts.items()
                if a.created_at >= cutoff
            }

        removed = old_count - len(self._alerts)
        if removed > 0:
            logger.info("Cleaned up old alerts", removed=removed)
        return removed


# Global store instance
_store: WatchStore | None = None


def get_watch_store(persist_path: Path | str | None = None) -> WatchStore:
    """Get the global watch store instance."""
    global _store
    if _store is None:
        _store = WatchStore(persist_path=persist_path)
    return _store
