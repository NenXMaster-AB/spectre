"""
Investigation Store

In-memory storage for investigation state.
Provides persistence layer for investigations with optional TTL cleanup.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from spectre.services.models import Investigation

from spectre.services.models import InvestigationStatus

logger = structlog.get_logger(__name__)


class InvestigationStore:
    """
    In-memory investigation store.

    Stores investigation state with automatic cleanup of old completed investigations.
    Thread-safe for concurrent access.
    """

    def __init__(
        self,
        max_investigations: int = 1000,
        completed_ttl_hours: int = 24,
    ) -> None:
        """
        Initialize the investigation store.

        Args:
            max_investigations: Maximum number of investigations to store
            completed_ttl_hours: Hours to keep completed investigations
        """
        self._investigations: dict[str, Investigation] = {}
        self._lock = asyncio.Lock()
        self._max_investigations = max_investigations
        self._completed_ttl = timedelta(hours=completed_ttl_hours)

    async def save(self, investigation: Investigation) -> None:
        """
        Save or update an investigation.

        Args:
            investigation: The investigation to save
        """
        async with self._lock:
            self._investigations[investigation.id] = investigation

            # Cleanup if over limit
            if len(self._investigations) > self._max_investigations:
                await self._cleanup_old()

    async def get(self, investigation_id: str) -> Investigation | None:
        """
        Get an investigation by ID.

        Args:
            investigation_id: The investigation ID

        Returns:
            The investigation or None if not found
        """
        async with self._lock:
            return self._investigations.get(investigation_id)

    async def list(
        self,
        status: InvestigationStatus | None = None,
        limit: int = 50,
        offset: int = 0,
        include_completed: bool = True,
    ) -> list[Investigation]:
        """
        List investigations with optional filtering.

        Args:
            status: Filter by status
            limit: Maximum number to return
            offset: Number to skip
            include_completed: Whether to include completed investigations

        Returns:
            List of investigations
        """
        async with self._lock:
            investigations = list(self._investigations.values())

        # Filter by status
        if status:
            investigations = [inv for inv in investigations if inv.status == status]
        elif not include_completed:
            investigations = [inv for inv in investigations if inv.is_active]

        # Sort by created_at descending (newest first)
        investigations.sort(key=lambda x: x.created_at, reverse=True)

        # Apply pagination
        return investigations[offset : offset + limit]

    async def delete(self, investigation_id: str) -> bool:
        """
        Delete an investigation.

        Args:
            investigation_id: The investigation ID

        Returns:
            True if deleted, False if not found
        """
        async with self._lock:
            if investigation_id in self._investigations:
                del self._investigations[investigation_id]
                return True
            return False

    async def get_active(self) -> list[Investigation]:
        """
        Get all active (non-completed) investigations.

        Returns:
            List of active investigations
        """
        async with self._lock:
            return [inv for inv in self._investigations.values() if inv.is_active]

    async def count(self, status: InvestigationStatus | None = None) -> int:
        """
        Count investigations.

        Args:
            status: Optional status filter

        Returns:
            Count of investigations
        """
        async with self._lock:
            if status:
                return sum(1 for inv in self._investigations.values() if inv.status == status)
            return len(self._investigations)

    async def _cleanup_old(self) -> None:
        """Remove old completed investigations beyond TTL."""
        now = datetime.now(timezone.utc)
        cutoff = now - self._completed_ttl

        to_remove = []
        for inv_id, inv in self._investigations.items():
            if not inv.is_active and inv.completed_at and inv.completed_at < cutoff:
                to_remove.append(inv_id)

        for inv_id in to_remove:
            del self._investigations[inv_id]

        if to_remove:
            logger.info("Cleaned up old investigations", count=len(to_remove))

    async def clear(self) -> None:
        """Clear all investigations (for testing)."""
        async with self._lock:
            self._investigations.clear()

    def __len__(self) -> int:
        """Get the number of stored investigations."""
        return len(self._investigations)


# Global store instance
_store: InvestigationStore | None = None


def get_investigation_store() -> InvestigationStore:
    """Get the global investigation store instance."""
    global _store
    if _store is None:
        _store = InvestigationStore()
    return _store
