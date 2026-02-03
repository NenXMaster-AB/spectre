"""
Event Bus

Async event publishing for real-time investigation updates.
Enables decoupled communication between the investigation service
and various consumers (WebSocket, CLI output, chat messages).
"""

from __future__ import annotations

import asyncio
from collections import defaultdict
from typing import AsyncIterator, Callable, Awaitable

import structlog

from spectre.services.models import InvestigationEvent, InvestigationEventType

logger = structlog.get_logger(__name__)

# Type for event handlers
EventHandler = Callable[[InvestigationEvent], Awaitable[None]]


class EventBus:
    """
    Async event bus for investigation events.

    Supports:
    - Per-investigation subscriptions
    - Global subscriptions (all events)
    - Async iteration for real-time streaming
    """

    def __init__(self) -> None:
        # Queues for each investigation subscription
        self._investigation_queues: dict[str, list[asyncio.Queue[InvestigationEvent]]] = defaultdict(list)
        # Global queues (receive all events)
        self._global_queues: list[asyncio.Queue[InvestigationEvent]] = []
        # Registered handlers by event type
        self._handlers: dict[InvestigationEventType, list[EventHandler]] = defaultdict(list)
        # Lock for thread safety
        self._lock = asyncio.Lock()

    async def publish(self, event: InvestigationEvent) -> None:
        """
        Publish an event to all subscribers.

        Args:
            event: The investigation event to publish
        """
        logger.debug(
            "Publishing event",
            event_type=event.type.value,
            investigation_id=event.investigation_id,
        )

        async with self._lock:
            # Send to investigation-specific subscribers
            if event.investigation_id in self._investigation_queues:
                for queue in self._investigation_queues[event.investigation_id]:
                    try:
                        queue.put_nowait(event)
                    except asyncio.QueueFull:
                        logger.warning("Event queue full, dropping event")

            # Send to global subscribers
            for queue in self._global_queues:
                try:
                    queue.put_nowait(event)
                except asyncio.QueueFull:
                    logger.warning("Global event queue full, dropping event")

        # Call registered handlers
        handlers = self._handlers.get(event.type, [])
        for handler in handlers:
            try:
                await handler(event)
            except Exception as e:
                logger.error("Event handler failed", error=str(e), handler=handler.__name__)

    async def subscribe(
        self,
        investigation_id: str | None = None,
        max_queue_size: int = 100,
    ) -> AsyncIterator[InvestigationEvent]:
        """
        Subscribe to investigation events.

        Args:
            investigation_id: Subscribe to specific investigation, or None for all
            max_queue_size: Maximum events to buffer

        Yields:
            Investigation events as they occur
        """
        queue: asyncio.Queue[InvestigationEvent] = asyncio.Queue(maxsize=max_queue_size)

        async with self._lock:
            if investigation_id:
                self._investigation_queues[investigation_id].append(queue)
            else:
                self._global_queues.append(queue)

        try:
            while True:
                event = await queue.get()
                yield event
        finally:
            # Clean up on unsubscribe
            async with self._lock:
                if investigation_id and investigation_id in self._investigation_queues:
                    if queue in self._investigation_queues[investigation_id]:
                        self._investigation_queues[investigation_id].remove(queue)
                    # Clean up empty lists
                    if not self._investigation_queues[investigation_id]:
                        del self._investigation_queues[investigation_id]
                elif queue in self._global_queues:
                    self._global_queues.remove(queue)

    def register_handler(
        self,
        event_type: InvestigationEventType,
        handler: EventHandler,
    ) -> None:
        """
        Register a handler for a specific event type.

        Args:
            event_type: The event type to handle
            handler: Async function to call when event occurs
        """
        self._handlers[event_type].append(handler)

    def unregister_handler(
        self,
        event_type: InvestigationEventType,
        handler: EventHandler,
    ) -> None:
        """
        Unregister an event handler.

        Args:
            event_type: The event type
            handler: The handler to remove
        """
        if event_type in self._handlers and handler in self._handlers[event_type]:
            self._handlers[event_type].remove(handler)

    async def cleanup_investigation(self, investigation_id: str) -> None:
        """
        Clean up subscriptions for a completed investigation.

        Args:
            investigation_id: The investigation ID to clean up
        """
        async with self._lock:
            if investigation_id in self._investigation_queues:
                # Signal end to all subscribers
                for queue in self._investigation_queues[investigation_id]:
                    # Put a sentinel None to signal end (subscribers should handle this)
                    try:
                        queue.put_nowait(None)  # type: ignore
                    except asyncio.QueueFull:
                        pass
                del self._investigation_queues[investigation_id]

    @property
    def active_subscriptions(self) -> int:
        """Get the number of active subscriptions."""
        return len(self._global_queues) + sum(
            len(queues) for queues in self._investigation_queues.values()
        )


# Global event bus instance
_event_bus: EventBus | None = None


def get_event_bus() -> EventBus:
    """Get the global event bus instance."""
    global _event_bus
    if _event_bus is None:
        _event_bus = EventBus()
    return _event_bus
