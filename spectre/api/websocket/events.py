"""WebSocket event definitions."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class EventType(str, Enum):
    """WebSocket event types."""

    # Investigation lifecycle
    INVESTIGATION_STARTED = "investigation.started"
    INVESTIGATION_COMPLETED = "investigation.completed"
    INVESTIGATION_FAILED = "investigation.failed"
    INVESTIGATION_CANCELLED = "investigation.cancelled"

    # Plugin execution
    PLUGIN_STARTED = "plugin.started"
    PLUGIN_COMPLETED = "plugin.completed"
    PLUGIN_FAILED = "plugin.failed"

    # Discovery events
    FINDING_DISCOVERED = "finding.discovered"
    ENTITY_DISCOVERED = "entity.discovered"
    THREAT_DETECTED = "threat.detected"

    # Progress updates
    PROGRESS_UPDATED = "progress.updated"

    # System events
    CONNECTION_ESTABLISHED = "connection.established"
    HEARTBEAT = "heartbeat"
    ERROR = "error"


class WebSocketEvent(BaseModel):
    """WebSocket event payload."""

    type: EventType
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    investigation_id: str | None = None
    data: dict[str, Any] = Field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        """Convert to JSON-serializable dict."""
        return {
            "type": self.type.value,
            "timestamp": self.timestamp,
            "investigation_id": self.investigation_id,
            "data": self.data,
        }


# Pre-built event factories
def connection_established_event() -> WebSocketEvent:
    """Create a connection established event."""
    return WebSocketEvent(
        type=EventType.CONNECTION_ESTABLISHED,
        data={"message": "SPECTRE intelligence feed connected"},
    )


def heartbeat_event() -> WebSocketEvent:
    """Create a heartbeat event."""
    return WebSocketEvent(
        type=EventType.HEARTBEAT,
        data={"status": "operational"},
    )


def progress_event(investigation_id: str, progress: float, stage: str) -> WebSocketEvent:
    """Create a progress update event."""
    return WebSocketEvent(
        type=EventType.PROGRESS_UPDATED,
        investigation_id=investigation_id,
        data={
            "progress": progress,
            "stage": stage,
        },
    )


def finding_event(investigation_id: str, finding: dict[str, Any]) -> WebSocketEvent:
    """Create a finding discovered event."""
    return WebSocketEvent(
        type=EventType.FINDING_DISCOVERED,
        investigation_id=investigation_id,
        data={"finding": finding},
    )


def entity_event(investigation_id: str, entity: dict[str, Any]) -> WebSocketEvent:
    """Create an entity discovered event."""
    return WebSocketEvent(
        type=EventType.ENTITY_DISCOVERED,
        investigation_id=investigation_id,
        data={"entity": entity},
    )


def plugin_started_event(investigation_id: str, plugin_name: str) -> WebSocketEvent:
    """Create a plugin started event."""
    return WebSocketEvent(
        type=EventType.PLUGIN_STARTED,
        investigation_id=investigation_id,
        data={"plugin": plugin_name},
    )


def plugin_completed_event(
    investigation_id: str, plugin_name: str, findings_count: int
) -> WebSocketEvent:
    """Create a plugin completed event."""
    return WebSocketEvent(
        type=EventType.PLUGIN_COMPLETED,
        investigation_id=investigation_id,
        data={
            "plugin": plugin_name,
            "findings_count": findings_count,
        },
    )


def investigation_completed_event(
    investigation_id: str, summary: dict[str, Any]
) -> WebSocketEvent:
    """Create an investigation completed event."""
    return WebSocketEvent(
        type=EventType.INVESTIGATION_COMPLETED,
        investigation_id=investigation_id,
        data={"summary": summary},
    )


def error_event(message: str, investigation_id: str | None = None) -> WebSocketEvent:
    """Create an error event."""
    return WebSocketEvent(
        type=EventType.ERROR,
        investigation_id=investigation_id,
        data={"error": message},
    )
