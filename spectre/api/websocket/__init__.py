"""WebSocket handling for real-time updates."""

from .manager import ConnectionManager
from .events import EventType, WebSocketEvent

__all__ = ["ConnectionManager", "EventType", "WebSocketEvent"]
