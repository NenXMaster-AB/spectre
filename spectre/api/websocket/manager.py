"""WebSocket connection manager for real-time updates."""

import asyncio
import json
from typing import Any

from fastapi import WebSocket, WebSocketDisconnect

from spectre.api.websocket.events import (
    WebSocketEvent,
    connection_established_event,
    heartbeat_event,
)
from spectre.api.config import settings


class ConnectionManager:
    """Manages WebSocket connections for real-time investigation updates."""

    def __init__(self):
        # Map of investigation_id -> list of connected websockets
        self._connections: dict[str, list[WebSocket]] = {}
        # Global connections (not tied to specific investigation)
        self._global_connections: list[WebSocket] = []
        # Lock for thread-safe operations
        self._lock = asyncio.Lock()

    async def connect(
        self, websocket: WebSocket, investigation_id: str | None = None
    ) -> None:
        """Accept and register a new WebSocket connection."""
        await websocket.accept()

        async with self._lock:
            if investigation_id:
                if investigation_id not in self._connections:
                    self._connections[investigation_id] = []
                self._connections[investigation_id].append(websocket)
            else:
                self._global_connections.append(websocket)

        # Send connection established event
        await self._send_event(websocket, connection_established_event())

    async def disconnect(
        self, websocket: WebSocket, investigation_id: str | None = None
    ) -> None:
        """Remove a WebSocket connection."""
        async with self._lock:
            if investigation_id and investigation_id in self._connections:
                if websocket in self._connections[investigation_id]:
                    self._connections[investigation_id].remove(websocket)
                # Clean up empty lists
                if not self._connections[investigation_id]:
                    del self._connections[investigation_id]
            elif websocket in self._global_connections:
                self._global_connections.remove(websocket)

    async def disconnect_all(self) -> None:
        """Disconnect all WebSocket connections (used on shutdown)."""
        async with self._lock:
            for websocket in self._global_connections:
                try:
                    await websocket.close()
                except Exception:
                    pass
            self._global_connections.clear()

            for investigation_id in list(self._connections.keys()):
                for websocket in self._connections[investigation_id]:
                    try:
                        await websocket.close()
                    except Exception:
                        pass
                del self._connections[investigation_id]

    async def broadcast_to_investigation(
        self, investigation_id: str, event: WebSocketEvent
    ) -> None:
        """Broadcast an event to all connections watching a specific investigation."""
        async with self._lock:
            connections = self._connections.get(investigation_id, [])
            # Also send to global connections
            all_connections = connections + self._global_connections

        # Send outside lock to avoid blocking
        disconnected = []
        for websocket in all_connections:
            try:
                await self._send_event(websocket, event)
            except WebSocketDisconnect:
                disconnected.append(websocket)
            except Exception:
                disconnected.append(websocket)

        # Clean up disconnected websockets
        if disconnected:
            async with self._lock:
                for ws in disconnected:
                    if investigation_id in self._connections and ws in self._connections[investigation_id]:
                        self._connections[investigation_id].remove(ws)
                    if ws in self._global_connections:
                        self._global_connections.remove(ws)

    async def broadcast_global(self, event: WebSocketEvent) -> None:
        """Broadcast an event to all global connections."""
        async with self._lock:
            connections = list(self._global_connections)

        disconnected = []
        for websocket in connections:
            try:
                await self._send_event(websocket, event)
            except Exception:
                disconnected.append(websocket)

        if disconnected:
            async with self._lock:
                for ws in disconnected:
                    if ws in self._global_connections:
                        self._global_connections.remove(ws)

    async def _send_event(self, websocket: WebSocket, event: WebSocketEvent) -> None:
        """Send an event to a specific WebSocket."""
        await websocket.send_json(event.to_json())

    async def send_heartbeat(self, websocket: WebSocket) -> None:
        """Send a heartbeat to keep connection alive."""
        await self._send_event(websocket, heartbeat_event())

    def get_connection_count(self, investigation_id: str | None = None) -> int:
        """Get the number of active connections."""
        if investigation_id:
            return len(self._connections.get(investigation_id, []))
        return len(self._global_connections) + sum(
            len(conns) for conns in self._connections.values()
        )


async def websocket_heartbeat_loop(
    websocket: WebSocket, manager: ConnectionManager
) -> None:
    """Run a heartbeat loop to keep WebSocket connections alive."""
    try:
        while True:
            await asyncio.sleep(settings.ws_heartbeat_interval)
            await manager.send_heartbeat(websocket)
    except Exception:
        pass  # Connection closed
