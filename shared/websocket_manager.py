"""
WebSocket connection manager for real-time device updates
"""
from fastapi import WebSocket
from typing import List, Optional, Dict, Any
import json
import logging

logger = logging.getLogger(__name__)


class WebSocketManager:
    """
    Manages WebSocket connections and broadcasts device updates
    """
    def __init__(self):
        self.active_connections: List[Dict[str, Any]] = []

    async def connect(self, websocket: WebSocket, controller_key: Optional[str] = None):
        """Accept and register a new WebSocket connection"""
        await websocket.accept()
        self.active_connections.append(
            {
                "websocket": websocket,
                "controller_key": controller_key,
            }
        )
        logger.info(
            "WebSocket connected (controller=%s). Total connections: %s",
            controller_key or "default",
            len(self.active_connections),
        )

    def disconnect(self, websocket: WebSocket):
        """Remove a WebSocket connection"""
        existing = next((entry for entry in self.active_connections if entry["websocket"] == websocket), None)
        if existing:
            self.active_connections.remove(existing)
            logger.info("WebSocket disconnected. Total connections: %s", len(self.active_connections))

    def _iter_targets(self, controller_key: Optional[str] = None):
        for entry in self.active_connections:
            subscribed_key = entry.get("controller_key")
            if controller_key and subscribed_key and subscribed_key != controller_key:
                continue
            if controller_key and not subscribed_key:
                # Backward-compatible clients without explicit selection receive default stream only.
                continue
            yield entry["websocket"]

    async def broadcast_device_update(self, device_data: dict, controller_key: Optional[str] = None):
        """
        Broadcast device update to all connected clients

        Args:
            device_data: Dictionary containing device information
        """
        if not self.active_connections:
            return

        message = {
            "type": "device_update",
            "device": device_data
        }

        # Send to all connected clients
        disconnected = []
        for connection in list(self._iter_targets(controller_key=controller_key)):
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.error(f"Error sending to WebSocket: {e}")
                disconnected.append(connection)

        # Remove disconnected clients
        for connection in disconnected:
            self.disconnect(connection)

    async def broadcast(self, data: dict, controller_key: Optional[str] = None):
        """
        Broadcast arbitrary data to all connected clients

        Args:
            data: Dictionary to send as JSON
        """
        if not self.active_connections:
            return

        disconnected = []
        for connection in list(self._iter_targets(controller_key=controller_key)):
            try:
                await connection.send_json(data)
            except Exception as e:
                logger.error(f"Error sending to WebSocket: {e}")
                disconnected.append(connection)

        for connection in disconnected:
            self.disconnect(connection)

    async def broadcast_status_update(self, status_data: dict, controller_key: Optional[str] = None):
        """
        Broadcast system status update to all connected clients

        Args:
            status_data: Dictionary containing status information
        """
        if not self.active_connections:
            return

        message = {
            "type": "status_update",
            "status": status_data
        }

        # Send to all connected clients
        disconnected = []
        for connection in list(self._iter_targets(controller_key=controller_key)):
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.error(f"Error sending to WebSocket: {e}")
                disconnected.append(connection)

        # Remove disconnected clients
        for connection in disconnected:
            self.disconnect(connection)


# Global WebSocket manager instance
ws_manager = WebSocketManager()


def get_ws_manager() -> WebSocketManager:
    """Get the global WebSocket manager instance"""
    return ws_manager


# Convenience function for broadcasting updates
async def broadcast_update(device_data: dict):
    """Broadcast device update to all connected WebSocket clients"""
    await ws_manager.broadcast_device_update(device_data)
