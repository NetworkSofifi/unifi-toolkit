"""
Shared UniFi session registry.

Provides persistent UniFiClient instances keyed by controller key to avoid
repeated logins and support a multi-controller future architecture.

Backward compatibility:
- `get_shared_client()` still returns the default controller client.
- Existing schedulers can remain unchanged during the transition.
"""
import logging
from typing import Dict, Optional

from shared.database import get_database
from shared.controller_registry import create_unifi_client, get_default_controller, get_controller_by_key
from shared.unifi_client import UniFiClient

logger = logging.getLogger(__name__)

# Persistent clients keyed by controller key
_shared_clients: Dict[str, UniFiClient] = {}


async def _get_or_connect_client(controller_key: str, build_client) -> Optional[UniFiClient]:
    """
    Reuse a live client if possible, otherwise build and connect a new one.
    """
    existing = _shared_clients.get(controller_key)
    if existing is not None and existing._session is not None and not existing._session.closed:
        return existing

    if existing is not None:
        try:
            await existing.disconnect()
        except Exception:
            pass
        _shared_clients.pop(controller_key, None)

    client = build_client()
    connected = await client.connect()
    if not connected:
        await client.disconnect()
        return None

    _shared_clients[controller_key] = client
    return client


async def get_shared_client(controller_key: Optional[str] = None) -> Optional[UniFiClient]:
    """
    Get a shared UniFi client.

    Args:
        controller_key: Optional controller key. When omitted, uses the current
            default controller from the registry.

    Returns:
        Connected UniFiClient, or None if no default controller exists or
        connection fails.
    """
    db_instance = get_database()
    async for session in db_instance.get_session():
        if controller_key:
            controller = await get_controller_by_key(session, controller_key, include_inactive=False)
        else:
            controller = await get_default_controller(session)
        if not controller:
            logger.warning(
                "No controller configured for shared session (controller_key=%s)",
                controller_key or "default"
            )
            return None

        logger.info("Ensuring shared UniFi session for controller '%s'", controller.controller_key)
        return await _get_or_connect_client(
            controller.controller_key,
            lambda: create_unifi_client(controller),
        )


async def invalidate_shared_client(controller_key: Optional[str] = None):
    """
    Disconnect and clear shared clients.

    Called when controller config changes so next scheduler run creates fresh clients.
    """
    if not _shared_clients:
        return

    if controller_key:
        client = _shared_clients.get(controller_key)
        if not client:
            return
        logger.info("Invalidating shared UniFi session for controller '%s'", controller_key)
        try:
            await client.disconnect()
        except Exception as e:
            logger.debug("Error disconnecting shared client '%s': %s", controller_key, e)
        _shared_clients.pop(controller_key, None)
        return

    logger.info("Invalidating all shared UniFi sessions (config changed)")
    for key, client in list(_shared_clients.items()):
        try:
            await client.disconnect()
        except Exception as e:
            logger.debug("Error disconnecting shared client '%s': %s", key, e)
    _shared_clients.clear()


async def close_shared_client():
    """
    Graceful shutdown — disconnect and clear all shared clients.

    Called from the app lifespan shutdown handler.
    """
    if not _shared_clients:
        return

    logger.info("Closing shared UniFi sessions (shutdown)")
    for key, client in list(_shared_clients.items()):
        try:
            await client.disconnect()
        except Exception as e:
            logger.debug(f"Error closing shared client '{key}': {e}")
    _shared_clients.clear()
