"""
Threat Watch FastAPI application factory
"""
from fastapi import FastAPI, Request, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pathlib import Path
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from datetime import datetime, timezone, timedelta

from tools.threat_watch import __version__
from tools.threat_watch.routers import events, config, webhooks, ignore_rules
from tools.threat_watch.database import ThreatEvent
from tools.threat_watch.models import SystemStatus
from tools.threat_watch.scheduler import get_last_refresh, DEFAULT_REFRESH_INTERVAL
from shared.controller_context import ControllerContext, get_controller_context
from shared.database import get_db_session
from shared.controller_registry import get_controller_by_key, create_unifi_client
import logging

logger = logging.getLogger(__name__)

# Get the directory containing this file
BASE_DIR = Path(__file__).parent

# Set up templates
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


def create_app() -> FastAPI:
    """
    Create and configure the Threat Watch sub-application

    Returns:
        Configured FastAPI application instance
    """
    app = FastAPI(
        title="Threat Watch",
        version=__version__,
        description="IDS/IPS monitoring and threat analysis for UniFi networks"
    )

    # Mount static files
    app.mount(
        "/static",
        StaticFiles(directory=str(BASE_DIR / "static")),
        name="threats_static"
    )

    # Include API routers
    app.include_router(events.router)
    app.include_router(config.router)
    app.include_router(webhooks.router)
    app.include_router(ignore_rules.router)

    # Dashboard route
    @app.get("/")
    async def dashboard(
        request: Request,
        controller: ControllerContext = Depends(get_controller_context),
        db: AsyncSession = Depends(get_db_session)
    ):
        """Serve the Threat Watch dashboard"""
        from shared import cache

        # Check gateway and IDS/IPS capability using cached data
        # This avoids making a separate connection - the main dashboard's
        # system-status call already fetches and caches this info
        supports_ids_ips = False
        gateway_info = None
        ips_settings = None
        gateway_error = None

        try:
            # First try to use cached gateway info
            cached_gateway = cache.get_gateway_info(controller_key=controller.controller_key)
            cached_ips = cache.get_ips_settings(controller_key=controller.controller_key)

            if cached_gateway is not None:
                logger.debug("Using cached gateway info for Threat Watch dashboard")
                gateway_info = cached_gateway
                ips_settings = cached_ips

                # Check if this is a legacy controller
                is_legacy = not cached_gateway.get("is_unifi_os", True)

                if not cached_gateway.get("has_gateway"):
                    gateway_error = "No UniFi Gateway found on this site"
                elif is_legacy:
                    gateway_name = cached_gateway.get("gateway_name", "Unknown")
                    gateway_error = f"IDS/IPS API not available on legacy controllers ({gateway_name})"
                elif not cached_gateway.get("supports_ids_ips"):
                    gateway_name = cached_gateway.get("gateway_name", "Unknown")
                    gateway_error = f"Your gateway ({gateway_name}) does not support IDS/IPS"
                else:
                    supports_ids_ips = True

                    # Check if IDS/IPS is actually enabled
                    if ips_settings and not ips_settings.get("ips_enabled"):
                        # Gateway supports it, but it's disabled
                        gateway_error = "ids_disabled"  # Special flag for UI

            else:
                # No cache - fetch data directly
                logger.debug("No cached gateway info, fetching directly for Threat Watch")
                unifi_config = await get_controller_by_key(
                    db,
                    controller_key=controller.controller_key,
                    include_inactive=False,
                )

                if not unifi_config:
                    gateway_error = "UniFi controller not configured"
                else:
                    # Fetch gateway info directly
                    client = create_unifi_client(unifi_config)

                    try:
                        connected = await client.connect()
                        if connected:
                            gateway_info = await client.get_gateway_info()
                            is_legacy = not client.is_unifi_os

                            # Cache for future use
                            cache.set_gateway_info({
                                **gateway_info,
                                "is_unifi_os": client.is_unifi_os
                            }, controller_key=controller.controller_key)

                            if not gateway_info.get("has_gateway"):
                                gateway_error = "No UniFi Gateway found on this site"
                            elif is_legacy:
                                gateway_name = gateway_info.get("gateway_name", "Unknown")
                                gateway_error = f"IDS/IPS API not available on legacy controllers ({gateway_name})"
                            elif not gateway_info.get("supports_ids_ips"):
                                gateway_name = gateway_info.get("gateway_name", "Unknown")
                                gateway_error = f"Your gateway ({gateway_name}) does not support IDS/IPS"
                            else:
                                supports_ids_ips = True
                                # Get IPS settings
                                ips_settings = await client.get_ips_settings()
                                if ips_settings:
                                    cache.set_ips_settings(ips_settings, controller_key=controller.controller_key)
                                    if not ips_settings.get("ips_enabled"):
                                        gateway_error = "ids_disabled"
                        else:
                            gateway_error = "Failed to connect to UniFi controller"
                    except Exception as e:
                        logger.error(f"Error fetching gateway info: {e}")
                        gateway_error = str(e)
                    finally:
                        await client.disconnect()

        except Exception as e:
            logger.error(f"Error loading gateway info: {e}")
            gateway_error = "Configuration error"

        return templates.TemplateResponse(
            "index.html",
            {
                "request": request,
                "version": __version__,
                "supports_ids_ips": supports_ids_ips,
                "gateway_info": gateway_info,
                "ips_settings": ips_settings,
                "gateway_error": gateway_error
            }
        )

    # Status endpoint
    @app.get("/api/status", response_model=SystemStatus, tags=["status"])
    async def get_status(
        controller: ControllerContext = Depends(get_controller_context),
        db: AsyncSession = Depends(get_db_session)
    ):
        """
        Get system status including last refresh time and event counts
        """
        controller_id = controller.controller_id

        now = datetime.now(timezone.utc)
        day_ago = now - timedelta(days=1)

        # Get total event count
        total_result = await db.execute(
            select(func.count(ThreatEvent.id)).where(ThreatEvent.controller_id == controller_id)
        )
        total_events = total_result.scalar() or 0

        # Get events in last 24 hours
        result_24h = await db.execute(
            select(func.count(ThreatEvent.id)).where(
                ThreatEvent.controller_id == controller_id,
                ThreatEvent.timestamp >= day_ago,
            )
        )
        events_24h = result_24h.scalar() or 0

        return SystemStatus(
            last_refresh=get_last_refresh(controller.controller_key),
            total_events=total_events,
            events_24h=events_24h,
            refresh_interval_seconds=DEFAULT_REFRESH_INTERVAL
        )

    return app
