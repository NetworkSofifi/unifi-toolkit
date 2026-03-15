"""
Wi-Fi Stalker FastAPI application factory
"""
import logging
from pathlib import Path

from fastapi import FastAPI, Request, Depends, WebSocket, WebSocketDisconnect, status
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from tools.wifi_stalker import __version__
from tools.wifi_stalker.routers import devices, config, webhooks
from tools.wifi_stalker.database import TrackedDevice
from tools.wifi_stalker.models import SystemStatus
from tools.wifi_stalker.scheduler import get_last_refresh
from shared.controller_context import (
    ControllerContext,
    get_controller_context,
    resolve_websocket_controller_context,
)
from shared.database import get_db_session
from shared.config import get_settings
from shared.websocket_manager import get_ws_manager
from app.routers.auth import is_auth_enabled, verify_session

logger = logging.getLogger(__name__)

# Get the directory containing this file
BASE_DIR = Path(__file__).parent

# Set up templates and static files
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


def create_app() -> FastAPI:
    """
    Create and configure the Wi-Fi Stalker sub-application

    Returns:
        Configured FastAPI application instance
    """
    app = FastAPI(
        title="Wi-Fi Stalker",
        version=__version__,
        description="Track specific Wi-Fi client devices through UniFi infrastructure"
    )

    # Mount static files
    app.mount(
        "/static",
        StaticFiles(directory=str(BASE_DIR / "static")),
        name="static"
    )

    # Include API routers
    app.include_router(devices.router)
    app.include_router(config.router)
    app.include_router(webhooks.router)

    # Dashboard route
    @app.get("/")
    async def dashboard(request: Request):
        """Serve the Wi-Fi Stalker dashboard"""
        return templates.TemplateResponse(
            "index.html",
            {"request": request, "version": __version__}
        )

    # Status endpoint
    @app.get("/api/status", response_model=SystemStatus, tags=["status"])
    async def get_status(
        controller: ControllerContext = Depends(get_controller_context),
        db: AsyncSession = Depends(get_db_session)
    ):
        """
        Get system status including last refresh time and device counts
        """
        settings = get_settings()
        controller_id = controller.controller_id

        # Get tracked device counts
        result = await db.execute(select(TrackedDevice).where(TrackedDevice.controller_id == controller_id))
        tracked_devices = result.scalars().all()

        tracked_count = len(tracked_devices)
        connected_count = sum(1 for d in tracked_devices if d.is_connected)

        return SystemStatus(
            last_refresh=get_last_refresh(controller.controller_key),
            tracked_devices=tracked_count,
            connected_devices=connected_count,
            refresh_interval_seconds=settings.stalker_refresh_interval
        )

    # WebSocket endpoint for real-time device updates (same manager as main app)
    @app.websocket("/ws")
    async def websocket_endpoint(websocket: WebSocket):
        """WebSocket for Stalker device/status updates. Requires controller_key in query."""
        if is_auth_enabled():
            session_token = websocket.cookies.get("session_token")
            if not session_token or not verify_session(session_token):
                await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
                logger.warning("Stalker WebSocket rejected: not authenticated")
                return

        selected_controller_key = websocket.query_params.get("controller_key")
        try:
            ws_context = await resolve_websocket_controller_context(selected_controller_key)
        except Exception:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            logger.warning(
                "Stalker WebSocket rejected: invalid controller (controller_key=%s)",
                selected_controller_key or "default",
            )
            return

        ws_manager = get_ws_manager()
        await ws_manager.connect(
            websocket,
            controller_key=ws_context.controller_key if ws_context else None,
        )
        try:
            while True:
                data = await websocket.receive_text()
                if data == "ping":
                    await websocket.send_json({"type": "pong"})
        except WebSocketDisconnect:
            pass
        except Exception as e:
            logger.error("Stalker WebSocket error: %s", e)
        finally:
            ws_manager.disconnect(websocket)

    return app
