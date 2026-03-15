"""
Shared controller resolution helpers for request-scoped controller selection.
"""
from dataclasses import dataclass
from typing import Optional

from fastapi import Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from shared.database import get_db_session, get_database
from shared.controller_registry import (
    ResolvedController,
    get_controller_by_key,
    get_default_controller,
)


@dataclass
class ControllerContext:
    controller_id: int
    controller_key: str
    display_name: str
    is_default: bool


def _to_context(controller: ResolvedController) -> ControllerContext:
    return ControllerContext(
        controller_id=controller.id,
        controller_key=controller.controller_key,
        display_name=controller.display_name,
        is_default=controller.is_default,
    )


async def resolve_controller_context(
    db: AsyncSession,
    controller_key: Optional[str] = None,
    include_inactive: bool = False,
) -> ControllerContext:
    """
    Resolve explicit controller key or fall back to default controller.
    """
    if controller_key:
        controller = await get_controller_by_key(
            db,
            controller_key=controller_key,
            include_inactive=include_inactive,
        )
        if not controller:
            raise HTTPException(status_code=404, detail=f"Controller '{controller_key}' not found")
    else:
        controller = await get_default_controller(db)
        if not controller:
            raise HTTPException(status_code=404, detail="No controller configured")

    if not include_inactive and not controller.is_active:
        raise HTTPException(
            status_code=400,
            detail=f"Controller '{controller.controller_key}' is disabled",
        )

    return _to_context(controller)


async def get_controller_context(
    controller_key: Optional[str] = Query(default=None, description="Optional controller key"),
    db: AsyncSession = Depends(get_db_session),
) -> ControllerContext:
    """
    FastAPI dependency for HTTP routes.
    """
    return await resolve_controller_context(db, controller_key=controller_key, include_inactive=False)


async def resolve_websocket_controller_context(
    controller_key: Optional[str] = None,
) -> Optional[ControllerContext]:
    """
    Resolve controller context for websocket subscriptions using query params.
    """
    db = get_database()
    async for session in db.get_session():
        return await resolve_controller_context(
            session,
            controller_key=controller_key,
            include_inactive=False,
        )
    return None
