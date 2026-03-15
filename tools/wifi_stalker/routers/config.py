"""
UniFi configuration API endpoints
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime, timezone

from shared.database import get_db_session
from shared.controller_context import ControllerContext, get_controller_context
from shared.crypto import encrypt_password, encrypt_api_key
from shared.models.controller_config import ControllerConfig
from shared.unifi_client import UniFiClient
from shared.controller_registry import (
    create_unifi_client,
    get_controller_by_key,
    upsert_default_controller,
)
from tools.wifi_stalker.models import (
    UniFiConfigCreate,
    UniFiConfigResponse,
    UniFiConnectionTest,
    SuccessResponse
)

router = APIRouter(prefix="/api/config", tags=["configuration"])


@router.post("/unifi", response_model=SuccessResponse)
async def save_unifi_config(
    config: UniFiConfigCreate,
    db: AsyncSession = Depends(get_db_session)
):
    """
    Save UniFi controller configuration
    Supports both legacy (username/password) and UniFi OS (API key) authentication
    """
    # Validate that either password or API key is provided
    if not config.password and not config.api_key:
        raise HTTPException(
            status_code=400,
            detail="Either password or api_key must be provided"
        )

    # Encrypt credentials
    encrypted_password = None
    encrypted_api_key = None

    if config.password:
        encrypted_password = encrypt_password(config.password)
    if config.api_key:
        encrypted_api_key = encrypt_api_key(config.api_key)

    await upsert_default_controller(
        db,
        controller_url=config.controller_url,
        username=config.username,
        password_encrypted=encrypted_password,
        api_key_encrypted=encrypted_api_key,
        site_id=config.site_id,
        verify_ssl=config.verify_ssl,
        is_unifi_os=False,
        display_name="Default Controller",
    )

    await db.commit()

    return SuccessResponse(
        success=True,
        message="UniFi configuration saved successfully"
    )


@router.get("/unifi", response_model=UniFiConfigResponse)
async def get_unifi_config(
    controller: ControllerContext = Depends(get_controller_context),
    db: AsyncSession = Depends(get_db_session)
):
    """
    Get current UniFi configuration (without password/API key)
    """
    config = await get_controller_by_key(db, controller.controller_key, include_inactive=False)

    if not config:
        raise HTTPException(
            status_code=404,
            detail="UniFi configuration not found. Please configure your UniFi controller first."
        )

    # Create response with has_api_key indicator
    return UniFiConfigResponse(
        id=config.id,
        controller_url=config.controller_url,
        username=config.username,
        has_api_key=config.api_key_encrypted is not None,
        site_id=config.site_id,
        verify_ssl=config.verify_ssl,
        last_successful_connection=config.last_successful_connection
    )


@router.get("/unifi/test", response_model=UniFiConnectionTest)
async def test_unifi_connection(
    controller: ControllerContext = Depends(get_controller_context),
    db: AsyncSession = Depends(get_db_session)
):
    """
    Test connection to UniFi controller
    """
    config = await get_controller_by_key(db, controller.controller_key, include_inactive=False)

    if not config:
        return UniFiConnectionTest(
            connected=False,
            error="UniFi configuration not found. Please configure your UniFi controller first."
        )

    try:
        client = create_unifi_client(config)
    except Exception as e:
        return UniFiConnectionTest(
            connected=False,
            error=f"Failed to decrypt credentials: {str(e)}"
        )

    test_result = await client.test_connection()

    # Update last successful connection time if successful
    if test_result.get("connected"):
        row = (
            await db.execute(
                select(ControllerConfig).where(ControllerConfig.controller_key == config.controller_key)
            )
        ).scalar_one_or_none()
        if row:
            row.last_successful_connection = datetime.now(timezone.utc)
            await db.commit()

    return UniFiConnectionTest(**test_result)


async def get_unifi_client(
    controller: ControllerContext = Depends(get_controller_context),
    db: AsyncSession = Depends(get_db_session),
) -> UniFiClient:
    """
    Dependency to get a configured UniFi client instance
    """
    config = await get_controller_by_key(db, controller.controller_key, include_inactive=False)

    if not config:
        raise HTTPException(
            status_code=404,
            detail="UniFi configuration not found. Please configure your UniFi controller first."
        )

    try:
        return create_unifi_client(config)
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to decrypt UniFi credentials: {str(e)}"
        )
