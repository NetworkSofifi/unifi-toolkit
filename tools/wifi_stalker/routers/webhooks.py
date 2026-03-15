"""
API endpoints for webhook configuration
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timezone

from shared.controller_context import ControllerContext, get_controller_context
from shared.database import get_db_session
from shared.webhooks import deliver_webhook
from shared.url_validator import validate_webhook_url
from tools.wifi_stalker.database import WebhookConfig, scoped_webhooks_query
from tools.wifi_stalker.models import (
    WebhookCreate,
    WebhookUpdate,
    WebhookResponse,
    WebhooksListResponse,
    SuccessResponse
)

router = APIRouter(prefix="/api/webhooks", tags=["webhooks"])


@router.get("", response_model=WebhooksListResponse)
async def list_webhooks(
    controller: ControllerContext = Depends(get_controller_context),
    session: AsyncSession = Depends(get_db_session),
):
    """
    Get all configured webhooks
    """
    controller_id = controller.controller_id

    result = await session.execute(scoped_webhooks_query(controller_id))
    webhooks = result.scalars().all()

    return WebhooksListResponse(
        webhooks=[WebhookResponse.model_validate(w) for w in webhooks],
        total=len(webhooks)
    )


@router.post("", response_model=WebhookResponse)
async def create_webhook(
    webhook: WebhookCreate,
    controller: ControllerContext = Depends(get_controller_context),
    session: AsyncSession = Depends(get_db_session)
):
    """
    Create a new webhook configuration
    """
    # Validate webhook type
    if webhook.webhook_type not in ['slack', 'discord', 'n8n']:
        raise HTTPException(
            status_code=400,
            detail="Invalid webhook type. Must be 'slack', 'discord', or 'n8n'"
        )

    # Validate webhook URL to prevent SSRF
    is_valid, error_msg = validate_webhook_url(webhook.url)
    if not is_valid:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid webhook URL: {error_msg}"
        )

    # Create new webhook
    controller_id = controller.controller_id

    new_webhook = WebhookConfig(
        controller_id=controller_id,
        name=webhook.name,
        webhook_type=webhook.webhook_type,
        url=webhook.url,
        event_device_connected=webhook.event_device_connected,
        event_device_disconnected=webhook.event_device_disconnected,
        event_device_roamed=webhook.event_device_roamed,
        enabled=webhook.enabled
    )

    session.add(new_webhook)
    await session.commit()
    await session.refresh(new_webhook)

    return WebhookResponse.model_validate(new_webhook)


@router.get("/{webhook_id}", response_model=WebhookResponse)
async def get_webhook(
    webhook_id: int,
    controller: ControllerContext = Depends(get_controller_context),
    session: AsyncSession = Depends(get_db_session)
):
    """
    Get a specific webhook by ID
    """
    controller_id = controller.controller_id
    result = await session.execute(scoped_webhooks_query(controller_id).where(WebhookConfig.id == webhook_id))
    webhook = result.scalar_one_or_none()

    if not webhook:
        raise HTTPException(status_code=404, detail="Webhook not found")

    return WebhookResponse.model_validate(webhook)


@router.put("/{webhook_id}", response_model=WebhookResponse)
async def update_webhook(
    webhook_id: int,
    webhook_update: WebhookUpdate,
    controller: ControllerContext = Depends(get_controller_context),
    session: AsyncSession = Depends(get_db_session)
):
    """
    Update an existing webhook
    """
    controller_id = controller.controller_id
    result = await session.execute(scoped_webhooks_query(controller_id).where(WebhookConfig.id == webhook_id))
    webhook = result.scalar_one_or_none()

    if not webhook:
        raise HTTPException(status_code=404, detail="Webhook not found")

    # Validate new URL if provided
    if webhook_update.url is not None:
        is_valid, error_msg = validate_webhook_url(webhook_update.url)
        if not is_valid:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid webhook URL: {error_msg}"
            )

    # Update fields if provided
    if webhook_update.name is not None:
        webhook.name = webhook_update.name
    if webhook_update.url is not None:
        webhook.url = webhook_update.url
    if webhook_update.event_device_connected is not None:
        webhook.event_device_connected = webhook_update.event_device_connected
    if webhook_update.event_device_disconnected is not None:
        webhook.event_device_disconnected = webhook_update.event_device_disconnected
    if webhook_update.event_device_roamed is not None:
        webhook.event_device_roamed = webhook_update.event_device_roamed
    if webhook_update.enabled is not None:
        webhook.enabled = webhook_update.enabled

    await session.commit()
    await session.refresh(webhook)

    return WebhookResponse.model_validate(webhook)


@router.delete("/{webhook_id}", response_model=SuccessResponse)
async def delete_webhook(
    webhook_id: int,
    controller: ControllerContext = Depends(get_controller_context),
    session: AsyncSession = Depends(get_db_session)
):
    """
    Delete a webhook
    """
    controller_id = controller.controller_id
    result = await session.execute(scoped_webhooks_query(controller_id).where(WebhookConfig.id == webhook_id))
    webhook = result.scalar_one_or_none()

    if not webhook:
        raise HTTPException(status_code=404, detail="Webhook not found")

    await session.delete(webhook)
    await session.commit()

    return SuccessResponse(success=True, message="Webhook deleted successfully")


@router.post("/{webhook_id}/test", response_model=SuccessResponse)
async def test_webhook(
    webhook_id: int,
    controller: ControllerContext = Depends(get_controller_context),
    session: AsyncSession = Depends(get_db_session)
):
    """
    Test a webhook by sending a test notification
    """
    controller_id = controller.controller_id
    result = await session.execute(scoped_webhooks_query(controller_id).where(WebhookConfig.id == webhook_id))
    webhook = result.scalar_one_or_none()

    if not webhook:
        raise HTTPException(status_code=404, detail="Webhook not found")

    if not webhook.enabled:
        raise HTTPException(status_code=400, detail="Webhook is disabled")

    # Send test notification
    success = await deliver_webhook(
        webhook_url=webhook.url,
        webhook_type=webhook.webhook_type,
        event_type='connected',
        device_name='Test Device',
        device_mac='AA:BB:CC:DD:EE:FF',
        ap_name='Test Access Point',
        signal_strength=-45
    )

    if success:
        # Update last_triggered
        webhook.last_triggered = datetime.now(timezone.utc)
        await session.commit()
        return SuccessResponse(success=True, message="Test webhook delivered successfully")
    else:
        raise HTTPException(status_code=500, detail="Failed to deliver test webhook")
