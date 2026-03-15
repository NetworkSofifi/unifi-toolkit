"""
API routes for Threat Watch webhook configuration
"""
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from shared.controller_context import ControllerContext, get_controller_context
from shared.database import get_db_session
from shared.webhooks import deliver_threat_webhook
from shared.url_validator import validate_webhook_url
from tools.threat_watch.database import ThreatWebhookConfig, scoped_threat_webhooks_query
from tools.threat_watch.models import (
    WebhookCreate,
    WebhookUpdate,
    WebhookResponse,
    WebhooksListResponse,
    SuccessResponse
)

router = APIRouter(prefix="/api/webhooks", tags=["webhooks"])


@router.get("", response_model=WebhooksListResponse)
async def get_webhooks(
    controller: ControllerContext = Depends(get_controller_context),
    db: AsyncSession = Depends(get_db_session)
):
    """
    Get all configured webhooks
    """
    controller_id = controller.controller_id
    result = await db.execute(scoped_threat_webhooks_query(controller_id))
    webhooks = result.scalars().all()

    return WebhooksListResponse(
        webhooks=[WebhookResponse.model_validate(w) for w in webhooks],
        total=len(webhooks)
    )


@router.post("", response_model=WebhookResponse)
async def create_webhook(
    webhook: WebhookCreate,
    controller: ControllerContext = Depends(get_controller_context),
    db: AsyncSession = Depends(get_db_session)
):
    """
    Create a new webhook configuration
    """
    # Validate webhook type
    valid_types = ['slack', 'discord', 'n8n']
    if webhook.webhook_type not in valid_types:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid webhook type. Must be one of: {', '.join(valid_types)}"
        )

    # Validate webhook URL to prevent SSRF
    is_valid, error_msg = validate_webhook_url(webhook.url)
    if not is_valid:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid webhook URL: {error_msg}"
        )

    controller_id = controller.controller_id
    new_webhook = ThreatWebhookConfig(
        controller_id=controller_id,
        name=webhook.name,
        webhook_type=webhook.webhook_type,
        url=webhook.url,
        min_severity=webhook.min_severity,
        event_alert=webhook.event_alert,
        event_block=webhook.event_block,
        enabled=webhook.enabled
    )

    db.add(new_webhook)
    await db.commit()
    await db.refresh(new_webhook)

    return WebhookResponse.model_validate(new_webhook)


@router.get("/{webhook_id}", response_model=WebhookResponse)
async def get_webhook(
    webhook_id: int,
    controller: ControllerContext = Depends(get_controller_context),
    db: AsyncSession = Depends(get_db_session)
):
    """
    Get a specific webhook configuration
    """
    controller_id = controller.controller_id
    result = await db.execute(scoped_threat_webhooks_query(controller_id).where(ThreatWebhookConfig.id == webhook_id))
    webhook = result.scalar_one_or_none()

    if not webhook:
        raise HTTPException(status_code=404, detail="Webhook not found")

    return WebhookResponse.model_validate(webhook)


@router.put("/{webhook_id}", response_model=WebhookResponse)
async def update_webhook(
    webhook_id: int,
    update: WebhookUpdate,
    controller: ControllerContext = Depends(get_controller_context),
    db: AsyncSession = Depends(get_db_session)
):
    """
    Update a webhook configuration
    """
    controller_id = controller.controller_id
    result = await db.execute(scoped_threat_webhooks_query(controller_id).where(ThreatWebhookConfig.id == webhook_id))
    webhook = result.scalar_one_or_none()

    if not webhook:
        raise HTTPException(status_code=404, detail="Webhook not found")

    # Validate new URL if provided
    if update.url is not None:
        is_valid, error_msg = validate_webhook_url(update.url)
        if not is_valid:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid webhook URL: {error_msg}"
            )

    # Update fields if provided
    if update.name is not None:
        webhook.name = update.name
    if update.url is not None:
        webhook.url = update.url
    if update.min_severity is not None:
        webhook.min_severity = update.min_severity
    if update.event_alert is not None:
        webhook.event_alert = update.event_alert
    if update.event_block is not None:
        webhook.event_block = update.event_block
    if update.enabled is not None:
        webhook.enabled = update.enabled

    await db.commit()
    await db.refresh(webhook)

    return WebhookResponse.model_validate(webhook)


@router.delete("/{webhook_id}", response_model=SuccessResponse)
async def delete_webhook(
    webhook_id: int,
    controller: ControllerContext = Depends(get_controller_context),
    db: AsyncSession = Depends(get_db_session)
):
    """
    Delete a webhook configuration
    """
    controller_id = controller.controller_id
    result = await db.execute(scoped_threat_webhooks_query(controller_id).where(ThreatWebhookConfig.id == webhook_id))
    webhook = result.scalar_one_or_none()

    if not webhook:
        raise HTTPException(status_code=404, detail="Webhook not found")

    await db.delete(webhook)
    await db.commit()

    return SuccessResponse(success=True, message=f"Webhook '{webhook.name}' deleted")


@router.post("/{webhook_id}/test", response_model=SuccessResponse)
async def test_webhook(
    webhook_id: int,
    controller: ControllerContext = Depends(get_controller_context),
    db: AsyncSession = Depends(get_db_session)
):
    """
    Test a webhook by sending a test threat notification
    """
    controller_id = controller.controller_id
    result = await db.execute(scoped_threat_webhooks_query(controller_id).where(ThreatWebhookConfig.id == webhook_id))
    webhook = result.scalar_one_or_none()

    if not webhook:
        raise HTTPException(status_code=404, detail="Webhook not found")

    if not webhook.enabled:
        raise HTTPException(status_code=400, detail="Webhook is disabled")

    # Send test notification
    success = await deliver_threat_webhook(
        webhook_url=webhook.url,
        webhook_type=webhook.webhook_type,
        threat_message="Test threat notification from UI Toolkit",
        severity=webhook.min_severity,
        action="block",
        src_ip="192.168.1.100",
        dest_ip="10.0.0.1",
        category="Test",
        is_test=True
    )

    if success:
        # Update last_triggered
        webhook.last_triggered = datetime.now(timezone.utc)
        await db.commit()
        return SuccessResponse(success=True, message="Test webhook delivered successfully")
    else:
        raise HTTPException(status_code=500, detail="Failed to deliver test webhook")
