"""
API routes for Threat Watch ignore rules configuration
"""
import re
import logging
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, or_, and_

from shared.controller_context import ControllerContext, get_controller_context
from shared.database import get_db_session
from tools.threat_watch.database import (
    ThreatIgnoreRule,
    ThreatEvent,
    scoped_threat_ignore_rules_query,
)
from tools.threat_watch.models import (
    IgnoreRuleCreate,
    IgnoreRuleUpdate,
    IgnoreRuleResponse,
    IgnoreRulesListResponse,
    SuccessResponse
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/ignore-rules", tags=["ignore-rules"])

# Simple IPv4 validation pattern
IP_PATTERN = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')


def is_valid_ip(ip: str) -> bool:
    """Validate IPv4 address format"""
    if not IP_PATTERN.match(ip):
        return False
    # Check each octet is 0-255
    octets = ip.split('.')
    return all(0 <= int(octet) <= 255 for octet in octets)


async def apply_ignore_rule_to_existing_events(db: AsyncSession, controller_id: int, rule: ThreatIgnoreRule) -> int:
    """
    Apply an ignore rule to existing events in the database.
    Returns the number of events that were marked as ignored.
    """
    if not rule.enabled:
        return 0

    # Build conditions for matching events
    ip_conditions = []
    if rule.match_source:
        ip_conditions.append(ThreatEvent.src_ip == rule.ip_address)
    if rule.match_destination:
        ip_conditions.append(ThreatEvent.dest_ip == rule.ip_address)

    if not ip_conditions:
        return 0

    # Build severity conditions
    severity_values = []
    if rule.ignore_high:
        severity_values.append(1)
    if rule.ignore_medium:
        severity_values.append(2)
    if rule.ignore_low:
        severity_values.append(3)

    if not severity_values:
        return 0

    # Update matching events that aren't already ignored
    result = await db.execute(
        update(ThreatEvent)
        .where(
            and_(
                or_(*ip_conditions),
                ThreatEvent.controller_id == controller_id,
                ThreatEvent.severity.in_(severity_values),
                ThreatEvent.ignored == False
            )
        )
        .values(ignored=True, ignored_by_rule_id=rule.id)
    )

    count = result.rowcount

    if count > 0:
        # Update rule stats
        rule.events_ignored += count
        rule.last_matched = datetime.now(timezone.utc)
        logger.info(f"Applied ignore rule {rule.id} ({rule.ip_address}) to {count} existing events")

    return count


async def remove_ignore_rule_from_events(db: AsyncSession, controller_id: int, rule_id: int) -> int:
    """
    Remove ignore flag from events that were ignored by a specific rule.
    Returns the number of events that were unmarked.
    """
    result = await db.execute(
        update(ThreatEvent)
        .where(
            ThreatEvent.controller_id == controller_id,
            ThreatEvent.ignored_by_rule_id == rule_id
        )
        .values(ignored=False, ignored_by_rule_id=None)
    )
    return result.rowcount


@router.get("", response_model=IgnoreRulesListResponse)
async def get_ignore_rules(
    controller: ControllerContext = Depends(get_controller_context),
    db: AsyncSession = Depends(get_db_session)
):
    """
    Get all configured ignore rules
    """
    controller_id = controller.controller_id
    result = await db.execute(
        scoped_threat_ignore_rules_query(controller_id).order_by(ThreatIgnoreRule.created_at.desc())
    )
    rules = result.scalars().all()

    return IgnoreRulesListResponse(
        rules=[IgnoreRuleResponse.model_validate(r) for r in rules],
        total=len(rules)
    )


@router.post("", response_model=IgnoreRuleResponse)
async def create_ignore_rule(
    rule: IgnoreRuleCreate,
    controller: ControllerContext = Depends(get_controller_context),
    db: AsyncSession = Depends(get_db_session)
):
    """
    Create a new ignore rule
    """
    controller_id = controller.controller_id

    # Validate IP address
    if not is_valid_ip(rule.ip_address):
        raise HTTPException(
            status_code=400,
            detail="Invalid IP address format. Must be a valid IPv4 address."
        )

    # At least one severity must be selected
    if not (rule.ignore_high or rule.ignore_medium or rule.ignore_low):
        raise HTTPException(
            status_code=400,
            detail="At least one severity level must be selected to ignore."
        )

    # At least one match direction must be selected
    if not (rule.match_source or rule.match_destination):
        raise HTTPException(
            status_code=400,
            detail="Must match at least source or destination IP."
        )

    new_rule = ThreatIgnoreRule(
        controller_id=controller_id,
        ip_address=rule.ip_address,
        description=rule.description,
        ignore_high=rule.ignore_high,
        ignore_medium=rule.ignore_medium,
        ignore_low=rule.ignore_low,
        match_source=rule.match_source,
        match_destination=rule.match_destination,
        enabled=rule.enabled
    )

    db.add(new_rule)
    await db.commit()
    await db.refresh(new_rule)

    # Apply rule to existing events
    if new_rule.enabled:
        await apply_ignore_rule_to_existing_events(db, controller_id, new_rule)
        await db.commit()
        await db.refresh(new_rule)

    return IgnoreRuleResponse.model_validate(new_rule)


@router.get("/{rule_id}", response_model=IgnoreRuleResponse)
async def get_ignore_rule(
    rule_id: int,
    controller: ControllerContext = Depends(get_controller_context),
    db: AsyncSession = Depends(get_db_session)
):
    """
    Get a specific ignore rule
    """
    controller_id = controller.controller_id
    result = await db.execute(
        scoped_threat_ignore_rules_query(controller_id).where(ThreatIgnoreRule.id == rule_id)
    )
    rule = result.scalar_one_or_none()

    if not rule:
        raise HTTPException(status_code=404, detail="Ignore rule not found")

    return IgnoreRuleResponse.model_validate(rule)


@router.put("/{rule_id}", response_model=IgnoreRuleResponse)
async def update_ignore_rule(
    rule_id: int,
    update: IgnoreRuleUpdate,
    controller: ControllerContext = Depends(get_controller_context),
    db: AsyncSession = Depends(get_db_session)
):
    """
    Update an ignore rule
    """
    controller_id = controller.controller_id
    result = await db.execute(
        scoped_threat_ignore_rules_query(controller_id).where(ThreatIgnoreRule.id == rule_id)
    )
    rule = result.scalar_one_or_none()

    if not rule:
        raise HTTPException(status_code=404, detail="Ignore rule not found")

    # Validate new IP if provided
    if update.ip_address is not None:
        if not is_valid_ip(update.ip_address):
            raise HTTPException(
                status_code=400,
                detail="Invalid IP address format. Must be a valid IPv4 address."
            )

    # Update fields if provided
    if update.ip_address is not None:
        rule.ip_address = update.ip_address
    if update.description is not None:
        rule.description = update.description
    if update.ignore_high is not None:
        rule.ignore_high = update.ignore_high
    if update.ignore_medium is not None:
        rule.ignore_medium = update.ignore_medium
    if update.ignore_low is not None:
        rule.ignore_low = update.ignore_low
    if update.match_source is not None:
        rule.match_source = update.match_source
    if update.match_destination is not None:
        rule.match_destination = update.match_destination
    if update.enabled is not None:
        rule.enabled = update.enabled

    # Validate after update
    if not (rule.ignore_high or rule.ignore_medium or rule.ignore_low):
        raise HTTPException(
            status_code=400,
            detail="At least one severity level must be selected to ignore."
        )
    if not (rule.match_source or rule.match_destination):
        raise HTTPException(
            status_code=400,
            detail="Must match at least source or destination IP."
        )

    # First, unmark events that were ignored by this rule
    await remove_ignore_rule_from_events(db, controller_id, rule.id)
    rule.events_ignored = 0

    await db.commit()
    await db.refresh(rule)

    # Re-apply rule to existing events with updated criteria
    if rule.enabled:
        await apply_ignore_rule_to_existing_events(db, controller_id, rule)
        await db.commit()
        await db.refresh(rule)

    return IgnoreRuleResponse.model_validate(rule)


@router.delete("/{rule_id}", response_model=SuccessResponse)
async def delete_ignore_rule(
    rule_id: int,
    controller: ControllerContext = Depends(get_controller_context),
    db: AsyncSession = Depends(get_db_session)
):
    """
    Delete an ignore rule
    """
    controller_id = controller.controller_id
    result = await db.execute(
        scoped_threat_ignore_rules_query(controller_id).where(ThreatIgnoreRule.id == rule_id)
    )
    rule = result.scalar_one_or_none()

    if not rule:
        raise HTTPException(status_code=404, detail="Ignore rule not found")

    ip = rule.ip_address

    # Unmark events that were ignored by this rule
    unmarked = await remove_ignore_rule_from_events(db, controller_id, rule_id)
    if unmarked > 0:
        logger.info(f"Unmarked {unmarked} events when deleting ignore rule {rule_id}")

    await db.delete(rule)
    await db.commit()

    return SuccessResponse(success=True, message=f"Ignore rule for '{ip}' deleted")


@router.post("/{rule_id}/reset-counter", response_model=SuccessResponse)
async def reset_ignore_counter(
    rule_id: int,
    controller: ControllerContext = Depends(get_controller_context),
    db: AsyncSession = Depends(get_db_session)
):
    """
    Reset the events_ignored counter for a rule
    """
    controller_id = controller.controller_id
    result = await db.execute(
        scoped_threat_ignore_rules_query(controller_id).where(ThreatIgnoreRule.id == rule_id)
    )
    rule = result.scalar_one_or_none()

    if not rule:
        raise HTTPException(status_code=404, detail="Ignore rule not found")

    rule.events_ignored = 0
    rule.last_matched = None
    await db.commit()

    return SuccessResponse(success=True, message="Counter reset")
