"""
Controller registry service.

Provides a compatibility layer that prefers the new multi-controller registry
while still supporting the legacy single-controller `unifi_config` row.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional, List
import re

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from shared.models.controller_config import ControllerConfig
from shared.models.unifi_config import UniFiConfig
from shared.crypto import decrypt_password, decrypt_api_key
from shared.unifi_client import UniFiClient


@dataclass
class ResolvedController:
    """
    Unified in-memory representation of a controller config.
    """

    id: int
    controller_key: str
    display_name: str
    controller_url: str
    username: Optional[str]
    password_encrypted: Optional[bytes]
    api_key_encrypted: Optional[bytes]
    site_id: str
    verify_ssl: bool
    is_unifi_os: bool
    last_successful_connection: Optional[datetime]
    is_default: bool
    is_active: bool
    source: str  # "registry" or "legacy"


def normalize_controller_key(value: str) -> str:
    """
    Normalize a controller key to a stable slug-like value.
    """
    normalized = re.sub(r"[^a-z0-9]+", "-", (value or "").strip().lower()).strip("-")
    return normalized or "default"


def _from_registry_row(row: ControllerConfig) -> ResolvedController:
    return ResolvedController(
        id=row.id,
        controller_key=row.controller_key,
        display_name=row.display_name,
        controller_url=row.controller_url,
        username=row.username,
        password_encrypted=row.password_encrypted,
        api_key_encrypted=row.api_key_encrypted,
        site_id=row.site_id,
        verify_ssl=row.verify_ssl,
        is_unifi_os=row.is_unifi_os,
        last_successful_connection=row.last_successful_connection,
        is_default=row.is_default,
        is_active=row.is_active,
        source="registry",
    )


def _from_legacy_row(row: UniFiConfig) -> ResolvedController:
    return ResolvedController(
        id=row.id,
        controller_key="default",
        display_name="Default Controller",
        controller_url=row.controller_url,
        username=row.username,
        password_encrypted=row.password_encrypted,
        api_key_encrypted=row.api_key_encrypted,
        site_id=row.site_id,
        verify_ssl=row.verify_ssl,
        is_unifi_os=row.is_unifi_os,
        last_successful_connection=row.last_successful_connection,
        is_default=True,
        is_active=True,
        source="legacy",
    )


async def list_controllers(db: AsyncSession, include_inactive: bool = True) -> List[ResolvedController]:
    """
    Return controller registry entries with legacy fallback.

    Transitional compatibility:
    - We still read legacy `unifi_config` when `controller_config` is empty.
    - Compatibility should remain until at least one stable release cycle has
      migrated all active installs to registry-backed rows.
    """
    query = select(ControllerConfig).order_by(ControllerConfig.is_default.desc(), ControllerConfig.id.asc())
    if not include_inactive:
        query = query.where(ControllerConfig.is_active.is_(True))

    registry_rows = (await db.execute(query)).scalars().all()
    if registry_rows:
        return [_from_registry_row(row) for row in registry_rows]

    legacy_row = (
        await db.execute(select(UniFiConfig).where(UniFiConfig.id == 1))
    ).scalar_one_or_none()
    if legacy_row:
        return [_from_legacy_row(legacy_row)]

    return []


async def list_enabled_controllers(db: AsyncSession) -> List[ResolvedController]:
    """
    Return active controller entries.
    """
    return await list_controllers(db, include_inactive=False)


async def get_controller_by_key(
    db: AsyncSession,
    controller_key: str,
    include_inactive: bool = False,
) -> Optional[ResolvedController]:
    """
    Resolve a controller by registry key with legacy fallback.
    """
    if not controller_key:
        return await get_default_controller(db)

    query = select(ControllerConfig).where(ControllerConfig.controller_key == controller_key)
    if not include_inactive:
        query = query.where(ControllerConfig.is_active.is_(True))
    row = (await db.execute(query)).scalar_one_or_none()
    if row:
        return _from_registry_row(row)

    legacy_row = (await db.execute(select(UniFiConfig).where(UniFiConfig.id == 1))).scalar_one_or_none()
    if legacy_row and controller_key in {"legacy-default", "default"}:
        return _from_legacy_row(legacy_row)

    return None


async def get_controller_by_id(
    db: AsyncSession,
    controller_id: int,
    include_inactive: bool = False,
) -> Optional[ResolvedController]:
    """
    Resolve a controller by registry ID.
    """
    if controller_id is None:
        return None

    query = select(ControllerConfig).where(ControllerConfig.id == controller_id)
    if not include_inactive:
        query = query.where(ControllerConfig.is_active.is_(True))
    row = (await db.execute(query)).scalar_one_or_none()
    if row:
        return _from_registry_row(row)
    return None


async def get_default_controller(db: AsyncSession) -> Optional[ResolvedController]:
    """
    Resolve the currently selected default controller.
    """
    default_row = (
        await db.execute(
            select(ControllerConfig)
            .where(ControllerConfig.is_default.is_(True), ControllerConfig.is_active.is_(True))
            .order_by(ControllerConfig.id.asc())
        )
    ).scalar_one_or_none()
    if default_row:
        return _from_registry_row(default_row)

    first_active_row = (
        await db.execute(
            select(ControllerConfig)
            .where(ControllerConfig.is_active.is_(True))
            .order_by(ControllerConfig.id.asc())
        )
    ).scalar_one_or_none()
    if first_active_row:
        return _from_registry_row(first_active_row)

    legacy_row = (
        await db.execute(select(UniFiConfig).where(UniFiConfig.id == 1))
    ).scalar_one_or_none()
    if legacy_row:
        return _from_legacy_row(legacy_row)

    return None


async def get_default_controller_id(db: AsyncSession) -> Optional[int]:
    """
    Resolve and return the default controller registry ID.

    If only the legacy row exists, lazily creates a registry-backed default row
    so controller-scoped tool tables can safely reference `controller_config.id`.
    """
    resolved = await get_default_controller(db)
    if not resolved:
        return None

    if resolved.source == "registry":
        return resolved.id

    # Legacy fallback path: materialize a default registry row from legacy config.
    materialized = await upsert_default_controller(
        db,
        controller_url=resolved.controller_url,
        username=resolved.username,
        password_encrypted=resolved.password_encrypted,
        api_key_encrypted=resolved.api_key_encrypted,
        site_id=resolved.site_id,
        verify_ssl=resolved.verify_ssl,
        is_unifi_os=resolved.is_unifi_os,
        display_name="Default Controller",
    )
    return materialized.id


async def upsert_default_controller(
    db: AsyncSession,
    *,
    controller_url: str,
    username: Optional[str],
    password_encrypted: Optional[bytes],
    api_key_encrypted: Optional[bytes],
    site_id: str,
    verify_ssl: bool,
    is_unifi_os: bool,
    display_name: str = "Default Controller",
) -> ResolvedController:
    """
    Create or update the default registry controller and mirror it to legacy row.
    """
    existing_default = (
        await db.execute(
            select(ControllerConfig)
            .where(ControllerConfig.is_default.is_(True))
            .order_by(ControllerConfig.id.asc())
        )
    ).scalar_one_or_none()

    if existing_default:
        existing_default.display_name = display_name
        existing_default.controller_url = controller_url
        existing_default.username = username
        existing_default.password_encrypted = password_encrypted
        existing_default.api_key_encrypted = api_key_encrypted
        existing_default.site_id = site_id
        existing_default.verify_ssl = verify_ssl
        existing_default.is_unifi_os = is_unifi_os
        existing_default.is_active = True
        existing_default.updated_at = datetime.now(timezone.utc)
        row = existing_default
    else:
        row = ControllerConfig(
            controller_key=normalize_controller_key(display_name),
            display_name=display_name,
            controller_url=controller_url,
            username=username,
            password_encrypted=password_encrypted,
            api_key_encrypted=api_key_encrypted,
            site_id=site_id,
            verify_ssl=verify_ssl,
            is_unifi_os=is_unifi_os,
            is_default=True,
            is_active=True,
        )
        db.add(row)

    # Ensure only one default in registry
    await db.flush()
    await db.execute(
        update(ControllerConfig)
        .where(ControllerConfig.id != row.id, ControllerConfig.is_default.is_(True))
        .values(is_default=False)
    )

    # Backward-compatibility mirror into legacy single-row table
    legacy_row = (await db.execute(select(UniFiConfig).where(UniFiConfig.id == 1))).scalar_one_or_none()
    if legacy_row:
        legacy_row.controller_url = controller_url
        legacy_row.username = username
        legacy_row.password_encrypted = password_encrypted
        legacy_row.api_key_encrypted = api_key_encrypted
        legacy_row.site_id = site_id
        legacy_row.verify_ssl = verify_ssl
        legacy_row.is_unifi_os = is_unifi_os
    else:
        db.add(
            UniFiConfig(
                id=1,
                controller_url=controller_url,
                username=username,
                password_encrypted=password_encrypted,
                api_key_encrypted=api_key_encrypted,
                site_id=site_id,
                verify_ssl=verify_ssl,
                is_unifi_os=is_unifi_os,
            )
        )

    await db.flush()
    await db.refresh(row)
    return _from_registry_row(row)


def create_unifi_client(controller: ResolvedController) -> UniFiClient:
    """
    Build a UniFiClient for the supplied resolved controller.
    """
    password = decrypt_password(controller.password_encrypted) if controller.password_encrypted else None
    api_key = decrypt_api_key(controller.api_key_encrypted) if controller.api_key_encrypted else None

    return UniFiClient(
        host=controller.controller_url,
        username=controller.username,
        password=password,
        api_key=api_key,
        site=controller.site_id,
        verify_ssl=controller.verify_ssl,
    )
