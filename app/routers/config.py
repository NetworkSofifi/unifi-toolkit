"""
UniFi configuration API endpoints for the main dashboard
"""
from urllib.parse import urlparse
import re
import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from datetime import datetime, timezone
from pydantic import BaseModel, Field, field_validator
from typing import Optional

from shared.database import get_db_session
from shared.controller_context import ControllerContext, get_controller_context
from shared.crypto import encrypt_password, encrypt_api_key
from shared.unifi_client import UniFiClient
from shared.controller_registry import (
    create_unifi_client,
    get_default_controller_id,
    get_controller_by_key,
    normalize_controller_key,
    upsert_default_controller,
)
from shared.models.controller_config import ControllerConfig

router = APIRouter(prefix="/api/config", tags=["configuration"])
logger = logging.getLogger(__name__)

SITE_ID_RE = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")


def _normalize_url(value: str) -> str:
    cleaned = (value or "").strip()
    parsed = urlparse(cleaned)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Controller URL must start with http:// or https://")
    if not parsed.netloc:
        raise ValueError("Controller URL must include a host")
    if parsed.params or parsed.query or parsed.fragment:
        raise ValueError("Controller URL must not include query strings or fragments")
    normalized = f"{parsed.scheme}://{parsed.netloc}".rstrip("/")
    return normalized


def _validate_site_id_or_raise(site_id: str) -> str:
    value = (site_id or "").strip() or "default"
    if not SITE_ID_RE.fullmatch(value):
        raise ValueError("Site ID must use only letters, numbers, underscore, and hyphen")
    return value


async def _require_config_mutation_request(request: Request):
    """
    Lightweight CSRF mitigation for browser mutation flows.

    - Requires X-Requested-With header for all mutations.
    - In production auth mode, requires same-origin Origin/Referer when present.
    """
    from app.routers.auth import is_auth_enabled

    xrw = request.headers.get("X-Requested-With", "")
    if xrw.lower() != "xmlhttprequest":
        raise HTTPException(status_code=400, detail="Missing expected mutation request header")

    if not is_auth_enabled():
        return

    host = request.headers.get("host")
    allowed_origin = f"{request.url.scheme}://{host}" if host else None
    origin = request.headers.get("origin")
    referer = request.headers.get("referer")

    if origin and allowed_origin and origin != allowed_origin:
        raise HTTPException(status_code=403, detail="Cross-origin mutation rejected")
    if referer and allowed_origin and not referer.startswith(allowed_origin):
        raise HTTPException(status_code=403, detail="Cross-site mutation rejected")


# Pydantic models
class UniFiConfigCreate(BaseModel):
    """
    Request model for UniFi controller configuration
    """
    controller_url: str = Field(..., description="UniFi controller URL")
    username: Optional[str] = Field(None, description="UniFi admin username (optional when using API key)")
    password: Optional[str] = Field(None, description="Password for legacy controllers or UniFi OS")
    api_key: Optional[str] = Field(None, description="API key for UniFi OS (UDM, UCG, etc.)")
    site_id: str = Field(default="default", description="UniFi site ID")
    verify_ssl: bool = Field(default=False, description="Verify SSL certificate")
    # Deprecated: is_unifi_os is now auto-detected during connection
    is_unifi_os: Optional[bool] = Field(default=None, description="Deprecated - auto-detected during connection")

    @field_validator("controller_url")
    @classmethod
    def validate_controller_url(cls, value: str) -> str:
        return _normalize_url(value)

    @field_validator("site_id")
    @classmethod
    def validate_site_id(cls, value: str) -> str:
        return _validate_site_id_or_raise(value)


class UniFiConfigResponse(BaseModel):
    """
    Response model for UniFi configuration (without password/API key)
    """
    id: int
    controller_url: str
    username: Optional[str]
    has_api_key: bool
    site_id: str
    verify_ssl: bool
    is_unifi_os: bool
    last_successful_connection: Optional[datetime] = None
    controller_key: Optional[str] = None


class UniFiConnectionTest(BaseModel):
    """
    Response model for UniFi connection test
    """
    connected: bool
    client_count: Optional[int] = None
    site_name: Optional[str] = None
    controller_version: Optional[str] = None
    error: Optional[str] = None


class SuccessResponse(BaseModel):
    """
    Generic success response
    """
    success: bool
    message: Optional[str] = None


class ControllerListItem(BaseModel):
    id: int
    controller_key: str
    display_name: str
    controller_url: str
    username: Optional[str]
    has_password: bool
    has_api_key: bool
    site_id: str
    verify_ssl: bool
    is_unifi_os: bool
    is_default: bool
    is_active: bool
    last_successful_connection: Optional[datetime] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class ControllerCreateRequest(BaseModel):
    display_name: str = Field(..., min_length=1, max_length=120)
    controller_key: Optional[str] = Field(default=None, description="Optional stable key override")
    controller_url: str
    username: Optional[str] = None
    password: Optional[str] = None
    api_key: Optional[str] = None
    site_id: str = "default"
    verify_ssl: bool = False
    is_unifi_os: Optional[bool] = None
    is_active: bool = True
    set_as_default: bool = False

    @field_validator("display_name")
    @classmethod
    def validate_display_name(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("Display name is required")
        return cleaned

    @field_validator("controller_key")
    @classmethod
    def validate_controller_key(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        normalized = normalize_controller_key(value)
        if normalized != value.strip().lower():
            raise ValueError("Controller key must be lower-case slug format (letters, numbers, hyphen)")
        return normalized

    @field_validator("controller_url")
    @classmethod
    def validate_controller_url(cls, value: str) -> str:
        return _normalize_url(value)

    @field_validator("site_id")
    @classmethod
    def validate_site_id(cls, value: str) -> str:
        return _validate_site_id_or_raise(value)


class ControllerUpdateRequest(BaseModel):
    display_name: Optional[str] = Field(default=None, min_length=1, max_length=120)
    controller_url: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    api_key: Optional[str] = None
    clear_password: bool = False
    clear_api_key: bool = False
    site_id: Optional[str] = None
    verify_ssl: Optional[bool] = None
    is_unifi_os: Optional[bool] = None

    @field_validator("display_name")
    @classmethod
    def validate_display_name(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("Display name cannot be empty")
        return cleaned

    @field_validator("controller_url")
    @classmethod
    def validate_controller_url(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        return _normalize_url(value)

    @field_validator("site_id")
    @classmethod
    def validate_site_id(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        return _validate_site_id_or_raise(value)


class ControllerActiveUpdateRequest(BaseModel):
    is_active: bool


def _controller_to_item(row: ControllerConfig) -> ControllerListItem:
    return ControllerListItem(
        id=row.id,
        controller_key=row.controller_key,
        display_name=row.display_name,
        controller_url=row.controller_url,
        username=row.username,
        has_password=row.password_encrypted is not None,
        has_api_key=row.api_key_encrypted is not None,
        site_id=row.site_id,
        verify_ssl=row.verify_ssl,
        is_unifi_os=row.is_unifi_os,
        is_default=row.is_default,
        is_active=row.is_active,
        last_successful_connection=row.last_successful_connection,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _validate_auth_payload(
    *,
    username: Optional[str],
    password: Optional[str],
    api_key: Optional[str],
):
    username = username.strip() if isinstance(username, str) else username
    password = password.strip() if isinstance(password, str) else password
    api_key = api_key.strip() if isinstance(api_key, str) else api_key

    # At least one auth method is required.
    if not api_key and not password:
        raise HTTPException(status_code=400, detail="Provide either API key or password")
    # Legacy auth requires both username and password.
    if not api_key and (not username or not password):
        raise HTTPException(
            status_code=400,
            detail="Username and password are required when API key is not provided",
        )


async def _generate_unique_controller_key(
    db: AsyncSession,
    display_name: str,
    requested_key: Optional[str] = None,
) -> str:
    base_key = normalize_controller_key(requested_key or display_name)
    key = base_key
    suffix = 2

    while True:
        exists = (
            await db.execute(
                select(ControllerConfig.id).where(ControllerConfig.controller_key == key)
            )
        ).scalar_one_or_none()
        if not exists:
            return key
        key = f"{base_key}-{suffix}"
        suffix += 1


async def _ensure_single_default(db: AsyncSession, default_id: int):
    await db.execute(
        update(ControllerConfig)
        .where(ControllerConfig.id != default_id, ControllerConfig.is_default.is_(True))
        .values(is_default=False)
    )


async def _pick_replacement_default(db: AsyncSession) -> Optional[ControllerConfig]:
    candidate = (
        await db.execute(
            select(ControllerConfig)
            .where(ControllerConfig.is_active.is_(True))
            .order_by(ControllerConfig.id.asc())
        )
    ).scalar_one_or_none()
    if candidate:
        candidate.is_default = True
        await _ensure_single_default(db, candidate.id)
    return candidate


class GatewayCheckResponse(BaseModel):
    """
    Response model for gateway availability check
    """
    has_gateway: bool
    supports_ids_ips: bool = False
    gateway_name: Optional[str] = None
    configured: bool
    error: Optional[str] = None
    # IPS settings (when available)
    ips_mode: Optional[str] = None  # "disabled", "ids", "ips", "ipsInline"
    ips_enabled: Optional[bool] = None


@router.post("/unifi", response_model=SuccessResponse)
async def save_unifi_config(
    config: UniFiConfigCreate,
    _mutation_guard: None = Depends(_require_config_mutation_request),
    db: AsyncSession = Depends(get_db_session)
):
    """
    Save UniFi controller configuration
    Supports both legacy (username/password) and UniFi OS (API key) authentication
    """
    from shared import cache
    from shared.unifi_session import invalidate_shared_client

    try:
        # Validate that either password or API key is provided
        if not config.password and not config.api_key:
            raise HTTPException(
                status_code=400,
                detail="Either password or api_key must be provided"
            )
        # For legacy auth, require both username and password
        if not config.api_key and (not config.username or not config.password):
            raise HTTPException(
                status_code=400,
                detail="Username and password are required when api_key is not provided"
            )

        # Invalidate cache and shared session since config is changing
        cache.invalidate_all()
        await invalidate_shared_client()

        # Encrypt credentials
        encrypted_password = None
        encrypted_api_key = None

        if config.password:
            logger.debug("Encrypting password...")
            encrypted_password = encrypt_password(config.password)
        if config.api_key:
            logger.debug("Encrypting API key...")
            encrypted_api_key = encrypt_api_key(config.api_key)

        # is_unifi_os is auto-detected during connection, default to False for storage
        is_unifi_os = config.is_unifi_os if config.is_unifi_os is not None else False
        await upsert_default_controller(
            db,
            controller_url=config.controller_url,
            username=config.username,
            password_encrypted=encrypted_password,
            api_key_encrypted=encrypted_api_key,
            site_id=config.site_id,
            verify_ssl=config.verify_ssl,
            is_unifi_os=is_unifi_os,
            display_name="Default Controller",
        )

        logger.debug("Committing updated default controller config")
        await db.commit()
        logger.info("Default UniFi controller configuration saved")

        return SuccessResponse(
            success=True,
            message="UniFi configuration saved successfully"
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to save default UniFi config: %s", type(e).__name__, exc_info=True)
        raise HTTPException(
            status_code=500,
            detail="Failed to save configuration"
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
        is_unifi_os=config.is_unifi_os,
        last_successful_connection=config.last_successful_connection,
        controller_key=config.controller_key,
    )


@router.post("/unifi/test", response_model=UniFiConnectionTest)
async def test_unifi_credentials(config: UniFiConfigCreate):
    """
    Test UniFi credentials WITHOUT saving them first.
    Use this to validate credentials before saving.
    """
    # Validate that either password or API key is provided
    if not config.password and not config.api_key:
        return UniFiConnectionTest(
            connected=False,
            error="Either password or api_key must be provided"
        )
    if not config.api_key and (not config.username or not config.password):
        return UniFiConnectionTest(
            connected=False,
            error="Username and password are required when api_key is not provided"
        )

    # Create UniFi client with provided credentials
    # is_unifi_os is auto-detected during connection
    client = UniFiClient(
        host=config.controller_url,
        username=config.username,
        password=config.password,
        api_key=config.api_key,
        site=config.site_id,
        verify_ssl=config.verify_ssl
    )

    try:
        test_result = await client.test_connection()
        return UniFiConnectionTest(**test_result)
    except Exception:
        logger.warning("Controller test failed for ad-hoc credentials")
        return UniFiConnectionTest(connected=False, error="Connection test failed")


@router.get("/unifi/test", response_model=UniFiConnectionTest)
async def test_saved_unifi_connection(
    controller: ControllerContext = Depends(get_controller_context),
    db: AsyncSession = Depends(get_db_session)
):
    """
    Test connection using saved UniFi configuration
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
        # Update last successful timestamp for selected controller.
        from shared.models.controller_config import ControllerConfig
        from sqlalchemy import select
        default_row = (
            await db.execute(
                select(ControllerConfig).where(ControllerConfig.controller_key == config.controller_key)
            )
        ).scalar_one_or_none()
        if default_row:
            default_row.last_successful_connection = datetime.now(timezone.utc)
            await db.commit()

    return UniFiConnectionTest(**test_result)


@router.get("/gateway-check", response_model=GatewayCheckResponse)
async def check_gateway_availability(
    controller: ControllerContext = Depends(get_controller_context),
    db: AsyncSession = Depends(get_db_session),
    invalidate: str = None,
    refresh: str = None
):
    """
    Check if a UniFi Gateway is present on the site.
    This is required for Threat Watch (IDS/IPS features).

    This endpoint uses cached data from system-status when available
    to avoid making multiple concurrent connections to the controller.

    Query params:
    - invalidate=1: Clear cache before checking
    - refresh=1: Bypass cache and fetch fresh data

    Note: Legacy controllers (Cloud Key, self-hosted) do NOT expose IDS/IPS
    API endpoints, regardless of what gateway hardware is present.
    """
    from shared import cache
    import logging

    logger = logging.getLogger(__name__)

    # Handle cache invalidation
    if invalidate or refresh:
        logger.debug("Invalidating gateway cache due to request parameter")
        cache.invalidate("gateway_info", controller_key=controller.controller_key)
        cache.invalidate("ips_settings", controller_key=controller.controller_key)

    # First, check if we have cached gateway info
    cached_info = cache.get_gateway_info(controller_key=controller.controller_key)
    cached_ips = cache.get_ips_settings(controller_key=controller.controller_key)

    if cached_info is not None:
        logger.debug("Using cached gateway info for gateway-check")
        is_legacy = not cached_info.get("is_unifi_os", True)

        if is_legacy:
            gateway_name = cached_info.get("gateway_name", "Unknown")
            return GatewayCheckResponse(
                has_gateway=cached_info.get("has_gateway", False),
                supports_ids_ips=False,
                gateway_name=f"{gateway_name} (Legacy Controller)",
                configured=True
            )

        # Include IPS settings if available
        ips_mode = cached_ips.get("ips_mode") if cached_ips else None
        ips_enabled = cached_ips.get("ips_enabled") if cached_ips else None

        return GatewayCheckResponse(
            has_gateway=cached_info.get("has_gateway", False),
            supports_ids_ips=cached_info.get("supports_ids_ips", False),
            gateway_name=cached_info.get("gateway_name"),
            configured=True,
            ips_mode=ips_mode,
            ips_enabled=ips_enabled
        )

    # No cache - need to check config and possibly connect
    logger.debug("No cached gateway info, checking config")

    config = await get_controller_by_key(db, controller.controller_key, include_inactive=False)

    if not config:
        return GatewayCheckResponse(
            has_gateway=False,
            configured=False,
            error="UniFi controller not configured"
        )

    try:
        client = create_unifi_client(config)
    except Exception as e:
        logger.warning(
            "Unable to create UniFi client for controller '%s'",
            controller.controller_key,
        )
        return GatewayCheckResponse(
            has_gateway=False,
            configured=True,
            error="Failed to prepare controller client"
        )

    try:
        # Connect to controller (auto-detects UniFi OS vs legacy)
        connected = await client.connect()
        if not connected:
            return GatewayCheckResponse(
                has_gateway=False,
                supports_ids_ips=False,
                configured=True,
                error="Failed to connect to UniFi controller"
            )

        # Get gateway info including IDS/IPS support
        gateway_info = await client.get_gateway_info()

        # Cache the result for future requests
        cache.set_gateway_info({
            **gateway_info,
            "is_unifi_os": client.is_unifi_os
        }, controller_key=controller.controller_key)

        # Check if this is a legacy controller (detected during connection)
        # Legacy controllers don't expose IDS/IPS API regardless of gateway hardware
        is_legacy_controller = not client.is_unifi_os

        if is_legacy_controller:
            gateway_name = gateway_info.get("gateway_name", "Unknown")
            return GatewayCheckResponse(
                has_gateway=gateway_info.get("has_gateway", False),
                supports_ids_ips=False,
                gateway_name=f"{gateway_name} (Legacy Controller)",
                configured=True
            )

        # Get IPS settings if gateway supports IDS/IPS
        ips_mode = None
        ips_enabled = None
        if gateway_info.get("has_gateway") and gateway_info.get("supports_ids_ips"):
            ips_settings = await client.get_ips_settings()
            if ips_settings:
                cache.set_ips_settings(ips_settings, controller_key=controller.controller_key)
                ips_mode = ips_settings.get("ips_mode")
                ips_enabled = ips_settings.get("ips_enabled")

        return GatewayCheckResponse(
            has_gateway=gateway_info.get("has_gateway", False),
            supports_ids_ips=gateway_info.get("supports_ids_ips", False),
            gateway_name=gateway_info.get("gateway_name"),
            configured=True,
            ips_mode=ips_mode,
            ips_enabled=ips_enabled
        )

    except Exception as e:
        logger.warning(
            "Gateway check failed for controller '%s': %s",
            controller.controller_key,
            type(e).__name__,
        )
        return GatewayCheckResponse(
            has_gateway=False,
            supports_ids_ips=False,
            configured=True,
            error="Gateway check failed"
        )
    finally:
        await client.disconnect()


@router.get("/controllers", response_model=list[ControllerListItem])
async def get_controller_registry(
    db: AsyncSession = Depends(get_db_session)
):
    """
    List controllers from the registry.

    Transitional endpoint for multi-controller backend adoption.
    """
    # Legacy compatibility: this call materializes a default registry row from
    # legacy unifi_config once, then all reads come from controller_config.
    await get_default_controller_id(db)
    rows = (
        await db.execute(select(ControllerConfig).order_by(ControllerConfig.is_default.desc(), ControllerConfig.id.asc()))
    ).scalars().all()
    return [_controller_to_item(row) for row in rows]


@router.get("/controllers/{controller_key}", response_model=ControllerListItem)
async def get_controller(
    controller_key: str,
    db: AsyncSession = Depends(get_db_session),
):
    row = (
        await db.execute(
            select(ControllerConfig).where(ControllerConfig.controller_key == controller_key)
        )
    ).scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail=f"Controller '{controller_key}' not found")
    return _controller_to_item(row)


@router.post("/controllers", response_model=ControllerListItem)
async def create_controller(
    payload: ControllerCreateRequest,
    _mutation_guard: None = Depends(_require_config_mutation_request),
    db: AsyncSession = Depends(get_db_session),
):
    _validate_auth_payload(
        username=payload.username,
        password=payload.password,
        api_key=payload.api_key,
    )

    key = await _generate_unique_controller_key(db, payload.display_name, payload.controller_key)
    encrypted_password = encrypt_password(payload.password) if payload.password else None
    encrypted_api_key = encrypt_api_key(payload.api_key) if payload.api_key else None

    has_default = (
        await db.execute(select(ControllerConfig.id).where(ControllerConfig.is_default.is_(True)))
    ).scalar_one_or_none()
    set_as_default = payload.set_as_default or has_default is None

    row = ControllerConfig(
        controller_key=key,
        display_name=payload.display_name.strip(),
        controller_url=payload.controller_url.strip(),
        username=(payload.username or None),
        password_encrypted=encrypted_password,
        api_key_encrypted=encrypted_api_key,
        site_id=(payload.site_id or "default").strip() or "default",
        verify_ssl=payload.verify_ssl,
        is_unifi_os=bool(payload.is_unifi_os) if payload.is_unifi_os is not None else False,
        is_default=set_as_default,
        is_active=payload.is_active,
    )
    db.add(row)
    await db.flush()

    if set_as_default:
        await _ensure_single_default(db, row.id)

    if not row.is_active and row.is_default:
        row.is_active = True

    await db.commit()
    await db.refresh(row)
    logger.info(
        "Controller '%s' created (default=%s, active=%s)",
        row.controller_key,
        row.is_default,
        row.is_active,
    )
    return _controller_to_item(row)


@router.put("/controllers/{controller_key}", response_model=ControllerListItem)
async def update_controller(
    controller_key: str,
    payload: ControllerUpdateRequest,
    _mutation_guard: None = Depends(_require_config_mutation_request),
    db: AsyncSession = Depends(get_db_session),
):
    row = (
        await db.execute(
            select(ControllerConfig).where(ControllerConfig.controller_key == controller_key)
        )
    ).scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail=f"Controller '{controller_key}' not found")

    if payload.display_name is not None:
        row.display_name = payload.display_name.strip()
    if payload.controller_url is not None:
        row.controller_url = payload.controller_url.strip()
    if payload.username is not None:
        row.username = payload.username or None
    if payload.site_id is not None:
        row.site_id = (payload.site_id or "default").strip() or "default"
    if payload.verify_ssl is not None:
        row.verify_ssl = payload.verify_ssl
    if payload.is_unifi_os is not None:
        row.is_unifi_os = payload.is_unifi_os

    if payload.clear_password:
        row.password_encrypted = None
    elif payload.password:
        row.password_encrypted = encrypt_password(payload.password)

    if payload.clear_api_key:
        row.api_key_encrypted = None
    elif payload.api_key:
        row.api_key_encrypted = encrypt_api_key(payload.api_key)

    # Guard against invalid auth state after updates.
    has_api_key = row.api_key_encrypted is not None
    has_password = row.password_encrypted is not None
    if not has_api_key and not has_password:
        raise HTTPException(
            status_code=400,
            detail="Controller must keep either API key or password",
        )
    if not has_api_key and (not row.username or not has_password):
        raise HTTPException(
            status_code=400,
            detail="Username and password are required when API key is not configured",
        )

    row.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(row)
    logger.info("Controller '%s' updated", row.controller_key)
    return _controller_to_item(row)


@router.delete("/controllers/{controller_key}", response_model=SuccessResponse)
async def delete_controller(
    controller_key: str,
    _mutation_guard: None = Depends(_require_config_mutation_request),
    db: AsyncSession = Depends(get_db_session),
):
    row = (
        await db.execute(
            select(ControllerConfig).where(ControllerConfig.controller_key == controller_key)
        )
    ).scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail=f"Controller '{controller_key}' not found")

    count = (
        await db.execute(select(ControllerConfig.id))
    ).scalars().all()
    if len(count) <= 1:
        raise HTTPException(status_code=400, detail="At least one controller is required")

    deleted_default = row.is_default
    await db.delete(row)
    await db.flush()

    if deleted_default:
        replacement = await _pick_replacement_default(db)
        if replacement is None:
            raise HTTPException(status_code=400, detail="Cannot delete the last active controller")

    await db.commit()
    logger.info("Controller '%s' deleted", controller_key)
    return SuccessResponse(success=True, message="Controller deleted")


@router.post("/controllers/{controller_key}/set-default", response_model=ControllerListItem)
async def set_default_controller(
    controller_key: str,
    _mutation_guard: None = Depends(_require_config_mutation_request),
    db: AsyncSession = Depends(get_db_session),
):
    row = (
        await db.execute(
            select(ControllerConfig).where(ControllerConfig.controller_key == controller_key)
        )
    ).scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail=f"Controller '{controller_key}' not found")
    if not row.is_active:
        raise HTTPException(status_code=400, detail="Cannot set a disabled controller as default")

    row.is_default = True
    await _ensure_single_default(db, row.id)
    row.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(row)
    logger.info("Controller '%s' marked as default", row.controller_key)
    return _controller_to_item(row)


@router.post("/controllers/{controller_key}/set-active", response_model=ControllerListItem)
async def set_controller_active_state(
    controller_key: str,
    payload: ControllerActiveUpdateRequest,
    _mutation_guard: None = Depends(_require_config_mutation_request),
    db: AsyncSession = Depends(get_db_session),
):
    row = (
        await db.execute(
            select(ControllerConfig).where(ControllerConfig.controller_key == controller_key)
        )
    ).scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail=f"Controller '{controller_key}' not found")

    if row.is_active == payload.is_active:
        return _controller_to_item(row)

    if not payload.is_active:
        active_ids = (
            await db.execute(
                select(ControllerConfig.id).where(ControllerConfig.is_active.is_(True))
            )
        ).scalars().all()
        if len(active_ids) <= 1 and row.id in active_ids:
            raise HTTPException(status_code=400, detail="At least one active controller is required")

    row.is_active = payload.is_active
    row.updated_at = datetime.now(timezone.utc)

    if not row.is_active and row.is_default:
        row.is_default = False
        replacement = await _pick_replacement_default(db)
        if replacement is None:
            raise HTTPException(status_code=400, detail="At least one active default controller is required")

    await db.commit()
    await db.refresh(row)
    logger.info("Controller '%s' active state set to %s", row.controller_key, row.is_active)
    return _controller_to_item(row)


@router.post("/controllers/{controller_key}/test", response_model=UniFiConnectionTest)
async def test_controller_connection(
    controller_key: str,
    _mutation_guard: None = Depends(_require_config_mutation_request),
    db: AsyncSession = Depends(get_db_session),
):
    controller = await get_controller_by_key(db, controller_key=controller_key, include_inactive=True)
    if not controller:
        raise HTTPException(status_code=404, detail=f"Controller '{controller_key}' not found")

    try:
        client = create_unifi_client(controller)
    except Exception:
        logger.warning("Failed to initialize client for controller '%s'", controller_key)
        return UniFiConnectionTest(connected=False, error="Failed to initialize controller client")

    result = await client.test_connection()
    if result.get("connected"):
        row = (
            await db.execute(
                select(ControllerConfig).where(ControllerConfig.controller_key == controller_key)
            )
        ).scalar_one_or_none()
        if row:
            row.last_successful_connection = datetime.now(timezone.utc)
            row.updated_at = datetime.now(timezone.utc)
            await db.commit()

    return UniFiConnectionTest(**result)
