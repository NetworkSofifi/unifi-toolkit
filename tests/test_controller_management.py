"""Tests for controller management operations."""
import pytest
from fastapi import HTTPException
from starlette.requests import Request
from sqlalchemy import select

from app.routers.config import (
    ControllerCreateRequest,
    ControllerUpdateRequest,
    ControllerActiveUpdateRequest,
    create_controller,
    _require_config_mutation_request,
    set_default_controller,
    set_controller_active_state,
    update_controller,
)
from shared.models.controller_config import ControllerConfig


@pytest.mark.asyncio
async def test_create_controller_generates_unique_keys(test_db):
    first = await create_controller(
        ControllerCreateRequest(
            display_name="Main Site",
            controller_url="https://10.0.0.1",
            username="admin",
            password="secret",
            site_id="default",
            verify_ssl=False,
        ),
        db=test_db,
    )
    second = await create_controller(
        ControllerCreateRequest(
            display_name="Main Site",
            controller_url="https://10.0.0.2",
            username="admin",
            password="secret2",
            site_id="default",
            verify_ssl=False,
        ),
        db=test_db,
    )

    assert first.controller_key == "main-site"
    assert second.controller_key == "main-site-2"


@pytest.mark.asyncio
async def test_set_default_controller_switches_default_flag(test_db):
    primary = await create_controller(
        ControllerCreateRequest(
            display_name="Primary",
            controller_url="https://10.0.0.1",
            username="admin",
            password="secret",
            site_id="default",
            verify_ssl=False,
            set_as_default=True,
        ),
        db=test_db,
    )
    secondary = await create_controller(
        ControllerCreateRequest(
            display_name="Secondary",
            controller_url="https://10.0.0.2",
            username="admin",
            password="secret",
            site_id="default",
            verify_ssl=False,
        ),
        db=test_db,
    )

    updated = await set_default_controller(secondary.controller_key, db=test_db)
    assert updated.controller_key == secondary.controller_key
    assert updated.is_default is True

    rows = (await test_db.execute(select(ControllerConfig))).scalars().all()
    default_keys = [row.controller_key for row in rows if row.is_default]
    assert default_keys == [secondary.controller_key]
    assert primary.controller_key in [row.controller_key for row in rows]


@pytest.mark.asyncio
async def test_cannot_disable_last_active_controller(test_db):
    created = await create_controller(
        ControllerCreateRequest(
            display_name="Only Controller",
            controller_url="https://10.0.0.1",
            username="admin",
            password="secret",
            site_id="default",
            verify_ssl=False,
        ),
        db=test_db,
    )

    with pytest.raises(HTTPException) as exc:
        await set_controller_active_state(
            created.controller_key,
            ControllerActiveUpdateRequest(is_active=False),
            db=test_db,
        )
    assert exc.value.status_code == 400


@pytest.mark.asyncio
async def test_update_controller_preserves_existing_secrets(test_db):
    created = await create_controller(
        ControllerCreateRequest(
            display_name="Controller A",
            controller_url="https://10.0.0.1",
            username="admin",
            password="secret",
            site_id="default",
            verify_ssl=False,
        ),
        db=test_db,
    )

    updated = await update_controller(
        created.controller_key,
        ControllerUpdateRequest(display_name="Controller A Updated", verify_ssl=True),
        db=test_db,
    )

    assert updated.display_name == "Controller A Updated"
    assert updated.verify_ssl is True
    assert updated.has_password is True


def test_controller_create_request_validates_url_and_site_id():
    with pytest.raises(ValueError):
        ControllerCreateRequest(
            display_name="X",
            controller_url="ftp://bad-host",
            username="admin",
            password="secret",
            site_id="default",
        )

    with pytest.raises(ValueError):
        ControllerCreateRequest(
            display_name="X",
            controller_url="https://controller.local/path?x=1",
            username="admin",
            password="secret",
            site_id="default",
        )

    with pytest.raises(ValueError):
        ControllerCreateRequest(
            display_name="X",
            controller_url="https://controller.local",
            username="admin",
            password="secret",
            site_id="invalid site id",
        )


@pytest.mark.asyncio
async def test_update_rejects_clearing_all_auth_material(test_db):
    created = await create_controller(
        ControllerCreateRequest(
            display_name="Controller B",
            controller_url="https://10.0.0.5",
            username="admin",
            password="secret",
            site_id="default",
            verify_ssl=False,
        ),
        db=test_db,
    )

    with pytest.raises(HTTPException) as exc:
        await update_controller(
            created.controller_key,
            ControllerUpdateRequest(clear_password=True),
            db=test_db,
        )
    assert exc.value.status_code == 400


@pytest.mark.asyncio
async def test_mutation_guard_requires_x_requested_with_header():
    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/api/config/controllers",
            "headers": [],
            "scheme": "http",
            "server": ("test", 80),
        }
    )
    with pytest.raises(HTTPException) as exc:
        await _require_config_mutation_request(request)
    assert exc.value.status_code == 400
