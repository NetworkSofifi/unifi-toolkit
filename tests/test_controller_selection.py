"""Tests for controller selection dependencies and websocket filtering."""
import pytest
from fastapi import HTTPException

from shared.controller_context import resolve_controller_context
from shared.controller_registry import ResolvedController
from shared.websocket_manager import WebSocketManager


def _controller(
    controller_id: int,
    key: str,
    *,
    default: bool = False,
    active: bool = True,
) -> ResolvedController:
    return ResolvedController(
        id=controller_id,
        controller_key=key,
        display_name=f"Controller {key}",
        controller_url=f"https://{key}.local",
        username="admin",
        password_encrypted=None,
        api_key_encrypted=None,
        site_id="default",
        verify_ssl=False,
        is_unifi_os=True,
        last_successful_connection=None,
        is_default=default,
        is_active=active,
        source="registry",
    )


@pytest.mark.asyncio
async def test_resolve_controller_context_defaults_when_not_specified(monkeypatch):
    expected = _controller(1, "default", default=True)

    async def fake_default(_db):
        return expected

    monkeypatch.setattr("shared.controller_context.get_default_controller", fake_default)
    context = await resolve_controller_context(db=object(), controller_key=None)
    assert context.controller_id == 1
    assert context.controller_key == "default"
    assert context.is_default is True


@pytest.mark.asyncio
async def test_resolve_controller_context_uses_explicit_controller(monkeypatch):
    expected = _controller(2, "branch-office")

    async def fake_lookup(_db, controller_key, include_inactive=False):
        assert controller_key == "branch-office"
        assert include_inactive is False
        return expected

    monkeypatch.setattr("shared.controller_context.get_controller_by_key", fake_lookup)
    context = await resolve_controller_context(db=object(), controller_key="branch-office")
    assert context.controller_id == 2
    assert context.controller_key == "branch-office"
    assert context.is_default is False


@pytest.mark.asyncio
async def test_resolve_controller_context_unknown_key_raises(monkeypatch):
    async def fake_lookup(_db, controller_key, include_inactive=False):
        return None

    monkeypatch.setattr("shared.controller_context.get_controller_by_key", fake_lookup)
    with pytest.raises(HTTPException) as exc:
        await resolve_controller_context(db=object(), controller_key="missing")
    assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_resolve_controller_context_disabled_controller_rejected(monkeypatch):
    disabled = _controller(3, "disabled", active=False)

    async def fake_lookup(_db, controller_key, include_inactive=False):
        return disabled

    monkeypatch.setattr("shared.controller_context.get_controller_by_key", fake_lookup)
    with pytest.raises(HTTPException) as exc:
        await resolve_controller_context(db=object(), controller_key="disabled")
    assert exc.value.status_code == 400


class _FakeWebSocket:
    def __init__(self):
        self.sent = []

    async def accept(self):
        return None

    async def send_json(self, payload):
        self.sent.append(payload)


@pytest.mark.asyncio
async def test_websocket_manager_broadcasts_by_controller():
    manager = WebSocketManager()
    ws_a = _FakeWebSocket()
    ws_b = _FakeWebSocket()
    ws_default = _FakeWebSocket()

    await manager.connect(ws_a, controller_key="alpha")
    await manager.connect(ws_b, controller_key="beta")
    await manager.connect(ws_default, controller_key=None)

    await manager.broadcast({"type": "stats_update"}, controller_key="alpha")

    assert len(ws_a.sent) == 1
    assert len(ws_b.sent) == 0
    # unspecified subscriptions are treated as legacy/default only
    assert len(ws_default.sent) == 0
