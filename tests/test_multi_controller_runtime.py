"""Runtime multi-controller scheduler/session tests."""
import pytest

from shared.controller_registry import ResolvedController
from tools.wifi_stalker import scheduler as stalker_scheduler
from tools.threat_watch import scheduler as threat_scheduler
from tools.network_pulse import scheduler as pulse_scheduler
from shared import unifi_session


class _FakeDb:
    async def get_session(self):
        yield object()


def _controller(controller_id: int, key: str, *, active: bool = True) -> ResolvedController:
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
        is_default=(key == "default"),
        is_active=active,
        source="registry",
    )


@pytest.mark.asyncio
async def test_wifi_scheduler_fanout_isolated(monkeypatch):
    stalker_scheduler._last_refresh = None
    stalker_scheduler._last_refresh_by_controller.clear()
    called = []
    invalidated = []
    controllers = [
        _controller(1, "good"),
        _controller(2, "bad"),
        _controller(3, "disabled", active=False),
    ]

    async def fake_list_enabled(_session):
        return controllers

    async def fake_refresh(_session, controller):
        called.append(controller.controller_key)
        if controller.controller_key == "bad":
            raise RuntimeError("controller offline")
        return True

    async def fake_invalidate(controller_key=None):
        invalidated.append(controller_key)

    monkeypatch.setattr(stalker_scheduler, "get_database", lambda: _FakeDb())
    monkeypatch.setattr(stalker_scheduler, "list_enabled_controllers", fake_list_enabled)
    monkeypatch.setattr(stalker_scheduler, "_refresh_tracked_devices_for_controller", fake_refresh)
    monkeypatch.setattr(stalker_scheduler, "invalidate_shared_client", fake_invalidate)

    await stalker_scheduler.refresh_tracked_devices()

    assert called == ["good", "bad"]
    assert invalidated == ["bad"]
    assert stalker_scheduler.get_last_refresh() is not None


@pytest.mark.asyncio
async def test_threat_scheduler_fanout_isolated(monkeypatch):
    threat_scheduler._last_refresh = None
    threat_scheduler._last_refresh_by_controller.clear()
    called = []
    invalidated = []
    controllers = [
        _controller(1, "good"),
        _controller(2, "bad"),
        _controller(3, "disabled", active=False),
    ]

    async def fake_list_enabled(_session):
        return controllers

    async def fake_refresh(_session, controller):
        called.append(controller.controller_key)
        if controller.controller_key == "bad":
            raise RuntimeError("threat API failed")
        return True

    async def fake_invalidate(controller_key=None):
        invalidated.append(controller_key)

    async def fake_purge():
        return None

    monkeypatch.setattr(threat_scheduler, "get_database", lambda: _FakeDb())
    monkeypatch.setattr(threat_scheduler, "list_enabled_controllers", fake_list_enabled)
    monkeypatch.setattr(threat_scheduler, "_refresh_threat_events_for_controller", fake_refresh)
    monkeypatch.setattr(threat_scheduler, "invalidate_shared_client", fake_invalidate)
    monkeypatch.setattr(threat_scheduler, "purge_old_threat_events", fake_purge)

    await threat_scheduler.refresh_threat_events()

    assert called == ["good", "bad"]
    assert invalidated == ["bad"]
    assert threat_scheduler.get_last_refresh() is not None


@pytest.mark.asyncio
async def test_network_pulse_single_enabled_controller(monkeypatch):
    pulse_scheduler._last_refresh = None
    pulse_scheduler._last_error = None
    pulse_scheduler._cached_data_by_controller.clear()
    pulse_scheduler._last_refresh_by_controller.clear()
    pulse_scheduler._last_error_by_controller.clear()
    controllers = [_controller(1, "solo", active=True)]
    called = []

    async def fake_list_enabled(_session):
        return controllers

    async def fake_default(_session):
        return controllers[0]

    async def fake_refresh(controller):
        called.append(controller.controller_key)
        pulse_scheduler._cached_data_by_controller[controller.controller_key] = {"ok": True}
        pulse_scheduler._last_refresh_by_controller[controller.controller_key] = object()
        pulse_scheduler._last_error_by_controller[controller.controller_key] = None
        return True

    async def fake_invalidate(controller_key=None):
        return None

    monkeypatch.setattr(pulse_scheduler, "get_database", lambda: _FakeDb())
    monkeypatch.setattr(pulse_scheduler, "list_enabled_controllers", fake_list_enabled)
    monkeypatch.setattr(pulse_scheduler, "get_default_controller", fake_default)
    monkeypatch.setattr(pulse_scheduler, "_refresh_network_stats_for_controller", fake_refresh)
    monkeypatch.setattr(pulse_scheduler, "invalidate_shared_client", fake_invalidate)

    await pulse_scheduler.refresh_network_stats()
    assert called == ["solo"]
    assert pulse_scheduler._last_error is None
    assert pulse_scheduler.get_cached_data("solo")["ok"] is True


@pytest.mark.asyncio
async def test_network_pulse_multi_controller_isolation(monkeypatch):
    pulse_scheduler._last_refresh = None
    pulse_scheduler._last_error = None
    pulse_scheduler._default_controller_key = None
    pulse_scheduler._cached_data_by_controller.clear()
    pulse_scheduler._last_refresh_by_controller.clear()
    pulse_scheduler._last_error_by_controller.clear()
    called = []
    invalidated = []
    controllers = [
        _controller(1, "alpha", active=True),
        _controller(2, "beta", active=False),
        _controller(3, "gamma", active=True),
    ]

    async def fake_list_enabled(_session):
        return controllers

    async def fake_default(_session):
        return controllers[0]

    async def fake_refresh(controller):
        called.append(controller.controller_key)
        if controller.controller_key == "gamma":
            raise RuntimeError("controller timeout")
        pulse_scheduler._cached_data_by_controller[controller.controller_key] = {"ok": controller.controller_key}
        pulse_scheduler._last_refresh_by_controller[controller.controller_key] = object()
        pulse_scheduler._last_error_by_controller[controller.controller_key] = None
        return True

    async def fake_invalidate(controller_key=None):
        invalidated.append(controller_key)

    monkeypatch.setattr(pulse_scheduler, "get_database", lambda: _FakeDb())
    monkeypatch.setattr(pulse_scheduler, "list_enabled_controllers", fake_list_enabled)
    monkeypatch.setattr(pulse_scheduler, "get_default_controller", fake_default)
    monkeypatch.setattr(pulse_scheduler, "_refresh_network_stats_for_controller", fake_refresh)
    monkeypatch.setattr(pulse_scheduler, "invalidate_shared_client", fake_invalidate)

    await pulse_scheduler.refresh_network_stats()

    # Disabled controller is skipped, failing controller is isolated.
    assert called == ["alpha", "gamma"]
    assert invalidated == ["gamma"]
    assert pulse_scheduler._last_error is None
    assert pulse_scheduler._default_controller_key == "alpha"


def test_network_pulse_cache_is_controller_aware():
    pulse_scheduler._cached_data_by_controller.clear()
    pulse_scheduler._default_controller_key = "default"
    pulse_scheduler._cached_data_by_controller["default"] = {"id": "d"}
    pulse_scheduler._cached_data_by_controller["other"] = {"id": "o"}

    assert pulse_scheduler.get_cached_data()["id"] == "d"
    assert pulse_scheduler.get_cached_data("other")["id"] == "o"


@pytest.mark.asyncio
async def test_shared_session_resolves_specific_controller(monkeypatch):
    captured = {}

    async def fake_get_or_connect(controller_key, build_client):
        captured["controller_key"] = controller_key
        return {"client": controller_key}

    async def fake_get_by_key(_session, controller_key, include_inactive=False):
        return _controller(2, controller_key, active=True)

    monkeypatch.setattr(unifi_session, "get_database", lambda: _FakeDb())
    monkeypatch.setattr(unifi_session, "_get_or_connect_client", fake_get_or_connect)
    monkeypatch.setattr(unifi_session, "get_controller_by_key", fake_get_by_key)

    result = await unifi_session.get_shared_client(controller_key="branch-office")

    assert captured["controller_key"] == "branch-office"
    assert result["client"] == "branch-office"
