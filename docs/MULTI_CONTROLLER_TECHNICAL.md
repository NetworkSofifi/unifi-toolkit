# Multi-Controller Implementation — Technical Summary

This document describes **what was changed and how it works** to add multi-controller support to the UniFi Toolkit. It is intended for developers and maintainers.

---

## 1. Overview

**Goal:** Support multiple UniFi controllers from a single dashboard instead of one global controller config.

**Approach:**

- Introduce a **controller registry** (`controller_config` table) as the source of truth.
- **Scope all persisted tool data** by `controller_id` so data from different controllers never mixes.
- **Resolve the active controller per request** via optional `controller_key` (query param or WebSocket query).
- **Fan out** background jobs (schedulers, refresh) across enabled controllers so each runs in isolation.
- **Frontend** keeps a selected controller in memory and localStorage, and passes `controller_key` on every API/WebSocket call.

**Backward compatibility:** Legacy single-controller installs continue to work. The old `unifi_config` row is still read and can be materialized into `controller_config` as the default during migration or when the registry is empty.

---

## 2. Architecture Summary

```
┌─────────────────────────────────────────────────────────────────────────┐
│ Frontend (dashboard + tools)                                            │
│  - controller-context.js: selected controller, apiFetch, websocketUrl   │
│  - controller selector UI, controller_key in URLs and API calls         │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ ?controller_key=...
                                    ▼
┌───────────────────────────────────────────────────────────────────────-──┐
│ API layer (FastAPI)                                                      │
│  - get_controller_context(controller_key: Optional[str] = Query(None))   │
│  - Routes use ControllerContext (controller_id, controller_key, ...)     │
└───────────────────────────────────────────────────────────────────────-──┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────-─┐
│ Controller registry + resolution                                         │
│  - controller_registry.py: list_controllers, get_controller_by_key,      │
│    get_default_controller, create_unifi_client, upsert_default_controller│
│  - controller_context.py: ControllerContext dataclass, get_controller_   │
│    context (dependency), resolve_websocket_controller_context            │
└───────────────────────────────────────────────────────────────────────-──┘
                                    │
          ┌─────────────────────────┼─────────────────────────┐
          ▼                         ▼                         ▼
┌─────────────────┐    ┌─────────────────────┐    ┌─────────────────────┐
│ controller_     │    │ shared/unifi_       │    │ shared/cache.py     │
│ config (DB)     │    │ session.py          │    │ (keyed by           │
│                 │    │ client per          │    │  controller_key)    │
│                 │    │ controller_key      │    │                     │
└─────────────────┘    └─────────────────────┘    └─────────────────────┘
          │
          │ controller_id FK
          ▼
┌──────────────────────────────────────────────────────────────────────--──┐
│ Tool tables (stalker_*, threats_*)                                       │
│  - controller_id on: stalker_tracked_devices, stalker_connection_history,│
│    stalker_webhook_config, stalker_hourly_presence, threats_events,      │
│    threats_webhook_config, threats_ignore_rules                          │
└───────────────────────────────────────────────────────────────────────-──┘
```

---

## 3. Backend Changes

### 3.1 Models and database

| File | Change |
|------|--------|
| **`shared/models/controller_config.py`** | **New.** SQLAlchemy model `ControllerConfig`: `id`, `controller_key` (unique), `display_name`, `controller_url`, `username`, `password_encrypted`, `api_key_encrypted`, `site_id`, `verify_ssl`, `is_unifi_os`, `last_successful_connection`, `is_default`, `is_active`, `created_at`, `updated_at`. |
| **`shared/database.py`** | Ensure `ControllerConfig` (and any shared models used by controller registry) are part of the metadata used for DB init. |
| **Tool models** (e.g. `tools/wifi_stalker/database.py`, threat_watch, network_pulse) | Add `controller_id` column (Integer, FK to `controller_config.id`) to every table that stores tool-specific data (tracked devices, connection history, webhooks, events, ignore rules, etc.). Queries and inserts now take `controller_id` from request context. |

### 3.2 Controller registry

| File | Change |
|------|--------|
| **`shared/controller_registry.py`** | **New.** Defines `ResolvedController` dataclass and: `normalize_controller_key()`, `list_controllers()`, `list_enabled_controllers()`, `get_controller_by_key()`, `get_controller_by_id()`, `get_default_controller()`, `get_default_controller_id()`, `upsert_default_controller()`, `create_unifi_client()`. Reads from `controller_config`; if registry is empty, can build a single entry from legacy `unifi_config` for compatibility. |

### 3.3 Request-scoped controller resolution

| File | Change |
|------|--------|
| **`shared/controller_context.py`** | **New.** Defines `ControllerContext` (controller_id, controller_key, display_name, is_default). `resolve_controller_context(db, controller_key=None)` resolves by key or default. `get_controller_context(controller_key=Query(None), db=Depends(get_db_session))` is the FastAPI dependency. `resolve_websocket_controller_context(controller_key)` used for WebSocket handshake (no request session). |

### 3.4 Shared UniFi client (session)

| File | Change |
|------|--------|
| **`shared/unifi_session.py`** | Refactored so clients are **per controller_key**. `get_shared_client(controller_key=None)` resolves default when key is omitted; otherwise returns or creates a client for that key. `_shared_clients` is a dict keyed by `controller_key`. `invalidate_shared_client(controller_key)` clears one or all. |

### 3.5 Cache

| File | Change |
|------|--------|
| **`shared/cache.py`** | All cache keys are **controller-scoped** when applicable. Helper `_scoped_key(key, controller_key)` builds `key:controller_key`. `get_gateway_info`, `set_gateway_info`, `get_ips_settings`, `set_ips_settings`, `get_ap_info`, `set_ap_info`, `get_system_status`, `set_system_status`, and invalidate functions accept optional `controller_key` and use the scoped key. |

### 3.6 WebSocket manager

| File | Change |
|------|--------|
| **`shared/websocket_manager.py`** | Connections are stored with an optional `controller_key`. `connect(websocket, controller_key=...)` saves that key. `_iter_targets(controller_key)` filters recipients: when broadcasting with a `controller_key`, only connections subscribed to that key receive the message. `broadcast_device_update` and `broadcast` take optional `controller_key`. |

### 3.7 API routes (config and main app)

| File | Change |
|------|--------|
| **`app/routers/config.py`** | **Major.** Legacy single-controller save continues to update the **default** controller and legacy `unifi_config`. **New** REST API for controller registry: `GET /api/config/controllers` (list), `GET /api/config/controllers/{controller_key}` (get one), `POST /api/config/controllers` (create), `PUT /api/config/controllers/{controller_key}` (update), `DELETE /api/config/controllers/{controller_key}` (delete), `POST .../set-default`, `POST .../set-active`, `POST .../test`. Pydantic request/response models; validation for URL, site_id, display_name, controller_key. Mutation endpoints protected by `_require_config_mutation_request` (X-Requested-With + same-origin in production). Secrets never returned; only `has_api_key` / similar flags. |
| **`app/main.py`** | `get_system_status` and other dashboard endpoints use `ControllerContext = Depends(get_controller_context)` and pass `controller.controller_key` (or id) into registry/cache. WebSocket endpoint at `/ws` reads `controller_key` from query params, calls `resolve_websocket_controller_context(controller_key)`, then connects with that key. |

### 3.8 Tool routers and schedulers

| Area | Change |
|------|--------|
| **Tool routers** (e.g. `tools/wifi_stalker/routers/devices.py`, threat_watch, network_pulse) | All relevant routes depend on `get_controller_context`. Every DB read/write uses `controller.controller_id` (or resolved controller id) to filter/insert by `controller_id`. |
| **Schedulers** (e.g. `tools/wifi_stalker/scheduler.py`, threat_watch scheduler, network_pulse scheduler) | Instead of a single global run: **iterate over `list_enabled_controllers(db)`**, and for each controller run the refresh/collect logic in isolation. Use `get_shared_client(controller.controller_key)` and pass `controller_key` into cache and WebSocket broadcasts. Failures are per-controller (logged, not fatal for other controllers). |

### 3.9 Migrations and schema repair

| File | Change |
|------|--------|
| **`alembic/versions/20260313_0000_add_controller_scoping_to_tool_tables.py`** | **New migration.** Creates `controller_config` if missing. Ensures one default row (from existing default or first registry row; or from legacy `unifi_config` if present). Adds nullable `controller_id` to: `stalker_tracked_devices`, `stalker_connection_history`, `stalker_webhook_config`, `stalker_hourly_presence`, `threats_events`, `threats_webhook_config`, `threats_ignore_rules`. Backfills existing rows with the default controller id. Then makes `controller_id` NOT NULL, adds FK and index. Adds unique constraints where needed (e.g. controller_id + mac_address for stalker devices). If tool tables have data but no default controller can be inferred, migration raises with a clear error. |
| **`run.py`** | **Schema repair** (after Alembic): for each of the controller-scoped tool tables above, if column `controller_id` is missing, add it (`ALTER TABLE ... ADD COLUMN controller_id INTEGER`). If `controller_config` exists and a default row exists, backfill `controller_id` for any NULL rows in those tables. This covers cases where the migration was skipped or only partially applied. |

---

## 4. Frontend Changes

### 4.1 Controller context (shared script)

| File | Change |
|------|--------|
| **`app/static/js/controller-context.js`** | **New.** Single place for “current controller” and controller-aware requests. State: `loaded`, `controllers[]`, `selectedKey`. `loadControllers()` fetches `GET /api/config/controllers`, then sets `selectedKey` from URL param, then localStorage, then default controller, then first active. Persists selection to localStorage and syncs `controller_key` to the page URL. Exposes: `addControllerKeyToUrl(url)`, `apiFetch(url, options)`, `websocketUrl(path)`, `setSelectedController(key)`, `decorateLinks()` (adds `controller_key` to `[data-controller-link]`), `initSelectorUi(options)` (dropdown or badge). Dispatches `controller-context-changed` when selection or list changes. |

### 4.2 Controller selector UI

| File | Change |
|------|--------|
| **`app/static/css/controller-selector.css`** | **New.** Styles for the controller dropdown and current-controller badge. |

### 4.3 Dashboard

| File | Change |
|------|--------|
| **`app/templates/dashboard.html`** | Includes `controller-context.js` and `controller-selector.css`. Header: controller selector dropdown or badge (via `ControllerContext.initSelectorUi()`). All API calls that must be controller-aware use `controllerAwareFetch(url)` (or equivalent) so the current `controller_key` is appended. **System status widget:** Waits for `controller-context-ready` (fired after `ControllerContext.loadControllers()` completes) before calling `loadSystemStatus()` so the first request uses the selected controller. Listens for `ControllerContext.changeEvent` and refetches system status and gateway availability when the user changes controller so the dashboard updates without a full reload. Controller selector `onChange` on dashboard is no-op (no reload). **Config modal:** Full controller management UI (list, create, edit, delete, set default, enable/disable, test connection). Test Connection no longer calls `loadControllerRegistry()` after success so the form is not overwritten. Confirmation dialogs for set default, enable/disable, delete. |

### 4.4 Tool pages (Wi‑Fi Stalker, Threat Watch, Network Pulse)

| Area | Change |
|------|--------|
| **Templates** (e.g. `tools/wifi_stalker/templates/index.html`, threat_watch, network_pulse) | Include `controller-context.js` and `controller-selector.css`. Header shows controller selector/badge via `ControllerContext.initSelectorUi()`. “Back to Dashboard” and tool links use `data-controller-link` so `decorateLinks()` adds `controller_key`. |
| **Tool JS** (e.g. `tools/wifi_stalker/static/js/app.js`) | On init: `ControllerContext.loadControllers()`, then `syncBrowserUrlParam()`, `decorateLinks()`, `initSelectorUi()`. All `fetch()` calls use `ControllerContext.apiFetch()` (or equivalent). WebSocket URLs built with `ControllerContext.websocketUrl(path)`. |

### 4.5 Wi‑Fi Stalker WebSocket

| File | Change |
|------|--------|
| **`tools/wifi_stalker/main.py`** | **New** `@app.websocket("/ws")` endpoint. Same pattern as main app and Network Pulse: auth check (if enabled), `resolve_websocket_controller_context(controller_key)` from query, then `get_ws_manager().connect(websocket, controller_key=...)`. Handles ping/pong. So `/stalker/ws?controller_key=...` works and receives controller-scoped device updates. |

---

## 5. How It Works (End-to-End)

### 5.1 Page load (dashboard or tool)

1. HTML loads; `controller-context.js` runs and calls `ControllerContext.loadControllers()` (async).
2. When that completes, selection is set (URL → localStorage → default → first active), saved to localStorage, URL updated with `?controller_key=...`, and `controller-context-ready` is dispatched (dashboard only).
3. **Dashboard:** System status and gateway-check wait for `controller-context-ready`, then call `controllerAwareFetch('/api/system-status')` and gateway-check. So the first request includes `?controller_key=...`.
4. **Tools:** After `loadControllers()`, tool JS calls `apiFetch` / `websocketUrl` for all API and WebSocket traffic, so every request carries the selected controller.

### 5.2 API request with controller

1. Frontend calls `controllerAwareFetch('/api/system-status')` → `ControllerContext.addControllerKeyToUrl('/api/system-status')` → `/api/system-status?controller_key=oxr` (for example).
2. FastAPI route uses `controller: ControllerContext = Depends(get_controller_context)`. `get_controller_context` reads `controller_key` from query; if missing, uses default.
3. `resolve_controller_context(db, controller_key)` in registry returns a `ControllerContext` (id, key, display_name, is_default).
4. Route uses `controller.controller_id` / `controller.controller_key` to query DB, call cache, or build a UniFi client via `get_shared_client(controller.controller_key)` or `create_unifi_client(resolved)`.

### 5.3 WebSocket with controller

1. Client connects to e.g. `/stalker/ws?controller_key=oxr`.
2. Backend calls `resolve_websocket_controller_context("oxr")` (gets DB session, resolves controller).
3. Backend calls `ws_manager.connect(websocket, controller_key="oxr")`.
4. When the scheduler broadcasts a device update for controller `oxr`, it calls `broadcast_device_update(..., controller_key="oxr")`; only connections registered with that key receive the message.

### 5.4 Background jobs (schedulers)

1. Scheduler runs on a timer (or startup).
2. It gets a DB session and calls `list_enabled_controllers(db)`.
3. For each enabled controller it: gets client with `get_shared_client(controller.controller_key)`, performs the tool’s refresh/collect logic, writes to DB with `controller_id=controller.id`, and broadcasts via WebSocket with `controller_key=controller.controller_key`.
4. One controller failing does not stop the others; errors are logged per controller.

### 5.5 Controller selection change (dashboard)

1. User changes the dropdown; `initSelectorUi`’s `onchange` calls `setSelectedController(select.value)` and then the provided `onChange` (on dashboard, no-op).
2. `setSelectedController` updates state, localStorage, and URL and dispatches `controller-context-changed`.
3. Dashboard listens for `controller-context-changed` and calls `loadSystemStatus()` and `checkGatewayAvailability(true)` so the widget and Threat Watch card update to the new controller without a full page reload.

---

## 6. File-by-File Summary

| Path | Action | Purpose |
|------|--------|---------|
| `shared/models/controller_config.py` | Added | Controller registry SQLAlchemy model. |
| `shared/controller_registry.py` | Added | Registry service: list/get/resolve controllers, create client, upsert default, legacy fallback. |
| `shared/controller_context.py` | Added | Request/WebSocket controller resolution and FastAPI dependency. |
| `shared/unifi_session.py` | Modified | Per-controller_key client map; get/invalidate by key. |
| `shared/cache.py` | Modified | Controller-scoped cache keys for gateway, IPS, AP, system status. |
| `shared/websocket_manager.py` | Modified | Store and filter by controller_key on connect and broadcast. |
| `shared/database.py` / models | Modified | Register ControllerConfig; tool models gain controller_id. |
| `app/routers/config.py` | Modified | Controller CRUD + set-default/set-active/test; mutation guard; validation. |
| `app/main.py` | Modified | System status and WebSocket use ControllerContext and controller_key. |
| `app/templates/dashboard.html` | Modified | Controller selector; controller-aware fetch; wait for context before first load; refetch on change; config modal management UI. |
| `app/static/js/controller-context.js` | Added | Frontend controller state, apiFetch, websocketUrl, selector UI, URL/localStorage sync. |
| `app/static/css/controller-selector.css` | Added | Controller selector/badge styles. |
| `tools/wifi_stalker/main.py` | Modified | WebSocket `/ws` with controller resolution; routes use ControllerContext. |
| `tools/wifi_stalker/routers/*.py` | Modified | All relevant routes use controller_id/controller_key from context. |
| `tools/wifi_stalker/scheduler.py` | Modified | Fan out over list_enabled_controllers; per-controller client and broadcasts. |
| `tools/wifi_stalker/templates/index.html` | Modified | Include context + selector; data-controller-link on links. |
| `tools/wifi_stalker/static/js/app.js` | Modified | loadControllers; apiFetch; websocketUrl; initSelectorUi. |
| `tools/threat_watch/*` | Modified | Same pattern: controller_id in models/routes; scheduler fanout; frontend context + selector. |
| `tools/network_pulse/*` | Modified | Same pattern; WebSocket already had controller_key support. |
| `alembic/versions/20260313_0000_add_controller_scoping_to_tool_tables.py` | Added | controller_config table; controller_id columns and backfill; FKs and indexes. |
| `run.py` | Modified | Schema repair: add controller_id to tool tables if missing; backfill from default if present. |
| `docs/MULTI_CONTROLLER.md` | Added/updated | User/operator overview, selection behavior, management, upgrade, security, limitations. |
| `docs/MULTI_CONTROLLER_TECHNICAL.md` | This file | Technical summary of all changes and behavior. |

---

## 7. Security and Validation (Summary)

- **Config mutations** (create/update/delete/set-default/set-active): Require `X-Requested-With: XMLHttpRequest`; in production auth mode, same-origin/referer checks are used as lightweight CSRF mitigation.
- **Secrets:** Never returned in API responses; only booleans like `has_api_key`. Connection test and save errors are sanitized so credentials are not leaked.
- **Validation:** Pydantic validators for controller URL (scheme, host, no query/fragment), site_id (allowed characters), display_name, and controller_key format.

---

## 8. Testing and Observability

- **Logging:** Scheduler and WebSocket code log `controller_key` (or controller identity) on errors and important actions so multi-controller issues can be traced.
- **Tests:** See `tests/test_controller_management.py`, `tests/test_controller_selection.py`, `tests/test_migration_controller_bootstrap.py` for controller API, selection behavior, and migration bootstrap.
