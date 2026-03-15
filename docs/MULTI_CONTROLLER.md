# Multi-Controller Architecture

This document describes how multi-controller support works, how upgrades from legacy installs behave, and what is intentionally out of scope for now.

## Overview

UI Toolkit now supports multiple UniFi controllers in one installation.

- Controller definitions are stored in `controller_config`.
- Tool data is controller-scoped via `controller_id` foreign keys.
- Runtime collection fans out across enabled controllers.
- API routes and WebSocket subscriptions accept optional `controller_key`.
- Frontend stores the selected controller and threads it through API/WebSocket calls.

## Controller Selection Behavior

Selection is explicit when `controller_key` is provided, otherwise default fallback is used.

Resolution order:
1. `controller_key` query parameter (when present)
2. Default active controller in registry
3. Legacy fallback (`unifi_config`) only during migration compatibility

Frontend behavior:
- Selected controller is persisted in browser local storage (`unifi-toolkit-selected-controller`).
- URLs are updated with `controller_key` for direct loads and bookmarks.
- If only one active controller exists, selector UI is minimized to a badge.

## Controller Management

Controller management is provided by `/api/config/controllers` endpoints and dashboard settings UI.

Supported operations:
- list, create, edit, delete
- enable/disable
- set default
- test connection

Safety rules:
- At least one active controller must remain.
- Disabled controllers cannot be set as default.
- Deleting or disabling the default controller triggers default reassignment to another active controller.
- Secrets are write-only in API responses (`has_password` / `has_api_key` booleans only).

## Upgrade Behavior (Legacy Single-Controller -> Multi-Controller)

For legacy installs:
- Existing `unifi_config` is materialized into `controller_config` as default during compatibility reads/migrations.
- Existing tool rows are backfilled to that default controller.

For installs with no legacy config:
- Migration no longer creates placeholder controllers.
- If controller-scoped tables have data but no controller can be inferred, migration fails clearly with operator guidance.
- If there is no controller config and no scoped tool data, migration completes without synthetic defaults.

## Security Notes

Config mutation endpoints use stricter request expectations:
- `X-Requested-With: XMLHttpRequest` is required.
- In production auth mode, cross-origin/cross-site mutation requests are rejected using Origin/Referer checks when present.

These checks are a lightweight CSRF mitigation for browser-session flows.

## Current Limitations (Intentional)

- No aggregate all-controller dashboards yet.
- No single view that merges data across controllers.
- Frontend selection is controller-scoped per page/session, not per-widget.

These are intentionally deferred until controller-scoped behavior is fully stable in production.
