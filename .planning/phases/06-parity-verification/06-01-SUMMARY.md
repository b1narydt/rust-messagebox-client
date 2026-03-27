---
phase: 06-parity-verification
plan: 01
subsystem: types, permissions, host_resolution, client, adapter
tags: [parity, types, override_host, websocket, overlay]
dependency_graph:
  requires: [05-02-PLAN.md]
  provides: [all missing types, override_host on 13 methods, localhost filter, joined_rooms tracking]
  affects: [src/types.rs, src/permissions.rs, src/host_resolution.rs, src/client.rs, src/adapter.rs]
tech_stack:
  added: []
  patterns: [override_host optional param pattern, joined_rooms HashSet tracking, get_joined_rooms blocking_lock accessor]
key_files:
  created: []
  modified:
    - src/types.rs
    - src/permissions.rs
    - src/host_resolution.rs
    - src/client.rs
    - src/adapter.rs
    - src/http_ops.rs
    - src/peer_pay.rs
decisions:
  - "get_joined_rooms uses blocking_lock — acceptable since it is only used from sync test context and the lock is never held across await"
  - "test_socket returns Option<bool> (is_connected state) not the socket itself — WS types are non-Clone and exposing them would be impractical"
  - "init(target_host) accepts the param but currently ignores it — assert_initialized always uses self.host for the anoint call; target_host is advisory and reserved for future use"
  - "send_live_message override_host applies to HTTP fallback path only — WS always connects to self.host()"
  - "get_message_box_quote_multi added to permissions.rs (linter-assisted) — issues one /permissions/quote request per recipient matching TS behavior"
metrics:
  duration: "8 min"
  completed: "2026-03-27"
  tasks: 2
  files: 7
---

# Phase 06 Plan 01: Parity — Missing Types, override_host, Localhost Filter, joined_rooms Summary

One-liner: Added 11 missing TS-parity types, override_host on 13 methods, localhost/non-HTTPS filter in query_advertisements, and joined_rooms tracking with get_joined_rooms/join_room/test_socket/initialize_connection on MessageBoxClient.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Add missing types, override_host, localhost filter, joined_rooms | eabc130 | src/types.rs, src/permissions.rs, src/host_resolution.rs, src/client.rs, src/adapter.rs, src/http_ops.rs, src/peer_pay.rs |
| 2 | Verify full test suite, confirm exports | 057aeba | src/websocket.rs |

## What Was Built

### New Types (src/types.rs)
- `SendListParams` — multi-recipient send parameters
- `SendListResult`, `SentRecipient`, `FailedRecipient`, `SendListTotals` — sendList response types
- `MessageBoxMultiQuote`, `RecipientQuote` — multi-recipient quote aggregation
- `Payment`, `PaymentOutput`, `PaymentRemittanceInfo`, `InsertionRemittanceInfo` — payment metadata for sendList

All types have `#[derive(Serialize, Deserialize, Clone, Debug)]` and `#[serde(rename_all = "camelCase")]`. Optional fields use `skip_serializing_if = "Option::is_none"`. All exported from lib.rs via `pub use types::*`.

### override_host Added to 13 Methods
- `set_message_box_permission` — `{override_host.unwrap_or(self.host())}/permissions/set`
- `get_message_box_permission` — same pattern
- `list_message_box_permissions` — same pattern
- `get_message_box_quote` — same pattern
- `allow_notifications_from_peer` — delegates with override_host
- `deny_notifications_from_peer` — delegates with override_host
- `check_peer_notification_status` — delegates with override_host
- `list_peer_notifications` — delegates with override_host
- `send_notification` — sends to override host directly when Some
- `register_device` — `{override_host.unwrap_or(self.host())}/registerDevice`
- `list_registered_devices` — `{override_host.unwrap_or(self.host())}/devices`
- `send_live_message` — override_host applied on HTTP fallback path
- `listen_for_live_messages` — override_host accepted (WS path deferred)
- `leave_room` — override_host accepted (WS path deferred)

### Localhost Filter in query_advertisements
After UTF-8 decoding the host field from PushDrop, the filter:
```rust
if !host_url.starts_with("https://") || host_url.contains("localhost") {
    continue;
}
```
Matches TS behavior of only returning HTTPS non-localhost hosts.

### joined_rooms Tracking + New Accessors on MessageBoxClient
- `joined_rooms: Mutex<HashSet<String>>` field added to struct
- Initialized as empty in `new()`
- `get_joined_rooms()` — returns clone of set (blocking_lock, sync-safe)
- `join_room(message_box)` — public join, inserts room_id into joined_rooms
- `leave_room(message_box, override_host)` — removes room_id from joined_rooms
- `listen_for_live_messages` — inserts room_id on join
- `test_socket()` — `#[cfg(test)]` accessor returning `Option<bool>` (is_connected)
- `initialize_connection(override_host)` — public wrapper for `ensure_ws_connected`
- `init(target_host)` — updated signature; target_host is advisory

### New Method: get_message_box_quote_multi (permissions.rs)
Added by linter during implementation — issues one `/permissions/quote` request per recipient, aggregates results into `MessageBoxMultiQuote`, tracks delivery agent identity keys per host. Used by `send_message_to_recipients` in http_ops.rs.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] send_message and send_message_to_host had more parameters than the plan showed**
- Found during: Task 1, Step 4
- Issue: Plan's context showed 3-arg `send_message` but http_ops.rs already had 7-arg version with skip_encryption, check_permissions, message_id, override_host from prior phases
- Fix: Updated all fallback call sites to pass the correct 7/8 args with sensible defaults (false, false, None, None)
- Files modified: src/client.rs, src/permissions.rs, src/peer_pay.rs, src/adapter.rs
- Commit: eabc130

**2. [Rule 2 - Missing] SendMessageRequest missing payment field in test**
- Found during: Task 1 compilation
- Issue: Linter added `payment: Option<MessagePayment>` to `SendMessageRequest` before our changes; test was using the old 1-field struct literal
- Fix: Added `payment: None` to test struct literal
- Files modified: src/http_ops.rs
- Commit: eabc130

**3. [Rule 2 - Missing] MessageBoxMultiQuote import removed from http_ops.rs**
- Found during: Task 2 (unused import warning)
- Issue: `MessageBoxMultiQuote` was imported in http_ops.rs but the type is now only used in permissions.rs
- Fix: Removed unused import
- Files modified: src/http_ops.rs
- Commit: eabc130

## Test Results

- `cargo test --lib`: 82 passed, 0 failed
- `cargo test` (lib + integration): 94 passed, 0 failed
- `cargo build`: clean, 0 errors, 0 warnings

## Self-Check: PASSED

- src/types.rs — FOUND
- src/permissions.rs — FOUND
- src/client.rs — FOUND
- src/host_resolution.rs — FOUND
- commit eabc130 — FOUND
- commit 057aeba — FOUND
