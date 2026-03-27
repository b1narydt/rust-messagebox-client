---
phase: 05-overlay-device-registration
plan: "02"
subsystem: overlay-init-host-resolution-device-registration
tags: [overlay, init-once, host-resolution, deduplication, device-registration, ts-parity]
dependency_graph:
  requires: ["05-01"]
  provides: ["init-once semantics", "host-resolved send_message", "multi-host list_messages dedup", "register_device", "list_registered_devices"]
  affects: ["src/client.rs", "src/http_ops.rs", "src/adapter.rs", "src/permissions.rs", "src/host_resolution.rs"]
tech_stack:
  added: ["futures_util::future::join_all", "std::collections::HashSet"]
  patterns: ["OnceCell init-once", "concurrent join_all with filter_map", "host override passthrough", "dedup by HashMap entry"]
key_files:
  created: []
  modified:
    - src/client.rs
    - src/http_ops.rs
    - src/adapter.rs
    - src/permissions.rs
    - src/host_resolution.rs
    - tests/integration.rs
decisions:
  - "send_message splits into public send_message (resolves host) + pub(crate) send_message_to_host (explicit host) — preserves public API while enabling override passthrough"
  - "list_messages uses HashSet deduplication + join_all: single-host path skips dedup overhead, multi-host path uses dedup_messages()"
  - "dedup_messages extracted as pub(crate) fn — enables unit testing without mock HTTP"
  - "send_live_message host_override in adapter goes directly to HTTP path (send_message_to_host) — WS always connects to self.host()"
  - "init_once changed from #[allow(dead_code)] to pub(crate) — needed for test_init_compiles to reference the field"
  - "Integration test 3-arg MessageBoxClient::new fixed (Rule 1 bug — stale call from before Network param added in 05-01)"
metrics:
  duration: "5 minutes"
  completed_date: "2026-03-27"
  tasks_completed: 3
  files_modified: 6
---

# Phase 5 Plan 2: Overlay Init, Host Resolution Wiring, Device Registration Summary

Wired init-once overlay advertisement semantics, host-resolved send_message (critical TS parity fix), multi-host list_messages deduplication, host_override passthrough through CommsLayer adapter, and device registration endpoints (register_device / list_registered_devices).

## Tasks Completed

| Task | Description | Commit | Files |
|------|-------------|--------|-------|
| 1 | init_once + host-resolved send_message + multi-host list_messages | 51cebfd | src/client.rs, src/http_ops.rs |
| 2 | host_override passthrough in adapter + send_notification cleanup | 263d722 | src/adapter.rs, src/permissions.rs |
| 3 | register_device and list_registered_devices | 7283b18 | src/host_resolution.rs |
| - | Fix integration test stale constructor (Rule 1) | 00dd0aa | tests/integration.rs |

## Key Changes

### assert_initialized — init_once.get_or_try_init

`assert_initialized` now uses `OnceCell::get_or_try_init` to ensure the full init sequence runs at most once even under concurrent access. Sequence: cache identity key → query advertisements → conditionally call `anoint_host` if no matching ad. Critical TS parity: anoint errors are caught with `eprintln!` and execution continues.

### send_message — TS parity host resolution

The most critical change: `send_message` now calls `resolve_host_for_recipient(recipient)` before every send (unless host_override given), exactly matching TS line 952: `const finalHost = overrideHost ?? await this.resolveHostForRecipient(message.recipient)`. Messages no longer blindly go to `self.host` — they go to the recipient's advertised host. The implementation splits into `send_message` (public, resolves host) + `send_message_to_host` (pub(crate), takes explicit host).

### list_messages — multi-host deduplication

`list_messages` now queries all advertised hosts for this identity concurrently via `join_all`, then deduplicates results by `message_id` using `dedup_messages()`. Single-host path skips the dedup overhead. If all hosts fail, returns error; if at least one succeeds, returns partial results (TS `Promise.allSettled` semantics).

### CommsLayer adapter — host_override no longer ignored

`RemittanceAdapter::send_message` now passes `host_override` through: `Some(host)` → `send_message_to_host`, `None` → `send_message` (with overlay resolution). `send_live_message` similarly routes: `Some(host)` → HTTP path to override host, `None` → WS+HTTP-fallback path.

### Device registration

`register_device` and `list_registered_devices` added to `src/host_resolution.rs`. Both call `assert_initialized` first. `register_device` POSTs camelCase JSON to `/registerDevice` and returns the full `RegisterDeviceResponse` (not void). `list_registered_devices` GETs `/devices` and returns `Vec<RegisteredDevice>` with all 8 server fields.

## Test Results

```
test result: ok. 82 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

Up from 77 at plan start (+5 new tests). Integration tests: 12 passed.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed stale 3-argument MessageBoxClient::new in integration tests**
- **Found during:** Task 3 full cargo test run
- **Issue:** `tests/integration.rs` used `MessageBoxClient::new(host, wallet, None)` — the 3-arg form from before the `Network` parameter was added in Phase 05-01. Integration tests failed to compile.
- **Fix:** Added `bsv::services::overlay_tools::Network::Mainnet` as 4th argument to all 3 call sites in `tests/integration.rs`.
- **Files modified:** tests/integration.rs
- **Commit:** 00dd0aa

## Self-Check: PASSED

All key files found. All commits verified in git log.
