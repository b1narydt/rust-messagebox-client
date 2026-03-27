---
phase: 04-websocket-live-messaging
plan: 02
subsystem: websocket
tags: [websocket, commslayer, peerpay, live-messaging, trait-override]
dependency_graph:
  requires: [04-01-websocket-core, 03-peerpay, 02-commslayer]
  provides: [commslayer-live-override, live-payment-send, live-payment-listen]
  affects: [src/adapter.rs, src/peer_pay.rs]
tech_stack:
  added: []
  patterns: [CommsLayer trait override delegation, Arc<dyn Fn> callback wrapping, safeParse silently-skip pattern]
key_files:
  created: []
  modified:
    - src/adapter.rs
    - src/peer_pay.rs
decisions:
  - "send_live_message and listen_for_live_messages ignore host_override — multi-host deferred to Phase 5 (same pattern as send_message)"
  - "listen_for_live_payments wraps PeerMessage callback with PaymentToken JSON parsing — silently skips non-payment messages matching TS safeParse behavior"
  - "send_live_payment delegates create_payment_token -> send_live_message — inherits WS + HTTP fallback from Plan 01 transport layer"
metrics:
  duration_minutes: 1
  completed_date: "2026-03-27"
  tasks_completed: 2
  files_changed: 2
---

# Phase 04 Plan 02: WebSocket CommsLayer + PeerPay Live Methods Summary

**One-liner:** CommsLayer trait overrides delegating live send/listen to the Plan 01 WebSocket transport, plus PeerPay live payment send/listen methods with PaymentToken callback wrapping.

## What Was Built

Wired the WebSocket transport (from Plan 01) into the `CommsLayer` trait boundary and added live payment methods to `PeerPayClient`.

### Task 1: Override CommsLayer live methods in RemittanceAdapter

- Added `send_live_message` override to `CommsLayer for RemittanceAdapter<W>` — delegates to `self.inner.send_live_message()`, ignores `host_override` (Phase 5 concern)
- Added `listen_for_live_messages` override — delegates to `self.inner.listen_for_live_messages()`, ignores `override_host`
- Both methods map `MessageBoxError` to `RemittanceError::Protocol` (consistent with existing `send_message` pattern)
- Added compile-check functions `send_live_message_compiles` and `listen_for_live_messages_compiles` to verify method resolution

### Task 2: Add send_live_payment and listen_for_live_payments to PeerPay

- Added `std::sync::Arc` and `bsv::remittance::types::PeerMessage` imports to `peer_pay.rs`
- Added `send_live_payment(recipient, amount)` — creates payment token, serializes to JSON, delivers via `send_live_message` (inherits WS + HTTP fallback)
- Added `listen_for_live_payments(on_payment)` — wraps `listen_for_live_messages` callback with `PaymentToken` JSON parsing; silently skips non-payment messages
- Added 3 tests: compile-check for `send_live_payment`, parsing-success and parsing-skip tests for callback wrapper logic

### Tests

2 new compile-check functions in `adapter.rs` (no runtime assertions needed — method resolution is the contract).
3 new tests in `peer_pay.rs`:
- `listen_for_live_payments_callback_parses_token` — valid PaymentToken JSON produces IncomingPayment
- `listen_for_live_payments_callback_skips_non_payment` — invalid body produces no IncomingPayment
- `send_live_payment_compile_check` — compile-time method resolution check

Total: 69 lib tests pass (67 existing + 2 new runtime tests).

## Deviations from Plan

None - plan executed exactly as written.

## Self-Check: PASSED

Files modified:
- src/adapter.rs: FOUND (send_live_message + listen_for_live_messages overrides)
- src/peer_pay.rs: FOUND (send_live_payment + listen_for_live_payments methods)

Commits:
- 5bf9017: feat(04-02): override CommsLayer live methods in RemittanceAdapter
- f28777d: feat(04-02): add send_live_payment and listen_for_live_payments to PeerPay
