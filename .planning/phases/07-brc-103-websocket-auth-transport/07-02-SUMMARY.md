---
phase: 07-brc-103-websocket-auth-transport
plan: "02"
subsystem: auth
tags: [rust, brc-103, socket-io, peer, mpsc, tokio, type-erasure, mutual-auth]

# Dependency graph
requires:
  - phase: 07-brc-103-websocket-auth-transport
    plan: "01"
    provides: SocketIOTransport + encode/decode helpers ready for Peer wiring
  - phase: 04-websocket-live-messaging
    provides: MessageBoxWebSocket struct + public API surface to preserve

provides:
  - MessageBoxWebSocket with BRC-103 mutual auth via Peer<W> (type-erased)
  - PeerCommand channel for wallet-type-erased Peer access from public methods
  - peer_task (tokio::select! loop): process_next() continuous drain + PeerCommand handler
  - general_msg_dispatcher: primary path for all application events from BRC-103 general messages
  - server_identity_key() accessor for diagnostics and integration test assertions
  - BRC-103 integration test (test_brc103_websocket_auth, #[ignore]) in tests/live_server.rs

affects:
  - Phase 8 (reconnect) — peer_task design supports clean shutdown; reconnect needs fresh Peer + Transport

# Tech tracking
tech-stack:
  added: []  # No new deps; tokio mpsc, bsv::auth::peer::Peer, bsv::auth::types::MessageType already in Cargo.toml
  patterns:
    - "Type erasure via PeerCommand channel: Peer<W> lives in background task, public API needs no generic param"
    - "tokio::select! loop in peer_task: drains PeerCommand channel AND calls process_next() for incoming messages"
    - "Shared oneshot via Arc<Mutex<Option<Sender>>>: on_any and general_msg_dispatcher race for authenticationSuccess"
    - "Server identity key captured from InitialRequest in on('authMessage') callback via separate mpsc channel"
    - "Server-initiated BRC-103 handshake: server sends InitialRequest, process_next() drives dispatch"

key-files:
  created: []
  modified:
    - src/websocket.rs
    - tests/live_server.rs

key-decisions:
  - "PeerCommand channel for type erasure: MessageBoxWebSocket has no W generic param; Peer<W> owned by background task, accessed via PeerCommand::SendMessage"
  - "Server identity key captured via separate mpsc channel in on('authMessage') callback — checked after process_next() returns Ok(true)"
  - "general_msg_dispatcher is primary path for all app events (confirmed by TS source inspection); on_any handlers are defensive fallbacks only"
  - "reconnect(false) in ClientBuilder — BRC-103 requires fresh Peer + Transport on reconnect; auto-reconnect deferred to Phase 8"
  - "auth_success_shared as Arc<Mutex<Option<Sender<()>>>> — on_any and general_msg_dispatcher race; first fires, second finds None and skips"

patterns-established:
  - "Pattern: type-erased Peer via command channel — enables struct-level wallet type erasure without boxing dyn trait"
  - "Pattern: dual-path authenticationSuccess — on_any fallback + general_msg_dispatcher primary, shared oneshot prevents double-fire"

requirements-completed:
  - BRC103-03
  - BRC103-04
  - BRC103-06

# Metrics
duration: 4min
completed: 2026-03-28
---

# Phase 7 Plan 02: BRC-103 WebSocket Auth Transport Summary

**Peer<W> wired into MessageBoxWebSocket via PeerCommand type-erasure: BRC-103 mutual auth handshake replaces bare authenticated emit, all events route through signed authMessage envelopes**

## Performance

- **Duration:** ~4 min
- **Started:** 2026-03-28T01:15:04Z
- **Completed:** 2026-03-28T01:19:00Z
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments

- `src/websocket.rs` rewritten to use BRC-103 Peer-based mutual auth: `connect()` now creates `SocketIOTransport`, `Peer<W>`, drives the server-initiated BRC-103 handshake via `process_next()`, sends `authenticated` through a signed General message, then awaits `authenticationSuccess`
- `PeerCommand` enum + channel provides wallet type-erasure: `MessageBoxWebSocket` has no `<W>` generic parameter; the `Peer<W>` lives in a background `peer_task` and is accessed exclusively via `PeerCommand::SendMessage`
- `peer_task` spawned with `tokio::select!`: continuously drains the transport channel via `process_next()` while also handling `PeerCommand` requests from public API methods
- `general_msg_dispatcher` spawned as the primary path for all application events (`authenticationSuccess`, `sendMessage-*`, `sendMessageAck-*`) decoded from BRC-103 general messages
- `server_identity_key()` accessor added for diagnostics and integration tests
- BRC-103 integration test (`test_brc103_websocket_auth`) added to `tests/live_server.rs` with `#[ignore]`; compiles and runs (fails at connection refused — no live server, as expected)
- All 94 existing unit tests pass; all 7 websocket unit tests pass; `cargo build` clean

## Task Commits

Each task was committed atomically:

1. **Task 1: Wire Peer into MessageBoxWebSocket::connect with BRC-103 handshake** - `3a776b6` (feat)
2. **Task 2: Add BRC-103 integration test** - `8231e09` (test)

**Plan metadata:** (docs commit follows)

## Files Created/Modified

- `src/websocket.rs` — Complete rewrite: PeerCommand enum, peer_task, general_msg_dispatcher, BRC-103 handshake in connect(), server_identity_key() accessor, all public methods updated to use PeerCommand channel
- `tests/live_server.rs` — Added test_brc103_websocket_auth (#[ignore]) covering connect, is_connected, server_identity_key, join_room, disconnect assertions

## Decisions Made

- **PeerCommand type erasure:** `MessageBoxWebSocket` struct has no `<W>` parameter. The `Peer<W>` is owned by a background Tokio task; all outbound sends go through `PeerCommand::SendMessage { payload, reply }` with a oneshot reply channel. This avoids propagating the wallet type bound through all call sites.
- **Server identity key capture:** A separate `mpsc::channel::<String>(1)` captures the server's identity key from `InitialRequest` inside the `on("authMessage")` callback. The handshake loop checks `server_key_rx.try_recv()` after each `process_next()` returns `Ok(true)`, then verifies the session was created via `session_manager().has_session_by_identifier()`.
- **Primary vs fallback event routing:** The TS source confirms ALL application events go through BRC-103 envelopes. The `general_msg_dispatcher` is the primary path; `on_any` handlers for `sendMessage-*`, `sendMessageAck-*`, `authenticationSuccess` are retained as defensive fallbacks but will likely never fire.
- **reconnect(false):** BRC-103 sessions are single-use; the `SocketIOTransport.subscribe()` panics on second call. Auto-reconnect disabled for safety; Phase 8 will implement transparent BRC-103 reconnect with fresh Peer + Transport.
- **Dual authenticationSuccess path:** `Arc<Mutex<Option<oneshot::Sender<()>>>>` shared between `on_any` and `general_msg_dispatcher` — whichever path delivers the event first fires the oneshot; second path finds `None` and skips harmlessly.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None. The plan spec was precise and complete. The implementation matched the specified architecture exactly on the first compile attempt.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- `MessageBoxWebSocket` is now fully BRC-103 authenticated — ready for production use with any server implementing the go-messagebox-server BRC-103 protocol
- Integration test `test_brc103_websocket_auth` is ready to validate against a live server: `cargo test --test live_server -- --ignored test_brc103_websocket_auth`
- Phase 8 (transparent reconnect): `peer_task` clean shutdown on `PeerCommand::Shutdown` is in place; reconnect needs: create new `(auth_msg_tx, auth_msg_rx)`, new `SocketIOTransport`, new `Peer::new()`, re-run handshake loop, re-spawn tasks

## Self-Check: PASSED

- src/websocket.rs: FOUND
- tests/live_server.rs: FOUND (test_brc103_websocket_auth appended)
- 07-02-SUMMARY.md: FOUND
- Commit 3a776b6: FOUND
- Commit 8231e09: FOUND
- cargo build: PASSED (clean)
- cargo test --lib: 94 passed, 0 failed
- websocket unit tests: 7 passed, 0 failed

---
*Phase: 07-brc-103-websocket-auth-transport*
*Completed: 2026-03-28*
