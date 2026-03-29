---
phase: 08-e2e-websocket-payment-validation
plan: 01
subsystem: testing
tags: [websocket, brc-103, socket-io, http-polling, live-tests, rust, tokio]

# Dependency graph
requires:
  - phase: 07-websocket-transport
    provides: BRC-103 transport, peer_task, general_msg_dispatcher, listen_for_live_messages
provides:
  - HTTP polling fallback for listen_for_live_messages (live Babbage server does not push via WS room)
  - test_two_client_live_messaging passing against messagebox.babbage.systems
  - test_bidirectional_live_messaging covering both directions
  - test_join_leave_room covering subscription lifecycle
affects:
  - 08-02-edge-cases
  - 08-03-funded-payment

# Tech tracking
tech-stack:
  added: []
  patterns:
    - HTTP polling fallback alongside Socket.IO subscription for server-stored messages
    - Arc<Mutex<T>> for shared state cloned into spawned tasks
    - try_send (not blocking_send) for mpsc channels inside async callbacks

key-files:
  created: []
  modified:
    - src/client.rs
    - src/websocket.rs
    - tests/live_server.rs

key-decisions:
  - "Live Babbage server stores sendMessage payloads but does NOT broadcast via Socket.IO room push to other clients; HTTP polling every 2s is required as primary delivery mechanism"
  - "auth_fetch and joined_rooms changed from Mutex<T> to Arc<Mutex<T>> to allow cloning into polling task"
  - "Callbacks invoked from polling task must use try_send not blocking_send to avoid panic inside Tokio runtime"
  - "Polling task exits cleanly when room_id is removed from joined_rooms (leave_room path)"

patterns-established:
  - "Polling fallback: spawn a background task that polls /listMessages every 2s, tracks seen_ids, fires callback for new messages"
  - "Leave-room stop signal: polling task checks joined_rooms set each iteration and breaks if room removed"

requirements-completed: []

# Metrics
duration: 95min
completed: 2026-03-29
---

# Phase 8 Plan 01: E2E WebSocket Live Messaging Summary

**HTTP polling fallback added to listen_for_live_messages resolves live-server delivery gap; three live two-client tests (basic, bidirectional, join/leave) all pass against messagebox.babbage.systems**

## Performance

- **Duration:** ~95 min
- **Started:** 2026-03-29T18:00:00Z
- **Completed:** 2026-03-29T20:29:39Z
- **Tasks:** 2
- **Files modified:** 3

## Accomplishments

- Diagnosed why test_two_client_live_messaging failed: the live Babbage server processes BRC-103 sendMessage and stores it, but does not broadcast via Socket.IO room push — zero authMessage events ever arrive at the subscribing client via WebSocket
- Added HTTP polling fallback inside listen_for_live_messages: background Tokio task polls /listMessages every 2s, deduplicates by message_id, fires callback for new arrivals; polling stops when leave_room removes room from joined_rooms
- All three two-client live tests pass: test_two_client_live_messaging, test_bidirectional_live_messaging, test_join_leave_room

## Task Commits

Each task was committed atomically:

1. **Task 1: Diagnose and fix two-client live messaging failure** - `f6124e2` (fix)
2. **Task 2: Add bidirectional and join/leave room tests** - `13ab78c` (feat)

## Files Created/Modified

- `src/client.rs` - Added HTTP polling fallback task in listen_for_live_messages; auth_fetch and joined_rooms changed to Arc<Mutex<T>>; new poll_list_messages and extract_plain_body free functions
- `src/websocket.rs` - Diagnostic eprintln added then removed; on_any comment updated noting server does not push via WS room
- `tests/live_server.rs` - Fixed blocking_send -> try_send in test_two_client_live_messaging; added test_bidirectional_live_messaging and test_join_leave_room

## Decisions Made

- Used HTTP polling as the primary delivery mechanism rather than fixing the server behavior (server is external/production, cannot change)
- Polling interval of 2 seconds chosen as a balance between responsiveness and API load
- Polling task linked to joined_rooms set: if leave_room removes the room, polling task self-terminates on next iteration, making the join/leave lifecycle test reliable
- try_send used instead of blocking_send in test callbacks because callbacks are invoked from inside the async polling task context

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] blocking_send panics inside Tokio runtime**
- **Found during:** Task 1 (test_two_client_live_messaging)
- **Issue:** Test callback used tx.blocking_send(msg) which panics when called from within an async context (the spawned polling task)
- **Fix:** Changed to tx.try_send(msg) in test callbacks
- **Files modified:** tests/live_server.rs
- **Verification:** Test ran without panic
- **Committed in:** f6124e2 (Task 1 commit)

**2. [Rule 3 - Blocking] Arc<Mutex<T>> required for polling task**
- **Found during:** Task 1 (listen_for_live_messages polling task)
- **Issue:** Rust borrow checker rejected cloning auth_fetch and joined_rooms into spawned task because they were plain Mutex<T> (not Clone)
- **Fix:** Changed both fields to Arc<Mutex<T>> in MessageBoxClient struct and constructor
- **Files modified:** src/client.rs
- **Verification:** Compiled cleanly
- **Committed in:** f6124e2 (Task 1 commit)

---

**Total deviations:** 2 auto-fixed (1 bug, 1 blocking compile error)
**Impact on plan:** Both auto-fixes were necessary for correctness and compilation. No scope creep.

## Issues Encountered

- Extensive diagnostic logging was added to peer_task, general_msg_dispatcher, on_any, and on("authMessage") to trace message flow. Output confirmed: after BRC-103 handshake completes, zero Socket.IO events arrive at Client A when Client B sends a message. HTTP list_messages confirmed the message was stored server-side. This ruled out BRC-103 session errors and timing races — the server simply does not broadcast via WebSocket. All diagnostic eprintln statements were removed before committing.

## User Setup Required

None - no external service configuration required. Tests connect to the live messagebox.babbage.systems server using the existing ArcWallet test fixture.

## Next Phase Readiness

- Two-client live messaging is validated end-to-end
- HTTP polling fallback is in place and tested via join/leave lifecycle
- Ready for 08-02 edge cases and 08-03 funded payment tests

---
*Phase: 08-e2e-websocket-payment-validation*
*Completed: 2026-03-29*
