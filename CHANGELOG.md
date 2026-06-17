# Changelog

All notable changes to `bsv-messagebox-client` are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.3] — 2026-06-16

### Fixed

- **Live WebSocket delivery now works through reverse proxies and load balancers**
  (`src/websocket.rs`). Two independent issues prevented the BRC-103 handshake
  from completing once a proxy sat between client and server, silently forcing
  every connection onto the slow HTTP long-poll fallback:
  - **Connect WebSocket-first** (`transport_type(TransportType::Websocket)`).
    The EngineIO default (long-poll, then upgrade) exchanges `2probe`/`3probe`
    upgrade frames that many intermediaries forward unreliably — the HTTP 101
    succeeds but the probe never round-trips. A WS-first connect runs the
    EngineIO handshake directly over the WebSocket, which proxies treat as an
    ordinary upgraded connection.
  - **Gate the first emit on the namespace connect-ack.** `rust_socketio`'s
    `connect()` sends the Socket.IO CONNECT (`40`) and returns without awaiting
    the server's ack (`40{sid}`), so the BRC-103 InitialRequest could be emitted
    before the namespace was established. Across a network hop the CONNECT and
    the event coalesce into one read, and spec-strict servers (e.g. socketioxide)
    reject the premature event and close the socket. The first emit now waits for
    `Event::Connect` (bounded by `CONNECT_ACK_TIMEOUT`).
  - Verified end-to-end against a deployed server behind a CDN + platform proxy:
    sequential receive latency p50 ≈ 0.1 s (was ~2 s on the poll fallback),
    0 timeouts, and 100% delivery across 50 concurrent WebSocket connections.

- **Connection-close detection now fires** (`src/websocket.rs`). Close handling
  was registered via `on_any`, which `rust_socketio` only invokes for
  Message/Custom events — so `Event::Close` was never observed. Moved to a
  dedicated `on(Event::Close, …)` handler so a dropped transport correctly marks
  the socket disconnected for reconnect-on-next-call.

---

## [0.1.2] — 2026-06-16

### Security

- **WS receive is BRC-103-verified general messages only** (`src/websocket.rs`)
  - Removed the raw `on_any` application-event fallback that accepted
    unsigned `sendMessage-`/`sendMessageAck-`/`authenticationSuccess` Socket.IO
    events — an unauthenticated receive path. All application events now arrive
    exclusively via `general_msg_dispatcher` (nonce + session + signature
    verified before dispatch). Exact parity with `@bsv/authsocket-client`,
    which processes only verified general messages.

### Fixed

- **Duplicate delivery across paths** (`src/client.rs`)
  - `listen_for_live_messages` funnels the WS dispatcher, WS fallback, and HTTP
    poll through one shared `exactly_once` dedup, so each `message_id` reaches
    the callback at most once (previously a WS+poll race could fire twice).
  - The dedup mutex recovers from poison instead of panicking.

### Changed

- **HTTP poll demoted to a WS-gated backstop** (`src/client.rs`)
  - The poll stands down for any interval in which WS push already delivered,
    cutting redundant `/listMessages` load at high connection counts, with a
    staleness bound (`MAX_POLL_SKIPS`) that forces a catch-up at least every
    ~16 s. A poll error is now logged instead of silently swallowed.

---

## [0.1.1] — 2026-04-23

### Fixed

- **`is_connected()` stale after silent WS death** (`src/websocket.rs`)
  - `peer_task` now stores `connected = false` on any send failure before
    exiting, so callers see the real state immediately.
  - `general_msg_dispatcher` stores `connected = false` when its incoming
    channel closes (peer task gone).
  - Added a 20-second keepalive ping in `peer_task`; a failed ping also
    marks the connection dead and exits cleanly.

- **Subscriptions lost on WS reconnect** (`src/client.rs`)
  - `MessageBoxClient` now maintains a durable `subscriptions` registry
    (room\_id → callback) that survives socket teardown.
  - `ensure_ws_connected` replays `joinRoom` and re-subscribes every
    registered callback on the fresh socket after a reconnect.

### Added

- **`DeliveryMode` enum** (`src/delivery.rs`, `src/client.rs`)
  - `send_live_message` now returns `Result<DeliveryMode, MessageBoxError>`
    where `DeliveryMode` is either `Live { message_id }` (WS ack received)
    or `Persisted { message_id }` (HTTP fallback used).
  - `RemittanceAdapter` and `PeerPay` extract `.message_id()` to remain
    compatible with the `CommsLayer` trait.
  - `DeliveryMode::is_live()` convenience predicate included.

---

## [0.1.0] — initial release
