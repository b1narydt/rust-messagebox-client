# Changelog

All notable changes to `bsv-messagebox-client` are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Fixed

- **Payment ordering now matches TS `@bsv/message-box-client` 2.5.1 / ts-stack #534**
  (`src/peer_pay.rs`, Atlas-Documentation#279). Notification and payment-acceptance
  paths, plus refund-eligible rejection paths, store the payment before the relay
  message is acknowledged, and a wallet answer of `accepted: false` is a failure
  rather than a success:
  - `accept_payment` returns `Err` and leaves the message queued when the wallet
    declines. Previously any `Ok` from `internalize_action` was treated as stored.
  - `reject_payment` now internalizes → refunds → makes one logical acknowledgement
    attempt. Previously it acknowledged before the refund (a failed refund stranded
    the sender with the queue record gone) and swallowed a 401 on the refund send as
    success. There is no durable refund journal: an uncertain refund send must be
    reconciled before retry, or a retry can refund again. The existing
    too-small-to-refund policy remains: payments below 2000 sats are acknowledged
    without internalization because the refund after fees would be non-positive.
  - `acknowledge_notification` keeps a payment on the relay when nothing in it can
    be stored (missing `tx`/`outputs`, only unsupported protocols such as
    `basket insertion`) and consumes the current nested
    `outputs[].paymentRemittance` wire shape, decoding its base64 derivation fields
    before wallet internalization. It returns `Err` on an empty transaction,
    malformed/missing remittance, invalid base64 or identity key, or mixed
    supported/unsupported output protocols, instead of acknowledging the payment
    away. This error result deliberately differs from TS, which resolves `false`;
    both retain the payment. Notifications with no payment envelope are still
    acknowledged. Rust also deliberately accepts absent output `protocol`, which TS
    skips. The notification gate now matches TS: only an object with its own
    `message` member can expose a payment for internalization. Notification payments
    also enforce the TS transaction (1..=32 MiB), output-count (at most 101),
    description (trimmed, nonempty, at most 50 UTF-8 bytes, no C0/C1 controls),
    nonempty base64, and compressed 66-hex-character sender-key constraints.
  Endpoint and wire-schema compatibility are unchanged. Acknowledgement is not an
  atomic multi-host transaction: the existing fan-out reports success when any host
  succeeds, so failed hosts can retain copies after a partial acknowledgement.

- **Half-open WebSocket detection (issue #7)** (`src/websocket.rs`, `src/client.rs`).
  A black-holed socket (peer gone, no TCP FIN) was previously invisible until the
  next write failed — up to 20 s+ of silently dropped inbound messages. Added an
  inbound **read-deadline watchdog**: every inbound frame (BRC-103 authMessage,
  general message, ack) stamps a monotonic timestamp, and a 1 s watchdog declares
  the socket dead if nothing arrives within `READ_DEADLINE` (5 s, ~2.5× the
  keepalive round-trip). The keepalive probe still runs every 20 s to elicit
  inbound traffic; the deadline, not the next write, is now the liveness gate.
- **Proactive reconnect** (`src/client.rs`). A background supervisor watches the
  connection flag and, on a half-open death, re-establishes the socket with
  jittered exponential backoff (250 ms → 10 s) and replays joinRoom +
  re-subscribe for every active subscription — without waiting for the next
  send/receive call. `is_ws_connected()` now reflects reality within the
  detection window.

### Changed

- **Un-serialized the WebSocket send path** (`src/websocket.rs`). Removed the
  single-command-at-a-time `peer_tx` funnel (one `tokio::select!` loop that
  awaited each `peer.send_message` before the next) — the WS-path twin of the
  `Arc<Mutex<AuthFetch>>` already removed from the HTTP path. Sends now sign
  through the `&self` `Peer::create_general_message` (lock-free against the
  shared session, bsv-sdk ≥ 0.2.86) and emit on the cloned Socket.IO `Client`
  (whose `emit` is `&self`), so N concurrent `send_live_message` calls on one
  socket sign + emit + await their acks in parallel. Ack correlation moved from a
  single `oneshot` per `sendMessageAck-{roomId}` to a FIFO `VecDeque` per key, so
  concurrent same-room sends each resolve against one room-scoped ack in order
  (the server ack carries no messageId). Wire format unchanged — TS/Go/Rust
  interop holds.

## [0.2.0] — 2026-08-19

> Housekeeping note: this file was not maintained across 0.1.4–0.1.7. The
> `[Unreleased]` block above predates those releases and describes work that has
> already shipped; it is left as written rather than silently re-dated.

### Changed

- **`bsv-sdk` 0.4 → 0.5**, and `authsocket` with it. *(breaking)* This crate's
  own source is unchanged — `Transaction::sighash_preimage` now returns
  `SighashPreimage` instead of `Vec<u8>`, but it derefs to `[u8]`, so
  `sha256(&preimage)` in `build_advertisement_unlock_script` compiles and hashes
  exactly the same bytes as before. The break is in the *public dependency*:
  `MessageBoxClient<W>`, `RemittanceAdapter<W>`, and every `encrypt_body` /
  `decrypt_body` signature are bounded on `bsv::wallet::interfaces::WalletInterface`,
  so a caller still on bsv-sdk 0.4 cannot supply a wallet this crate will accept.
  That is a breaking change for every consumer, which is why this is 0.2.0 and
  not 0.1.8.

  The `authsocket` requirement moves to `0.2.0` for the same reason, and it is
  not optional: authsocket 0.1.3 declares `bsv-sdk ^0.4.0`, and a `0.1.x`
  requirement here would happily resolve back to it — putting two `bsv` packages
  in one graph, at which point `AuthSocketClient::connect` rejects our `W` with
  *"the trait bound `W: bsv::wallet::interfaces::WalletInterface` is not
  satisfied"* even though the trait is spelled identically in both copies.

### Fixed

- **`revoke_host_advertisement` signs `sha256(preimage)`, not the raw preimage**
  (rust-mpc#342). `create_signature` applies SHA-256 to its `data` exactly once
  and a BSV sighash is `sha256d(preimage)`, so the caller owes the FIRST hash.
  Passing the preimage itself produced a signature over `sha256(preimage)` — a
  digest no script engine recomputes. The unlocking script was well-formed and
  the revocation transaction was simply unspendable.
  `revocation_unlock_script_validates_against_the_advertisement_lock` now
  ECDSA-verifies the DER against `sha256d(preimage)` under the advertisement
  key, so handing over the raw preimage again turns the assertion red.

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
