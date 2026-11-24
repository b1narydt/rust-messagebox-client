# Changelog

All notable changes to `bsv-messagebox-client` are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.6.0] — 2026-11-23

Parity with what the Atlas relay does (rust-mpc#462). The README's "Relay
behaviour" section describes the result.

### Changed (breaking)

- **Relay errors carry the relay's code** (`src/transport.rs`). Every relay
  HTTP answer maps through one place. `MessageBoxError` gains
  `Relay { status, code, description }` (the body's `code`, or the identity
  gate's `error` such as `not_certified`), `RateLimited { retry_after, tier }`
  and `RelayIdentityMismatch { expected, observed }`. A relay JSON error that
  was `Http(status, url)` is now `Relay` or `RateLimited`; `Http` remains for a
  body that names no code. A list or ack sent to several hosts that every
  host fails returns the client's own host's error, not `Http(0, ...)`.
- **Live-send answers are matched by message id** (`src/websocket.rs`).
  `MessageBoxWebSocket::emit_send_message(&self, &WsSendMessageData)` now
  returns a `LiveSendAck`; `LiveSendAck::wait(timeout)` gives the relay's
  answer, and dropping it withdraws that waiter and no other.
  `remove_pending_ack` is removed. The relay's ack names the message (the
  earlier note that it does not was wrong), and its refusal, `messageFailed`,
  names none, so a refusal fails every pending live send on the socket. One
  WebSocket dial runs at a time, so concurrent sends on a cold client share
  one socket. A reconnect replaces only a dead socket; it closes that socket
  and fails the sends still waiting on it at once. A refused, unanswered or
  failed emit falls back to HTTP with
  the same message id. The WebSocket room and recipient are sent lowercase, as the relay joins
  rooms lowercase and compares them exactly.
- **Sends and lists honour the relay's rate budget** (`src/transport.rs`,
  `src/http_ops.rs`). After a refusal the client holds every send and list to
  that relay for `retry_after` (at least 1 s) and resends the same bytes, so
  the same id, within `with_rate_limit_wait` (default 60 s); past it the call
  returns `RateLimited`. A call can now wait up to that long. A live send's
  wait before its emit and its HTTP fallback share that one wait; its 10 s
  ack wait and network time are on top. A live send waits on, and a refusal
  on the socket holds, the relay the socket is open to.
- **The poll backstop lists sparingly** (`src/client.rs`). It replaces the 2 s
  poll that stood down on WebSocket activity: one list on each WebSocket
  connect and reconnect, then every 15 s while connected
  (`with_poll_interval`); with no connected socket, after 1 s, doubling to 8 s.
  It waits out a rate-limit refusal and backs off up to 60 s after a failed
  list. An oversize list (over the 32 MiB bound) is logged as an error, and
  the poll then waits 60 s before it lists again, connected or not.

### Added

- `MessageBoxClient::with_expected_relay_key` and `expected_relay_key`: pin the
  relay's identity key on every HTTP answer and WebSocket connect. A pinned
  client talks only to its own host: it skips overlay host lookup and the
  multi-host list and ack fan-out, and refuses any other named host, including
  `init`'s `target_host` and `anoint_host`'s, with the new
  `MessageBoxError::RelayHostRefused { pinned, requested }` before any request,
  payment or advertisement, including the overlay lookup a first call makes to
  initialize. Its HTTP and WebSocket channels sign a request only for a server
  that proved the pinned key, so a request is never sent to one that proved
  another; they prove certificates only to the pinned key, never pay a `402`,
  and reveal no key linkage.
- `MessageBoxClient::with_certificate_provider`,
  `MessageBoxWebSocket::connect_with_certificate_provider`, and the
  `websocket::CertificateProvider` re-export: answer the relay's certificate
  request on the WebSocket. HTTP has no provider hook in bsv-sdk 0.8.0.
- `MessageBoxClient::with_rate_limit_wait` and `with_poll_interval` (at
  least 1 s; a shorter interval is raised to 1 s).
- Pinned-host payment APIs: `list_incoming_payments_from_host`,
  `accept_payment_from_host` and `request_payment_to_host`, which use only the
  named host.

### Known limits

- A refusal on the socket fails live sends the relay may already have
  accepted, and each is resent over HTTP with its id: `messageFailed` names no
  message (atlas-relay#27).
- A box whose list exceeds 32 MiB cannot be listed or drained:
  `/listMessages` has no limit or paging (atlas-relay#28).

### Fixed

- **An ack that beats the relay's insert is retried** (`src/http_ops.rs`).
  `ERR_INVALID_ACKNOWLEDGMENT`, and only that answer, is retried for up to 5 s.
- **The payment-request whitelist error keys on `ERR_DELIVERY_BLOCKED`**
  instead of any 403, so an uncertified sender is no longer told it is off the
  whitelist.
- **The `ERR_DUPLICATE_MESSAGE` success path is removed.** The relay never
  sends that code: it stores with INSERT IGNORE, answers a resend 200 while
  the first row exists, and stores it again after an ack deletes the row.
- **List-message payments now retain explicit outcomes and byte-exact retry data**
  (`src/http_ops.rs`, Atlas-Documentation#383). New source-compatible
  `list_messages_detailed` and `list_messages_lite_detailed` APIs return the
  decrypted inner message alongside `NoPayment`, `Internalized`, `Skipped`,
  `Declined`, `Failed`, or `Unprocessable`. Every in-limit non-successful payment
  result includes the exact raw outer envelope, including unknown fields. The legacy
  list methods retain their signatures and prior inner-body behavior for
  no-payment/success cases; skipped, declined, failed, and unprocessable payments
  now leave the raw wrapper in `body` instead of silently discarding retry data.
  Recipient payments consume the nested TS `paymentRemittance` base64 wire shape,
  support wallet-payment and basket-insertion outputs (including valid mixed
  sets), validate the TS transaction/output/description/remittance limits, build
  all outputs before one wallet call, forward `originator`, and treat only
  `accepted: true` as success. Multi-host source provenance, cross-host atomicity,
  and exactly-once refund behavior remain out of scope (source issue #12). Each
  host's list response is capped at 32 MiB (the largest bounded server profile)
  before status inspection or outer JSON deserialization across full, lite, and
  background-poll paths. Successful pages now use one typed parse instead of a
  preceding full `serde_json::Value` parse. Individual stored bodies above a
  conservative 4 MiB nested-envelope processing cap are rejected before nested
  JSON parsing as `Unprocessable`, with a bounded marker and no raw copy;
  derivation remittances are capped before base64 decoding at the send-side
  32-byte nonce size. `AuthFetch` still buffers the authenticated response frame
  before returning its `Vec<u8>`; a pre-buffer transport cap requires upstream
  bsv-sdk support.

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

## [Unreleased]

### Fixed

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
