# Project Research Summary

**Project:** BSV MessageBox Client (Rust) — TS→Rust translation of `@bsv/message-box-client` v1.3.0
**Domain:** Async Rust library — BRC-31 authenticated messaging over HTTP and WebSocket
**Researched:** 2026-03-26
**Confidence:** HIGH

## Executive Summary

This project is a faithful Rust translation of a TypeScript BSV MessageBox client library, not a greenfield design. The TS implementation is the ground truth: all wire formats, HTTP endpoint conventions, encryption parameters, and behavioral edge cases must match exactly to interoperate with existing TypeScript clients and the Go server. The primary consumer is `metawatt-edge-rs`, which needs the `CommsLayer` trait implemented via `RemittanceAdapter` — this is the integration target that drives the entire MVP scope.

The recommended approach leans entirely on the `bsv-rust-sdk` (git dependency from `b1narydt/bsv-rust-sdk`) for authentication (`AuthFetch`), WebSocket transport, wallet crypto (`WalletInterface`), and the `CommsLayer` trait itself. There is no need for external cryptography crates — all HMAC and encryption operations must flow through the SDK wallet to produce identity-bound results that match TS behavior. The library should be generic over `W: WalletInterface + Clone + 'static` and use `Arc<Mutex<AuthFetch<W>>>` with tokio's async mutex for thread-safe HTTP operations.

The critical risks are all interoperability hazards: wrong base64 variant, wrong encryption protocol constants, wrong HTTP verb or query parameter casing, and wrong mutex type causing deadlocks in async context. All of these must be tested against the running server and a real TS client before building any higher-level features. Design the interior mutability model and encryption helpers correctly in Phase 1 — retrofitting these later requires touching every method in the codebase.

## Key Findings

### Recommended Stack

The stack is intentionally minimal and closely mirrors the SDK's own dependency graph. The `bsv` crate (network feature) is the single dominant dependency and brings along `tokio`, `serde`, `serde_json`, `async-trait`, and `thiserror` — all of which can be shared via Cargo deduplication. The only independent additions are `base64 = "0.22"` for wire-format encoding and `wiremock = "0.6"` for integration testing.

**Critical constraint:** Do not add `hmac`, `sha2`, `reqwest`, `ring`, `tokio-tungstenite`, or `uuid` crates directly. All of these are either already provided by the SDK, would cause version conflicts, or would produce outputs that diverge from TS behavior. The message ID is a hex-encoded HMAC derived through `WalletInterface::create_hmac()` with protocol `[1, "messagebox"]` and keyID `"1"` — raw HMAC would produce different IDs and break deduplication across TS/Rust clients.

**Core technologies:**
- `bsv` (git, network feature): AuthFetch, WebSocketTransport, WalletInterface, CommsLayer trait — the entire SDK layer
- `tokio = "1"`: Async runtime — required by SDK, use rt-multi-thread + macros + sync + time features
- `serde` + `serde_json = "1"`: Serialization — wire format for all HTTP request/response bodies
- `base64 = "0.22"`: Encode/decode encrypted message bodies — use `STANDARD` engine (with padding) to match TS `Utils.toBase64`
- `thiserror = "2"`: Typed error enum (`MessageBoxError`) — library crate needs matchable error variants, not `anyhow`

### Expected Features

Full parity with TS v1.3.0 is the table stakes requirement. The MVP (v1.0) is scoped tightly to what `metawatt-edge-rs` needs for the 6-node demo: HTTP messaging, PeerPay, WebSocket live messaging, and the `CommsLayer` trait. Permission management, overlay host advertisement, and full `list_messages` with payment auto-internalization are v1.x additions once the core is validated.

**Must have (v1.0 — blocks metawatt-edge-rs):**
- `send_message` + `list_messages_lite` + `acknowledge_message` — HTTP messaging core
- BRC-78 encryption/decryption + HMAC message ID — required by all messaging operations
- `CommsLayer` trait implementation (`RemittanceAdapter`) — the primary integration point
- `get_identity_key` + `resolve_host_for_recipient` — required by all outbound operations
- PeerPay: `create_payment_token`, `send_payment`, `accept_payment`, `reject_payment`, `list_incoming_payments`, `listen_for_live_payments`
- WebSocket: `listen_for_live_messages`, `send_live_message`, `join_room`, `leave_room`, `disconnect_web_socket`

**Should have (v1.x — full parity):**
- `list_messages` with payment auto-internalization
- Permission management (set/get/list/quote)
- `init` with real overlay host advertisement (`anoint_host`, `revoke_host_advertisement`)
- Multi-host querying with deduplication

**Defer (v2+):**
- Notification convenience methods (allow/deny/check/list/send notifications) — no consumer needs them
- Device registration (`registerDevice`, `listRegisteredDevices`) — irrelevant for Rust edge agents
- Feature flags for optional subsystems — premature before multiple consumers with divergent needs

### Architecture Approach

The library is structured as a single generic struct `MessageBoxClient<W: WalletInterface + Clone + 'static>` that owns all state: `Mutex<AuthFetch<W>>` for HTTP, `Arc<Mutex<WsState>>` for WebSocket, `OnceLock<String>` for cached identity key, and `tokio::sync::OnceCell<()>` for one-shot initialization. A separate `RemittanceAdapter<W>` wraps `Arc<MessageBoxClient<W>>` and implements the `CommsLayer` trait. `PeerPayClient<W>` uses composition (not TS-style inheritance) by holding `Arc<MessageBoxClient<W>>`.

**Major components:**
1. `MessageBoxClient<W>` — central coordinator, owns all state, exposes all 28 public operations
2. `RemittanceAdapter<W>` — `CommsLayer` trait impl, bridges `&self` trait boundary to interior-mutable client
3. `PeerPayClient<W>` — payment-specific operations, composes `Arc<MessageBoxClient<W>>`
4. `encryption` module — pure functions for BRC-78 encrypt/decrypt and HMAC ID generation
5. `http_ops` module — all REST API calls through `Mutex<AuthFetch<W>>`
6. `websocket` module — room-based live messaging via SDK's `WebSocketTransport` + `Peer`
7. `host_resolution` module — overlay lookup via `LookupResolver`, advertisement via `TopicBroadcaster`

### Critical Pitfalls

1. **AuthFetch requires `tokio::sync::Mutex`, not `std::sync::Mutex`** — holding a std mutex guard across an `.await` point will deadlock the tokio runtime. Use `tokio::sync::Mutex` throughout, never hold the lock across await, and structure HTTP helpers to lock → build args → drop → fetch → re-lock.

2. **Encryption protocol constants must match TS exactly** — protocol `[1, "messagebox"]`, keyID `"1"`, `Counterparty::PublicKey(recipient)` for normal messages, `base64::STANDARD` (with padding). Any deviation causes silent decryption failure on the TS receiver — write a cross-language interop test in Phase 1 before building anything on top.

3. **Lazy initialization has a concurrency race** — the TS boolean `initialized` flag is not safe in Rust's concurrent async context. Use `tokio::sync::OnceCell::get_or_try_init()` to guarantee exactly-once initialization even when multiple tasks call any public method simultaneously.

4. **HTTP endpoints have mixed verb/param conventions** — some endpoints are POST with JSON body, others are GET with query parameters. The `/permissions/list` endpoint uses `message_box` (snake_case) for its query parameter — the only snake_case param in the entire API. Build an endpoint routing table and test each endpoint against the running server early.

5. **Message body has two distinct JSON envelope layers** — the encryption envelope `{"encryptedMessage": "..."}` and the payment wrapper `{"message": ..., "payment": ...}` must be unwrapped in order: check for payment wrapper first, then encryption. Modeling `PeerMessage.body` as `String` only breaks payment-wrapped messages entirely.

## Implications for Roadmap

Based on the module dependency graph from ARCHITECTURE.md and the feature dependencies from FEATURES.md, a natural 4-phase structure emerges.

### Phase 1: Foundation and HTTP Core

**Rationale:** Everything depends on the type system (`error.rs`, `types.rs`), encryption helpers, and basic HTTP messaging. The most critical interoperability pitfalls all manifest here — mutex choice, encryption format, endpoint routing, body parsing, init guard. Getting this right is load-bearing for all subsequent phases. Do not proceed past Phase 1 without a passing cross-language interop test.

**Delivers:** A working `MessageBoxClient` that can send, list (lite), and acknowledge messages against the running go-messagebox-server, with correct BRC-78 encryption, HMAC message IDs, multi-host deduplication, and thread-safe initialization.

**Addresses:** `send_message`, `list_messages_lite`, `acknowledge_message`, `get_identity_key`, `resolve_host_for_recipient`, BRC-78 encryption/decryption, HMAC message ID generation

**Avoids:** AuthFetch mutex deadlock, encryption format mismatch, lazy init race condition, dual-envelope parsing failure, multi-host deduplication omission, `listMessagesLite` originator parity

### Phase 2: CommsLayer Adapter + Permissions

**Rationale:** Once HTTP core is proven, implement the `CommsLayer` trait in `RemittanceAdapter` — this is the primary integration point for `metawatt-edge-rs` and should unlock even before WebSocket or PeerPay are complete. Permissions are thin HTTP wrappers that can be co-delivered with the adapter for full v1.x completeness on the HTTP layer.

**Delivers:** `RemittanceAdapter<W>` implementing `CommsLayer`, permission management (set/get/list/quote), and the `getMessageBoxQuote` header extraction pattern.

**Uses:** `Arc<MessageBoxClient<W>>` composition pattern, `async_trait`, error mapping to `RemittanceError`

**Avoids:** `getMessageBoxQuote` missing header extraction, `message_box` snake_case query param bug

**Implements:** `adapter.rs`, `permissions.rs`

### Phase 3: PeerPay

**Rationale:** PeerPay depends on working HTTP messaging (Phase 1) and the wallet transaction APIs. `list_messages` with payment auto-internalization depends on PeerPay's `accept_payment`. Building PeerPay as a dedicated phase keeps the payment logic isolated and testable before it is wired into the message listing path.

**Delivers:** `PeerPayClient<W>` with create/send/accept/reject/list payment tokens; `listen_for_live_payments` (depends on WebSocket — may ship with Phase 4 if WebSocket is concurrent); `list_messages` with payment auto-internalization.

**Uses:** `WalletInterface` transaction operations, `create_nonce` from SDK, payment protocol ID `[2, '3241645161d8']`

**Avoids:** 1000-satoshi refund threshold deviation, `createPaymentToken` nonce mismatch, `recipientFee == -1` sentinel mishandling

**Implements:** `peer_pay/mod.rs`, `peer_pay/types.rs`, `peer_pay/ops.rs`

### Phase 4: WebSocket Live Messaging

**Rationale:** WebSocket is the most complex state management in the codebase and depends on all prior phases. `send_live_message` falls back to `send_message` (Phase 1), and `listen_for_live_payments` wraps `listen_for_live_messages`. The 6-node metawatt demo requires this, but it is safest to build last when the foundational layers are stable.

**Delivers:** Full WebSocket live messaging: `listen_for_live_messages`, `send_live_message` (with HTTP fallback and `DashMap`-based ack tracking), `join_room`, `leave_room`, `disconnect_web_socket`.

**Uses:** SDK `WebSocketTransport`, `Peer<W>`, `tokio::sync::oneshot` for ack tracking, `tokio::time::timeout` for 5-second auth handshake

**Avoids:** WebSocket ack listener accumulation, 5-second blind auth timeout, callback-based API anti-pattern, duplicate room listener registration

**Implements:** `websocket.rs`

### Phase 5: Overlay Host Advertisement (v1.x)

**Rationale:** `init()` with real overlay advertisement and `anoint_host` are deferred to v1.x — they can be stubbed as "always use explicit host" in earlier phases. This phase completes full TS parity. It is the most complex overlay operation (PushDrop transaction construction) and has no dependency on it for the 6-node demo.

**Delivers:** `init()` with overlay-based host advertisement, `anoint_host`, `revoke_host_advertisement`, `query_advertisements`, multi-host `list_messages` with full deduplication.

**Uses:** `LookupResolver`, `TopicBroadcaster`, PushDrop transaction pattern

**Avoids:** Duplicate anointing on concurrent init, `anoint_host` idempotency violation

**Implements:** `host_resolution.rs` (fully), `client.rs` `init()` method (fully)

### Phase Ordering Rationale

- **Encryption and mutex design must precede all HTTP work** — these are architectural decisions that cannot be retrofitted without touching every method
- **`CommsLayer` adapter is unlocked immediately after HTTP core** — do not delay the primary integration point by bundling it with PeerPay or WebSocket
- **PeerPay before WebSocket** — `listen_for_live_payments` wraps `listen_for_live_messages`; WebSocket must exist first, but PeerPay types and payment logic can be tested against HTTP alone
- **Overlay advertisement last** — `init()` can stub host resolution throughout earlier phases; overlay adds complexity with no benefit until full parity is required
- **No feature flags in initial phases** — premature optimization; add only when a second consumer with divergent needs exists

### Research Flags

Phases likely needing deeper research during planning:
- **Phase 3 (PeerPay):** `createPaymentToken` transaction construction uses `WalletInterface` in ways not fully documented; need to verify `create_nonce` function signature and payment derivation protocol ID against SDK source before implementation
- **Phase 5 (Overlay):** PushDrop transaction format for `anoint_host` and `revoke_host_advertisement` requires verifying `TopicBroadcaster` API and SHIP overlay topic constants against SDK source

Phases with standard patterns (skip research-phase):
- **Phase 1 (HTTP Core):** All patterns verified — `AuthFetch` usage, base64 engine, serde wire types, endpoint routing table all documented in research files
- **Phase 2 (Adapter + Permissions):** `CommsLayer` trait signature verified from SDK source; permission endpoints are thin HTTP wrappers with known conventions
- **Phase 4 (WebSocket):** `WebSocketTransport` and `Peer` usage patterns verified from SDK source; `oneshot`-based ack tracking is standard tokio pattern

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| Stack | HIGH | All dependencies verified against live SDK Cargo.toml and docs.rs; version compatibility matrix confirmed; explicit "never use" list with rationale |
| Features | HIGH | Source is the complete TS implementation (2,272 + 395 lines); all 28 operations enumerated; feature dependency graph fully mapped |
| Architecture | HIGH | Based on direct inspection of SDK source files; `AuthFetch`, `WebSocketTransport`, `CommsLayer`, `WalletInterface` signatures all confirmed |
| Pitfalls | HIGH | 12 pitfalls from direct TS source inspection plus known SDK constraints; each pitfall includes specific warning signs and recovery cost |

**Overall confidence:** HIGH

### Gaps to Address

- **`TopicBroadcaster` API for `anoint_host`**: Not fully inspected in this research round. The broadcast method signature and SHIP topic constant need verification before Phase 5 planning.
- **`PeerPayClient` nonce derivation**: `create_nonce` function location in SDK (module path) needs confirmation before Phase 3 implementation begins.
- **`LookupResolver` query API for overlay**: The `ls_messagebox` service name and query argument structure were referenced but not verified against the latest SDK source. Confirm during Phase 5 planning.
- **WebSocket `Peer` API**: The `general_message_rx` channel name and `send_message` method signature on `Peer<W>` should be verified against SDK source before Phase 4 implementation.

## Sources

### Primary (HIGH confidence)

- `https://github.com/b1narydt/bsv-rust-sdk` — Cargo.toml, AuthFetch, WebSocketTransport, WalletInterface, CommsLayer, RemittanceError all directly inspected
- `node_modules/@bsv/message-box-client/src/MessageBoxClient.ts` (v1.3.0, 2,272 lines) — complete TS reference; all pitfalls and feature dependencies sourced from here
- `node_modules/@bsv/message-box-client/src/PeerPayClient.ts` (v1.3.0, 395 lines) — PeerPay feature surface and payment token format
- `https://docs.rs/base64/latest` — base64 0.22.1 engine API confirmed
- `https://docs.rs/wiremock/latest` — wiremock 0.6.5 confirmed as dev-dep
- `https://docs.rs/tokio/latest` — tokio 1.50.0 confirmed

### Secondary (MEDIUM confidence)

- `.planning/PROJECT.md` — primary consumer requirements, `metawatt-edge-rs` integration scope, `CommsLayer` trait purpose

### Tertiary (LOW confidence — needs validation during implementation)

- TopicBroadcaster broadcast API for SHIP overlay (referenced but not inspected)
- `create_nonce` SDK function path (referenced in PROJECT.md but module location not confirmed)
- `LookupResolver` `ls_messagebox` service constants (inferred from TS `LookupResolver` pattern)

---
*Research completed: 2026-03-26*
*Ready for roadmap: yes*
