# Feature Research

**Domain:** BSV MessageBox Client — Rust translation of TypeScript `@bsv/message-box-client` v1.3.0
**Researched:** 2026-03-26
**Confidence:** HIGH (source is the fully-documented TS implementation)

## Feature Landscape

### Table Stakes (Users Expect These)

Table stakes = full parity with the TS client. Rust consumers expect the same API surface; anything missing breaks the "direct translation" promise and blocks adoption by `metawatt-edge-rs`.

| Feature | Why Expected | Complexity | Notes |
|---------|--------------|------------|-------|
| `send_message` — BRC-31 authenticated HTTP POST | Core purpose of the library | MEDIUM | Must call `AuthFetch.fetch()` with BRC-78 encrypted body; `AuthFetch` takes `&mut self` so needs `Mutex<AuthFetch<W>>` for thread safety |
| `list_messages` — with auto payment internalization | Expected read path; TS processes incoming payments inline | HIGH | Calls PeerPay `accept_payment` per message; requires PeerPayClient to exist first |
| `list_messages_lite` — without payment processing | Simpler list for non-payment boxes | LOW | Same HTTP path as `list_messages` but skips payment handling; implement alongside it |
| `acknowledge_message` — mark message read | Needed to clear inbox; servers expect this | LOW | Single HTTP POST; straightforward |
| BRC-78 encryption/decryption | Every message is encrypted in transit to recipient's identity key | MEDIUM | Protocol `[1, 'messagebox']`, keyID `'1'`; body wrapped as `{"encryptedMessage": base64}` JSON — must match TS format exactly for interop |
| HMAC message ID generation | Idempotency on send; prevents duplicate delivery | LOW | HMAC over sender + recipient + body using `WalletInterface` HMAC method |
| `set_message_box_permission` | Servers gate delivery on permissions; clients must set them | MEDIUM | HTTP PUT to server with auth |
| `get_message_box_permission` | Read current permission state | LOW | HTTP GET; pairs with set |
| `get_message_box_quote` | Get fee quote before setting permission | LOW | HTTP GET; needed before payment flows |
| `list_message_box_permissions` | Enumerate all configured permissions | LOW | HTTP GET; optional params |
| `listen_for_live_messages` — WebSocket subscription | Required for real-time use cases (6-node metawatt demo) | HIGH | Uses SDK's `WebSocketTransport`; handles reconnect with exponential backoff already |
| `send_live_message` — WebSocket send with HTTP fallback | Real-time send; degrades gracefully | HIGH | 10-second timeout before falling back to HTTP; fallback path reuses `send_message` |
| `join_room` / `leave_room` / `disconnect_web_socket` | WebSocket session lifecycle | MEDIUM | Room management is required for targeted live delivery |
| `CommsLayer` trait implementation (`RemittanceAdapter`) | The primary reason this crate exists | HIGH | Bridges to `metawatt-edge-rs`; must implement the trait exactly as defined in `bsv-rust-sdk`; `PeerMessage` and `RemittanceError` types must match |
| `init` — auto-initialization with host advertisement | TS client calls this lazily on first use | MEDIUM | Queries overlay for existing host advertisement, anoint if none found |
| `get_identity_key` | Self-lookup; many methods need this | LOW | Delegates to `WalletInterface` |
| `resolve_host_for_recipient` | Find which MessageBox server a recipient uses | MEDIUM | Queries overlay SLAP/SHIP advertisements; multi-host deduplication |
| `query_advertisements` | Low-level overlay query | MEDIUM | Uses SDK's `LookupResolver` |
| `anoint_host` | Publish host advertisement via PushDrop overlay tx | HIGH | Requires constructing and broadcasting a PushDrop transaction; most complex overlay operation |
| `revoke_host_advertisement` | Remove stale host advertisement | MEDIUM | Overlay tx to spend the PushDrop output |
| PeerPay: `create_payment_token` | Gate of PeerPay system; creates BSV payment | HIGH | Requires `WalletInterface` to create transaction; token format must match TS |
| PeerPay: `send_payment` / `send_live_payment` | Send token via message / WebSocket | MEDIUM | Wraps `create_payment_token` + `send_message` / `send_live_message` |
| PeerPay: `accept_payment` / `reject_payment` | Internalize or decline incoming payment token | HIGH | `accept_payment` submits tx to network; must use `WalletInterface` internalize flow |
| PeerPay: `list_incoming_payments` | Enumerate unprocessed payment messages | LOW | Filtered `list_messages` call |
| PeerPay: `listen_for_live_payments` | Real-time payment receipt | HIGH | Wraps `listen_for_live_messages` with payment decoding; needed for metawatt settlement loop |
| Multi-host querying with deduplication | TS queries all known hosts for a recipient, deduplicates by message ID | MEDIUM | Required for correctness when recipient has multiple host advertisements |

### Differentiators (Competitive Advantage)

This is a library translation, not a product competing in a market. Differentiators are Rust-specific improvements that make this crate better than a mechanical port.

| Feature | Value Proposition | Complexity | Notes |
|---------|-------------------|------------|-------|
| `async` throughout with `tokio` | Native async I/O; no blocking; matches Rust ecosystem expectations | LOW | Already required by SDK traits; just don't introduce blocking calls |
| Type-safe error enum (not stringly-typed) | TS throws `Error` strings; Rust enums with variants give exhaustive handling and better DX | LOW | Define `MessageBoxError` with variants for HTTP, WebSocket, Encryption, Payment, Overlay errors; reuse `RemittanceError` where it fits |
| `Send + Sync` client | Rust apps share the client across threads trivially; TS client is single-threaded JS | MEDIUM | `Mutex<AuthFetch<W>>` and `Arc<Mutex<WebSocketTransport>>` are required; design the public API around `Arc<MessageBoxClient>` from the start |
| Zero-copy deserialization where possible | Lower memory pressure for high-throughput edge agents | MEDIUM | Use `serde` with `Cow<str>` or borrowed types in hot paths (message listing) |
| Builder pattern for complex params | TS uses plain objects; Rust builders provide better construction ergonomics and compile-time validation | LOW | Apply to `SendMessageParams`, `PermissionParams`, etc. |
| Feature flags for optional subsystems | Crate users who only need HTTP messaging don't pay compile cost for WebSocket or PeerPay | LOW | `features = ["websocket", "peerpay", "overlay"]`; core HTTP always on |

### Anti-Features (Commonly Requested, Often Problematic)

| Feature | Why Requested | Why Problematic | Alternative |
|---------|---------------|-----------------|-------------|
| MessageBox server implementation | "While you're at it..." | Entirely different scope — server is `go-messagebox-server`; mixing client + server in one crate blurs responsibility, doubles maintenance | Stay client-only; server is a separate binary in Go |
| Custom transport abstraction beyond SDK's `Transport` trait | "Make it pluggable" | The SDK already provides `Transport`; adding a second layer creates impedance mismatch and forces every caller to understand two abstractions | Use SDK's `Transport` trait directly; if needed, wrap it |
| Tokio-agnostic async runtime support | "Support async-std too" | Adds significant complexity (runtime detection, conditional compilation); SDK crate itself requires tokio; fighting this is wasted effort | Declare `tokio` as required; document this clearly in crate README |
| Built-in retry logic beyond SDK WebSocket reconnect | "Add retries for HTTP calls" | HTTP idempotency is caller's responsibility; blind retries on BSV transactions cause double-spend attempts | Expose errors clearly; let callers implement backoff policy with their own context |
| Notification subsystem (allow/deny/check/list/send notifications) | "Full parity" | These 5 methods are convenience wrappers around permission + message operations; they add API surface without new capability; `metawatt-edge-rs` does not use them | Implement as a `notifications` feature flag or defer to v1.x; don't block core shipping |
| Device registration (registerDevice / listRegisteredDevices) | "Full parity" | Push notification device tokens are a mobile/server concern; a Rust library running on an edge agent has no devices to register | Mark as `notifications` feature or stub returning `Unimplemented`; no primary consumer needs this |
| Sync (blocking) API surface | "Not everyone uses async" | Forces internal thread spawning, which defeats the purpose of async I/O and adds hidden overhead | Recommend `tokio::runtime::Handle::block_on` in docs for the rare sync caller; don't bake it in |

## Feature Dependencies

```
[BRC-78 Encryption/Decryption]
    └──required by──> [send_message]
    └──required by──> [list_messages] (decryption of received bodies)
    └──required by──> [PeerPay: create_payment_token] (token body encrypted)

[HMAC Message ID]
    └──required by──> [send_message] (idempotency header)

[get_identity_key]
    └──required by──> [init]
    └──required by──> [resolve_host_for_recipient]
    └──required by──> [anoint_host]

[resolve_host_for_recipient]
    └──required by──> [send_message] (when no overrideHost)
    └──required by──> [send_live_message] (WebSocket connect)
    └──required by──> [listen_for_live_messages]

[init] (auto-initialization, host advertisement)
    └──required by──> all outbound operations (lazily called on first use)
    └──depends on──> [anoint_host]
    └──depends on──> [query_advertisements]

[send_message]
    └──required by──> [send_live_message] (HTTP fallback path)
    └──required by──> [PeerPay: send_payment]

[list_messages_lite]
    └──required by──> [list_messages] (same HTTP call, different post-processing)

[PeerPay: create_payment_token]
    └──required by──> [PeerPay: send_payment]
    └──required by──> [PeerPay: send_live_payment]

[PeerPay: accept_payment]
    └──required by──> [list_messages] (auto-internalizes payments inline)
    └──required by──> [PeerPay: listen_for_live_payments]

[listen_for_live_messages]
    └──required by──> [PeerPay: listen_for_live_payments]

[CommsLayer trait (RemittanceAdapter)]
    └──requires──> [send_message]
    └──requires──> [list_messages] or [list_messages_lite]
    └──requires──> [PeerPay: send_payment]
    └──requires──> [PeerPay: accept_payment]
    └──requires──> [PeerPay: listen_for_live_payments] (for settlement loop)

[set_message_box_permission]
    └──required by──> [allow_notifications_from_peer] (if implemented)
    └──required by──> [deny_notifications_from_peer] (if implemented)
```

### Dependency Notes

- **BRC-78 Encryption requires WalletInterface:** Encryption is not standalone — it delegates to the SDK wallet. Any phase building encryption must have `WalletInterface` wired up first.
- **list_messages requires PeerPay accept_payment:** The TS implementation internalizes payments inline during `listMessages`. This means PeerPay must be at least partially built before `list_messages` is complete. Build `list_messages_lite` first as the unblocked version.
- **init depends on overlay (anoint_host):** Auto-initialization publishes a host advertisement as a PushDrop transaction. This is the most complex part of `init`. The overlay feature should be built before `init` reaches production quality, but `init` can be stubbed (manual host override) during early phases.
- **CommsLayer trait is the integration point:** This is what `metawatt-edge-rs` calls. Everything else is supporting it. Get the trait implemented as early as possible even if some backing methods are stubbed.
- **send_live_message depends on send_message:** The HTTP fallback means WebSocket and HTTP phases are not independent — WebSocket live messaging builds on top of working HTTP messaging.

## MVP Definition

### Launch With (v1.0 — what metawatt-edge-rs needs)

- [ ] `send_message` — required by `CommsLayer::send`
- [ ] `list_messages_lite` — required by `CommsLayer::receive` (without payment processing initially)
- [ ] `acknowledge_message` — required to clear inbox after processing
- [ ] BRC-78 encryption/decryption — required by all messaging
- [ ] HMAC message ID generation — required for idempotent send
- [ ] `CommsLayer` trait implementation (`RemittanceAdapter`) — the integration point
- [ ] `get_identity_key` — needed by most operations
- [ ] `resolve_host_for_recipient` — needed for sending to peers
- [ ] PeerPay: `create_payment_token`, `send_payment`, `accept_payment`, `reject_payment`, `list_incoming_payments` — required for settlement
- [ ] PeerPay: `listen_for_live_payments` — required for real-time settlement loop
- [ ] `listen_for_live_messages`, `send_live_message`, `join_room`, `leave_room`, `disconnect_web_socket` — required for real-time coordination in 6-node demo

### Add After Validation (v1.x — full parity)

- [ ] `list_messages` (with payment internalization) — trigger: any consumer needs auto-payment processing
- [ ] Permission management (set/get/list/quote) — trigger: server starts enforcing permissions for the consumer
- [ ] `init` with real host advertisement (anoint_host, revoke) — trigger: consumer needs overlay-based host discovery
- [ ] `query_advertisements` — trigger: needed for multi-host scenarios
- [ ] Multi-host querying with deduplication — trigger: any peer uses multiple MessageBox servers

### Future Consideration (v2+)

- [ ] Notification convenience methods (allow/deny/check/list/send) — defer: no consumer needs them; they're wrappers around permissions + messages
- [ ] Device registration (register/list) — defer: no Rust edge agent registers mobile push tokens
- [ ] Feature flags (`websocket`, `peerpay`, `overlay`) — defer: premature optimization; add when crate has multiple consumers with divergent needs

## Feature Prioritization Matrix

| Feature | User Value | Implementation Cost | Priority |
|---------|------------|---------------------|----------|
| `send_message` | HIGH | MEDIUM | P1 |
| `list_messages_lite` | HIGH | LOW | P1 |
| `acknowledge_message` | HIGH | LOW | P1 |
| BRC-78 encrypt/decrypt | HIGH | MEDIUM | P1 |
| HMAC message ID | HIGH | LOW | P1 |
| `CommsLayer` trait (`RemittanceAdapter`) | HIGH | HIGH | P1 |
| `get_identity_key` | HIGH | LOW | P1 |
| `resolve_host_for_recipient` | HIGH | MEDIUM | P1 |
| PeerPay: create/send/accept/reject/list | HIGH | HIGH | P1 |
| PeerPay: `listen_for_live_payments` | HIGH | HIGH | P1 |
| WebSocket live messaging (listen/send/rooms) | HIGH | HIGH | P1 |
| `list_messages` (with payment auto-internalize) | MEDIUM | HIGH | P2 |
| Permission management (set/get/list/quote) | MEDIUM | MEDIUM | P2 |
| `init` + `anoint_host` + overlay host resolution | MEDIUM | HIGH | P2 |
| `revoke_host_advertisement` | LOW | MEDIUM | P2 |
| `query_advertisements` | LOW | MEDIUM | P2 |
| Multi-host querying with deduplication | MEDIUM | MEDIUM | P2 |
| Notification convenience methods | LOW | MEDIUM | P3 |
| Device registration | LOW | LOW | P3 |
| Feature flags for optional subsystems | LOW | LOW | P3 |
| Builder pattern for params | LOW | LOW | P3 |
| Zero-copy deserialization | LOW | MEDIUM | P3 |

**Priority key:**
- P1: Must have for v1.0 — blocks `metawatt-edge-rs` integration
- P2: Full parity — add in v1.x once core is validated
- P3: Nice to have — future consideration

## Sources

- TypeScript `@bsv/message-box-client` v1.3.0 source (2,272 lines MessageBoxClient.ts + 395 lines PeerPayClient.ts) — documented in project local_context
- `PROJECT.md` — primary consumer requirements (`metawatt-edge-rs`, `CommsLayer` trait)
- `bsv-rust-sdk` SDK surface — `AuthFetch`, `WebSocketTransport`, `WalletInterface`, `CommsLayer`, `PeerMessage`, `RemittanceError`, `Transport`, `TopicBroadcaster`, `LookupResolver`

---
*Feature research for: BSV MessageBox Client (Rust)*
*Researched: 2026-03-26*
