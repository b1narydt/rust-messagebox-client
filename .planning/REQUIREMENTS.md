# Requirements: BSV MessageBox Client (Rust)

**Defined:** 2026-03-26
**Core Value:** Rust applications can send, receive, and manage BRC-31 authenticated messages with full parity to the TypeScript @bsv/message-box-client

## v1 Requirements

Full parity with TypeScript `@bsv/message-box-client` v1.3.0 + `PeerPayClient`.

### Project Setup

- [x] **SETUP-01**: Crate builds with `bsv-rust-sdk` (network feature), `serde`, `async-trait`, `thiserror`, `base64`
- [x] **SETUP-02**: Module structure: `client.rs`, `adapter.rs`, `encryption.rs`, `types.rs`, `peer_pay.rs`, `websocket.rs`, `host_resolution.rs`, `error.rs`
- [x] **SETUP-03**: `MessageBoxClient<W: WalletInterface + Clone + 'static>` uses `tokio::sync::Mutex<AuthFetch<W>>` for interior mutability

### HTTP Messaging

- [x] **HTTP-01**: `send_message` sends BRC-31 authenticated POST to `/sendMessage` with BRC-78 encrypted body
- [x] **HTTP-02**: `list_messages` retrieves messages with auto payment internalization (delegates to PeerPay)
- [x] **HTTP-03**: `list_messages_lite` retrieves messages without payment processing
- [x] **HTTP-04**: `acknowledge_message` marks messages as read via POST to `/acknowledgeMessage`
- [x] **HTTP-05**: HMAC-based message ID generation for idempotency (using `WalletInterface::create_hmac`)

### Encryption

- [x] **ENC-01**: BRC-78 encryption using `WalletInterface::encrypt` with protocol `[1, "messagebox"]`, keyID `"1"`
- [x] **ENC-02**: Encrypted body wrapped as `{"encryptedMessage": "<base64>"}` JSON for TS interop
- [x] **ENC-03**: Auto-decryption of received messages using `WalletInterface::decrypt` with sender as counterparty
- [x] **ENC-04**: Graceful fallback when message body is not encrypted (plaintext pass-through)

### Permissions

- [x] **PERM-01**: `set_message_box_permission` configures sender fees/blocking via POST to `/permissions/set`
- [x] **PERM-02**: `get_message_box_permission` retrieves permission for sender/box via GET `/permissions/get`
- [x] **PERM-03**: `list_message_box_permissions` enumerates all permissions with pagination via GET `/permissions/list`
- [x] **PERM-04**: `get_message_box_quote` retrieves delivery fee quote via GET `/permissions/quote`

### Notifications

- [x] **NOTF-01**: `allow_notifications_from_peer` sets permission with optional fee for a peer
- [x] **NOTF-02**: `deny_notifications_from_peer` blocks notifications from a peer (recipientFee = -1)
- [x] **NOTF-03**: `check_peer_notification_status` checks if a peer can send notifications
- [x] **NOTF-04**: `list_peer_notifications` lists all notification permissions
- [x] **NOTF-05**: `send_notification` sends notification with auto-quote/payment

### CommsLayer Integration

- [x] **COMM-01**: `RemittanceAdapter<W>` implements `CommsLayer` trait from `bsv-rust-sdk`
- [x] **COMM-02**: `send_message` maps to `CommsLayer::send_message` returning server-assigned message ID
- [x] **COMM-03**: `list_messages` maps to `CommsLayer::list_messages` returning `Vec<PeerMessage>`
- [x] **COMM-04**: `acknowledge_message` maps to `CommsLayer::acknowledge_message`
- [ ] **COMM-05**: Live messaging methods use default trait impls until WebSocket phase completes, then wire through

### PeerPay

- [x] **PAY-01**: `create_payment_token` generates BSV payment via `WalletInterface::create_action`
- [x] **PAY-02**: `send_payment` sends payment token over HTTP via `send_message`
- [ ] **PAY-03**: `send_live_payment` sends payment token over WebSocket with HTTP fallback
- [x] **PAY-04**: `accept_payment` internalizes payment transaction via `WalletInterface::internalize_action`
- [x] **PAY-05**: `reject_payment` refunds payment with fee deduction
- [x] **PAY-06**: `list_incoming_payments` filters messages from `payment_inbox` box
- [ ] **PAY-07**: `listen_for_live_payments` wraps live message listener with payment decoding

### WebSocket Live Messaging

- [x] **WS-01**: `listen_for_live_messages` subscribes to WebSocket room with auto-decryption callback
- [x] **WS-02**: `send_live_message` sends via WebSocket with 10-second timeout, falls back to HTTP
- [x] **WS-03**: `join_room` / `leave_room` manage WebSocket room subscriptions
- [x] **WS-04**: `disconnect_web_socket` closes WebSocket connection cleanly
- [x] **WS-05**: Uses SDK's `WebSocketTransport` with reconnect and exponential backoff

### Host Resolution & Overlay

- [ ] **HOST-01**: `get_identity_key` returns authenticated user's identity public key
- [ ] **HOST-02**: `resolve_host_for_recipient` looks up recipient's MessageBox host via overlay
- [ ] **HOST-03**: `query_advertisements` queries overlay for host advertisement tokens
- [ ] **HOST-04**: `anoint_host` broadcasts PushDrop overlay transaction advertising host
- [ ] **HOST-05**: `revoke_host_advertisement` spends existing advertisement to remove it
- [ ] **HOST-06**: `init` auto-initializes on first use (query existing advertisements, anoint if needed)
- [ ] **HOST-07**: Multi-host querying with message deduplication by message ID

### Device Registration

- [ ] **DEV-01**: `register_device` registers device for FCM push notifications
- [ ] **DEV-02**: `list_registered_devices` lists registered devices

### Parity Verification

- [ ] **PARITY-01**: API surface audit confirms all 35 TS public methods (28 MessageBoxClient + 7 PeerPayClient) have Rust equivalents
- [ ] **PARITY-02**: Cross-language encryption test: Rust-encrypted message decryptable by TS client (and vice versa)
- [ ] **PARITY-03**: Cross-language payment test: Rust `create_payment_token` accepted by TS `acceptPayment` (and vice versa)
- [ ] **PARITY-04**: Smoke test exercises every public method against live `go-messagebox-server` with no panics
- [ ] **PARITY-05**: Wire format comparison: JSON request/response bodies match TS client for identical operations

### Testing

- [x] **TEST-01**: Unit tests for all request/response type serialization (camelCase JSON)
- [x] **TEST-02**: Unit tests for encryption round-trip (encrypt → decrypt = original)
- [x] **TEST-03**: Unit tests for HMAC message ID generation
- [x] **TEST-04**: Unit tests for RemittanceAdapter mapping (ServerMessage → PeerMessage)
- [x] **TEST-05**: Integration tests against local `go-messagebox-server` (send → list → ack cycle)
- [x] **TEST-06**: Integration tests for PeerPay payment flow (create → send → accept)

## v2 Requirements

- **V2-01**: Feature flags for optional subsystems (`websocket`, `peerpay`, `overlay`)
- **V2-02**: Zero-copy deserialization with `Cow<str>` for high-throughput paths
- **V2-03**: Builder pattern for complex parameter structs
- **V2-04**: Comprehensive documentation with examples for each public method

## Out of Scope

| Feature | Reason |
|---------|--------|
| MessageBox server | Already exists in Go (`go-messagebox-server`) |
| Wallet implementation | Uses `WalletInterface` from `bsv-rust-sdk` |
| BRC-31 auth protocol | Handled by SDK's `AuthFetch` |
| Custom transport abstraction | SDK's `Transport` trait is sufficient |
| Sync (blocking) API | Callers can use `tokio::runtime::Handle::block_on` |
| Tokio-agnostic runtime | SDK requires tokio; fighting this is wasted effort |
| Built-in HTTP retry logic | Idempotency is caller's responsibility; blind retries risk double-spend |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| SETUP-01 | Phase 1 | Complete |
| SETUP-02 | Phase 1 | Complete |
| SETUP-03 | Phase 1 | Complete |
| HTTP-01 | Phase 1 | Complete |
| HTTP-02 | Phase 3 | Complete |
| HTTP-03 | Phase 1 | Complete |
| HTTP-04 | Phase 1 | Complete |
| HTTP-05 | Phase 1 | Complete |
| ENC-01 | Phase 1 | Complete |
| ENC-02 | Phase 1 | Complete |
| ENC-03 | Phase 1 | Complete |
| ENC-04 | Phase 1 | Complete |
| PERM-01 | Phase 2 | Complete |
| PERM-02 | Phase 2 | Complete |
| PERM-03 | Phase 2 | Complete |
| PERM-04 | Phase 2 | Complete |
| NOTF-01 | Phase 2 | Complete |
| NOTF-02 | Phase 2 | Complete |
| NOTF-03 | Phase 2 | Complete |
| NOTF-04 | Phase 2 | Complete |
| NOTF-05 | Phase 2 | Complete |
| COMM-01 | Phase 2 | Complete |
| COMM-02 | Phase 2 | Complete |
| COMM-03 | Phase 2 | Complete |
| COMM-04 | Phase 2 | Complete |
| COMM-05 | Phase 4 | Pending |
| PAY-01 | Phase 3 | Complete |
| PAY-02 | Phase 3 | Complete |
| PAY-03 | Phase 4 | Pending |
| PAY-04 | Phase 3 | Complete |
| PAY-05 | Phase 3 | Complete |
| PAY-06 | Phase 3 | Complete |
| PAY-07 | Phase 4 | Pending |
| WS-01 | Phase 4 | Complete |
| WS-02 | Phase 4 | Complete |
| WS-03 | Phase 4 | Complete |
| WS-04 | Phase 4 | Complete |
| WS-05 | Phase 4 | Complete |
| HOST-01 | Phase 5 | Pending |
| HOST-02 | Phase 5 | Pending |
| HOST-03 | Phase 5 | Pending |
| HOST-04 | Phase 5 | Pending |
| HOST-05 | Phase 5 | Pending |
| HOST-06 | Phase 5 | Pending |
| HOST-07 | Phase 5 | Pending |
| DEV-01 | Phase 5 | Pending |
| DEV-02 | Phase 5 | Pending |
| TEST-01 | Phase 1 | Complete |
| TEST-02 | Phase 1 | Complete |
| TEST-03 | Phase 1 | Complete |
| TEST-04 | Phase 2 | Complete |
| TEST-05 | Phase 2 | Complete |
| TEST-06 | Phase 3 | Complete |
| PARITY-01 | Phase 6 | Pending |
| PARITY-02 | Phase 6 | Pending |
| PARITY-03 | Phase 6 | Pending |
| PARITY-04 | Phase 6 | Pending |
| PARITY-05 | Phase 6 | Pending |

**Coverage:**
- v1 requirements: 58 total
- Mapped to phases: 58
- Unmapped: 0 ✓

---
*Requirements defined: 2026-03-26*
*Last updated: 2026-03-26 — added Phase 6 parity verification requirements*
