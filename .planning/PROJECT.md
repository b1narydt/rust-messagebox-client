# BSV MessageBox Client (Rust)

## What This Is

A Rust client library for BSV MessageBox servers, providing full feature parity with the TypeScript `@bsv/message-box-client` v2.0.x. A direct translation following the same pattern used for `bsv-rust-sdk` and `rust-wallet-toolbox` — same API surface, same behavior, different language. The crate is a standalone reusable package consumed by any Rust BSV application needing authenticated peer-to-peer messaging.

## Core Value

Rust applications can send, receive, and manage BRC-31 authenticated messages with full encryption, payment support, and real-time WebSocket messaging — identical capability to the TypeScript MessageBox client.

## Requirements

### Validated

- ✓ HTTP messaging (send, list, list_lite, acknowledge) via AuthFetch — v1.3
- ✓ BRC-78 message encryption/decryption via WalletInterface — v1.3
- ✓ HMAC-based message ID generation for idempotency — v1.3
- ✓ Permission management (set, get, list, quote) — v1.3
- ✓ Notification convenience methods (allow/deny/check/list/send) — v1.3
- ✓ CommsLayer trait implementation (RemittanceAdapter) — v1.3
- ✓ PeerPay (create/send/accept/reject payments, list incoming) — v1.3
- ✓ WebSocket live messaging (send, listen, join/leave rooms) with BRC-103 auth — v1.3
- ✓ Overlay host resolution (resolve recipient host, anoint/revoke host advertisements) — v1.3
- ✓ Device registration for push notifications (register, list) — v1.3
- ✓ Auto-initialization with host advertisement on first use — v1.3
- ✓ Multi-host querying with message deduplication — v1.3

### Active

(Next milestone requirements TBD)

### Out of Scope

- MessageBox server implementation — already exists in Go (`go-messagebox-server`)
- Wallet implementation — uses `WalletInterface` from `bsv-rust-sdk`
- BRC-31 auth protocol — handled by SDK's `AuthFetch`
- Overlay infrastructure (SHIP/SLAP) — separate concern, uses SDK's overlay tools
- Mobile/desktop UI — this is a library crate only

## Context

**Ecosystem position:** Fills the same role as `@bsv/message-box-client` in the TypeScript ecosystem. The BSV blockchain has SDK implementations in TypeScript, Go, and Rust — the MessageBox client exists in TS but not yet in Rust.

**Primary consumer:** `metawatt-edge-rs` — a Rust edge agent for programmable energy commodity settlement. Needs `CommsLayer` for `RemittanceManager` to handle P2P PPA negotiation between nodes. The `metawatt-demo` runs 6 simultaneous edge agents that negotiate via MessageBox.

**Translation source:** TypeScript `@bsv/message-box-client` v1.3.0 (2,272 lines in MessageBoxClient.ts + 395 lines in PeerPayClient.ts). Located at `node_modules/@bsv/message-box-client/` in the draigfi-sdk project.

**Existing Rust infrastructure:**
- `bsv-rust-sdk` provides: `AuthFetch` (BRC-31 HTTP), `WebSocketTransport` (BRC-31 WebSocket), `WalletInterface` (encrypt/decrypt), `CommsLayer` trait, `PeerMessage` type, `RemittanceError` enum, `Transport` trait abstraction, overlay tools (`TopicBroadcaster`, `LookupResolver`)
- `rust-wallet-toolbox` provides: production `WalletInterface` implementation with SQLite backend
- Both repos are under the `b1narydt` GitHub organization and follow established TS→Rust translation patterns

**Key SDK details discovered during research:**
- `AuthFetch.fetch()` takes `&mut self` — client needs `Mutex<AuthFetch<W>>` for interior mutability
- `EncryptArgs` uses `Protocol` struct (not `ProtocolID`), `Counterparty` type, plus `privileged` and `seek_permission` fields
- `encrypt`/`decrypt` on `WalletInterface` take extra `originator: Option<&str>` parameter
- `RemittanceError::InvalidStateTransition` uses named fields `{ from, to }`
- TS encryption protocol is `[1, 'messagebox']` with keyID `'1'` — must match for interop
- TS wraps encrypted bodies as `{ encryptedMessage: base64(...) }` JSON — must match for interop
- SDK's `WebSocketTransport` already handles reconnect with exponential backoff

## Constraints

- **Tech stack**: Rust 2021 edition, `bsv-rust-sdk` with `network` feature, `async-trait`, `serde`, `tokio` runtime
- **Dependency**: Must use `bsv` crate from `github.com/b1narydt/bsv-rust-sdk` (not published to crates.io)
- **Interop**: Wire format must be compatible with existing TS clients talking to the same MessageBox servers
- **API surface**: Must implement all 28 public methods from the TS MessageBoxClient + PeerPayClient for full parity
- **Trait compliance**: `RemittanceAdapter` must implement `CommsLayer` trait exactly as defined in SDK

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Standalone crate, not inline in edge-rs | Reusable across BSV Rust ecosystem, same pattern as TS package | ✓ Good — clean separation |
| Full parity with TS client | Demo needs RemittanceManager + payments + potentially live messaging for 6-node negotiation | ✓ Good — 54/54 methods |
| Custom SocketIOTransport + Peer for BRC-103 | SDK's WebSocketTransport didn't support BRC-103 auth; built SocketIOTransport implementing Transport trait | ✓ Good — mutual auth works |
| Match TS encryption format exactly | Interop with existing TS clients on same MessageBox servers | ✓ Good — live-tested |
| Tiered implementation (HTTP → Payments → WebSocket → Overlay) | Build order follows dependency chain and allows incremental testing | ✓ Good — clean progression |
| Client-initiated BRC-103 handshake | Server waits for client to send InitialRequest, not the other way around | ✓ Good — discovered via live testing |

## Current State

Shipped v1.3 with 6,613 lines of Rust across 11 source files.
Tech stack: Rust 2021, bsv-rust-sdk (network feature), tokio, serde, rust_socketio.
143 tests pass (94 unit + 12 integration + 6 parity + 31 live server).
All 64 requirements complete. 2 low-severity tech debt items carried forward.

---
*Last updated: 2026-03-28 after v1.3 milestone*
