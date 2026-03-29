# bsv-messagebox-client

A Rust implementation of the BSV MessageBox client — a peer-to-peer messaging and payment toolkit for the BSV blockchain. Full parity with the TypeScript [`@bsv/message-box-client`](https://github.com/bsv-blockchain/message-box-client) v2.0.x.

## Overview

MessageBox is a store-and-forward messaging system built on the BSV blockchain. Messages are authenticated using [BRC-103](https://brc.dev/103) mutual authentication and encrypted using [BRC-78](https://brc.dev/78) (AES-256-GCM with ECDH key derivation). The system supports both HTTP polling and WebSocket live delivery, with overlay network host discovery for decentralized message routing.

This crate provides two main components:

- **`MessageBoxClient`** — Authenticated messaging with encryption, WebSocket live delivery, overlay host resolution, permission management, and device registration.
- **`RemittanceAdapter`** — A [`CommsLayer`](https://github.com/bsv-blockchain/bsv-rust-sdk) trait implementation that bridges `MessageBoxClient` into the BSV SDK's remittance system.

### PeerPay

Built directly into `MessageBoxClient`, the PeerPay methods provide peer-to-peer Bitcoin payment functionality:

- Create, send, accept, and reject payment tokens
- Live payment delivery over WebSocket with HTTP fallback
- Automatic payment internalization during message listing

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
bsv-messagebox-client = { git = "https://github.com/b1narydt/rust-messagebox-client", branch = "main" }
```

### Requirements

- Rust 1.87+
- A [`WalletInterface`](https://github.com/bsv-blockchain/bsv-rust-sdk) implementation (e.g., `ProtoWallet` for testing)
- Tokio async runtime

## Quick Start

### Sending a Message

```rust
use bsv_messagebox_client::MessageBoxClient;

let client = MessageBoxClient::new(
    "https://messagebox.babbage.systems".to_string(),
    wallet,
    None,           // originator
    Network::Mainnet,
);

// Initialize (discovers/creates overlay advertisement)
client.init(None).await?;

// Send an encrypted message
let message_id = client.send_message(
    recipient_pubkey,   // recipient's identity key (hex)
    "inbox",            // message box name
    "Hello, world!",    // body (auto-encrypted via BRC-78)
    false,              // skip_encryption
    false,              // check_permissions
    None,               // message_id (auto-generated via HMAC)
    None,               // override_host
).await?;
```

### Receiving Messages

```rust
// List messages with automatic payment internalization
let messages = client.list_messages("inbox", true).await?;

for msg in &messages {
    println!("From: {}, Body: {}", msg.sender, msg.body);
}

// Acknowledge (delete from server)
let ids: Vec<String> = messages.iter().map(|m| m.message_id.clone()).collect();
client.acknowledge_message(ids, None).await?;
```

### WebSocket Live Messaging

```rust
use std::sync::Arc;

// Listen for live messages
client.listen_for_live_messages(
    "inbox",
    Arc::new(|msg| {
        println!("Live message from {}: {}", msg.sender, msg.body);
    }),
    None,
).await?;

// Send via WebSocket (falls back to HTTP after 10s timeout)
client.send_live_message(
    recipient, "inbox", "Real-time hello!",
    false, false, None, None,
).await?;

// Cleanup
client.disconnect_web_socket().await?;
```

### Peer-to-Peer Payments

```rust
// Send a payment
let msg_id = client.send_payment(recipient_pubkey, 5000).await?;

// List incoming payments
let payments = client.list_incoming_payments().await?;

// Accept a payment (internalizes to wallet)
client.accept_payment(&payments[0]).await?;

// Reject a payment (refund minus 1000 sat fee)
client.reject_payment(&payments[1]).await?;
```

### CommsLayer Integration

```rust
use bsv_messagebox_client::RemittanceAdapter;
use std::sync::Arc;

let client = Arc::new(MessageBoxClient::new(/* ... */));
let adapter = RemittanceAdapter::new(client);

// Use as a CommsLayer implementation with RemittanceManager
let comms: Arc<dyn CommsLayer + Send + Sync> = Arc::new(adapter);
```

## API Reference

### MessageBoxClient

#### Constructor

| Method | Description |
|--------|-------------|
| `new(host, wallet, originator, network)` | Create a new client |
| `new_mainnet(host, wallet, originator)` | Convenience constructor for mainnet |

#### Core Messaging

| Method | Description |
|--------|-------------|
| `send_message(recipient, mb, body, skip_enc, check_perms, msg_id, host)` | Send encrypted message via HTTP |
| `send_message_to_recipients(params, host)` | Batch send to multiple recipients |
| `list_messages(mb, accept_payments)` | List messages with multi-host dedup |
| `list_messages_lite(mb)` | List messages from default host only |
| `acknowledge_message(ids, host)` | Mark messages as read |

#### WebSocket Live Messaging

| Method | Description |
|--------|-------------|
| `initialize_connection(host)` | Establish authenticated WebSocket connection |
| `send_live_message(recipient, mb, body, skip_enc, check_perms, msg_id, host)` | Send via WS with 10s ack timeout, HTTP fallback |
| `listen_for_live_messages(mb, callback, host)` | Subscribe to live messages with auto-decrypt |
| `join_room(mb)` | Join a WebSocket room |
| `leave_room(mb, host)` | Leave a WebSocket room |
| `disconnect_web_socket()` | Close WebSocket connection |
| `get_joined_rooms()` | Get set of joined room IDs |

#### PeerPay Payments

| Method | Description |
|--------|-------------|
| `create_payment_token(recipient, amount)` | Generate a payment token |
| `send_payment(recipient, amount)` | Send payment via HTTP |
| `send_live_payment(recipient, amount)` | Send payment via WebSocket |
| `accept_payment(payment)` | Internalize received payment |
| `reject_payment(payment)` | Refund payment (minus 1000 sat fee) |
| `list_incoming_payments()` | List pending payments |
| `listen_for_live_payments(callback)` | Subscribe to live payments |
| `acknowledge_notification(message)` | Acknowledge with payment internalization |

#### Permissions

| Method | Description |
|--------|-------------|
| `set_message_box_permission(params, host)` | Set sender permission/fee |
| `get_message_box_permission(recipient, mb, sender, host)` | Get permission for sender |
| `list_message_box_permissions(mb, limit, offset, host)` | List all permissions |
| `get_message_box_quote(recipient, mb, host)` | Get delivery fee quote |
| `get_message_box_quote_multi(recipients, mb, host)` | Multi-recipient quote |

#### Notifications

| Method | Description |
|--------|-------------|
| `allow_notifications_from_peer(sender, fee, host)` | Allow notifications |
| `deny_notifications_from_peer(sender, host)` | Block notifications |
| `check_peer_notification_status(peer, host)` | Check notification permission |
| `list_peer_notifications(host)` | List notification permissions |
| `send_notification(recipient, body, host)` | Send notification (checks permissions) |
| `send_notification_to_recipients(recipients, body, host)` | Batch notifications |

#### Host Resolution & Overlay

| Method | Description |
|--------|-------------|
| `init(target_host)` | Auto-initialize (query/create overlay advertisement) |
| `get_identity_key()` | Get authenticated identity public key |
| `resolve_host_for_recipient(recipient)` | Resolve host via overlay |
| `query_advertisements(identity_key, host)` | Query overlay advertisements |
| `anoint_host(host)` | Broadcast host advertisement |
| `revoke_host_advertisement(token)` | Remove host advertisement |

#### Device Registration

| Method | Description |
|--------|-------------|
| `register_device(fcm_token, device_id, platform, host)` | Register for push notifications |
| `list_registered_devices(host)` | List registered devices |

### RemittanceAdapter

Implements the BSV SDK `CommsLayer` trait:

| Method | Description |
|--------|-------------|
| `send_message(recipient, mb, body, host)` | Send via CommsLayer |
| `list_messages(mb, host)` | List via CommsLayer |
| `acknowledge_message(ids)` | Acknowledge via CommsLayer |
| `send_live_message(recipient, mb, body, host)` | Live send via CommsLayer |
| `listen_for_live_messages(mb, host, callback)` | Live listen via CommsLayer |

## Architecture

```
src/
  lib.rs               # Module exports and public re-exports
  client.rs            # MessageBoxClient struct, WebSocket integration
  adapter.rs           # RemittanceAdapter (CommsLayer trait impl)
  http_ops.rs          # HTTP messaging operations, multi-host logic
  peer_pay.rs          # PeerPay payment operations
  permissions.rs       # Permission management and notification wrappers
  encryption.rs        # BRC-78 encryption/decryption, HMAC message IDs
  websocket.rs         # Socket.IO WebSocket connection with BRC-103 auth
  socket_transport.rs  # SocketIOTransport (SDK Transport trait over Socket.IO)
  host_resolution.rs   # Overlay network host discovery (PushDrop)
  types.rs             # Request/response types with serde serialization
  error.rs             # Unified error type
tests/
  integration.rs       # CommsLayer adapter integration tests
  parity.rs            # TypeScript parity verification tests
  live_server.rs       # Live server tests against messagebox.babbage.systems
```

## TypeScript Parity

This crate targets full behavioral parity with `@bsv/message-box-client` v2.0.x. Key parity points:

- **Wire format**: All JSON request/response bodies use camelCase field names matching the TS client exactly
- **Encryption**: BRC-78 with STANDARD base64 encoding (with padding), `{"encryptedMessage": "<base64>"}` format
- **Message IDs**: HMAC-derived using `JSON.stringify(body)` semantics (`serde_json::to_string`)
- **Multi-host**: `list_messages` and `acknowledge_message` fan out to all overlay-advertised hosts concurrently
- **Payment protocols**: PeerPay uses `[2, "3241645161d8"]`, message delivery uses `[1, "messagebox"]`
- **Pitfall parity**: snake_case `message_box` query param on `/permissions/list` (unique endpoint), delivery agent key from `x-bsv-auth-identity-key` header, `PeerMessage.recipient` from identity key (not server response)

## Testing

```bash
# Run all offline tests (112 tests: 94 unit + 12 integration + 6 parity)
cargo test

# Run specific test suites
cargo test --lib               # Unit tests (94)
cargo test --test integration  # Integration tests (12)
cargo test --test parity       # Parity verification tests (6)

# Run live server tests against messagebox.babbage.systems (31 tests)
# Use --test-threads=1 to avoid server rate limiting under parallel load
cargo test --test live_server -- --ignored --test-threads=1
```

Offline tests use `ProtoWallet` instances — no live server required. Coverage includes:

- Encryption round-trip (BRC-78, STANDARD base64)
- Wire format serialization (camelCase JSON for all types)
- CommsLayer adapter mapping (all 5 PeerMessage fields)
- Payment token shape and derivation encoding
- BRC-103 SocketIOTransport encoding/decoding and auth message parsing
- Critical pitfall guards (snake_case params, header extraction, recipient population)

Live server tests validate 30+ operations against the production Babbage MessageBox service, including messaging, encryption, permissions, payments, overlay queries, host resolution, and device registration.

## Default Hosts

| Network | Host |
|---------|------|
| Mainnet | `https://messagebox.babbage.systems` |
| Testnet | `https://staging-messagebox.babbage.systems` |

## Examples

Runnable examples are in the `examples/` directory. All examples connect to the live MessageBox server at `https://messagebox.babbage.systems`.

### Send a message (HTTP)

```bash
cargo run --example send_message
```

Demonstrates: `send_message`, `list_messages`, `acknowledge_message` — the basic HTTP messaging round-trip.

### Live messaging (WebSocket)

```bash
cargo run --example live_messaging
```

Demonstrates: `listen_for_live_messages`, `send_live_message` — real-time WebSocket messaging between two peers with BRC-103 authentication.

### Payments (PeerPay)

```bash
cargo run --example payments
```

Demonstrates: `create_payment_token`, `send_payment`, `list_incoming_payments`, `accept_payment` — the PeerPay payment lifecycle.

### CommsLayer adapter

```bash
cargo run --example comms_layer
```

Demonstrates: `RemittanceAdapter` implementing the `CommsLayer` trait — the integration pattern for `RemittanceManager`.

## License

Open BSV License - see [LICENSE](LICENSE) for details.
