# bsv-messagebox-client

A Rust implementation of the BSV MessageBox client — a peer-to-peer messaging and payment toolkit for the BSV blockchain. Full parity with the TypeScript [`@bsv/message-box-client`](https://github.com/bsv-blockchain/message-box-client) v2.0.x, and follows what the Atlas relay does ([Relay behaviour](#relay-behaviour)).

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
// Prefer the detailed API when messages may carry recipient payments.
let receipts = client.list_messages_detailed("inbox", true, None).await?;

for receipt in &receipts {
    println!(
        "From: {}, Body: {}, Payment: {:?}",
        receipt.message.sender,
        receipt.message.body,
        receipt.payment_outcome,
    );
}

// Only acknowledge after the application accepts the reported outcome.
let ids: Vec<String> = receipts
    .iter()
    .filter(|r| r.payment_outcome.payment_is_safe())
    .map(|r| r.message.message_id.clone())
    .collect();
client.acknowledge_message(ids, None).await?;
```

`PaymentAwarePeerMessage` keeps the normal decrypted inner `PeerMessage` plus a
`ListMessagePaymentOutcome`. For `Skipped`, `Declined`, `Failed`, or
`Unprocessable`, `raw_payment_envelope` is the byte-exact outer body returned by
the relay, suitable for durable retention and retry. The lite detailed API uses
`PaymentAwareServerPeerMessage` and reports every present payment as `Skipped`.
Every full, lite, and background-poll list path caps each host's authenticated
response at 32 MiB—the largest bounded message-box server response profile—before
status inspection or outer list JSON deserialization. Successful pages use one
typed streaming-deserialization pass; only malformed or logical-error responses
receive a second lightweight status/description projection. Within a valid page,
an individual stored body above this crate's conservative 4 MiB nested-envelope
processing cap is `Unprocessable` with a short marker body and no retained raw
copy, preventing an oversized hostile envelope from being parsed or duplicated
in memory.

This is an application-level parsing boundary, not a transport allocation limit:
bsv-sdk `AuthFetch` currently buffers the complete authenticated response frame
and copies its body into a `Vec<u8>` before returning it to this crate. Enforcing
the 32 MiB cap before that buffering requires a bounded/streaming upstream API.

The legacy `list_messages` and `list_messages_lite` signatures remain available.
They preserve their historical inner-body result for messages with no payment or
a successfully internalized payment. For every unsuccessful payment outcome they
now return the exact raw wrapper in `body`, preventing callers from accidentally
acknowledging away the only retry data.

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

// Send via WebSocket. Falls back to HTTP, with the same message id, if the
// relay refuses it or no ack names it within 10 s.
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

## Relay behaviour

What the client does against the Atlas relay.

**Errors.** A request the relay refuses returns
`MessageBoxError::Relay { status, code, description }` with the relay's code
(`ERR_DELIVERY_BLOCKED`, `not_certified`, ...). A rate-limit refusal that
outlasts the client's wait returns `RateLimited { retry_after, tier }`.
`Http(status, url)` is left for answers whose body names no code. A list or
acknowledgement sent to several hosts fails only when every host fails, with
the client's own host's error.

**Rate budget.** The relay charges HTTP sends, WebSocket sends and lists to one
budget per identity: 10 a minute for an uncertified key, 300 for a certified
one. A send costs one per recipient; acknowledgements are free. A refused
request changes nothing on the relay. After a refusal the client holds every
send and list to that relay for the relay's `retry_after` (at least 1 s), then
resends the same bytes, so the same message id. When the wait would pass
`with_rate_limit_wait` (default 60 s; `Duration::ZERO` never waits) the call
returns `RateLimited` instead. A send to more recipients than the key's
per-minute budget is always refused.

**Live sends.** `send_live_message` first waits out a rate-limit hold on the
relay its WebSocket is open to, then emits over the WebSocket and waits up to
10 s for the relay's ack naming that message. If the emit fails, the relay
refuses, or no ack arrives, it sends over HTTP with the same message id. A
rate-limit refusal on the socket holds the socket's relay, which is not the
host the call names when an earlier call opened the socket. The wait before
the emit and the fallback's waits share one `with_rate_limit_wait`, counted
from the start of the call; the 10 s ack wait and network time are on top. A
refusal (`messageFailed`) names no message, so it fails every pending live
send on that socket. One WebSocket dial runs at a time, so concurrent sends on
a cold client share one socket. A reconnect replaces only a dead socket; it
closes that socket and fails the sends still waiting on it at once, and each
falls back to HTTP. The relay
is not exactly-once: it keeps one row per id only until the recipient
acknowledges it, so receivers dedup by message id.

**Acknowledgements.** The relay pushes a live message before it stores it. An
ack that arrives first is answered `ERR_INVALID_ACKNOWLEDGMENT`; the client
retries that answer, and only that one, for up to 5 s.

**Poll backstop.** `listen_for_live_messages` also lists the box over HTTP,
which spends the rate budget: once on each WebSocket connect and reconnect,
then every 15 s while connected (`with_poll_interval`); with no connected
socket, after 1 s, doubling to 8 s. It waits out a rate-limit refusal and backs
off, up to 60 s, after a failed list. A list over 32 MiB fails (see Known
limits): the poll logs an error and lists again 60 s later, connected or not,
while live delivery continues.

**Relay identity pin.** `with_expected_relay_key(key)` ties the client to its
own host and to the relay there that proves `key`:
- It talks only to its own host. It looks up no host on the overlay, and lists
  and acknowledges on its own host alone. A call that names another host (an
  `override_host`, a `_from_host` / `_to_host` method, `init`'s
  `target_host`, or `anoint_host`) returns `RelayHostRefused` before any
  request, payment or
  advertisement. Hosts compare by scheme, host, port
  and path, ignoring case, a default port and a trailing slash.
- Over HTTP and the WebSocket, the wallet signs a message only for a server
  that proved `key` in the BRC-103 handshake. A server that proved another
  key gets the handshake and nothing after it: the request is never signed,
  so never sent, and the call returns `RelayIdentityMismatch`. The next
  request handshakes again, so it reaches the pinned relay once that relay
  answers the host.
- Every HTTP answer must also come from a server that proved `key`, else
  `RelayIdentityMismatch`; a server that proved no key fails too.
- Every WebSocket connect and reconnect is checked the same way and
  disconnects on a mismatch. A live send then returns the error and sends
  nothing over HTTP.
- In either handshake the client proves certificates only to a server that
  proved `key`, never pays a `402` answer, and reveals no key linkage.

Without a pin the client trusts whichever relay answers the host.

**Certificates.** A relay with its identity gate armed asks for a certificate
during the handshake.
- WebSocket: `with_certificate_provider(provider)` answers it on every connect
  and reconnect. `MessageBoxWebSocket::connect_with_certificate_provider` does
  the same for a socket you open yourself.
- HTTP: bsv-sdk 0.8.0's `AuthFetch` has no provider hook. It answers from the
  wallet's `list_certificates` and `prove_certificate`. If the wallet holds no
  matching certificate, or either call fails, it sends nothing, and the relay
  answers 408 after its 30 s certificate timeout.

**Pinned-host payments.** `list_incoming_payments_from_host`,
`accept_payment_from_host` and `request_payment_to_host` use only the named
host: no overlay lookup and no multi-host fan-out.

**Known limits.** Both wait on relay changes.
- A refusal on the socket fails live sends the relay may already have
  accepted, and each is resent over HTTP with its id: `messageFailed` names no
  message (atlas-relay#27).
- A box whose list exceeds 32 MiB cannot be listed or drained:
  `/listMessages` has no limit or paging (atlas-relay#28).

## API Reference

### MessageBoxClient

#### Constructor

| Method | Description |
|--------|-------------|
| `new(host, wallet, originator, network)` | Create a new client |
| `new_mainnet(host, wallet, originator)` | Convenience constructor for mainnet |
| `with_expected_relay_key(key)` | Pin the relay identity key ([Relay behaviour](#relay-behaviour)) |
| `expected_relay_key()` | The pin, if set (lowercase hex) |
| `with_certificate_provider(provider)` | Answer the relay's certificate request on WebSocket connects |
| `with_rate_limit_wait(duration)` | Longest a send or list waits on the rate limit (default 60 s) |
| `with_poll_interval(duration)` | Poll backstop interval while the WebSocket is connected (default 15 s, at least 1 s) |

#### Core Messaging

| Method | Description |
|--------|-------------|
| `send_message(recipient, mb, body, skip_enc, check_perms, msg_id, host)` | Send encrypted message via HTTP |
| `send_message_to_recipients(params, host)` | Batch send to multiple recipients |
| `list_messages(mb, accept_payments, host)` | Legacy list with multi-host dedup; unsuccessful payment wrappers remain in `body` |
| `list_messages_detailed(mb, accept_payments, host)` | Payment-aware multi-host list with typed outcome and exact retry envelope |
| `list_messages_lite(mb, host)` | Legacy list from one host; present payment wrappers remain in `body` |
| `list_messages_lite_detailed(mb, host)` | Payment-aware single-host list; payments are reported as skipped |
| `acknowledge_message(ids, host)` | Mark messages as read |

#### WebSocket Live Messaging

| Method | Description |
|--------|-------------|
| `initialize_connection(host)` | Establish authenticated WebSocket connection |
| `send_live_message(recipient, mb, body, skip_enc, check_perms, msg_id, host)` | Send via WS; HTTP with the same id if refused or not acked within 10 s |
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
| `list_incoming_payments_from_host(host)` | List pending payments on one host only |
| `accept_payment_from_host(payment, host)` | Accept, acknowledging on one host only |
| `request_payment_to_host(recipient, amount, description, expires_at, host)` | Request a payment through one host, no overlay lookup |
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
  client.rs            # MessageBoxClient struct, WebSocket integration, poll backstop
  delivery.rs          # DeliveryMode (live or persisted)
  transport.rs         # Every relay HTTP request: error mapping, identity pin, rate-limit hold
  adapter.rs           # RemittanceAdapter (CommsLayer trait impl)
  http_ops.rs          # HTTP messaging operations, multi-host logic
  peer_pay.rs          # PeerPay payment operations
  payment_requests.rs  # Payment requests
  permissions.rs       # Permission management and notification wrappers
  encryption.rs        # BRC-78 encryption/decryption, HMAC message IDs
  websocket.rs         # Socket.IO WebSocket over authsocket (BRC-103), live-send acks
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
# Run all offline tests (179 tests: 161 unit + 12 integration + 6 parity)
cargo test

# Run specific test suites
cargo test --lib               # Unit tests (161)
cargo test --test integration  # Integration tests (12)
cargo test --test parity       # Parity verification tests (6)

# Run live server tests against messagebox.babbage.systems (38 tests)
# Use --test-threads=1 to avoid server rate limiting under parallel load
cargo test --test live_server -- --ignored --test-threads=1
```

Offline tests use `ProtoWallet` instances — no live server required. Coverage includes:

- Encryption round-trip (BRC-78, STANDARD base64)
- Wire format serialization (camelCase JSON for all types)
- CommsLayer adapter mapping (all 5 PeerMessage fields)
- Payment token shape and derivation encoding
- Relay answers driven through a scripted HTTP transport: error codes, rate-limit waits and resends, the ack retry, the identity pin
- Live-send ack matching and the poll backstop's cadence
- WebSocket guards against authsocket's own server on a loopback port: the identity pin, the lowercase recipient, the rate-limit hold before a live send, kept on the socket's relay, and the one rate deadline it shares with its fallback, the sends a reconnect strands, the certificate provider
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
