# Architecture Research

**Domain:** BSV MessageBox Client Library (Rust)
**Researched:** 2026-03-26
**Confidence:** HIGH — based on direct inspection of SDK source code and TS reference implementation

## Standard Architecture

### System Overview

```
┌────────────────────────────────────────────────────────────────────┐
│                         Consuming Application                       │
│  (metawatt-edge-rs / any Rust BSV app)                             │
├────────────────────────────────────────────────────────────────────┤
│                       Public API Surface                            │
│  ┌────────────────────┐   ┌────────────────────────────────────┐   │
│  │  MessageBoxClient  │   │      RemittanceAdapter             │   │
│  │  <W: WalletInterface>  │  (implements CommsLayer trait)     │   │
│  │  All 28 public ops │   │  Arc<Mutex<MessageBoxClient<W>>>   │   │
│  └─────────┬──────────┘   └─────────────┬──────────────────────┘   │
│            │                            │                           │
│            │ (composition, not inherit) │                           │
│  ┌─────────┴──────────────────────────┐ │                           │
│  │        PeerPayClient               │ │                           │
│  │  wraps Arc<MessageBoxClient<W>>    │ │                           │
│  └─────────────────────────────────────┘                           │
├────────────────────────────────────────────────────────────────────┤
│                        Internal Modules                             │
│  ┌────────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
│  │  http_ops.rs   │  │encryption.rs│  │  host_resolution.rs     │  │
│  │  send_message  │  │encrypt_body │  │  resolve_recipient_host │  │
│  │  list_messages │  │decrypt_body │  │  anoint_host / revoke   │  │
│  │  acknowledge   │  │hmac_id_gen  │  │  query_advertisements   │  │
│  │  list_lite     │  └─────────────┘  └─────────────────────────┘  │
│  └────────────────┘                                                 │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  websocket.rs                                                │   │
│  │  join_room / leave_room / send_live_message                  │   │
│  │  listen_for_live_messages                                    │   │
│  │  Wraps SDK's WebSocketTransport + Peer (BRC-31 handshake)   │   │
│  └─────────────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  permissions.rs + notifications.rs + devices.rs              │   │
│  │  (thin HTTP wrappers — set/get/list/quote, register, etc.)  │   │
│  └─────────────────────────────────────────────────────────────┘   │
├────────────────────────────────────────────────────────────────────┤
│                      bsv-rust-sdk Dependencies                      │
│  ┌──────────────┐  ┌──────────────┐  ┌─────────────────────────┐  │
│  │  AuthFetch   │  │WebSocketTran-│  │  WalletInterface        │  │
│  │  <W>         │  │sport         │  │  encrypt / decrypt      │  │
│  │  BRC-31 HTTP │  │BRC-31 WS     │  │  create_hmac            │  │
│  │  &mut self   │  │Send+Sync     │  │  get_public_key         │  │
│  └──────────────┘  └──────────────┘  └─────────────────────────┘  │
│  ┌──────────────┐  ┌──────────────┐                               │
│  │LookupResolver│  │TopicBroadcast│                               │
│  │ls_messagebox │  │SHIP overlay  │                               │
│  └──────────────┘  └──────────────┘                               │
└────────────────────────────────────────────────────────────────────┘
```

### Component Responsibilities

| Component | Responsibility | Key Constraint |
|-----------|---------------|----------------|
| `MessageBoxClient<W>` | Central coordinator; owns `Mutex<AuthFetch<W>>`, identity key cache, room set, init flag | Generic over `W: WalletInterface + Clone + 'static` |
| `RemittanceAdapter<W>` | Implements `CommsLayer` trait; bridges `&self` CommsLayer into `&mut self` AuthFetch via Mutex | Must be `Send + Sync`; wraps `Arc<MessageBoxClient<W>>` |
| `PeerPayClient<W>` | Payment-specific operations (create/send/accept/reject payment tokens) | Composes `Arc<MessageBoxClient<W>>` — not inheritance |
| `http_ops` (module) | All HTTP operations against MessageBox server REST API | All go through `Mutex<AuthFetch<W>>` |
| `encryption` (module) | BRC-78 message body encrypt/decrypt using wallet ECDH, HMAC-based ID generation | Protocol: `[1, "messagebox"]`, keyID: `"1"` |
| `host_resolution` (module) | Overlay lookup via `LookupResolver`, host advertisement via `TopicBroadcaster` | Uses SDK's `ls_messagebox` service |
| `websocket` (module) | Room-based live messaging; wraps SDK's `WebSocketTransport` with BRC-31 `Peer` | Channel-based (`mpsc`) not callback; `Arc<Mutex<WsState>>` for room tracking |
| `permissions` (module) | Set/get/list permissions, get quote | Thin HTTP wrappers |
| `notifications` (module) | Allow/deny/check/send notification convenience methods | Thin HTTP wrappers |
| `devices` (module) | Register device, list registered devices (push notification support) | Thin HTTP wrappers |
| `types` (module) | All wire types: `MessageBoxClientOptions`, `SendMessageParams`, `PeerMessage`, `EncryptedMessage`, etc. | Must match TS wire format for interop |
| `error` (module) | `MessageBoxError` enum with `thiserror` derive; `From<AuthError>`, `From<RemittanceError>`, `From<WalletError>` | — |

## Recommended Project Structure

```
src/
├── lib.rs                    # Public exports; crate-level docs
├── error.rs                  # MessageBoxError enum (thiserror)
├── types.rs                  # Wire types: SendMessageParams, PeerMessage, EncryptedMessage, etc.
├── client.rs                 # MessageBoxClient<W> struct + init + getIdentityKey + assertInitialized
├── http_ops.rs               # send_message, list_messages, list_messages_lite, acknowledge_message
├── encryption.rs             # encrypt_body, decrypt_body, generate_message_id (HMAC)
├── host_resolution.rs        # resolve_host_for_recipient, anoint_host, revoke_host, query_advertisements
├── websocket.rs              # WsState, join_room, leave_room, send_live_message, listen_for_live_messages
├── permissions.rs            # set_permission, get_permission, list_permissions, get_quote
├── notifications.rs          # allow_notification, deny_notification, check_notification, list, send
├── devices.rs                # register_device, list_devices
├── peer_pay/
│   ├── mod.rs                # PeerPayClient<W> struct
│   ├── types.rs              # PaymentToken, IncomingPayment, PaymentParams (local to peer_pay)
│   └── ops.rs                # create_payment, send_payment, accept_payment, reject_payment, list_incoming
└── adapter.rs                # RemittanceAdapter<W> — CommsLayer impl for RemittanceManager
```

### Structure Rationale

- **`client.rs` as coordinator:** `MessageBoxClient<W>` holds `Mutex<AuthFetch<W>>`, identity key cache, `LookupResolver`, initialized flag, and `Arc<Mutex<WsState>>`. All module functions receive `&self` and unlock what they need.
- **Modules as free functions or impl blocks:** `http_ops`, `encryption`, etc. are `impl MessageBoxClient<W>` blocks split across files (Rust allows this with `mod` declarations), keeping the struct thin while organizing related operations.
- **`peer_pay/` as subdirectory:** PeerPayClient has enough types and logic to warrant its own directory, matching the TS package's separate file.
- **`adapter.rs` isolated:** RemittanceAdapter is consumed by an entirely different crate (`metawatt-edge-rs`). Keeping it separate makes the boundary visible and testable in isolation.
- **`types.rs` at crate root:** Wire format types must be public and discoverable; co-locating with the client module creates circular import issues.

## Architectural Patterns

### Pattern 1: Generic Client with Mutex Interior Mutability

**What:** `MessageBoxClient<W: WalletInterface + Clone + 'static>` holds `Mutex<AuthFetch<W>>` and `Arc<Mutex<WsState>>` to safely share across tasks.

**When to use:** AuthFetch.fetch() requires `&mut self` (mutates the per-server peer cache). Wrapping in `Mutex` is the correct solution — it preserves the generic type (no object safety issue with `dyn WalletInterface`) while allowing concurrent access from multiple tokio tasks.

**Trade-offs:** Monomorphizes the entire client per wallet type (binary size), but produces zero-cost dispatch and allows the wallet to be `Clone`d into `AuthFetch` without `Arc` indirection. This matches what `AuthFetch` already does internally.

**Example:**
```rust
pub struct MessageBoxClient<W: WalletInterface + Clone + 'static> {
    host: String,
    auth_fetch: Mutex<AuthFetch<W>>,    // &mut self fetch → behind Mutex
    wallet: W,                           // retained for direct encrypt/decrypt calls
    lookup_resolver: LookupResolver,
    identity_key: OnceLock<String>,      // cached after first init
    ws_state: Arc<Mutex<WsState>>,
    initialized: AtomicBool,
}
```

### Pattern 2: CommsLayer Bridge via Arc Wrapping

**What:** `RemittanceAdapter<W>` wraps `Arc<MessageBoxClient<W>>` and implements `CommsLayer` (which takes `&self`). The bridge works because `MessageBoxClient` uses `Mutex` internally — `&self` on the adapter can lock `&self.inner.auth_fetch`.

**When to use:** Any time an `&self` async trait must drive an internally-mutable struct. This is the standard Rust solution for the TS "class with mutable state shared across callbacks" pattern.

**Trade-offs:** The `Arc` adds one indirection layer. In practice this is negligible compared to network I/O.

**Example:**
```rust
pub struct RemittanceAdapter<W: WalletInterface + Clone + 'static> {
    inner: Arc<MessageBoxClient<W>>,
}

#[async_trait]
impl<W: WalletInterface + Clone + 'static + Send + Sync> CommsLayer for RemittanceAdapter<W> {
    async fn send_message(&self, recipient: &str, message_box: &str, body: &str, host_override: Option<&str>)
        -> Result<String, RemittanceError>
    {
        self.inner.send_message(SendMessageParams { recipient, message_box, body }, host_override)
            .await
            .map(|r| r.message_id)
            .map_err(RemittanceError::from)
    }
    // ...
}
```

### Pattern 3: WebSocket State as Separate Locked Struct

**What:** Rather than putting WS fields directly on `MessageBoxClient`, extract into `WsState` behind `Arc<Mutex<WsState>>`.

**When to use:** WebSocket lifecycle (connect, join rooms, disconnect) has state that changes independently of HTTP operations. Separating it reduces contention on the main auth_fetch mutex and makes the WebSocket code easier to test in isolation.

**Trade-offs:** One additional `Arc<Mutex>` allocation. Worth it for clarity and reduced lock contention.

**Example:**
```rust
struct WsState {
    peer: Option<Arc<Mutex<Peer<W>>>>,
    transport: Option<Arc<WebSocketTransport>>,
    joined_rooms: HashSet<String>,
    identity_key: Option<String>,
}
```

### Pattern 4: PeerPayClient as Composition, not Inheritance

**What:** In TS, `PeerPayClient extends MessageBoxClient`. In Rust, use composition: `PeerPayClient<W>` holds `Arc<MessageBoxClient<W>>` and delegates all MessageBox operations.

**When to use:** Always in Rust — there is no class inheritance. Trait extension would require re-implementing every MessageBox method on PeerPayClient, which creates maintenance burden and API confusion.

**Trade-offs:** Callers of `PeerPayClient` must explicitly access `client.message_box` for base operations, or re-expose methods as delegates. In practice the primary consumer (metawatt) uses PeerPayClient directly for payments and CommsLayer via the adapter for messaging.

## Data Flow

### HTTP Message Send Flow

```
Caller calls send_message(params, host_override)
    ↓
assertInitialized() → OnceLock identity_key, init flag (atomic)
    ↓
resolve_host_for_recipient(recipient)
    → LookupResolver.query(ls_messagebox, {identityKey})
    → returns host URL (or falls back to self.host)
    ↓
encryption::encrypt_body(wallet, body, recipient)
    → wallet.encrypt(EncryptArgs { protocol: [1,"messagebox"], keyID: "1", ... })
    → base64-encode ciphertext
    → wrap in JSON: {"encryptedMessage": "<b64>"}
    ↓
encryption::generate_message_id(wallet, body, recipient)
    → wallet.create_hmac(CreateHmacArgs { protocol: [1,"messagebox"], keyID: "1", data: body_bytes, counterparty: recipient })
    → hex-encode hmac bytes
    ↓
http_ops::post(auth_fetch, host+"/sendMessage", {recipient, messageBox, body, messageId})
    → Mutex::lock(auth_fetch).fetch(url, "POST", payload, headers)
    → BRC-31 handshake on first request to host
    → returns AuthFetchResponse
    ↓
Deserialize JSON response → SendMessageResponse { status, message_id }
```

### WebSocket Live Message Flow

```
Caller calls listen_for_live_messages(message_box, on_message)
    ↓
ws_state.lock() → check if Peer connected
    if not: WebSocketTransport::new(ws_url) → transport.connect()
            Peer::new(wallet, transport) → BRC-31 handshake
            ws_state.peer = Some(peer)
    ↓
join_room(message_box)
    → room_id = "{identity_key}-{message_box}"
    → peer.send_message("joinRoom", room_id)
    → ws_state.joined_rooms.insert(room_id)
    ↓
Spawn tokio task:
    loop {
        msg = peer.general_message_rx.recv().await
        parse body → check for {"encryptedMessage": ...}
        if encrypted: wallet.decrypt(...) → plaintext
        on_message(PeerMessage { ... plaintext body ... })
    }
```

### RemittanceAdapter Flow (CommsLayer → MessageBoxClient)

```
RemittanceManager calls adapter.send_message(recipient, message_box, body, None)
    ↓
RemittanceAdapter::send_message(&self, ...)
    ↓
self.inner.send_message(SendMessageParams {...}, None).await
    (goes through full HTTP message send flow above)
    ↓
map Ok(response.message_id) → Result<String, RemittanceError>
map Err(MessageBoxError) → RemittanceError::Protocol(e.to_string())
```

### Initialization / Host Advertisement Flow

```
First call to any public method
    ↓
assertInitialized() → initialized.load(Relaxed) == false
    ↓
init(target_host)
    ↓
get_identity_key() → wallet.get_public_key({identityKey: true})
    → cache in OnceLock<String>
    ↓
query_advertisements(identity_key, Some(host))
    → LookupResolver.query(ls_messagebox, {identityKey, host})
    ↓
if no matching advertisement found:
    anoint_host(host)
        → TopicBroadcaster.broadcast(SHIP, PushDrop token with [identityKey, host])
        → records txid (non-fatal if fails)
    ↓
initialized.store(true, Release)
```

## Scaling Considerations

This is a library crate used by a single application process (or a small set of edge agent instances). Traditional scaling concerns don't apply directly, but concurrency matters:

| Concern | Reality | Approach |
|---------|---------|---------|
| Multiple tasks sharing client | 6 concurrent edge agents in same process | `Arc<MessageBoxClient<W>>` — share one instance |
| AuthFetch mutex contention | Per-host Peer cache mutates on first request per host | In practice 1-2 hosts; contention negligible |
| WebSocket room state | Multiple rooms joined concurrently | `HashSet<String>` behind `Mutex<WsState>` |
| Message deduplication | Multi-host querying (list from multiple hosts) | Deduplicate by message_id in `list_messages` |

The primary bottleneck is the Mutex around AuthFetch when multiple tasks send messages simultaneously. If this becomes a measured problem, the AuthFetch peer map could be refactored to use `DashMap` or per-host `Mutex`. Do not optimize prematurely.

## Anti-Patterns

### Anti-Pattern 1: Using `Arc<dyn WalletInterface>` instead of generics

**What people do:** Define `MessageBoxClient` with `wallet: Arc<dyn WalletInterface>` to avoid the generic parameter.

**Why it's wrong:** `AuthFetch<W>` is already generic. To use it, you'd need to either make `AuthFetch` take `Arc<dyn WalletInterface>` too (requires WalletInterface to be object-safe — it is, but the SDK doesn't use it that way) or create a separate wallet reference. The SDK's established pattern is generics. Breaking from this creates impedance mismatch at the SDK boundary and double-dispatch overhead.

**Do this instead:** Keep `MessageBoxClient<W: WalletInterface + Clone + 'static>`. Callers monomorphize once at their type; the compiler produces a single concrete type per wallet implementation. In metawatt-edge-rs, this will be `MessageBoxClient<SqliteWallet>`.

### Anti-Pattern 2: TS-style inheritance for PeerPayClient

**What people do:** Attempt to share `MessageBoxClient` state with `PeerPayClient` via trait inheritance or by putting payment methods directly on `MessageBoxClient`.

**Why it's wrong:** Rust has no struct inheritance. Embedding `MessageBoxClient` fields in `PeerPayClient` would require duplicating all initialization/state management. Trait extension adds 28 delegation methods.

**Do this instead:** `PeerPayClient<W>` holds `Arc<MessageBoxClient<W>>`. Payment callers use `PeerPayClient`. If they need basic messaging, they access `client.message_box` or the library exposes a `From<MessageBoxClient>` conversion to `PeerPayClient`.

### Anti-Pattern 3: Callback-based WebSocket API

**What people do:** Mirror the TS `onMessage: (message) => void` callback pattern by storing `Box<dyn Fn(PeerMessage) + Send + Sync>` callbacks on the client.

**Why it's wrong:** TS callbacks work because JS is single-threaded. In async Rust, callbacks stored as fields require `Arc<dyn Fn + Send + Sync>` and can't `.await` inside. The CommsLayer trait already uses `Arc<dyn Fn(PeerMessage) + Send + Sync>` for its callback, which is acceptable at that interface boundary.

**Do this instead:** Internally, use `mpsc::channel` from the SDK's WebSocketTransport. Route incoming messages from the channel in a spawned task. For the `listen_for_live_messages` public API that must accept a callback (to match CommsLayer), accept `Arc<dyn Fn(PeerMessage) + Send + Sync>` and invoke it from the spawned task. This is the pattern CommsLayer already defines.

### Anti-Pattern 4: Storing initialized state as `bool` without atomics

**What people do:** Use a plain `bool` field behind `Mutex<bool>` for the initialized flag, locking the whole client on every call.

**Why it's wrong:** The initialization check is on every public method call path. Locking a separate mutex for a flag when `AtomicBool` suffices wastes cycles and increases contention.

**Do this instead:** `initialized: AtomicBool`. Use `Relaxed` load for the fast path (already initialized), `Release` store after completing init, `Acquire` load when reading after the store. For the init body itself, use a `OnceLock<()>` or `tokio::sync::OnceCell` to ensure only one task runs initialization.

## Integration Points

### External Services

| Service | Integration Pattern | Notes |
|---------|---------------------|-------|
| MessageBox Server REST API | `AuthFetch<W>.fetch()` → BRC-31 authenticated HTTP | One `AuthFetch` per client; per-host Peer cache inside |
| MessageBox Server WebSocket | `WebSocketTransport` + `Peer<W>` — SDK's BRC-31 WS auth | `connect()` once; transport spawns read/write tasks |
| BSV Overlay Network | `LookupResolver.query("ls_messagebox", ...)` | For host resolution per recipient |
| SHIP Overlay | `TopicBroadcaster.broadcast(...)` | For `anointHost` advertisement during `init()` |
| Wallet (BRC-78 crypto) | `wallet.encrypt()`, `wallet.decrypt()`, `wallet.create_hmac()` | Protocol `[1, "messagebox"]`, keyID `"1"`, counterparty = recipient pubkey |

### Internal Boundaries

| Boundary | Communication | Notes |
|----------|---------------|-------|
| `MessageBoxClient` ↔ `http_ops` | `impl` methods on same struct; access `auth_fetch` via `Mutex::lock()` | No additional indirection |
| `MessageBoxClient` ↔ `websocket` | `impl` methods on same struct; access `ws_state` via `Arc<Mutex<WsState>>` | WsState encapsulates Peer + room set |
| `MessageBoxClient` ↔ `encryption` | Pure functions taking `&W` and message bytes; no state | Easiest to test in isolation |
| `MessageBoxClient` ↔ `host_resolution` | `impl` methods; accesses `lookup_resolver` (no lock needed — LookupResolver is already `Send+Sync`) | — |
| `RemittanceAdapter` ↔ `MessageBoxClient` | `Arc<MessageBoxClient<W>>` clone; calls `await` on public methods | The `Arc` is the only coupling |
| `PeerPayClient` ↔ `MessageBoxClient` | `Arc<MessageBoxClient<W>>` delegation | Payment-specific wallet ops go through `PeerPayClient`'s own wallet reference |

## Build Order Implications

The module dependency graph determines a natural phase order:

1. **`error.rs` + `types.rs`** — no dependencies; everything else depends on these. Build first.

2. **`encryption.rs`** — depends on `types.rs` and `WalletInterface`. Pure crypto, fully testable with `ProtoWallet`.

3. **`client.rs` skeleton** — struct definition with `Mutex<AuthFetch<W>>`, `OnceLock`, `AtomicBool`. No method implementations yet.

4. **`http_ops.rs`** — depends on `client.rs` struct, `encryption.rs`, `types.rs`. Covers the core 4 methods (send, list, list_lite, acknowledge). Enables first integration tests against a real server.

5. **`host_resolution.rs`** — depends on `LookupResolver`, `TopicBroadcaster`. Enables `init()` to work properly.

6. **`permissions.rs`, `notifications.rs`, `devices.rs`** — thin HTTP wrappers; depends on `http_ops` patterns. All are similar boilerplate.

7. **`adapter.rs`** — depends on `client.rs` + CommsLayer trait. The metawatt primary use case unlocks here.

8. **`peer_pay/`** — depends on `client.rs` + wallet transaction ops. PeerPayClient with payment token creation/receipt.

9. **`websocket.rs`** — depends on SDK's `WebSocketTransport`, `Peer`, `WsState`. Live messaging; most complex state management.

## Sources

- Direct inspection: `/Users/elisjackson/Projects/bsv-rust-sdk/src/auth/clients/auth_fetch.rs` — AuthFetch struct, `&mut self fetch()`, Mutex<Peer> pattern
- Direct inspection: `/Users/elisjackson/Projects/bsv-rust-sdk/src/auth/transports/websocket.rs` — WebSocketTransport, mpsc channels, reconnect logic
- Direct inspection: `/Users/elisjackson/Projects/bsv-rust-sdk/src/remittance/comms_layer.rs` — CommsLayer trait, `&self` methods, `Send + Sync` requirement
- Direct inspection: `/Users/elisjackson/Projects/bsv-rust-sdk/src/remittance/error.rs` — RemittanceError, `From<AuthError>` impl
- Direct inspection: `/Users/elisjackson/Projects/bsv-rust-sdk/src/wallet/interfaces.rs` — `WalletInterface::encrypt/decrypt/create_hmac` signatures with `originator: Option<&str>`
- Direct inspection: `/Users/elisjackson/Projects/bsv-rust-sdk/src/wallet/types.rs` — `Protocol { security_level, protocol }` struct, `Counterparty` enum
- Direct inspection: `/Users/elisjackson/Projects/draigfi-sdk/node_modules/@bsv/message-box-client/src/MessageBoxClient.ts` — TS reference: room ID format, encryption protocol constants, init flow, WebSocket ack pattern
- Direct inspection: `/Users/elisjackson/Projects/draigfi-sdk/node_modules/@bsv/message-box-client/src/PeerPayClient.ts` — TS reference: PeerPayClient extends MessageBoxClient pattern

---
*Architecture research for: BSV MessageBox Client (Rust)*
*Researched: 2026-03-26*
