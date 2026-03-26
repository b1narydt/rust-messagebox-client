# Pitfalls Research

**Domain:** TS-to-Rust translation of an async BSV MessageBox client library
**Researched:** 2026-03-26
**Confidence:** HIGH — based on direct inspection of the TS source (2,272-line MessageBoxClient.ts + 395-line PeerPayClient.ts) combined with known SDK constraints from PROJECT.md

---

## Critical Pitfalls

### Pitfall 1: AuthFetch Mutability vs. CommsLayer Trait Object Safety

**What goes wrong:**
`AuthFetch::fetch()` in the Rust SDK takes `&mut self`, but `CommsLayer` trait methods (and the general async client API) need `&self` to be usable as `Arc<dyn CommsLayer>`. If you model `MessageBoxClient` with a direct `auth_fetch: AuthFetch<W>` field, calling any HTTP method from a shared reference becomes a compile error. If you then wrap in `Mutex<AuthFetch<W>>` but acquire the lock *inside* a closure or callback that itself holds the client reference, you get a deadlock at runtime.

**Why it happens:**
The TS `AuthFetch` is a stateful object (tracks nonce/handshake state), and the Rust SDK mirrors this mutability faithfully. Developers reaching for `Arc<Mutex<AuthFetch<W>>>` as the obvious fix don't notice that `listenForLiveMessages` registers a callback that fires on a background tokio task — that callback may call `send_message` (the HTTP fallback path), which re-acquires the same mutex that the outer WebSocket handler already holds.

**How to avoid:**
Wrap `AuthFetch<W>` in `Arc<tokio::sync::Mutex<AuthFetch<W>>>` and use `tokio::sync::Mutex` (not `std::sync::Mutex`) throughout — blocking the thread inside an async context while holding a mutex will deadlock the runtime. Never hold the lock across an `.await` point. Structure HTTP call helpers as: lock → build request args → drop lock → perform fetch → re-lock only to update state. The WebSocket callback path must never call any method that acquires the auth_fetch lock while on the same task that could be holding it.

**Warning signs:**
- Compiler error: `the trait Send is not satisfied` on `std::sync::MutexGuard` held across await
- Runtime hang: all 6 metawatt-demo nodes freeze simultaneously during high-throughput negotiation
- Tests pass in isolation but deadlock under concurrent load (>2 agents calling `send_message` at the same time)

**Phase to address:** Phase 1 (HTTP Core) — design the interior mutability wrapper before writing the first HTTP method. Wrong choice here requires refactoring every method.

---

### Pitfall 2: Encryption Protocol Exact-Match Requirement

**What goes wrong:**
The TS client encrypts every message body with `protocolID: [1, 'messagebox']`, `keyID: '1'`, and wraps the result as `{ "encryptedMessage": "<base64>" }`. If the Rust client uses any variation — different protocol tuple representation, different key ID, different JSON field name, or wrong base64 variant (standard vs. URL-safe, with or without padding) — the TS receiver will silently fail to decrypt and return `'[Error: Failed to decrypt or parse message]'` as the message body. No error is surfaced to the sender.

**Why it happens:**
The `Protocol` struct in the Rust SDK serializes as a JSON array `[securityLevel, "protocolName"]`, but a developer may pass it as a string `"messagebox"` or use the wrong security level integer. The TS `Utils.toBase64` produces standard base64 with padding; the Rust `base64` crate defaults differ between engines. The `Counterparty` type has enum variants (`Self_`, `Anyone`, `PublicKey(String)`) — passing `Counterparty::Anyone` instead of `Counterparty::PublicKey(recipient_key)` generates a completely different shared secret.

**How to avoid:**
Write a cross-language interop test in Phase 1: encrypt a known plaintext with the Rust client, send it to a running TS client (or the go-messagebox-server + TS receiver), confirm successful decryption. Use `base64::engine::general_purpose::STANDARD` (with padding). Serialize the protocol as `[1, "messagebox"]`. Use `Counterparty::PublicKey(recipient_key.to_string())` for normal messages and `Counterparty::Self_` only when `recipient == sender`. The `keyID` must be the string literal `"1"`, not an integer.

**Warning signs:**
- Receiver body contains `[Error: Failed to decrypt or parse message]` — this is the TS error string emitted on decryption failure
- `listMessages` returns messages with body length shorter than expected (truncated base64 padding)
- HMAC-based message IDs differ between TS and Rust clients for the same input body

**Phase to address:** Phase 1 (HTTP Core) — get interop test passing before building any higher-level features on top.

---

### Pitfall 3: Mixed HTTP Method/Body vs. Query Parameter Endpoints

**What goes wrong:**
The TS client uses inconsistent HTTP conventions across endpoints — some are POST with JSON body, others are GET with query string parameters. Translating these mechanically without noting which is which causes `405 Method Not Allowed` or silent empty responses from the server.

**Why it happens:**
The endpoints split as follows (from the TS source):
- POST JSON body: `/sendMessage`, `/listMessages`, `/acknowledgeMessage`, `/permissions/set`, `/registerDevice`
- GET query string: `/permissions/get?recipient=...&messageBox=...&sender=...`, `/permissions/quote?recipient=...&messageBox=...`, `/permissions/list?message_box=...&limit=...&offset=...`, `/devices`

Note the snake_case parameter name `message_box` (not camelCase) in `/permissions/list`, while all other query params use camelCase. This inconsistency exists in the live TS code and the server accepts it — the Rust client must match exactly.

**How to avoid:**
Define a lookup table in a comment or test matrix mapping each method name to its HTTP verb and parameter style. Use `reqwest::RequestBuilder::query()` for GET endpoints and `.json()` for POST endpoints. Add a test for each endpoint shape before implementing the logic inside it.

**Warning signs:**
- 405 responses on permission or device endpoints during testing
- Empty permission lists returned when filter params are correct but casing is wrong
- `getMessageBoxPermission` returns `null` when a permission exists (query string not sent)

**Phase to address:** Phase 1 (HTTP Core) — build the endpoint routing table in Phase 1 and validate each endpoint against the running go-messagebox-server before adding business logic.

---

### Pitfall 4: Lazy Initialization Race Condition

**What goes wrong:**
The TS client uses a boolean `initialized` flag and calls `assertInitialized()` (which calls `init()`) from every public method. In a concurrent Rust context with `Arc<MessageBoxClient>`, two tasks calling `send_message` simultaneously both see `initialized == false`, both enter `init()`, and both attempt to `anoint_host()` — creating duplicate on-chain advertisements for the same identity/host pair. The overlay network can handle duplicates, but the second broadcast wastes satoshis and may cause test failures if the test asserts exactly one advertisement.

**Why it happens:**
A boolean flag is not atomic. Even with `AtomicBool`, the init sequence involves multiple async steps (get identity key, query advertisements, maybe anoint). `compare_exchange` protects only the flag, not the multi-step sequence. The TS codebase is single-threaded so this never manifests there.

**How to avoid:**
Use `tokio::sync::OnceCell<()>` or `tokio::sync::Mutex<Option<()>>` as an initialization guard. The correct pattern:

```rust
async fn assert_initialized(&self) -> Result<()> {
    self.init_once.get_or_try_init(|| self.do_init()).await?;
    Ok(())
}
```

`OnceCell::get_or_try_init` guarantees exactly-once execution even under concurrent callers — subsequent callers block until the first completes, then return the cached result.

**Warning signs:**
- Duplicate advertisements in the overlay (visible via `queryAdvertisements` returning >1 entry for same host)
- Transaction creation errors on second init because the basket already contains an advertisement output
- Test flakes when running agent tests in parallel

**Phase to address:** Phase 1 (HTTP Core) — the initialization guard must be in place before any concurrent test runs.

---

### Pitfall 5: WebSocket Ack Listener Accumulation

**What goes wrong:**
The TS `sendLiveMessage` registers a one-shot `ackEvent` listener per message, removes it either on ack receipt or on the 10-second timeout. If the Rust translation attaches the listener but the timeout branch does not cleanly remove it, every timed-out message leaks a callback. In the metawatt-demo with 6 agents each sending hundreds of negotiation messages, this results in hundreds of stale listeners on the same socket, all firing (incorrectly) when any future ack arrives for any message.

**Why it happens:**
The TS code casts to `any` and calls `.off(ackEvent, ackHandler)` via duck typing. This is easy to miss when translating to Rust's `WebSocketTransport` API, which may have a different event listener removal interface. The SDK's `WebSocketTransport` event system may not provide per-event-name removal, requiring a different approach (e.g., a `tokio::sync::oneshot` channel per in-flight message keyed by `roomId`).

**How to avoid:**
Use a `DashMap<String, oneshot::Sender<SendMessageResponse>>` (or `tokio::sync::Mutex<HashMap<...>>`) keyed by `ack_event` name. When a send fires, insert a sender. When the ack arrives via the WebSocket message handler, look up and complete the sender. The 10-second timeout should use `tokio::time::timeout()` wrapping the receiver — if it times out, remove the entry from the map and trigger the HTTP fallback. This approach is naturally leak-free.

**Warning signs:**
- Memory growth in long-running agent processes that send many messages
- Incorrect ack being received by a message that didn't send it (wrong `resolve()` called)
- Messages "acknowledging" themselves immediately without network round-trip in tests

**Phase to address:** Phase 3 (WebSocket) — design the ack tracking map before writing `send_live_message`.

---

### Pitfall 6: Multi-Host Message Deduplication Semantics

**What goes wrong:**
`listMessages` queries multiple hosts in parallel (the default host plus all advertised hosts), then deduplicates by `messageId` using first-seen-wins semantics. A naive translation that concatenates results from all hosts and returns them will surface duplicate messages to the caller. Additionally, `listMessages` sorts results newest-first using a `timestamp` field that is not part of the typed `PeerMessage` interface — it exists as an untyped server-added field. If the Rust struct derives `serde::Deserialize` strictly (denying unknown fields), the timestamp is dropped and sort order becomes undefined.

**Why it happens:**
The TS code accesses `(m as any).timestamp` — an escape hatch that Rust's type system prevents. Developers model `PeerMessage` strictly and lose the sort key. The multi-host deduplication is also easy to overlook; developers implementing `list_messages` against a single-host test environment never observe duplicates and skip the deduplication step.

**How to avoid:**
Include `timestamp: Option<u64>` as a field on `PeerMessage` (or use `#[serde(flatten)]` with a `HashMap<String, serde_json::Value>` for extra fields). Use `#[serde(deny_unknown_fields)]` only on request types you control, not on server response types. Implement deduplication using `IndexMap<String, PeerMessage>` (insertion-order-preserving, first-seen-wins). Write a test with two hosts returning overlapping message sets.

**Warning signs:**
- Duplicate messages appearing in metawatt-demo negotiation logs
- Message ordering non-deterministic between runs (missing timestamp field)
- Test with two mock host responses returns 2x expected messages

**Phase to address:** Phase 1 (HTTP Core) — `list_messages` is a core method and the deduplication logic must be correct from the start.

---

### Pitfall 7: Payment Body Wrapping — Two Separate JSON Envelope Layers

**What goes wrong:**
The TS `listMessages` handles two distinct envelope formats, both of which look like JSON objects but mean different things:
1. `{ encryptedMessage: "..." }` — the encryption envelope from `sendMessage`
2. `{ message: <inner>, payment: <payment_data> }` — the payment wrapper added by the server when a payment was attached

The code unwraps the payment envelope first, then checks if the inner content is an encryption envelope. A Rust translation that checks for `encryptedMessage` before checking for `message/payment` will attempt to decrypt a payment wrapper as if it were ciphertext, fail, and return an error string to the caller instead of the actual message content plus payment.

**Why it happens:**
The dual-envelope pattern is not obvious from reading the method signature or the type definitions. `PeerMessage.body` is typed as `string | Record<string, any>` in TS, hiding the actual shape. The wrapping is done server-side, not by the client, so it's invisible when writing `sendMessage` — you only discover it when reading via `listMessages`.

**How to avoid:**
Model the response body as an enum:
```rust
enum MessageBody {
    PaymentWrapped { message: Box<MessageBody>, payment: PaymentData },
    Encrypted { encrypted_message: String },  // base64
    PlainText(String),
    Structured(serde_json::Value),
}
```
Parse in this order: check for `message` key (payment wrapper), then for `encryptedMessage` key (encryption), then fall back to plain text. Write unit tests for all four cases before integration testing.

**Warning signs:**
- Messages that include payments always show decryption errors
- `accept_payment` in `PeerPayClient` receives empty/malformed token structs
- `list_messages` tests pass for plain messages but fail for messages sent with `check_permissions: true`

**Phase to address:** Phase 1 (HTTP Core) — get body parsing correct in `list_messages` before implementing the payment path.

---

### Pitfall 8: `listMessagesLite` Missing the `originator` Argument on Decrypt

**What goes wrong:**
`listMessagesLite` in the TS source calls `walletClient.decrypt(...)` without the second `this.originator` argument, while all other decrypt calls in `listMessages` and `listenForLiveMessages` pass `this.originator`. This inconsistency exists in the live TS code. If the Rust implementation treats all wallet calls symmetrically and adds `originator` to `list_messages_lite`'s decrypt call, it may fail in contexts where `originator` affects key derivation. If it omits `originator` to match the TS behavior, it will be inconsistent with the rest of the codebase. The safe choice: match TS behavior exactly (omit originator on `list_messages_lite` decrypt) and document the inconsistency as a known parity issue.

**Why it happens:**
This is a latent TS bug preserved in translation. The developer writing `listMessagesLite` used a local `tryParse` lambda instead of `this.tryParse` and forgot the originator parameter. The Rust translator following the "match behavior exactly" principle should replicate this faithfully.

**How to avoid:**
In the Rust implementation, pass `originator: None` to the wallet decrypt call in `list_messages_lite` even if the rest of the client uses `self.originator`. Add a `// PARITY: matches TS listMessagesLite which omits originator` comment. Track this as a known deviation for future cleanup.

**Warning signs:**
- `list_messages_lite` decryption fails in originator-scoped wallet environments while `list_messages` succeeds
- Different message body content returned by `list_messages_lite` vs `list_messages` for the same message box

**Phase to address:** Phase 1 (HTTP Core) — call this out explicitly in the `list_messages_lite` implementation.

---

### Pitfall 9: `listPermissions` Query Param Uses Snake_case, Not CamelCase

**What goes wrong:**
The `/permissions/list` endpoint uses `message_box` (snake_case) as the query parameter name, not `messageBox`. This is the only endpoint in the entire TS client that uses snake_case in a query string. All others use camelCase. If the Rust client builds query params with a generic camelCase convention, the filter is silently ignored by the server, returning all permissions instead of only those for the requested message box.

**Why it happens:**
The server was implemented by a different team (Go) and the `/permissions/list` endpoint was not harmonized with the rest. The TS code hardcodes `'message_box'` as the key, which makes it easy to miss when scanning for conventions.

**How to avoid:**
Hardcode the query parameter key as `"message_box"` in the `list_message_box_permissions` implementation. Add a test that verifies a permission for box `"notifications"` is returned when filtering with `message_box=notifications` and is excluded when filtering with `message_box=other`.

**Warning signs:**
- `listPeerNotifications` returns permissions for all boxes, not just `notifications`
- Pagination (`limit`/`offset`) appears to work but filtering does not

**Phase to address:** Phase 2 (Permissions) — test the exact query string format against the go-messagebox-server.

---

### Pitfall 10: `getMessageBoxQuote` Requires Identity Key from Response Header

**What goes wrong:**
`getMessageBoxQuote` reads `deliveryAgentIdentityKey` from the `x-bsv-auth-identity-key` response header, not from the JSON body. If the Rust HTTP client does not preserve and expose response headers, this field is always `None`, causing `get_message_box_quote` to throw an error even on successful HTTP 200 responses. The payment path (`createMessagePayment`) then fails, making all fee-based message delivery non-functional.

**Why it happens:**
Developers building HTTP clients often model only the response body, not headers. `reqwest::Response::headers()` is available but requires explicit access. The TS code uses `response.headers.get('x-bsv-auth-identity-key')` — easy to miss when translating the JSON response parsing.

**How to avoid:**
After receiving the HTTP response, extract the header value before consuming the body with `.json()`:
```rust
let identity_key = response
    .headers()
    .get("x-bsv-auth-identity-key")
    .and_then(|v| v.to_str().ok())
    .ok_or_else(|| Error::MissingDeliveryAgentIdentityKey)?;
let data: QuoteResponse = response.json().await?;
```
Add a test that verifies the header is present and the identity key is non-empty.

**Warning signs:**
- `get_message_box_quote` returns `MissingDeliveryAgentIdentityKey` error even when server responds with 200
- Payment-gated message delivery always fails even when recipient has set a fee

**Phase to address:** Phase 2 (Permissions and Payments) — test quote endpoint early in the phase.

---

### Pitfall 11: PeerPayClient's `rejectPayment` Has a 1000-Satoshi Refund Threshold Hardcoded

**What goes wrong:**
`rejectPayment` hardcodes a 1000-satoshi fee deduction and a minimum viable refund of 1000 satoshis. Payments smaller than 2000 satoshis are acknowledged-and-silently-dropped rather than refunded. This is a deliberate TS behavior. A Rust translation that tries to "fix" this or generalize it will diverge from the TS contract. In the 6-node metawatt-demo, agents that receive rejected payments expect this exact behavior.

**How to avoid:**
Match exactly: if `payment.token.amount - 1000 < 1000`, acknowledge and return without refund. Do not make the fee configurable. Document the magic number.

**Warning signs:**
- metawatt-demo agents going into an inconsistent state after a rejected payment for amounts between 1000-1999 sats
- Payment refund amounts differ between TS and Rust agents

**Phase to address:** Phase 3 (PeerPay) — note this explicitly in the `reject_payment` implementation.

---

### Pitfall 12: WebSocket Authentication Uses a 5-Second Blind Timeout

**What goes wrong:**
The TS `initializeConnection` waits exactly 5 seconds after connection, then checks whether an `authenticationSuccess` event was received. This is not a proper promise race — it is a `setTimeout` that resolves or rejects once. If the server authenticates in 4.9 seconds, it works. If it takes 5.1 seconds on a slow network, the connection is rejected as timed out even though it would have succeeded. The Rust translation using `tokio::time::timeout()` wrapping a `oneshot::Receiver<()>` is strictly better, but changes behavior in edge cases. The correct Rust approach is to use `tokio::time::timeout(Duration::from_secs(5), rx.recv())` — this races properly and resolves as soon as auth succeeds rather than always waiting 5 seconds.

**How to avoid:**
Use `tokio::time::timeout(Duration::from_secs(5), auth_rx.await)` where `auth_rx` is a `oneshot::Receiver` completed by the `authenticationSuccess` handler. This is both correct and more efficient than the TS implementation.

**Warning signs:**
- WebSocket connections always take exactly 5 seconds to establish in tests
- Fast local server connections fail because the auth handler fires before the listener is registered

**Phase to address:** Phase 3 (WebSocket) — design the auth handshake using proper async primitives from the start.

---

## Technical Debt Patterns

| Shortcut | Immediate Benefit | Long-term Cost | When Acceptable |
|----------|-------------------|----------------|-----------------|
| Skip multi-host `listMessages` deduplication initially | Simpler implementation | Duplicate messages in overlay environments | Never — the demo uses the overlay |
| Use `serde_json::Value` for entire message body | Avoids modeling envelope variants | No compile-time guarantee on message shape, hard to test | Only for exploratory spike, remove before Phase 1 complete |
| Omit `checkPermissions` flow from `sendMessage` initially | Fewer dependencies on payment infrastructure | Payment-gated boxes silently fail | Acceptable until Phase 2 (Payments) |
| Use `std::sync::Mutex` instead of `tokio::sync::Mutex` | Familiar API | Deadlock under async concurrent callers | Never in async context |
| Model `PeerMessage.body` as `String` only | Avoids enum | Payment-wrapped and structured bodies silently lost | Never — breaks `listMessages` |
| Hardcode `host = "https://messagebox.babbage.systems"` | Faster Phase 1 | Overlay resolution skipped, TS interop broken | Only in unit tests with mock server |

---

## Integration Gotchas

| Integration | Common Mistake | Correct Approach |
|-------------|----------------|------------------|
| AuthFetch HTTP | Call `authFetch.fetch()` directly from `&self` method | Wrap in `Arc<tokio::sync::Mutex<AuthFetch<W>>>`, acquire before call, release before `.await` |
| WalletInterface encrypt/decrypt | Omit `originator` parameter | Pass `self.originator.as_deref()` to every wallet call (except `list_messages_lite` decrypt — match TS) |
| go-messagebox-server response parsing | Use `#[serde(deny_unknown_fields)]` on response types | Allow unknown fields; server may add fields not in TS types |
| Overlay `ls_messagebox` query | Assume all query results are valid advertisements | Wrap PushDrop decode in try/catch equivalent; skip malformed outputs silently |
| BRC-78 encryption `Counterparty` | Pass `Counterparty::Anyone` as default | Use `Counterparty::Self_` when recipient == own identity key, else `Counterparty::PublicKey(recipient)` |
| `getPublicKey` for payment derivation | Use standard protocol ID | Delivery fee uses `[2, '3241645161d8']` — this is the hardcoded BSV wallet payment derivation protocol |
| `createNonce` for PeerPay derivation | Implement custom nonce generation | Use the `create_nonce` function from `bsv-rust-sdk` — matches TS `createNonce(walletClient)` |

---

## Performance Traps

| Trap | Symptoms | Prevention | When It Breaks |
|------|----------|------------|----------------|
| Calling `getIdentityKey()` (wallet round-trip) on every method call | High latency on all operations | Cache identity key after first successful fetch — use `OnceCell<String>` | At >1 message/second |
| Parallel `listMessages` from N hosts with no timeout per host | One slow host blocks the entire call | Use `tokio::time::timeout` per-host fetch, discard timed-out hosts | When any overlay node is slow |
| Serializing large message bodies to UTF-8 twice (HMAC + encrypt) | 2x CPU cost on large bodies | Serialize once, use the bytes for both HMAC and encrypt input | At payload size >100KB |
| No connection pooling for `reqwest::Client` | New TCP connection per message | Share a single `reqwest::Client` across all `AuthFetch` calls | At >10 messages/second |
| Registering new `on("sendMessage-${roomId}")` listener on every `listenForLiveMessages` call | Duplicate callbacks, messages processed N times | Guard with `joinedRooms` HashSet same as TS — check before registering listener | On any reconnect cycle |

---

## Security Mistakes

| Mistake | Risk | Prevention |
|---------|------|------------|
| Logging the `encryptedMessage` base64 field in debug output | Exposes ciphertext to log aggregators | Log only message metadata (sender, messageId, messageBox), never body content |
| Accepting `skipEncryption: true` without validation | Plaintext messages leak message content to the server operator | Only set `skip_encryption` to true when explicitly configured by the caller — never as a default or fallback |
| Using `recipientFee == -1` as a sentinel for "blocked" without explicit check | Fee logic confusion — a fee of -2 or any negative value would not be caught | Always use `fee < 0` for blocked check, or model as `enum PermissionStatus { AlwaysAllow, Blocked, RequiresFee(u64) }` |
| Exposing wallet private key material in error messages | Key compromise | Ensure error types from wallet operations do not include key material; wrap with `Error::Wallet("operation failed")` |

---

## "Looks Done But Isn't" Checklist

- [ ] **`listMessages` multi-host:** Fetches from all advertised hosts, not just `self.host` — verify deduplication logic removes exact-id duplicates
- [ ] **`listMessages` payment unwrap:** Handles `{ message: ..., payment: ... }` wrapper before looking for `encryptedMessage` — verify with a payment-attached message
- [ ] **`getMessageBoxQuote` header extraction:** Reads `x-bsv-auth-identity-key` from response headers before calling `.json()` — verify with a live quote request
- [ ] **`initializeConnection` auth timeout:** Uses `tokio::time::timeout` racing against auth receiver, not a fixed sleep — verify connection completes before 5 seconds elapses
- [ ] **`send_live_message` HTTP fallback:** Falls back to `sendMessage` HTTP when WebSocket ack times out or `socket.connected` is false — verify the fallback path is tested
- [ ] **`list_message_box_permissions` query param:** Sends `message_box=notifications` (snake_case) not `messageBox=notifications` — verify against live server
- [ ] **`anoint_host` idempotency:** Does NOT anoint again when an advertisement already exists for this host — verify existing advertisement detection
- [ ] **`reject_payment` threshold:** Payments under 2000 sats are acknowledged-and-dropped, not refunded — verify the 1000-sat threshold logic
- [ ] **PeerPay `createPaymentToken` nonce:** Uses `create_nonce(wallet)` from the SDK, not a raw random byte generator — verify nonce format matches TS
- [ ] **`listenForLiveMessages` room guard:** Does not re-register the `on("sendMessage-${roomId}")` handler if already joined — verify with reconnect scenario
- [ ] **Encryption counterparty for self-messages:** Uses `Counterparty::Self_` when sender == recipient — verify this case explicitly
- [ ] **`listMessagesLite` originator:** Deliberately passes `None` for originator on decrypt to match TS behavior — documented as intentional parity choice

---

## Recovery Strategies

| Pitfall | Recovery Cost | Recovery Steps |
|---------|---------------|----------------|
| Wrong mutex type causes deadlock | HIGH | Audit every `.lock()` call site, replace `std::sync::Mutex` with `tokio::sync::Mutex`, re-run concurrent tests |
| Encryption format mismatch discovered post-deploy | HIGH | Add interop test against known-good TS client immediately; fix base64 encoding and re-test cross-language decrypt |
| Ack listener accumulation causes memory growth | MEDIUM | Replace per-message `on/off` pattern with `DashMap<ack_event, oneshot::Sender>` pattern; restart affected agent process |
| Multi-host deduplication skipped | MEDIUM | Add deduplication pass to `list_messages` return path; verify no behavioral regression on single-host setups |
| Init guard allows duplicate anointing | LOW | Delete duplicate advertisement tokens using `revoke_host_advertisement`; add `OnceCell` guard |
| `message_box` vs `messageBox` query param | LOW | Fix the one hardcoded key in `list_message_box_permissions`; integration test confirms |

---

## Pitfall-to-Phase Mapping

| Pitfall | Prevention Phase | Verification |
|---------|------------------|--------------|
| AuthFetch mutability / mutex choice | Phase 1 (HTTP Core) | Concurrent `send_message` stress test with 2+ tasks |
| Encryption format interop | Phase 1 (HTTP Core) | Cross-language test: Rust encrypts, TS decrypts |
| HTTP method vs query param shape | Phase 1 (HTTP Core) | Integration test each endpoint against go-messagebox-server |
| Lazy init race condition | Phase 1 (HTTP Core) | Concurrent init test with `tokio::join!` |
| Payment body dual-envelope parsing | Phase 1 (HTTP Core) | Unit test `list_messages` with payment-wrapped message fixture |
| `listMessages` multi-host deduplication | Phase 1 (HTTP Core) | Mock two hosts returning overlapping message sets |
| `listMessagesLite` originator omission | Phase 1 (HTTP Core) | Parity note in implementation; originator-scoped wallet test |
| `message_box` snake_case query param | Phase 2 (Permissions) | Integration test filter against live server |
| `getMessageBoxQuote` header extraction | Phase 2 (Permissions/Payments) | Test quote endpoint, assert `delivery_agent_identity_key` is populated |
| PeerPay 1000-sat refund threshold | Phase 3 (PeerPay) | Unit test `reject_payment` at 999, 1000, 1999, 2000 sat amounts |
| WebSocket ack listener accumulation | Phase 3 (WebSocket) | Send 100 messages with mocked timeout; assert no listener growth |
| WebSocket 5-second auth blind timeout | Phase 3 (WebSocket) | Assert connection completes <100ms on localhost, not always 5000ms |

---

## Sources

- Direct inspection: `/Users/elisjackson/Projects/draigfi-sdk/node_modules/@bsv/message-box-client/src/MessageBoxClient.ts` (2,272 lines, v1.3.0)
- Direct inspection: `/Users/elisjackson/Projects/draigfi-sdk/node_modules/@bsv/message-box-client/src/PeerPayClient.ts` (395 lines, v1.3.0)
- Direct inspection: `/Users/elisjackson/Projects/draigfi-sdk/node_modules/@bsv/message-box-client/src/types.ts` and `types/permissions.ts`
- Project context: `.planning/PROJECT.md` (SDK constraint details, known risk areas)
- Known SDK constraints from research: `AuthFetch::fetch(&mut self)`, `Counterparty` enum variants, `Protocol` struct shape

---

*Pitfalls research for: TS-to-Rust BSV MessageBox client translation*
*Researched: 2026-03-26*
