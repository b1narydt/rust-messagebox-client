# Stack Research

**Domain:** Rust async client library — BSV blockchain authenticated messaging (TS→Rust translation)
**Researched:** 2026-03-26
**Confidence:** HIGH

## Recommended Stack

### Core Technologies

| Technology | Version | Purpose | Why Recommended |
|------------|---------|---------|-----------------|
| `bsv` (bsv-rust-sdk) | git `b1narydt/bsv-rust-sdk` | BRC-31 auth, HTTP, WebSocket, wallet interface, HMAC, CommsLayer trait | The primary dependency — provides AuthFetch, WebSocketTransport, WalletInterface (including create_hmac), CommsLayer trait, PeerMessage, RemittanceError. All crypto operations delegate to the wallet; no separate hmac/sha2 crates needed. |
| `tokio` | 1.50.0 | Async runtime | Already required by bsv-rust-sdk's network feature. The SDK uses tokio throughout; using a different runtime would cause conflicts. |
| `serde` | 1.x | Serialization/deserialization | Already a bsv-rust-sdk dependency. Needed for request/response structs and JSON wire format. |
| `serde_json` | 1.x | JSON encoding/decoding | Already a bsv-rust-sdk dependency. Used for HTTP request bodies and response parsing. |

### Supporting Libraries

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `base64` | 0.22.1 | Encode/decode encrypted message bodies | Required. The JSON wire format wraps ciphertext as `{"encryptedMessage": "<base64>"}`. The SDK does not re-export a base64 API. Use `base64::engine::general_purpose::STANDARD` engine. |
| `async-trait` | 0.1.x | Async trait methods | Already a bsv-rust-sdk dependency. Required if this crate defines its own async traits or exposes the CommsLayer implementation as a public trait object. |
| `thiserror` | 2.0.x | Error type derivation | Already a bsv-rust-sdk dependency. Use for `MessageBoxError` enum. Consistent with SDK error style. |

### Development Tools

| Tool | Purpose | Notes |
|------|---------|-------|
| `wiremock` | 0.6.5 | Async HTTP mock server for integration tests | Already used by bsv-rust-sdk dev-deps (same version). Fully async, tokio-compatible, supports parallel test execution with isolated mock servers on random ports. |
| `tokio-test` | 0.4.5 | Testing utilities for tokio async code | Provides `assert_ready!`, `assert_pending!`, block_on helpers. Lighter weight than spinning up a full tokio runtime in each test. |
| `hex` | 0.4.3 | Hex encoding in test assertions | Already a bsv-rust-sdk dev-dep. Needed when asserting on HMAC-derived message IDs (which are hex strings). |

## Installation

```toml
[dependencies]
bsv = { git = "https://github.com/b1narydt/bsv-rust-sdk", features = ["network"] }
tokio = { version = "1", features = ["rt-multi-thread", "macros", "sync", "time"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
base64 = "0.22"
async-trait = "0.1"
thiserror = "2"

[dev-dependencies]
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
wiremock = "0.6"
tokio-test = "0.4"
hex = "0.4"
```

## Alternatives Considered

| Recommended | Alternative | When to Use Alternative |
|-------------|-------------|-------------------------|
| `base64` 0.22 | `base64ct` (constant-time) | Only if timing-attack resistance on the encoded output matters. For message bodies this is not a security requirement — the ciphertext itself is already encrypted. |
| `thiserror` 2.0 | `anyhow` | Use `anyhow` only in binary crates (applications). This is a library crate; `thiserror` gives typed errors that downstream consumers can match on. |
| `wiremock` 0.6.5 | `mockito` | `mockito` works but uses a global server state by default (though async API exists). `wiremock` is fully isolated per-test — better for concurrent test suites. |
| WalletInterface::create_hmac | `hmac` + `sha2` crates | Never use external hmac/sha2 for message ID generation. The TS client delegates to walletClient.createHmac(), which binds the HMAC to the BRC-31 identity protocol — using raw HMAC would produce different (incompatible) message IDs. |
| String format! for URLs | `url` crate | The TS client uses plain string interpolation (`${host}/sendMessage`). The `url` crate adds complexity and a ~200KB dependency for no gain when host strings are already validated at construction time. |

## What NOT to Use

| Avoid | Why | Use Instead |
|-------|-----|-------------|
| `hmac` + `sha2` crates for message IDs | Breaking interop. The TS client calls `walletClient.createHmac()` which uses the BRC-31 protocol context (`[1, "messagebox"]`, key ID `"1"`) to derive identity-bound HMACs. Raw HMAC would produce wrong message IDs and break deduplication across TS/Rust clients on the same server. | `WalletInterface::create_hmac()` from bsv-rust-sdk |
| `sha2` 0.11.0 | Brand new (released 2026-03-25), requires `digest` 0.11, which is incompatible with `hmac` 0.12.1 (requires `digest ^0.10.3`). The whole RustCrypto ecosystem hasn't migrated yet. Moot anyway since we use the wallet for HMAC. | N/A — HMAC goes through WalletInterface |
| `reqwest` as a direct dependency | The SDK's `AuthFetch` wraps reqwest internally. Adding reqwest directly risks version conflicts if the SDK bumps its reqwest version. | Use `AuthFetch` from bsv-rust-sdk exclusively |
| `ring` crate | Brings in a C/assembly build dependency, complicates cross-compilation, and is unnecessary when the SDK already handles all cryptographic operations. | WalletInterface crypto methods |
| `tokio-tungstenite` as a direct dependency | The SDK's `WebSocketTransport` already handles authenticated WebSocket connections with exponential-backoff reconnect (348 lines). Duplicating this would diverge from SDK behavior. | `WebSocketTransport` from bsv-rust-sdk |
| `uuid` crate | Message IDs come from HMAC derivation via the wallet (hex-encoded 32 bytes). The TS client never uses UUIDs — adding this would break wire format compatibility. | WalletInterface::create_hmac() → hex string |

## Stack Patterns by Variant

**For the core HTTP messaging layer (Phase 1):**
- Use `AuthFetch` from the SDK directly — do not construct raw `reqwest::Client`
- Wrap `AuthFetch<W>` in `Arc<Mutex<AuthFetch<W>>>` because `fetch()` takes `&mut self`
- Serialize request bodies with `serde_json::to_string()`, parse responses with `serde_json::from_str()`

**For encrypted message transport:**
- Call `wallet.encrypt()` → get `Vec<u8>` ciphertext
- Encode to base64 with `base64::engine::general_purpose::STANDARD.encode(&ciphertext)`
- Wrap as `serde_json::json!({"encryptedMessage": base64_string})` — this is the exact wire format from TS
- On receive: decode with `STANDARD.decode(encrypted_message_str)?` → pass `Vec<u8>` to `wallet.decrypt()`

**For WebSocket live messaging (Phase 3):**
- Use SDK's `WebSocketTransport` — handles BRC-31 auth handshake and reconnect
- Room ID format matches TS: `"{identity_key}-{message_box}"` (plain string concat)

## Version Compatibility

| Package | Compatible With | Notes |
|---------|-----------------|-------|
| `bsv` git dep (network feature) | `tokio = "1"`, `reqwest = "0.12"`, `tokio-tungstenite = "0.24"`, `serde = "1"`, `serde_json = "1"`, `async-trait = "0.1"`, `thiserror = "2.0"` | These are re-used from the SDK's own deps — Cargo will deduplicate them automatically |
| `base64 = "0.22"` | No conflicts — not used by bsv-rust-sdk | Safe to add independently |
| `wiremock = "0.6"` | Dev-dep only — matches bsv-rust-sdk dev-dep version | Same version avoids duplicate wiremock in the dep graph |

## Sources

- `https://raw.githubusercontent.com/b1narydt/bsv-rust-sdk/main/Cargo.toml` — SDK dependency list verified (HIGH confidence)
- `https://raw.githubusercontent.com/b1narydt/bsv-rust-sdk/main/src/wallet/interfaces.rs` — WalletInterface::create_hmac confirmed (HIGH confidence)
- `https://raw.githubusercontent.com/b1narydt/bsv-rust-sdk/main/src/primitives/hash.rs` — SDK implements HMAC internally from RFC 2104; no external hmac/sha2 crates (HIGH confidence)
- `https://docs.rs/crate/base64/latest` — base64 0.22.1 confirmed latest stable (HIGH confidence)
- `https://lib.rs/crates/sha2` — sha2 0.11.0 released 2026-03-25, requires digest 0.11 (HIGH confidence)
- `https://docs.rs/hmac/0.12.1/hmac/` — hmac 0.12.1 requires digest ^0.10.3, incompatible with sha2 0.11.0 (HIGH confidence)
- `https://docs.rs/crate/wiremock/latest` — wiremock 0.6.5 latest stable (HIGH confidence)
- `https://docs.rs/crate/tokio/latest` — tokio 1.50.0 latest stable (HIGH confidence)
- `https://docs.rs/crate/uuid/latest` — uuid 1.22.0 verified, explicitly ruled out (HIGH confidence)
- Local TS source: `node_modules/@bsv/message-box-client/src/MessageBoxClient.ts` — base64/HMAC usage patterns verified (HIGH confidence)

---
*Stack research for: BSV MessageBox Client (Rust) — TS→Rust translation, Rust 2021 edition*
*Researched: 2026-03-26*
