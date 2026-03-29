---
gsd_state_version: 1.0
milestone: v1.3
milestone_name: milestone
status: executing
stopped_at: Completed 08-e2e-websocket-payment-validation 08-03-PLAN.md
last_updated: "2026-03-29T19:32:15.651Z"
last_activity: 2026-03-26 — Plan 01-01 executed (crate scaffolding + encryption)
progress:
  total_phases: 8
  completed_phases: 7
  total_plans: 19
  completed_plans: 16
  percent: 50
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-03-26)

**Core value:** Rust applications can send, receive, and manage BRC-31 authenticated messages with full parity to the TypeScript @bsv/message-box-client
**Current focus:** Phase 1 — HTTP Core + Foundation

## Current Position

Phase: 1 of 6 (HTTP Core + Foundation)
Plan: 1 of 2 in current phase (01-01-PLAN.md complete)
Status: In progress
Last activity: 2026-03-26 — Plan 01-01 executed (crate scaffolding + encryption)

Progress: [█████░░░░░] 50%

## Performance Metrics

**Velocity:**
- Total plans completed: 0
- Average duration: -
- Total execution time: 0 hours

**By Phase:**

| Phase | Plans | Total | Avg/Plan |
|-------|-------|-------|----------|
| - | - | - | - |

**Recent Trend:**
- Last 5 plans: n/a
- Trend: n/a

*Updated after each plan completion*
| Phase 01-http-core-foundation P01 | 6min | 2 tasks | 5 files |
| Phase 01-http-core-foundation P02 | 5min | 2 tasks | 3 files |
| Phase 02-commslayer-adapter-permissions P01 | 4min | 2 tasks | 4 files |
| Phase 02-commslayer-adapter-permissions P02 | 5min | 2 tasks | 3 files |
| Phase 03-peerpay P01 | 3min | 2 tasks | 3 files |
| Phase 03-peerpay P02 | 8min | 2 tasks | 2 files |
| Phase 04-websocket-live-messaging P04-01 | 4 | 2 tasks | 6 files |
| Phase 04-websocket-live-messaging P04-02 | 1 | 2 tasks | 2 files |
| Phase 05-overlay-device-registration P01 | 43 | 2 tasks | 9 files |
| Phase 05-overlay-device-registration P02 | 5 | 3 tasks | 6 files |
| Phase 06-parity-verification PP01 | 8 | 2 tasks | 7 files |
| Phase 06-parity-verification P02 | 25 | 2 tasks | 5 files |
| Phase 06-parity-verification P06-03 | 6 | 2 tasks | 1 files |
| Phase 07-brc-103-websocket-auth-transport P01 | 10 | 1 tasks | 2 files |
| Phase 07-brc-103-websocket-auth-transport P02 | 4 | 2 tasks | 2 files |
| Phase 08-e2e-websocket-payment-validation P03 | 8 | 1 tasks | 1 files |

## Accumulated Context

### Decisions

Decisions are logged in PROJECT.md Key Decisions table.
Recent decisions affecting current work:

- [Pre-phase]: Use `tokio::sync::Mutex<AuthFetch<W>>` — std mutex deadlocks across .await; this is load-bearing and cannot be retrofitted
- [Pre-phase]: Encryption must use protocol `[1, "messagebox"]`, keyID `"1"`, base64 STANDARD (with padding) — any deviation causes silent TS interop failure
- [Pre-phase]: `RemittanceAdapter<W>` wraps `Arc<MessageBoxClient<W>>` via composition — not TS-style inheritance
- [Phase 01-http-core-foundation]: Package name is bsv-sdk in Cargo.toml (not bsv); lib crate name bsv so use bsv:: paths unchanged
- [Phase 01-http-core-foundation]: MessageBoxError uses Wallet(String)/Auth(String) variants (not From<WalletError>) to decouple from SDK internals
- [Phase 01-http-core-foundation]: generate_message_id uses serde_json::to_string(body) to replicate TS JSON.stringify for HMAC parity
- [Phase 01-http-core-foundation]: ProtoWallet has no Clone impl — ArcWallet test helper wraps Arc<ProtoWallet> to satisfy W: Clone bound on MessageBoxClient
- [Phase 01-http-core-foundation]: init_once field retained with #[allow(dead_code)] — Phase 5 overlay init will use it; removing now causes breaking struct change
- [Phase 02-commslayer-adapter-permissions]: MessageBoxPermission uses per-field serde alias to accept both camelCase (/get) and snake_case (/list) server responses in one struct
- [Phase 02-commslayer-adapter-permissions]: MessageBoxQuote has no serde annotations — constructed manually from wrapped JSON body and x-bsv-auth-identity-key response header
- [Phase 02-commslayer-adapter-permissions]: get_json and check_status_error use allow(dead_code) as intentional pre-built infrastructure for permissions.rs in plan 02-02
- [Phase 02-commslayer-adapter-permissions]: list_message_box_permissions uses snake_case message_box query param — unique Pitfall 1 endpoint
- [Phase 02-commslayer-adapter-permissions]: get_message_box_quote reads x-bsv-auth-identity-key from response header, not JSON body
- [Phase 02-commslayer-adapter-permissions]: AuthFetch BRC-31 handshake incompatible with wiremock — integration tests validate mapping logic at struct layer
- [Phase 03-peerpay]: outputIndex is None at creation, defaulted to 0 at accept time (TS parity)
- [Phase 03-peerpay]: accept_payment uses .as_bytes().to_vec() for derivation prefix/suffix (not base64)
- [Phase 03-peerpay]: reject_payment threshold at 2000 satoshis with double-ack pattern for TS parity
- [Phase 03-peerpay]: Server delivery-fee internalization is best-effort — errors silently ignored matching TS try/catch behavior
- [Phase 03-peerpay]: ServerPaymentOutput fields are all Option to handle partial/malformed server delivery-fee data gracefully
- [Phase 04-websocket-live-messaging]: Decryption in on_any callback (not tokio::spawn) preserves message ordering via rust_socketio internal mutex serialization
- [Phase 04-websocket-live-messaging]: split_room_id uses 66-char hex key boundary — compressed pubkeys are always 66 hex chars, unambiguous even with hyphens in mb names
- [Phase 04-websocket-live-messaging]: auth_tx wrapped in Arc<Mutex<Option>> — on_any is FnMut not FnOnce, oneshot::Sender is non-Clone, take() ensures exactly-once delivery
- [Phase 04-websocket-live-messaging]: send_live_message and listen_for_live_messages ignore host_override in RemittanceAdapter — multi-host deferred to Phase 5
- [Phase 04-websocket-live-messaging]: listen_for_live_payments wraps PeerMessage callback with PaymentToken JSON parsing; silently skips non-payment messages matching TS safeParse behavior
- [Phase 05-overlay-device-registration]: query_advertisements returns Ok(vec![]) on ANY error including overlay unreachability — matches TS try/catch pattern exactly
- [Phase 05-overlay-device-registration]: MessageBoxClient::new() now requires a Network parameter (4th arg); new_mainnet() convenience constructor added
- [Phase 05-overlay-device-registration]: revoke_host_advertisement uses sighash_preimage() + wallet.create_signature(data=preimage) to avoid exposing private key while producing valid PushDrop unlock
- [Phase 05-overlay-device-registration]: send_message splits into public send_message (overlay host resolution) + pub(crate) send_message_to_host (explicit host) — preserves public API while enabling adapter host_override passthrough
- [Phase 05-overlay-device-registration]: list_messages deduplicates via dedup_messages(HashMap) across concurrent join_all per-host results — single-host path skips dedup overhead
- [Phase 06-parity-verification]: get_joined_rooms uses blocking_lock — acceptable for sync test context; lock never held across await
- [Phase 06-parity-verification]: init(target_host) ignores param currently — assert_initialized always uses self.host for anoint; target_host reserved for future use
- [Phase 06-parity-verification]: send_live_message override_host applies to HTTP fallback path only — WS always connects to self.host()
- [Phase 06-parity-verification]: MessagePayment wire type uses [1, messagebox] protocol/keyID — distinct from PeerPay [2, 3241645161d8]
- [Phase 06-parity-verification]: acknowledge_message requires override_host: Option<&str> second param; None triggers multi-host fan-out via overlay advertisements
- [Phase 06-parity-verification]: acknowledge_notification composes accept_payment (PeerPay) + acknowledge_message — notification bodies carry PaymentToken not server WrappedMessageBody
- [Phase 06-parity-verification]: size_of_val pattern for async method compile-checks avoids fn pointer lifetime issues
- [Phase 06-parity-verification]: get_joined_rooms() uses blocking_lock; must only be called from sync test context, not async #[tokio::test]
- [Phase 06-parity-verification]: test_socket() cfg(test) gating applies to library unit tests only, not integration test crates
- [Phase 07-brc-103-websocket-auth-transport]: SocketIOTransport::new takes already-built Client + Receiver — avoids owning ClientBuilder; Sender captured in on('authMessage') callback during ClientBuilder setup in Plan 02
- [Phase 07-brc-103-websocket-auth-transport]: subscribe() panics via expect() on second call per SDK contract — create fresh SocketIOTransport on reconnect rather than reusing instance
- [Phase 07-brc-103-websocket-auth-transport]: PeerCommand channel for type erasure: MessageBoxWebSocket has no W generic param; Peer<W> owned by background task, accessed via PeerCommand::SendMessage
- [Phase 07-brc-103-websocket-auth-transport]: general_msg_dispatcher is primary path for all application events (confirmed by TS source); on_any handlers are defensive fallbacks only
- [Phase 07-brc-103-websocket-auth-transport]: reconnect(false) in ClientBuilder: BRC-103 requires fresh Peer + Transport on reconnect; transparent reconnect deferred to Phase 8
- [Phase 08-e2e-websocket-payment-validation]: ArcHttpWallet wraps Arc<HttpWalletJson> — HttpWalletJson is non-Clone; Arc-wrapping is the established project convention for adding Clone to non-Clone SDK wallet types

### Roadmap Evolution

- Phase 7 added: BRC-103 WebSocket Auth Transport — build SocketIOTransport implementing SDK Transport trait, wire Peer-based mutual auth into websocket.rs, replace raw event emitting with signed authMessage envelopes
- Phase 8 added: E2E WebSocket + Payment Validation — two-client live messaging test and funded payment round-trip research

### Pending Todos

None yet.

### Blockers/Concerns

- [Phase 3]: `create_nonce` module path in `bsv-rust-sdk` not confirmed — verify before Phase 3 planning
- [Phase 5]: `TopicBroadcaster` broadcast API and SHIP topic constants not fully inspected — verify before Phase 5 planning
- [Phase 5]: `LookupResolver` `ls_messagebox` service name needs confirmation against latest SDK source

## Session Continuity

Last session: 2026-03-29T19:32:15.648Z
Stopped at: Completed 08-e2e-websocket-payment-validation 08-03-PLAN.md
Resume file: None
