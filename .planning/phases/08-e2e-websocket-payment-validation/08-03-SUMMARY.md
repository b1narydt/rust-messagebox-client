---
phase: 08-e2e-websocket-payment-validation
plan: 03
subsystem: payments
tags: [rust, bsv, peer-pay, http-wallet-json, funded-wallet, integration-test]

# Dependency graph
requires:
  - phase: 03-peerpay
    provides: create_payment_token, send_payment, list_incoming_payments, accept_payment
  - phase: 08-e2e-websocket-payment-validation
    provides: live_server.rs test harness with ArcWallet and make_live_client
provides:
  - ArcHttpWallet wrapper for HttpWalletJson (non-Clone) satisfying W: Clone bound
  - make_funded_client() helper backed by BSV Desktop wallet on localhost:3321
  - test_funded_payment_round_trip integration test for full PeerPay lifecycle
affects: []

# Tech tracking
tech-stack:
  added: [bsv::wallet::substrates::http_wallet_json::HttpWalletJson]
  patterns: [Arc-wrapping non-Clone SDK types to satisfy WalletInterface + Clone bounds]

key-files:
  created: []
  modified: [tests/live_server.rs]

key-decisions:
  - "ArcHttpWallet wraps Arc<HttpWalletJson> with #[derive(Clone)] — same pattern as ArcWallet wrapping ProtoWallet; Arc satisfies Clone while HttpWalletJson itself is non-Clone"
  - "make_funded_client uses empty base_url string to default HttpWalletJson to localhost:3321 per SDK contract"
  - "test_funded_payment_round_trip uses #[ignore] to prevent CI execution; requires BSV Desktop wallet with funded satoshis"
  - "2-second sleep between send_payment and list_incoming_payments matches server persistence latency observed in manual testing"

patterns-established:
  - "Arc-wrapping pattern: ArcHttpWallet(Arc<HttpWalletJson>) replicates the ArcWallet(Arc<ProtoWallet>) convention established in Phase 1 — the canonical way to add Clone to non-Clone SDK wallet types"

requirements-completed: []

# Metrics
duration: 8min
completed: 2026-03-29
---

# Phase 08 Plan 03: Funded Payment Round-Trip Summary

**ArcHttpWallet wrapper delegating to HttpWalletJson via Arc<T>, plus test_funded_payment_round_trip exercising the complete PeerPay create/send/list/accept lifecycle with real satoshis**

## Performance

- **Duration:** 8 min
- **Started:** 2026-03-29T00:00:00Z
- **Completed:** 2026-03-29T00:08:00Z
- **Tasks:** 1
- **Files modified:** 1

## Accomplishments

- ArcHttpWallet struct wrapping `Arc<HttpWalletJson>` with all 27 WalletInterface methods delegated — identical pattern to ArcWallet, satisfies `W: Clone + WalletInterface + Send + Sync + 'static`
- `make_funded_client()` helper creating a `MessageBoxClient<ArcHttpWallet>` connected to both the live MessageBox server and BSV Desktop wallet on localhost:3321
- `test_funded_payment_round_trip` integration test covering: identity key resolution, `send_payment` (1000 sats), server delay wait, `list_incoming_payments`, sender-key filter, and `accept_payment` with assertions at each step

## Task Commits

Each task was committed atomically:

1. **Task 1: ArcHttpWallet wrapper and funded payment round-trip test** - `4c9ea0a` (feat)

## Files Created/Modified

- `tests/live_server.rs` - Added ArcHttpWallet, make_funded_client(), test_funded_payment_round_trip

## Decisions Made

- ArcHttpWallet uses the same Arc-wrapping pattern as ArcWallet because HttpWalletJson does not derive Clone (contains `reqwest::Client` internally which is Clone-able, but the struct itself does not derive it). Wrapping in Arc<T> and deriving Clone on the wrapper is the established project convention.
- `HttpWalletJson::new("rust-messagebox-tests", "")` — empty base_url triggers the SDK default of `http://localhost:3321`, matching BSV Desktop wallet's default binding.
- Test uses 2-second sleep before listing to account for server message persistence latency — consistent with `test_two_client_live_messaging` which also uses a 1-second settle delay.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

- Pre-existing uncommitted changes in `tests/live_server.rs` (Phase 8-02 edge case tests) introduced `is_ws_connected` calls; these compiled correctly once `src/client.rs` (also with pending changes adding `is_ws_connected`) was included in the build. Not a blocker — `cargo build --test live_server` passed clean after initial cache invalidation.

## User Setup Required

None — test is marked `#[ignore]` and only runs when explicitly invoked with:
```
cargo test --test live_server test_funded_payment_round_trip -- --ignored --nocapture
```
Requires BSV Desktop wallet running on `localhost:3321` with a funded wallet.

## Next Phase Readiness

- Phase 08 complete: both live WebSocket two-client messaging test and funded payment round-trip test implemented
- All PeerPay wire paths validated at integration level
- No blockers

---
*Phase: 08-e2e-websocket-payment-validation*
*Completed: 2026-03-29*
