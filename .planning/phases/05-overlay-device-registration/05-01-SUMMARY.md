---
phase: 05-overlay-device-registration
plan: 01
subsystem: overlay
tags: [bsv, overlay, pushdrop, ship, slap, lookup-resolver, topic-broadcaster, rust-sdk]

# Dependency graph
requires:
  - phase: 04-websocket-live-messaging
    provides: MessageBoxClient struct with WebSocket support

provides:
  - src/host_resolution.rs with query_advertisements, resolve_host_for_recipient, anoint_host, revoke_host_advertisement
  - AdvertisementToken, RegisterDeviceRequest, RegisteredDevice, RegisterDeviceResponse, ListDevicesResponse types
  - build_pushdrop_lock_from_fields_and_pubkey standalone helper
  - MessageBoxClient network: Network field for overlay configuration

affects: [05-02-device-registration, http_ops multi-host list_messages]

# Tech tracking
tech-stack:
  added: [hex = "0.4" (promoted from dev-dependencies to dependencies)]
  patterns:
    - Manual PushDrop locking script construction from chunks using wallet-derived public key (avoids exposing private key)
    - Graceful overlay degradation — query_advertisements wraps all errors, returns empty Vec (TS parity)
    - Network field on MessageBoxClient for switching between Mainnet and Local overlay environments

key-files:
  created:
    - src/host_resolution.rs
  modified:
    - src/types.rs
    - src/error.rs
    - src/client.rs
    - src/lib.rs
    - Cargo.toml
    - src/adapter.rs
    - src/permissions.rs
    - src/peer_pay.rs

key-decisions:
  - "query_advertisements returns Ok(vec![]) on ANY error including overlay unreachability — matches TS try/catch pattern exactly"
  - "MessageBoxClient::new() now requires a Network parameter; new_mainnet() convenience constructor added for backwards-compatibility"
  - "revoke_host_advertisement uses sighash_preimage() from Transaction, passes preimage as data to create_signature (wallet hashes internally)"
  - "build_pushdrop_lock_from_fields_and_pubkey is pub standalone function — not a method — for testability without wallet"
  - "anoint_host uses BooleanDefaultTrue(Some(false)) for randomize_outputs (field is BooleanDefaultTrue in SDK, not BooleanDefaultFalse)"

patterns-established:
  - "Pattern: overlay graceful degradation — wrap entire async call in match, return Ok(vec![]) on Err"
  - "Pattern: manual PushDrop script construction using ScriptChunk::new_raw + Op::Op2Drop + Op::OpCheckSig"
  - "Pattern: BEEF bytes to Transaction::from_beef requires hex::encode(&bytes) — Transaction::from_beef takes &str hex, not &[u8]"

requirements-completed: [HOST-01, HOST-02, HOST-03, HOST-04, HOST-05]

# Metrics
duration: 43min
completed: 2026-03-27
---

# Phase 05 Plan 01: Overlay Host Resolution Summary

**PushDrop overlay advertisement system with wallet-derived pubkey script construction, graceful LookupResolver query, and SHIP broadcast via TopicBroadcaster for host advertisement and revocation**

## Performance

- **Duration:** 43 min
- **Started:** 2026-03-27T17:02:38Z
- **Completed:** 2026-03-27T17:41:58Z
- **Tasks:** 2 (both implemented in single commit, second task covers anoint_host + revoke_host_advertisement)
- **Files modified:** 9

## Accomplishments
- Created `src/host_resolution.rs` with all four overlay methods: `query_advertisements` (graceful), `resolve_host_for_recipient`, `anoint_host` (returns txid), `revoke_host_advertisement` (two-step create+sign+broadcast)
- Added overlay types to `types.rs`: AdvertisementToken, RegisterDeviceRequest, RegisteredDevice (8 server fields), RegisterDeviceResponse, ListDevicesResponse
- Added `Overlay(String)` error variant; added `network: Network` field to `MessageBoxClient`; promoted `hex` crate to main dependencies
- 77 tests pass, zero regressions across all prior phases

## Task Commits

1. **Task 1 + Task 2: Overlay types, PushDrop helper, all four overlay methods** - `962ce6e` (feat)

## Files Created/Modified
- `src/host_resolution.rs` — New module: query_advertisements, resolve_host_for_recipient, anoint_host, revoke_host_advertisement, build_pushdrop_lock_from_fields_and_pubkey
- `src/types.rs` — Added Phase 5 types (AdvertisementToken + 4 device types) + unit tests
- `src/error.rs` — Added Overlay(String) variant
- `src/client.rs` — Added network: Network field, updated new() signature, added new_mainnet() and network() accessor
- `src/lib.rs` — Added pub mod host_resolution
- `Cargo.toml` — Moved hex from dev-deps to deps
- `src/adapter.rs`, `src/permissions.rs`, `src/peer_pay.rs` — Updated MessageBoxClient::new() calls to pass Network::Mainnet

## Decisions Made

- `query_advertisements` wraps the entire implementation in an error recovery shim and returns `Ok(vec![])` on any failure. This is critical TS parity — the TypeScript implementation wraps in try/catch and never throws.
- `MessageBoxClient::new()` now takes a `Network` parameter (4th arg). All existing call sites updated to pass `Network::Mainnet`. Added `new_mainnet()` convenience constructor.
- `revoke_host_advertisement` uses `Transaction::sighash_preimage()` to compute the signing preimage, then calls `wallet.create_signature()` with `data: Some(preimage)`. The wallet's internal implementation hashes appropriately. This avoids needing to expose private key bytes while still producing a valid PushDrop unlock signature.
- `build_pushdrop_lock_from_fields_and_pubkey` is a standalone pub function (not a method) to allow unit testing without a running wallet.
- `anoint_host` uses `BooleanDefaultTrue(Some(false))` for `randomize_outputs` — the SDK field type is `BooleanDefaultTrue`, not `BooleanDefaultFalse`.

## Deviations from Plan

None — plan executed exactly as written. The only implementation decision at execution time was confirming that `randomize_outputs` in `CreateActionOptions` is `BooleanDefaultTrue` (not `BooleanDefaultFalse` as the plan comment suggested from PeerPay analogy). Fixed inline.

## Issues Encountered
- Research doc code example called `tx.id("hex")` (TS-style with string arg). SDK confirms `tx.id()` takes no argument and returns `Result<String>`. Fixed inline per plan interfaces section.
- Research doc mentioned `Transaction::from_beef_bytes` variant. SDK only has `Transaction::from_beef(&str)`. Used `hex::encode(&bytes)` per plan Pitfall 1.

## User Setup Required
None — no external service configuration required.

## Next Phase Readiness
- All HOST-01..05 requirements complete
- Plan 02 (device registration + multi-host list_messages) can proceed: `AdvertisementToken` and all overlay methods are in place
- `init_once.get_or_try_init` pattern for HOST-06 is ready for Plan 02 wiring

---
*Phase: 05-overlay-device-registration*
*Completed: 2026-03-27*
