---
phase: 03-peerpay
plan: "02"
subsystem: payments
tags: [rust, bsv, peerpay, internalization, serde, integration-tests]

# Dependency graph
requires:
  - phase: 03-01
    provides: PaymentToken, IncomingPayment, PaymentCustomInstructions types in src/types.rs
  - phase: 02-01
    provides: list_messages_lite, post_json, check_status_error in src/http_ops.rs

provides:
  - list_messages method returning Vec<PeerMessage> with auto payment internalization
  - WrappedMessageBody and ServerPayment helper types for server delivery fee parsing
  - 6 integration tests covering PaymentToken wire format and safeParse behavior

affects:
  - Phase 04 (any phase using CommsLayer list_messages)
  - Phase 05 (overlay integration that relies on full message retrieval)

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Server payment wrapper parsed defensively — internalization errors are ignored (TS try/catch parity)"
    - "WrappedMessageBody type distinguishes server delivery-fee wrapper from plain bodies"
    - "get_identity_key() called once before loop to populate PeerMessage.recipient for all messages"

key-files:
  created: []
  modified:
    - src/http_ops.rs
    - tests/integration.rs

key-decisions:
  - "Server delivery-fee internalization is best-effort — errors are silently ignored matching TS try/catch behavior"
  - "WrappedMessageBody is pub(crate) so unit tests can import it via super::WrappedMessageBody"
  - "ServerPaymentOutput fields are all Option to handle partial/malformed server data gracefully"
  - "test_accept_payment_derivation_args guards Pitfall 3: derivation bytes are raw UTF-8, not base64-decoded"

patterns-established:
  - "Defensive parsing: try serde_json::from_str as wrapper; if fails, treat as plain body"
  - "integration tests use serde round-trip to verify wire format without HTTP calls"

requirements-completed: [HTTP-02, TEST-06]

# Metrics
duration: 8min
completed: 2026-03-27
---

# Phase 03 Plan 02: list_messages with PeerPay Integration Tests Summary

**list_messages returning Vec<PeerMessage> with server delivery-fee auto-internalization and 6 PeerPay wire-format integration tests**

## Performance

- **Duration:** 8 min
- **Started:** 2026-03-27T03:00:00Z
- **Completed:** 2026-03-27T03:08:00Z
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments

- Added `list_messages(message_box, accept_payments)` returning `Vec<PeerMessage>` with recipient from identity_key
- Server `{ message, payment }` wrapper parsed; delivery-fee payment internalized via wallet when `accept_payments=true` (errors ignored)
- Plain message bodies fall through unchanged via defensive parse-or-passthrough pattern
- 6 new integration tests prove PaymentToken camelCase wire format, round-trip serialization, derivation byte encoding, and safeParse behavior
- Total test count: 72 (60 lib + 12 integration), all passing; clippy clean

## Task Commits

1. **Task 1: list_messages with auto payment internalization** - `c463002` (feat)
2. **Task 2: Integration tests for PeerPay payment flow** - `f6f6a12` (test)

**Plan metadata:** (docs commit to follow)

_Note: TDD tasks confirmed GREEN immediately for Task 2 — type system was already correct from Plan 01, integration tests validated existing implementation._

## Files Created/Modified

- `src/http_ops.rs` - Added WrappedMessageBody/ServerPayment/ServerPaymentOutput helper types and list_messages method with 3 unit tests
- `tests/integration.rs` - 6 new integration tests: PaymentToken wire format, round-trip, derivation bytes, IncomingPayment construction, safeParse valid/invalid

## Decisions Made

- Server delivery-fee internalization is best-effort — errors silently ignored, matching TS `try/catch` behavior. Partial server payment data (missing sender_identity_key) causes that output to be skipped via `filter_map`.
- `WrappedMessageBody` is `pub(crate)` (not private) so `#[cfg(test)]` can reference it via `use super::WrappedMessageBody`.
- `ServerPaymentOutput` fields are all `Option<_>` — the server delivery-fee output format is not fully documented; being permissive here avoids breaking on new server fields.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Corrected Payment struct field types in server payment internalization**

- **Found during:** Task 1 (list_messages implementation)
- **Issue:** Plan showed `Payment { derivation_prefix: None, ... }` but the SDK's `Payment` struct requires `Vec<u8>` (not `Option`), and `sender_identity_key` requires `PublicKey` (not `Option<String>`)
- **Fix:** Created `ServerPaymentOutput` struct with all-optional fields; parse sender key via `PublicKey::from_string`; skip output via `filter_map` if key invalid; use `.unwrap_or_default()` for byte fields
- **Files modified:** src/http_ops.rs
- **Verification:** `cargo test --lib http_ops` passes, `cargo clippy -- -D warnings` clean
- **Committed in:** c463002 (Task 1 commit)

**2. [Rule 3 - Blocking] Fixed BooleanDefaultTrue import path**

- **Found during:** Task 1 (compilation)
- **Issue:** `BooleanDefaultTrue` is not re-exported from `bsv::wallet::interfaces` — it lives in `bsv::wallet::types`
- **Fix:** Changed import to `use bsv::wallet::types::BooleanDefaultTrue`
- **Files modified:** src/http_ops.rs
- **Verification:** Compiles clean
- **Committed in:** c463002 (Task 1 commit)

---

**Total deviations:** 2 auto-fixed (1 type bug, 1 blocking import)
**Impact on plan:** Both fixes necessary for correctness. No scope creep.

## Issues Encountered

None beyond the two auto-fixed compilation issues.

## Next Phase Readiness

- PeerPay subsystem complete: create, send, accept, reject, list_incoming_payments, list_messages all implemented
- Phase 03 requirements HTTP-02 and TEST-06 satisfied
- Ready to proceed to Phase 04 (or whatever the next phase is per ROADMAP)
- `base64` crate used in test_accept_payment_derivation_args — already in dev-dependencies or transitively available via bsv-sdk

---
*Phase: 03-peerpay*
*Completed: 2026-03-27*
