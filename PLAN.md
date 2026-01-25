# Implementation Plan: Parallel Development for Issue #9, #10 & #11

## Overview

Two agents work in parallel on feature sections:
- **Issue #9**: Section 3 - Slashing Protection (EIP-3076)
- **Issue #10**: Section 4 - Metrics Foundation
- **Issue #11**: Section 5 - Core Attestation Flow

---

## Phase 1: Foundation Layer ✅

**Status: COMPLETE**

| Agent | Issue | Task | PR | Status |
|-------|-------|------|-----|--------|
| A | #23 | SQLite Database Layer | [#76](https://github.com/rootwarp/rvc/pull/76) | ✅ |
| B | #28 | Metrics HTTP Endpoint | [#77](https://github.com/rootwarp/rvc/pull/77) | ✅ |

---

## Phase 2: Core Functionality ✅

**Status: COMPLETE**

| Agent | Issue | Task | PR | Status |
|-------|-------|------|-----|--------|
| A | #24 | Attestation Safety Checks | [#78](https://github.com/rootwarp/rvc/pull/78) | ✅ |
| B | #29 | Core Metrics Definitions | [#79](https://github.com/rootwarp/rvc/pull/79) | ✅ |

---

## Phase 3: Recording & Timing ✅

**Status: COMPLETE**

| Agent | Issue | Task | PR | Status |
|-------|-------|------|-----|--------|
| A | #25 | Attestation Recording | [#80](https://github.com/rootwarp/rvc/pull/80) | ✅ |
| B | #31 | Slot Timing Service | [#81](https://github.com/rootwarp/rvc/pull/81) | ✅ |

**#25 Delivered:**
- `record_attestation()` method with idempotent behavior
- 6 new unit tests

**#31 Delivered:**
- `SlotClock` trait + `SystemSlotClock` implementation
- `AttestationTimer` firing at 1/3 slot time
- `MockSlotClock` for testing
- Metrics integration
- 28 new timing tests

---

## Phase 4: Import/Export & Duty Tracker ✅

**Status: COMPLETE**

| Agent | Issue | Task | PR | Status |
|-------|-------|------|-----|--------|
| A | #26 | EIP-3076 Import/Export | [#82](https://github.com/rootwarp/rvc/pull/82) | ✅ |
| B | #30 | Duty Tracker + Beacon | [#83](https://github.com/rootwarp/rvc/pull/83) | ✅ |

**#26 Delivered:**
- `export()` method for EIP-3076 InterchangeFormat
- `import()` method with genesis root validation
- Round-trip compatibility
- 12 new unit tests

**#30 Delivered:**
- `DutyTracker` struct with beacon client integration
- `fetch_duties_for_epoch(epoch)` method
- `get_duty(slot, committee_index)` cache lookup
- Dependent root tracking for cache invalidation
- Metrics: `RVC_DUTY_CACHE_OPERATIONS_TOTAL`, `RVC_DEPENDENT_ROOT_CHANGES_TOTAL`, `RVC_DUTY_FETCH_DURATION_SECONDS`
- 15 new unit tests

---

## Phase 5: Signer & Propagator Services ✅

**Status: COMPLETE**

| Agent | Issue | Task | PR | Status |
|-------|-------|------|-----|--------|
| A | #32 | Signer Service | [#84](https://github.com/rootwarp/rvc/pull/84) | ✅ |
| B | #33 | Propagator Service | [#85](https://github.com/rootwarp/rvc/pull/85) | ✅ |

**#32 Delivered:**
- `SignerService` struct combining `KeyManager` and `SlashingDb`
- `sign_attestation()` method with EIP-3076 slashing protection
- Records attestation in slashing DB after successful signing
- Metrics: `RVC_SIGNING_DURATION_SECONDS`, `RVC_SLASHING_PROTECTION_CHECKS_TOTAL`
- 13 new unit tests

**#33 Delivered:**
- `Propagator<S>` struct generic over `AttestationSubmitter` trait
- `propagate()` and `propagate_batch()` methods
- Leverages BeaconClient's built-in retry logic
- `PropagationResult` struct with success/failure tracking
- Metrics: `RVC_ATTESTATIONS_TOTAL` with success/failed labels
- 18 new unit tests

---

## Phase 6: Duty Orchestrator

**Status: TODO**

| Agent | Issue | Task | Branch | Complexity | Blocked By |
|-------|-------|------|--------|------------|------------|
| A+B | #34 | Duty Orchestrator | `feature/34-duty-orchestrator` | L | #30 ✓, #31 ✓, #32 ✓, #33 ✓ |

**#34 Scope:**
- `DutyOrchestrator` struct coordinating all services
- Workflow: duty fetch → wait for slot → get attestation data → sign → propagate
- Handles multiple validators in parallel
- Graceful handling of missed slots
- Proper shutdown handling

---

## Phase 7: Main Server Integration

**Status: TODO**

| Agent | Issue | Task | Branch | Complexity | Blocked By |
|-------|-------|------|--------|------------|------------|
| A+B | #35 | Main Server Wiring | `feature/35-main-server-wiring` | M | #34 |

**#35 Scope:**
- Configuration struct for all settings
- Config file support (TOML)
- CLI arguments for overrides
- Service initialization and dependency injection
- Graceful shutdown on SIGTERM/SIGINT

---

## Summary

### Dependency Graph

```
Section 3: Slashing Protection (Issue #9) ✅ COMPLETE
=====================================================
#22 ✓ → #23 ✓ → #24 ✓
              → #25 ✓
              → #26 ✓

Section 4: Metrics Foundation (Issue #10) ✅ COMPLETE
=====================================================
#27 ✓ → #28 ✓
      → #29 ✓

Section 5: Core Attestation Flow (Issue #11)
============================================
#30 ✓ ─────────────┐
#31 ✓ ─────────────┼──> #34 [Phase 6] ──> #35 [Phase 7]
#32 ✓ ─────────────┤
#33 ✓ ─────────────┘
```

### Phase Overview

| Phase | Agent A | Agent B | Status |
|-------|---------|---------|--------|
| 1 | #23 SQLite DB | #28 HTTP Endpoint | ✅ |
| 2 | #24 Safety Checks | #29 Core Metrics | ✅ |
| 3 | #25 Recording | #31 Slot Timing | ✅ |
| 4 | #26 Import/Export | #30 Duty Tracker | ✅ |
| 5 | #32 Signer Service | #33 Propagator | ✅ |
| 6 | #34 Duty Orchestrator (joint) | | TODO |
| 7 | #35 Main Server (joint) | | TODO |

### Completed PRs

| PR | Issue | Status |
|----|-------|--------|
| [#76](https://github.com/rootwarp/rvc/pull/76) | #23 | ✅ Merged |
| [#77](https://github.com/rootwarp/rvc/pull/77) | #28 | ✅ Merged |
| [#78](https://github.com/rootwarp/rvc/pull/78) | #24 | ✅ Merged |
| [#79](https://github.com/rootwarp/rvc/pull/79) | #29 | ✅ Merged |
| [#80](https://github.com/rootwarp/rvc/pull/80) | #25 | ✅ Merged |
| [#81](https://github.com/rootwarp/rvc/pull/81) | #31 | ✅ Merged |
| [#82](https://github.com/rootwarp/rvc/pull/82) | #26 | ✅ Merged |
| [#83](https://github.com/rootwarp/rvc/pull/83) | #30 | ✅ Merged |
| [#84](https://github.com/rootwarp/rvc/pull/84) | #32 | ✅ Merged |
| [#85](https://github.com/rootwarp/rvc/pull/85) | #33 | ✅ Merged |

---

## Verification Commands

```bash
# Run all tests
cargo test --workspace

# Slashing tests
cargo test -p rvc slashing

# Metrics tests
cargo test -p rvc metrics

# Timing tests
cargo test -p rvc timing

# Duty tracker tests
cargo test -p rvc duty_tracker

# Signer tests
cargo test -p rvc signer

# Propagator tests
cargo test -p rvc propagator

# Lint
cargo clippy --all-targets
cargo fmt --check
```
