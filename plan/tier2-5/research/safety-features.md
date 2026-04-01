# Safety Features Research for rvc (Rust Validator Client)

Research findings for implementing safety features in the rvc Ethereum validator client.
Compiled: 2026-04-01.

---

## 1. Prysm Builder Circuit Breakers

### Overview

Prysm implements a circuit breaker pattern that automatically falls back from MEV builder (relay) block construction to the local execution engine when the builder causes missed blocks. This protects the validator from missing proposals entirely when the builder is unhealthy.

### Flag Definitions (Go source)

```go
MaxBuilderConsecutiveMissedSlots = &cli.IntFlag{
    Name:  "max-builder-consecutive-missed-slots",
    Usage: "Number of consecutive skip slot to fallback from using relay/builder
            to local execution engine for block construction",
    Value: 3,
}

MaxBuilderEpochMissedSlots = &cli.IntFlag{
    Name:  "max-builder-epoch-missed-slots",
    Usage: "Number of total skip slot to fallback from using relay/builder to
            local execution engine for block construction in last epoch rolling
            window. The values are on the basis of the networks and the default
            value for mainnet is 5.",
}
```

### Default Values

| Parameter | Default (Mainnet) |
|---|---|
| `--max-builder-consecutive-missed-slots` | **3** |
| `--max-builder-epoch-missed-slots` | **5** (network-dependent) |

### How Tracking Works

- The beacon node monitors the canonical chain for **skip slots** (slots where no block was proposed).
- **Consecutive tracking**: Counts the number of sequential skip slots leading up to the current proposal slot.
- **Epoch rolling window**: Counts total skip slots within the last epoch (~32 slots on mainnet).

### Circuit Breaker Trigger and Reset

- **Trigger**: The circuit breaker activates when **either** threshold is exceeded: 3+ consecutive missed slots OR 5+ missed slots in the epoch window.
- **Reset**: The circuit breaker **automatically resets** without requiring a beacon node restart. Once triggered, local execution continues until **both** conditions are no longer true (consecutive misses drop below 3 AND epoch misses drop below 5).
- No manual intervention is required.

### Additional Builder Safety Parameters

Prysm also supports:
- `--min-builder-bid`: Absolute value (in Gwei) that a builder bid must meet for the node to use it; reverts to local building if below threshold.
- `--local-block-value-boost`: Percentage boost applied to local block value when comparing against builder bids.

### Gotchas

- The epoch missed slots default is **network-dependent** and not hardcoded for all networks in the flag definition itself (mainnet = 5).
- The circuit breaker operates at the **beacon node** level, not the validator client level.
- The v4.0.1 release specifically lowered the epoch threshold to 5 (from a previously higher value).

### Sources

- [Prysm MEV Builder Configuration](https://prysm.offchainlabs.com/docs/configure-prysm/builder/)
- [Prysm v5 Flag Definitions (Go Packages)](https://pkg.go.dev/github.com/prysmaticlabs/prysm/v5/cmd/beacon-chain/flags)
- [Prysm v4.0.1 Release Notes](https://github.com/prysmaticlabs/prysm/releases/tag/v4.0.1)

---

## 2. Lighthouse Chain Health Fallback for Builder

### Overview

Lighthouse implements a "chain health" model for deciding whether to use the builder API or fall back to local block construction. Three independent conditions define a "healthy chain" -- if **any** condition fails, the node falls back to local execution engine payload construction.

### Configuration Flags and Defaults

| Flag | Default | Description |
|---|---|---|
| `--builder-fallback-skips` | **3** | Number of **consecutive** skip slots on the canonical chain before falling back |
| `--builder-fallback-skips-per-epoch` | **8** | Number of skip slots in the last `SLOTS_PER_EPOCH` (32 slots) before falling back |
| `--builder-fallback-epochs-since-finalization` | **3** | Number of epochs without finality before falling back |
| `--builder-fallback-disable-checks` | **false** (flag) | Disables all chain health checks; builder is always used |

### Chain Health Logic

The beacon node evaluates all three conditions at block proposal time:

1. **Consecutive skip slots**: If `N` or more consecutive skip slots have occurred immediately prior to the proposal slot, the chain is considered unhealthy.
2. **Skips per epoch**: If `N` or more skip slots have occurred in the last 32 slots (one epoch window), the chain is unhealthy.
3. **Epochs since finalization**: If finality has not occurred within `N` epochs, the chain is unhealthy.

**All three conditions must pass for the builder to be queried.** If any single check fails, the node uses the local execution engine.

### Design Rationale

From Lighthouse issue [#3355](https://github.com/sigp/lighthouse/issues/3355):

> The proposal prioritizes liveness -- a missed proposal is considered worse than potential MEV loss.

The developers also note that **intentional diversity** across client implementations is preferable to standardization, making coordinated attacks more difficult.

### Comparison with Prysm

| Aspect | Prysm | Lighthouse |
|---|---|---|
| Consecutive skip threshold | 3 | 3 |
| Epoch skip threshold | 5 | 8 |
| Finalization check | No | Yes (3 epochs) |
| Logic | OR (either triggers) | AND (all must pass) |
| Reset | Auto, both must clear | Per-proposal evaluation |

### Gotchas

- Setting `--builder-fallback-epochs-since-finalization` to a value less than 2 will cause the node to **never** query builders (since finality naturally takes 2 epochs).
- The `--builder-fallback-disable-checks` flag is dangerous in production -- it means builder will always be used regardless of chain health.
- These checks run on the **beacon node**, not the validator client.

### Sources

- [Lighthouse Beacon Node Help](https://lighthouse-book.sigmaprime.io/help_bn.html)
- [Lighthouse MEV Documentation](https://lighthouse-book.sigmaprime.io/builders.html)
- [Builder API Chain Health Checks Issue #3355](https://github.com/sigp/lighthouse/issues/3355)
- [Lighthouse Configuration (DeepWiki)](https://deepwiki.com/sigp/lighthouse/5-configuration-management)

---

## 3. Teku Slashed Validator Auto-Shutdown

### Overview

Teku provides a `--shut-down-when-validator-slashed-enabled` flag that monitors for slashing events affecting owned validators. When a slashing is detected, Teku terminates the entire validator client with a specific exit code.

### Configuration

```bash
teku validator-client --shut-down-when-validator-slashed-enabled=true
```

### Detection Mechanism

- Teku subscribes to the beacon node's **SSE (Server-Sent Events)** stream, specifically:
  - `proposer_slashing` events
  - `attester_slashing` events
- When running a separate validator client, the connected beacon node **must** support both of these SSE event topic streams.
- On each slashing event, Teku checks whether any of its **owned validators** are among the slashed validators.

### Shutdown Behavior

- **Exit code**: `2` (distinct from normal exit)
- **Scope**: The **entire** validator client shuts down -- all running validators stop performing duties (not just the slashed one).
- **Side effects**: Stopping causes missed attestations, sync committee contributions, and block proposals, incurring penalties.

### Recovery Procedure

1. **Do not restart Teku immediately** -- validators will likely continue to be slashed.
2. **Remove the slashed validator** from the owned validators list before restarting.
3. If you restart without removing the slashed validator, Teku will detect it as still-slashed and shut down again immediately.
4. Consider restarting with **doppelganger detection** enabled.

### Limitations

- The feature is explicitly described as **"imperfect"** in the official documentation.
- It **"might fail to detect slashing events rapidly"**.
- It is intended as a **"last resort option"** that might prevent further slashing.
- Detection speed depends on the beacon node's SSE event delivery latency.
- Cannot detect slashing if the beacon node connection is lost.

### Slashing Protection Database (Separate Feature)

Teku stores slashing protection records per-validator in YAML files at `<data-path>/validator/slashprotection/<validator-pubkey>.yml` (without 0x prefix). This is a separate mechanism from the shutdown feature.

### Sources

- [Teku: Stop When Validator Slashed](https://docs.teku.consensys.io/how-to/prevent-slashing/detect-slashing)
- [Teku: Slashing Protection Concepts](https://docs.teku.consensys.io/concepts/slashing-protection)
- [Teku: Prevent Slashing Offenses](https://docs.teku.consensys.io/how-to/prevent-slashing)

---

## 4. Teku Keystore File Locking

### Overview

Teku implements a file-based locking mechanism to prevent two validator clients from simultaneously loading the same keystore files. This is enabled by default.

### Configuration

```bash
# Default: true
teku validator-client --validators-keystore-locking-enabled=true
```

### Lock File Mechanism

- **Type**: Filesystem `.lock` files (sentinel files, not OS-level `flock`/`FileLock`)
- **Naming Convention**: Lock file name = `<keystore-filename>.lock`
  - Example: `my-keystore.json` produces `my-keystore.json.lock`
- **Scope**: Locks all keystores listed in `--validator-keys`. If a directory is specified, all keystores in that directory are locked.
- **Lifecycle**: Lock files are created on startup and removed on clean shutdown.

### Error Messages

| Error | Cause |
|---|---|
| `"Keystore file <file>.lock already in use"` | Another VC is using the keystore, OR Teku exited uncleanly and left the lock file behind |
| `"Unexpected error when trying to lock a keystore file"` | The keystore directory is not writable by Teku |

### Resolution

- **If stale lock**: Manually delete the `.lock` file (verify no other VC is running first).
- **If permission issue**: Fix directory permissions.
- **Disable locking**: Set `--validators-keystore-locking-enabled=false` (dangerous -- risk of slashing).

### Limitations

- **Single-machine only**: The `.lock` file mechanism cannot prevent the same key from being used across different machines or different validator clients.
- The lock is a **cooperative mechanism** -- only Teku respects Teku's lock files. Other validator clients (Lighthouse, Prysm, etc.) will not check for `.lock` files.
- An **unclean shutdown** (crash, SIGKILL) leaves stale lock files that must be manually cleaned.

### Design Context

This mechanism was introduced following Ethereum Foundation Discord discussions about standardizing lockfile conventions for EIP-2335 keystores (see Teku issue [#2412](https://github.com/ConsenSys/teku/issues/2412)). The PR implementing it was [#2729](https://github.com/ConsenSys/teku/pull/2729).

### Sources

- [Teku: Slashing Protection (Keystore Locking)](https://docs.teku.consensys.io/concepts/slashing-protection)
- [Teku: Troubleshooting General Issues](https://docs.teku.consensys.io/how-to/troubleshoot/general)
- [Teku Issue #2412: Lockfile for Signing Keystores](https://github.com/ConsenSys/teku/issues/2412)

---

## 5. Lighthouse SQLite Exclusive Locking

### Overview

Lighthouse uses SQLite with `PRAGMA locking_mode=EXCLUSIVE` and `EXCLUSIVE` transactions to prevent duplicate validator instances from running simultaneously against the same slashing protection database.

### Database Location

```
$datadir/validators/slashing_protection.sqlite
```

Default: `~/.lighthouse/{network}/validators/slashing_protection.sqlite`

### Locking Implementation (Defense in Depth)

Lighthouse employs a **three-layer** protection model:

1. **`PRAGMA locking_mode=EXCLUSIVE`**: Instructs SQLite to only allow a **single connection** to the database. Once a connection acquires any lock, it holds it for the lifetime of the connection. This means the second validator client instance **cannot even start**.

2. **`EXCLUSIVE` transactions**: All database transactions (reads and writes) operate in `EXCLUSIVE` mode, providing an additional layer of protection beyond the pragma setting.

3. **Schema-level uniqueness constraints**: The `signed_attestations` and `signed_blocks` tables have uniqueness constraints that prevent duplicate votes at the SQL schema level.

### Duplicate Instance Prevention

- If a second validator client attempts to start with the same `$datadir`, it will **fail to open** the slashing protection database because the first instance holds an exclusive lock.
- The second instance **will not start at all** -- it cannot sign anything slashable.

### Import/Export (EIP-3076)

- Lighthouse supports the EIP-3076 interchange format for portable slashing protection records.
- Since v1.6.0, import **ignores slashable data** and safely updates low watermarks.
- The validator client **must be stopped** during both import and export operations.
- Lighthouse stores only the maximum-slot block/attestation (low watermark approach) rather than a complete history.

### Doppelganger Detection (Complementary Feature)

- Enabled via `--enable-doppelganger-detection`
- Waits 2-3 epochs (~12-20 minutes) after startup, staying silent while listening for other instances.
- Uses a **check counter** approach: the VC queries the BN each epoch asking if doppelgangers were seen; each negative response decrements the remaining checks by 1.
- If a doppelganger is found, the **entire VC shuts down**.
- Avoids timing-based false positives from suspend/resume by using counter-based checks rather than wallclock assumptions.

### Limitations

- **Single-machine only**: The SQLite exclusive lock cannot protect against validators running on different machines with different datadirs.
- If the database file is copied to another machine, both instances can run independently.
- The lock is released on process termination (including crashes), so there is no stale lock problem (advantage over Teku's `.lock` file approach).

### Sources

- [Lighthouse: Slashing Protection](https://lighthouse-book.sigmaprime.io/slashing-protection.html)
- [Lighthouse PR #1116: Implement Slashing Protection](https://github.com/sigp/lighthouse/pull/1116)
- [Lighthouse Issue #1537: Improve Atomicity of Slashing Protection DB](https://github.com/sigp/lighthouse/issues/1537)
- [Lighthouse: Doppelganger Protection](https://lighthouse-book.sigmaprime.io/validator-doppelganger.html)

---

## 6. Rust File Locking Crates Comparison

### Crate Overview

| Crate | Latest Version | Total Downloads | Maintained | Lock Type | Underlying API |
|---|---|---|---|---|---|
| **fs2** | 0.4.3 | ~51M | No (last release ~2017) | Advisory | `flock(2)` on Unix, `LockFile` on Windows |
| **fd-lock** | 4.0.4 | ~31M | Yes (yoshuawuyts) | Advisory | `rustix` (no raw libc) |
| **file-lock** | varies | Lower | Moderate | Advisory | `fcntl()` POSIX.1 |
| **fs4** | 0.13.1 | ~18M | Yes (fork of fs2) | Advisory | `rustix` (no raw libc) |

### fs2 (Unmaintained -- Use fs4 Instead)

- **Status**: Effectively unmaintained. Last release was ~8 years ago. There is an actively maintained fork called **fs4**.
- **API**: Extension trait `FileExt` on `std::fs::File` providing `lock_shared()`, `lock_exclusive()`, `try_lock_shared()`, `try_lock_exclusive()`, `unlock()`.
- **Platform**: `flock(2)` on Unix, `LockFile` on Windows.
- **Key warning**: "File locks may only be relied upon to be advisory."
- **Minimum Rust**: 1.8+

```rust
use fs2::FileExt;

let file = std::fs::File::open("my.lock")?;
file.lock_exclusive()?;  // blocks until lock acquired
// ... critical section ...
file.unlock()?;
```

### fd-lock (Recommended for Simple Use Cases)

- **Status**: Actively maintained by yoshuawuyts.
- **API**: RAII-based `RwLock` wrapping a file, returning `RwLockReadGuard` / `RwLockWriteGuard` that auto-release on drop.
- **Platform**: `rustix` on Unix, `windows-sys` on Windows. No raw `libc` calls.
- **Async variant**: `async-fd-lock` crate available separately.
- **Dependencies**: `cfg-if`, `rustix`, `windows-sys`

```rust
use fd_lock::RwLock;

let mut lock = RwLock::new(std::fs::File::open("my.lock")?);
let guard = lock.write()?;  // exclusive lock, RAII release
// ... critical section ...
drop(guard);  // lock released
```

### file-lock (POSIX-Only)

- **Status**: Moderately maintained.
- **API**: Uses `fcntl()` for POSIX.1 advisory record locks.
- **Platform**: **Unix only** (not cross-platform).
- **Key difference**: Supports **byte-range locking** (record locks) rather than whole-file locks.
- **Gotcha**: `fcntl()` locks are per-process, not per-file-descriptor. Closing *any* FD to the same file releases the lock.

### fs4 (Recommended for Async / Modern Codebases)

- **Status**: Actively maintained fork of fs2.
- **API**: Same `FileExt` trait as fs2, plus async support.
- **Platform**: Pure Rust via `rustix` (no `libc`).
- **Async runtimes**: Feature flags for `tokio`, `async-std`, `smol`.
- **Additional**: `fs-err` integration for better error messages.

```toml
[dependencies]
fs4 = { version = "0.13", features = ["tokio"] }
```

### Recommendation for rvc

For a Rust validator client:

1. **For simple exclusive file locking** (e.g., keystore lock files): Use **`fd-lock`** -- RAII guards, no `libc`, actively maintained.
2. **For SQLite-like database locking**: Use SQLite's built-in `PRAGMA locking_mode=EXCLUSIVE` (following Lighthouse's pattern) rather than a separate file lock crate.
3. **For async file operations with locking**: Use **`fs4`** with `tokio` feature flag.
4. **Avoid**: `fs2` (unmaintained), `file-lock` (Unix-only, `fcntl` gotchas).

### Important: Advisory Lock Semantics

All of these crates provide **advisory locks**. This means:
- Cooperating processes must opt-in to the locking protocol.
- A malicious or unaware process can freely ignore the lock.
- For validator safety, this is acceptable because the goal is preventing *accidental* double-signing, not defending against adversarial access.

### Sources

- [fs2 on crates.io](https://crates.io/crates/fs2)
- [fd-lock on crates.io](https://crates.io/crates/fd-lock)
- [fd-lock docs.rs](https://docs.rs/fd-lock/latest/fd_lock/)
- [fs2 FileExt docs.rs](https://docs.rs/fs2/latest/fs2/trait.FileExt.html)
- [fs4 GitHub (al8n/fs4-rs)](https://github.com/al8n/fs4-rs)
- [Rust Forum: Cross-platform File Locking](https://users.rust-lang.org/t/cross-platform-library-for-file-locking/68698)

---

## 7. Runtime Flag Toggling for Attestation Disable

### Lighthouse's `--disable-attesting` Flag

- **Flag**: `--disable-attesting`
- **Description**: "Disable the performance of attestation duties (and sync committee duties). This flag should only be used in emergencies to prioritise block proposal duties."
- **Scope**: Disables attestation AND sync committee duties. Block proposals remain active.
- **Toggleability**: **Startup-only**. Cannot be toggled at runtime without restarting the validator client.

### Lighthouse's Runtime Validator Control (API-Based Alternative)

While `--disable-attesting` is startup-only, Lighthouse provides a **PATCH API** endpoint for runtime validator management:

```
PATCH /lighthouse/validators/{voting_pubkey}
Authorization: Bearer <token>
Content-Type: application/json

{
  "enabled": false
}
```

Supported fields for runtime update:
- `enabled` (bool) -- enables/disables the validator entirely
- `gas_limit` (u64)
- `builder_proposals` (bool)
- `builder_boost_factor` (u64)
- `prefer_builder_proposals` (bool)
- `graffiti` (string)

**Key distinction**: This disables/enables an **individual validator** (all duties), not attestation as a duty type. There is no API to toggle attestation-only at runtime.

### Best Practices for AtomicBool-Based Runtime Flags in Async Rust

For implementing runtime-toggleable flags in rvc:

#### Pattern 1: Arc<AtomicBool> Shared Across Tasks

```rust
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

struct ValidatorDuties {
    attesting_enabled: Arc<AtomicBool>,
}

impl ValidatorDuties {
    async fn attestation_loop(&self) {
        loop {
            if !self.attesting_enabled.load(Ordering::Relaxed) {
                // Skip attestation this slot
                tokio::time::sleep(slot_duration).await;
                continue;
            }
            self.perform_attestation().await;
        }
    }
}
```

#### Pattern 2: tokio::sync::watch for Change Notification

```rust
use tokio::sync::watch;

let (tx, rx) = watch::channel(true); // attesting_enabled

// In the duty loop:
tokio::select! {
    _ = rx.changed() => {
        let enabled = *rx.borrow();
        // React to flag change immediately
    }
    _ = next_slot_timer => {
        if *rx.borrow() {
            perform_attestation().await;
        }
    }
}
```

#### Ordering Recommendations

| Use Case | Ordering | Rationale |
|---|---|---|
| Simple on/off toggle (no data dependency) | `Relaxed` | No happens-before needed; eventual consistency is fine per-slot |
| Flag that gates access to shared mutable state | `Acquire`/`Release` | Ensures visibility of data written before the flag change |
| Flag set during shutdown | `SeqCst` or `Release`/`Acquire` pair | Ensures all tasks see the shutdown signal |

#### Best Practices

1. **Use `Relaxed` ordering for duty toggles**: Attestation duty flags are checked once per slot (~12s). The worst case with `Relaxed` is a one-slot delay before the flag change takes effect, which is acceptable.

2. **Prefer `watch` channel over polling AtomicBool**: If you need immediate reaction to flag changes (e.g., for an HTTP API handler toggling the flag), `tokio::sync::watch` provides both the flag value and a change notification mechanism.

3. **RAII pattern for flag guards**: If a flag temporarily disables a duty (e.g., during key rotation), consider an RAII guard that resets the flag on drop to prevent stuck-disabled states.

4. **Avoid `Mutex` for simple booleans**: `AtomicBool` is strictly better than `Mutex<bool>` for performance in async contexts (no await point during access, no task parking).

5. **Task cancellation awareness**: Dropping a `JoinHandle` in tokio results in eventual (not immediate) task cancellation. If a flag-controlled task must stop promptly, use a `CancellationToken` from `tokio_util` in combination with the flag.

```rust
use tokio_util::sync::CancellationToken;

let cancel = CancellationToken::new();
let attesting = Arc::new(AtomicBool::new(true));

tokio::select! {
    _ = cancel.cancelled() => { /* shutdown */ }
    _ = attestation_loop(attesting.clone()) => {}
}
```

6. **HTTP API integration**: Expose a `POST /admin/duties/attestation` endpoint that flips the `AtomicBool` and returns the new state. This is simpler than Lighthouse's per-validator PATCH approach when you want a global toggle.

### Sources

- [Lighthouse Validator Client Help](https://lighthouse-book.sigmaprime.io/help_vc.html)
- [Lighthouse Validator Client API Endpoints](https://lighthouse-book.sigmaprime.io/api-vc-endpoints.html)
- [Rust std::sync::atomic Documentation](https://doc.rust-lang.org/std/sync/atomic/)
- [Tokio Tutorial: Async in Depth](https://tokio.rs/tokio/tutorial/async)

---

## Summary: Cross-Client Safety Feature Comparison

| Feature | Prysm | Lighthouse | Teku | rvc (Proposed) |
|---|---|---|---|---|
| Builder circuit breaker | OR logic: consecutive (3) + epoch (5) | AND logic: consecutive (3) + epoch (8) + finality (3 epochs) | N/A | Combine both approaches |
| Duplicate instance prevention | N/A | SQLite `EXCLUSIVE` lock | Keystore `.lock` files | SQLite EXCLUSIVE + keystore lock files |
| Slashing auto-shutdown | N/A | N/A | SSE-based, exit code 2 | SSE-based detection |
| Doppelganger detection | Yes | Yes (2-3 epoch delay, counter-based) | Yes | Yes |
| Attestation disable | N/A | `--disable-attesting` (startup only) | N/A | AtomicBool runtime toggle + API |
| Runtime validator control | N/A | PATCH API (per-validator enable/disable) | N/A | PATCH API + global duty toggles |
| Stale lock cleanup needed | N/A | No (SQLite releases on exit) | Yes (manual `.lock` file removal) | No (SQLite approach preferred) |
