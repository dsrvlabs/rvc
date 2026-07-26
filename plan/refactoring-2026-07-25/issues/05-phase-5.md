# Refactoring Phase 5 — Composition roots & configuration (Theme F, items F1–F7)

> Each binary becomes CLI-parse + one library call; adding a config knob touches one place.
>
> Authoritative inputs: [`../refactoring-plan.md`](../refactoring-plan.md) (Theme F table, Phase 5
> table, §6 validation strategy, appendix rows F4/F9/F13–F15/F18/F20–F22/F24/F25/F31/F34/F69/F71/
> F75–F78/F111/F128) and [`../refactoring-findings.json`](../refactoring-findings.json).
> Format follows [`../../security-2026-07-18/issues/01-phase-1.md`](../../security-2026-07-18/issues/01-phase-1.md).
> All file:line references re-verified against HEAD `develop` (`a7f8cdf`) on 2026-07-25.

## Phase Overview

- **Goal:** `bin/rvc`'s 898-line `run_validator` and `bin/rvc-signer`'s 472-line `run_serve` become
  library bootstrap modules of independently testable phase functions; the two config stacks stop
  requiring 5–6 edits per knob; the keymanager server gets a real assembly seam; validator-store gets a
  single lock. This phase *moves and restructures* wiring — it adds no new subsystem.
- **Issue count:** 32 issues, 80 points.
- **Estimated duration:** ~40–80 working days single-stream; ~21–41 days with 2 developers
  (Stream A = `bin/rvc` + `crates/rvc`, 41 pts; Stream B = `bin/rvc-signer` + `crates/keymanager-api` +
  `crates/validator-store` + `bin/rvc-keygen`, 39 pts).
- **Point scale:** 1 / 2 / 3 (no Phase-5 issue exceeds 3). ~1 point ≈ 0.5–1 working day, including
  coding, tests, and review. The plan rates F1/F2/F3/F5 as **L**; each is split here into an ordered
  chain of 1–3-point sub-issues.
- **Entry criteria:**
  - Phase 2 **B2** merged (`ServiceBuilder::build_all` / `BuiltServices` / `build_doppelganger_service`
    deleted) — otherwise F1 extracts phase functions next to a dead, drifted twin.
  - Phase 4 merged, specifically **E7** (`BeaconBlockAdapter` takes `Arc<dyn BeaconNodeClient>`,
    `main.rs:1525-1569`), **D2/D3** (signer/gate cores + error taxonomy consumed at both bootstraps),
    **D4** (rvc-signer SignPlan dispatcher, which rewrites the handlers `run_serve` assembles), and
    **E8c** (doppelganger consolidation, which owns `crates/rvc/src/startup.rs:139`).
  - Workspace green on the standing invariant: `cargo fmt --all -- --check`,
    `cargo clippy --workspace --all-targets -- -D warnings`, `cargo nextest run --workspace`,
    `crates/architecture-tests`.
- **Exit criteria (phase gate):**
  - [ ] `bin/rvc/src/main.rs` < ~600 lines; it does CLI parse + logging init + one `rvc::bootstrap::run`
        call. No startup step remains inline in the binary.
  - [ ] `bin/rvc-signer` server assembly lives in `crates/signer-server`; `bin/rvc-signer/src/main.rs`
        is a CLI shim; no test shells out to `cargo build`.
  - [ ] CLI startup smoke tests run **un-ignored** in CI against a mock beacon node (clean start, clean
        SIGTERM shutdown, exit code 0) and pass at every step of the F1 and F2 chains.
  - [ ] A production `rvc.toml` written before this phase still loads unchanged (fixture test), and
        `rvc-signer --config f.toml --listen-address <the default value>` keeps the CLI value.
  - [ ] Adding a hypothetical flag to either binary = 1 struct field + 1 clap attribute (demonstrated in
        the PR description of RF5-15 and RF5-23).
  - [ ] Manual devnet/mock-BN boot performed and recorded before RF5-10 merges.
  - [ ] Release notes drafted for the three deliberate behavior changes (see *Release-note items*).
  - [ ] Workspace green on the standing invariant.

## Assumptions (verified against HEAD `a7f8cdf`)

- **P5-A1 — SEC-1 has already landed; F5's stated dependency is satisfied.** The plan says "coordinate
  with SEC-1 tracked_keys work (F119) — land SEC-1 first". SEC-1a (`e0b06e0`), SEC-1b (`6d77dad`) and
  SEC-2a (`0200aab`) are merged on `develop`: `KeystoreManagerAdapter::list_keys`
  (`crates/rvc/src/keymanager_adapters.rs:303`) already delegates to
  `CompositeSigner::local_public_keys()`, and `with_denylist` exists at `:84` and is wired at
  `bin/rvc/src/main.rs:1626`. `tracked_keys` survives at `:54` only as an import serialization lock
  (documented at `:41`). **Consequence:** the F5 issues here may proceed without waiting on the security
  plan; re-confirm at kickoff that no further SEC issue is mid-flight in `handlers.rs`.
- **P5-A2 — the CLI smoke-test harness already exists but is disabled.** `bin/rvc/tests/integration_test.rs`
  already uses `env!("CARGO_BIN_EXE_rvc")` (`:8-15`) and spawns the binary, but the three startup tests
  (`test_startup_and_health_endpoint:129`, `test_startup_and_metrics_endpoint:172`,
  `test_graceful_shutdown_sigterm:212`) are `#[ignore = "Requires network access and may be slow"]`
  because there is no beacon node to talk to. `wiremock`, `reqwest` (blocking), `tempfile` and
  `tokio-util` are already dev-dependencies of `rvc-bin`. RF5-01 is therefore "supply a mock BN and
  un-ignore", not "build a harness from scratch"; `assert_cmd` is optional and **not** recommended (the
  existing `std::process::Command` harness is sufficient and adds no dependency).
- **P5-A3 — F128 is partially stale.** `crates/validator-store/src/store.rs:1` is already
  `use parking_lot::{Mutex, RwLock}`, so the L-22 sub-claim ("`RwLock::read().unwrap()` panics on
  poison") no longer applies. F128 also says "two RwLocks"; the struct holds **three** RwLocks plus a
  Mutex (`validators:61`, `defaults:62`, a `Mutex` at `:63`, `global_block_selection_mode:64`). The live
  half is confirmed: `effective_config:156-158` takes `validators` → `defaults` while
  `save_config:306,316-317` takes `defaults` → `validators`; with parking_lot's write-preferring
  fairness a writer queued between the two reads makes that a real deadlock, not a theoretical one.
- **P5-A4 — the config numbers check out.** `Config` = 63 fields (`crates/rvc/src/config/types.rs:22-231`),
  `CliOverrides` = 65 fields (`:946-1016`), `merge_with_cli` = 275 lines (`:651-925`), `Default` impl
  `:338-406`, `validate` `:441-566`. `Commands::Start` spans `bin/rvc/src/main.rs:43-391` under
  `#[allow(clippy::large_enum_variant)]` (`:40`), destructured at `:506-582`, copied into a
  `CliOverrides` literal at `:628-718`.
- **P5-A5 — Config construction is dominated by functional-update syntax.** ~66 `Config { … }` /
  `Config::default()` sites exist, overwhelmingly of the form `Config { two_or_three_fields,
  ..Config::default() }` (e.g. `bin/rvc/tests/tier3_operations.rs:21,37,53,91`). Only sites naming a
  *moved* field break under nesting; ~84 such lines exist outside `types.rs`, concentrated in
  `bin/rvc/tests/tier2_safety.rs`, `tier3_operations.rs`, `bin/rvc/src/main.rs`,
  `crates/rvc/src/config/builder.rs`, `keymanager_adapters.rs`, `orchestrator/coordinator.rs`. This is
  why F3's nesting is split into "introduce + shim" (RF5-12) and "migrate + delete shims" (RF5-13)
  rather than one 3-point issue.
- **P5-A6 — F21's divergence is real and unfixed.** `bin/rvc-keygen/src/exit.rs:69-73` and
  `bls_to_execution.rs:94-98` fall back to plain `fs::write` on non-unix (silent overwrite of a signed
  message), while `new_mnemonic.rs:29,44,265,276` keep `create_new(true)` on both arms.
- **P5-A7 — minor citation drift, no material change.** F21 cites `bls_to_execution.rs:77` /
  `exit.rs:52`; the `create_new` calls are at `:85` and `:60` (block starts match). F71 cites
  `handlers.rs:198/377/513`; those offsets sit inside `import_keystores` (`:139-318`),
  `delete_keystores` (`:319-457`) and `import_remote_keys` (`:474-565`) as described. Everything else
  in the Theme F table verified exactly.

## Phase Summary

| Issue | Title | Pts | Type | Blocked by | Stream |
|-------|-------|----:|------|------------|--------|
| RF5-01 | CLI startup smoke tests against a mock beacon node (un-ignore + readiness) | 3 | test | — | A |
| RF5-02 | `KeymanagerServer::new(deps, settings)` replaces 14 positional args | 2 | refactor | — | B |
| RF5-03 | `rvc::bootstrap` module + `open_slashing_db` phase (DB, lock, denylist) | 2 | refactor | RF5-01 | A |
| RF5-04 | `bootstrap::connect_beacon` phase + single GVR parse | 2 | refactor | RF5-03 | A |
| RF5-05 | `bootstrap::load_signing_keys` phase (keystores, providers, gRPC signer) | 3 | refactor | RF5-04 | A |
| RF5-06 | `bootstrap::wire_signing_enablement` phase (forward window, liveness, refresh) | 3 | refactor | RF5-05 | A |
| RF5-07 | `bootstrap::build_services` phase (fork gate, proposer, adapters, toggle) | 3 | refactor | RF5-06 | A |
| RF5-08 | `bootstrap::spawn_keymanager_api` phase + hoisted `scan_and_rearm_gate` | 2 | refactor | RF5-02, RF5-07 | A |
| RF5-09 | `slashing_monitor::spawn` + `SlashedOutcome` enum | 2 | refactor | RF5-07 | A |
| RF5-10 | `bootstrap::spawn_background_tasks` + shutdown; main.rs < 600 lines | 3 | refactor | RF5-08, RF5-09 | A |
| RF5-11 | Typed config enums (SlashedAction, BroadcastTopic, TracingExporter, BnRole) | 2 | refactor | RF5-09 | A |
| RF5-12 | Nested config sub-structs + serde aliases + prod-config fixture test | 3 | refactor | RF5-11 | A |
| RF5-13 | Migrate call sites to nested config; delete compatibility shims | 3 | refactor | RF5-12 | A |
| RF5-14 | `Start(StartArgs)` with flattened clap groups + `From<StartArgs>` | 3 | refactor | RF5-10, RF5-13 | A |
| RF5-15 | Macro-generated merge + `tracing_sample_rate: Option<f64>` + OTEL precedence | 3 | refactor | RF5-14 | A |
| RF5-16 | `build_signed_exit` shared helper; no `panic!` in exit command paths | 3 | refactor | RF5-10 | A |
| RF5-17 | Move `prepare_exit.rs` / `submit_exit.rs` next to their `bin/rvc` consumers | 1 | refactor | RF5-16 | A |
| RF5-18 | rvc-signer: kill cargo-build-in-test; `CARGO_BIN_EXE` + in-process harness | 2 | test | — | B |
| RF5-19 | `server::run` + `ServerError` thiserror skeleton (verbatim body move) | 3 | refactor | RF5-18 | B |
| RF5-20 | Decompose `server::run` into `open_slashing_db` + `build_backend` | 3 | refactor | RF5-19 | B |
| RF5-21 | Decompose into `build_grpc_router` + `spawn_http_api` | 3 | refactor | RF5-20 | B |
| RF5-22 | TLS split: `tls_config.rs` + `accept_loop.rs`; `src/tls` → `grpc_tls` | 3 | refactor | RF5-21 | B |
| RF5-23 | rvc-signer config: `Option<T>` args, `*_is_default` heuristics deleted | 3 | bugfix | RF5-19 | B |
| RF5-24 | `Backend` stays an enum through `ResolvedConfig` | 2 | refactor | RF5-23 | B |
| RF5-25 | Promote the lib to `crates/signer-server`; bin becomes a shim | 3 | refactor | RF5-22, RF5-24 | B |
| RF5-26 | `DoppelgangerLifecycle` component owns the KM-2 invariant | 3 | refactor | RF5-02 | B |
| RF5-27 | thiserror enums for keymanager traits; one central sanitizing mapper | 3 | refactor | RF5-26 | B |
| RF5-28 | Collapse `sign_voluntary_exit` / `prepare_exit` into one `handle_exit` | 1 | refactor | RF5-27 | B |
| RF5-29 | validator-store: shared `parse_config` with fallback consts defined once | 1 | refactor | — | B |
| RF5-30 | validator-store: single lock over one state struct; atomic reload | 3 | bugfix | RF5-29 | B |
| RF5-31 | rvc-keygen `write_new_0600` helper; `create_new` on all platforms | 2 | bugfix | — | B |
| RF5-32 | rvc-keygen `GenerateArgs` struct for new/existing mnemonic | 2 | refactor | RF5-31 | B |

**Total: 32 issues, 80 points. Stream A: 16 issues, 41 points. Stream B: 16 issues, 39 points.**

## Execution Plan

Two streams, deliberately split along the two binaries so the file sets are disjoint.

- **Stream A** owns `bin/rvc/**` and `crates/rvc/**`: the F1 bootstrap chain (RF5-01 → RF5-10), then the
  F3 config chain (RF5-11 → RF5-15), then the F6 exit-command work (RF5-16 → RF5-17).
- **Stream B** owns `bin/rvc-signer/**`, `crates/keymanager-api/**`, `crates/validator-store/**` and
  `bin/rvc-keygen/**`: the keymanager ctor seam (RF5-02) first, then the F2 rvc-signer chain
  (RF5-18 → RF5-22, RF5-25) interleaved with the F4 config work (RF5-23 → RF5-24), then the
  keymanager-internal work (RF5-26 → RF5-28), validator-store (RF5-29 → RF5-30) and keygen
  (RF5-31 → RF5-32).

**The one cross-stream edge is RF5-02 → RF5-08.** Stream A's `spawn_keymanager_api` extraction should
move already-structified code, so B does the `KeymanagerServer::new(deps, settings)` change **first**
(it is dependency-free and touches only `crates/keymanager-api/src/server.rs:33-73` plus three call
sites). A's chain has six issues ahead of RF5-08, so B has ample slack.

Two shared-file contacts to coordinate at kickoff:

1. `bin/rvc/src/main.rs:1696-1711` — the 14-arg call site. RF5-02 (B) edits it; RF5-08 (A) then moves
   the whole block. B lands first; A rebases.
2. `crates/rvc/src/slashing_monitor.rs` — RF5-09 rewrites `check_slashed_validators:32` while RF5-11
   replaces `SlashedAction::FromStr:16`. Both are Stream A and RF5-11 is sequenced after RF5-09.

**Config work does not need to wait for the whole bootstrap chain.** F3 lives in
`crates/rvc/src/config/types.rs` and `bin/rvc/src/main.rs:43-718`, disjoint from F1's `:1055-1953`;
Stream A serializes them only because one developer owns both. If a third developer joins, RF5-11 →
RF5-13 can run in parallel with RF5-03 → RF5-09 — but RF5-14 must still follow RF5-10, because both
rewrite `main()`.

## Dependency Map

```text
Stream A (bin/rvc + crates/rvc)
RF5-01 smoke tests
  └─▶ RF5-03 ─▶ RF5-04 ─▶ RF5-05 ─▶ RF5-06 ─▶ RF5-07 ─┬─▶ RF5-08 ─┬─▶ RF5-10 ─┬─▶ RF5-14 ─▶ RF5-15
                                                       └─▶ RF5-09 ─┘           └─▶ RF5-16 ─▶ RF5-17
                                    RF5-09 ─▶ RF5-11 ─▶ RF5-12 ─▶ RF5-13 ─────────▶ RF5-14

Stream B (bin/rvc-signer + keymanager-api + validator-store + rvc-keygen)
RF5-02 (km ctor) ──────────────────────────────────────────▶ [RF5-08 in Stream A]
RF5-02 ─▶ RF5-26 ─▶ RF5-27 ─▶ RF5-28
RF5-18 ─▶ RF5-19 ─┬─▶ RF5-20 ─▶ RF5-21 ─▶ RF5-22 ─┬─▶ RF5-25
                  └─▶ RF5-23 ─▶ RF5-24 ───────────┘
RF5-29 ─▶ RF5-30
RF5-31 ─▶ RF5-32
```

**Critical path (longest dependency chain, 27 pts):**
`RF5-01 → RF5-03 → RF5-04 → RF5-05 → RF5-06 → RF5-07 → RF5-08 → RF5-10 → RF5-14 → RF5-15`.
Stream A's serialized total (41 pts) is the real schedule driver.

**Cross-phase dependencies:** B2 (P2) before RF5-03; E7 (P4) before RF5-07; D2/D3/D4 (P4) before RF5-19;
E8c (P4) before RF5-06 and RF5-26; SEC-1 (already merged, P5-A1) before RF5-08/RF5-26. Phase 6 items
H1 (handlers.rs test relocation), H3 (bin/rvc test relocation) and H7 (`keymanager_adapters/` module
dir) must land **after** this phase — they move the same files.

## Phase Risk Flags

- **RF5-03..RF5-10 is the biggest wiring risk in the whole plan.** `run_validator` carries ~40
  interdependent locals across non-adjacent phases (`epoch_clock` created at `:1359` is consumed at
  `:1647`; `doppelganger_window` computed at `:1637` is used at `:1707`; `forward_window_machine` from
  `:1401` is used at `:1649`). The failure mode is not a compile error — it is shipping the same
  god-blob renamed `BootstrapCtx`. RF5-03 fixes the context struct's shape and every later issue carries
  the checkable criterion "adds at most 3 named, doc-commented fields; no field is an `Option<T>` used
  as a phase-ordering flag."
- **Startup ordering is behavior.** Log line order, health-status transitions and fail-fast points are
  observable. RF5-01's golden startup-sequence assertion is what makes each extraction reviewable; it
  must be updated deliberately (with a note in the PR) rather than incidentally.
- **`cfg(feature = "dvt")` permutations in rvc-signer.** `run_serve:396-462` and `resolve_config:982-990`
  both have dvt/non-dvt arms. Every F2 and F4 issue must build and test under both feature sets; add
  `--features dvt` to the CI matrix for this chain if it is not already there.
- **RF5-25 puts rvc-signer under the layer policy for the first time** (F111). With 6 subsystems and 11
  thiserror enums, `crates/architecture-tests` may surface real violations rather than needing only a
  table entry.
- **Config-file backward compatibility** is the one thing operators feel immediately. RF5-12's serde
  aliases plus a fixture test loading a real pre-phase `rvc.toml` are non-negotiable.
- **RF5-30 changes hot-path locking.** `effective_config` is called per duty; a single `RwLock` over one
  state struct must not serialize readers that used to proceed independently. Benchmark or reason
  explicitly in the PR.

## Release-note items (deliberate behavior changes)

1. **RF5-23 (F4):** an explicitly passed CLI value that happens to equal the built-in default now wins
   over the config file (`rvc-signer --config f.toml --listen-address 127.0.0.1:50052` previously took
   the file's value). Bug fix; operators relying on the old precedence must remove the flag.
2. **RF5-31 (F21):** on non-unix platforms, writing a signed voluntary exit or BLS-to-execution change
   to an existing path now **fails** instead of silently overwriting.
3. **RF5-11 (F9):** invalid `slashed_validators_action` / `broadcast` / `tracing_exporter` values now
   fail at deserialization with a serde error naming the field, not later in `Config::validate()`. The
   set of accepted values is unchanged; the error text and failure point are not.

---

## Issues

### Issue RF5-01: CLI startup smoke tests against a mock beacon node

- **Points:** 3 · **Scope:** ~2 days · **Type:** test · **Stream:** A
- **Plan item:** F1 (guard) — pulls H3's "real CLI-level tests" forward, per the Phase 5 note
  "H3's CLI tests (pull forward the startup smoke test) guard each step"
- **Findings:** F13, F17 (partial)
- **Blocked by:** none · **Blocks:** RF5-03 (and therefore the entire F1 chain)

**Files to touch:**
- `bin/rvc/tests/integration_test.rs` — `get_binary_path:8-15` (keep), `create_test_config:17-35`,
  `spawn_validator:36-45`, `wait_for_http_endpoint:59-71`, and the three `#[ignore]`d tests at `:129`,
  `:172`, `:212`.
- New `bin/rvc/tests/common/mock_bn.rs` — a `wiremock`-backed beacon node stub.
- `bin/rvc/Cargo.toml` — `wiremock`, `reqwest` (blocking), `tempfile`, `tokio-util` are already
  dev-dependencies; no new dependency should be required.

**What / why:**
The F1 chain moves ~900 lines of startup wiring one phase at a time. Without an executable definition
of "the binary still starts and stops cleanly", each step is reviewed by eye. The harness already
exists (`CARGO_BIN_EXE_rvc`), but the three startup tests are ignored because startup cannot get past
beacon reachability and genesis-root validation (`bin/rvc/src/main.rs:1164-1221`) with no BN. This
issue supplies a mock BN, un-ignores the tests, and adds the startup-sequence assertion that makes
every later extraction reviewable.

**Implementation sketch:**
1. `mock_bn.rs` serves the endpoints startup requires: `/eth/v1/beacon/genesis` (genesis time +
   genesis_validators_root matching the test config), `/eth/v1/config/spec`,
   `/eth/v1/config/fork_schedule`, `/eth/v1/node/syncing`, `/eth/v1/node/version`, and
   `POST /eth/v1/beacon/states/head/validators`. Expose `MockBn::start() -> (Url, MockBn)` and a
   `with_fork(ForkName)` builder so RF5-07 can exercise the fork-compat gate.
2. Extend `create_test_config` to point `beacon_url` at the mock, use `--init-slashing-db` for the
   fresh-DB path (SEC-3), pick ports via `:0`-bind-then-release or a per-test offset, and default
   `keymanager_enabled = false`.
3. Un-ignore the three tests. Assert: `/health` reachable, `/metrics` served, `SIGTERM` → exit code 0
   within a bounded timeout, and stderr contains the startup markers in order
   (`"Starting validator client"` → slashing-DB ready → beacon connected → validators loaded →
   duty loop started).
4. Add `test_startup_fails_closed_on_genesis_root_mismatch` (mock returns a different GVR → non-zero
   exit) so the smoke suite also pins a fail-closed path, not only the happy path.
5. Keep the golden marker list in one `const STARTUP_SEQUENCE: &[&str]` so later issues update it in one
   place with an explicit diff.

**Acceptance criteria:**
- [x] No `#[ignore]` remains on the three startup tests; they pass in a normal `cargo nextest run`
      with no network access.
- [x] Clean start and clean SIGTERM shutdown (exit code 0) asserted, with a bounded timeout.
- [x] Startup log markers asserted **in order** from a single named constant.
- [x] A genesis-root mismatch exits non-zero (fail-closed pin).
- [x] Tests are hermetic and parallel-safe (no fixed global ports, no shared temp paths).
- [x] Workspace green on the standing invariant.

**TDD test plan** (RED first):
- `test_startup_reaches_ready_against_mock_bn` — **RED**: fails today because the ignored test cannot
  reach a BN; goes green once `mock_bn` is served.
- `test_startup_sequence_markers_in_order`
- `test_graceful_shutdown_sigterm_exit_code_zero`
- `test_startup_fails_closed_on_genesis_root_mismatch`
- `test_metrics_and_health_endpoints_served`

**Risks:** flaky timing under loaded CI — use polling with a generous deadline, never fixed sleeps
(the current `std::thread::sleep(Duration::from_secs(2))` at `integration_test.rs:139` is exactly the
pattern to remove). Port collisions under `nextest`'s parallelism — allocate ports per test.

---

### Issue RF5-02: `KeymanagerServer::new(deps, settings)` replaces 14 positional args

- **Points:** 2 · **Scope:** ~1 day · **Type:** refactor · **Stream:** B
- **Plan item:** F5 (part) · **Findings:** F76
- **Blocked by:** none · **Blocks:** RF5-08 (Stream A), RF5-26

**Files to touch:**
- `crates/keymanager-api/src/server.rs:33-73` — the `#[allow(clippy::too_many_arguments)]` constructor.
- `bin/rvc/src/main.rs:1696-1711` — the production call site.
- `crates/keymanager-api/src/handlers.rs:2635`, `:2675` — the two test call sites.

**What / why:**
`KeymanagerServer::new` takes 7 trait objects + token + addr + cors_origins + body_limit +
`allow_insecure_remote_signer` + `attesting_enabled` + `doppelganger_window` positionally. Adjacent
same-typed parameters (two bools, a `usize` and a `Duration`) can be transposed without a compile
error, and the last three were appended by security fixes — the signature grows at every call site.
Doing this **first** in Stream B means Stream A's RF5-08 moves already-clean code.

**Implementation sketch:**
1. `pub struct KeymanagerDeps` — the 7 `Arc<dyn …>` objects (`keystore_manager`, `slashing_protection`,
   `validator_manager`, `doppelganger_monitor`, `remote_key_manager`, `config_manager`,
   `exit_manager: Option<…>`).
2. `pub struct KeymanagerSettings` — `token`, `addr`, `cors_origins`, `body_limit`,
   `allow_insecure_remote_signer`, `attesting_enabled`, `doppelganger_window`, with a `Default` impl
   using `DEFAULT_ADDR:20` and `DEFAULT_BODY_LIMIT:23`.
3. `pub fn new(deps: KeymanagerDeps, settings: KeymanagerSettings) -> Self`; drop the
   `#[allow(clippy::too_many_arguments)]`. `AppState` construction (`:52-67`) is unchanged.
4. Update the three call sites. No behavior change; the router (`:75-125`) and `run` (`:127`) are
   untouched.

**Acceptance criteria:**
- [x] `#[allow(clippy::too_many_arguments)]` is gone from `server.rs`.
- [x] `KeymanagerServer::new` takes exactly two arguments; all fields are named at every call site.
- [x] `KeymanagerSettings::default()` supplies addr and body limit from the existing constants.
- [x] No behavioral change: existing keymanager tests pass untouched except for construction syntax.
- [x] Workspace green.

**TDD test plan** (RED first):
- `test_keymanager_settings_default_uses_declared_constants` — **RED**: `KeymanagerSettings` does not
  exist yet.
- `test_server_new_from_deps_and_settings_builds_same_router` (route table equality against the
  pre-change router — a snapshot of the 8 registered paths)
- Existing `crates/keymanager-api/tests/*` suites pass unchanged.

**Risks:** none material. Keep the struct field order matching the old parameter order to make the diff
reviewable.

---

### Issue RF5-03: `rvc::bootstrap` module + `open_slashing_db` phase

- **Points:** 2 · **Scope:** ~1 day · **Type:** refactor · **Stream:** A
- **Plan item:** F1 · **Findings:** F13
- **Blocked by:** RF5-01, and cross-phase B2 (P2) · **Blocks:** RF5-04

**Files to touch:**
- New `crates/rvc/src/bootstrap/mod.rs` and `crates/rvc/src/bootstrap/slashing.rs`; register in
  `crates/rvc/src/lib.rs` next to `startup.rs`.
- `bin/rvc/src/main.rs:1102-1163` — Step 1 (`build_slashing_db`), Step 2 (`check_integrity`),
  Step 2a (strict semantics), Step 2b (permissions), Step 2c (keystore lock), Step 2d (denylist load).

**What / why:**
First extraction, and the one that fixes the shape of everything after it. `open_slashing_db` is the
cleanest phase boundary: its inputs are `&Config` + two CLI booleans, its outputs are the DB handle,
the keystore lock guard and the denylist — no dependency on the beacon node or on keys.

**Implementation sketch:**
1. Define the context type in `bootstrap/mod.rs`:
   ```rust
   /// Values produced by one bootstrap phase and consumed by later ones.
   /// Invariant: every field is populated by exactly one phase and never reassigned.
   pub struct BootstrapCtx { /* … */ }
   ```
   Each phase function takes `&Config` plus what it needs by explicit parameter and **returns** a small
   named output struct; `run()` moves those outputs into `BootstrapCtx`. Phases never take
   `&mut BootstrapCtx`.
2. `pub fn open_slashing_db(config: &Config, strict_permissions: bool, strict_slashing_semantics: bool)
   -> Result<SlashingDbHandles, BootstrapError>` returning `{ db, keystore_lock, denylist }`.
   Health-status updates stay in `main.rs` for now via a returned outcome, or take a
   `&SharedHealthStatus` parameter — pick one in this issue and keep it for all later phases.
3. `main.rs` calls it and keeps the surrounding logging identical (same messages, same order).
4. Unit-test the phase directly in `crates/rvc` with `tempfile` dirs: fresh-DB refusal without
   `allow_fresh_db`, integrity failure, permission strictness, lock contention.

**Acceptance criteria:**
- [ ] `bootstrap::open_slashing_db` exists in `crates/rvc` and is unit-tested without spawning a binary.
- [ ] `main.rs:1102-1163` is replaced by one call; log lines and their order are byte-identical.
- [ ] `BootstrapCtx` is documented with the "populated once, never reassigned" invariant; it has no
      `Option<T>` field used as a phase-ordering flag.
- [ ] RF5-01's smoke tests pass unchanged (including the startup-marker order).
- [ ] Workspace green.

**TDD test plan** (RED first):
- `test_open_slashing_db_refuses_missing_path_without_allow_fresh_db` — **RED**: the function does not
  exist; today this behavior is only reachable by spawning the binary.
- `test_open_slashing_db_rejects_corrupt_header`
- `test_open_slashing_db_enforces_strict_permissions`
- `test_open_slashing_db_acquires_keystore_lock_and_reports_contention`
- `test_open_slashing_db_loads_existing_denylist`

**Risks:** the health-status plumbing decision made here propagates to five later issues — state it in
the PR description explicitly. `crates/rvc` must not gain a dependency on `bin/rvc`-only types.

---

### Issue RF5-04: `bootstrap::connect_beacon` phase + single GVR parse

- **Points:** 2 · **Scope:** ~1 day · **Type:** refactor · **Stream:** A
- **Plan item:** F1 · **Findings:** F13 (double GVR parse)
- **Blocked by:** RF5-03 · **Blocks:** RF5-05

**Files to touch:**
- New `crates/rvc/src/bootstrap/beacon.rs`.
- `bin/rvc/src/main.rs:1164-1221` — Step 3 (beacon client + BnManager), Step 4 (genesis-root
  validation, with the duplicated parse at `:1186-1211`), Step 5 (reachability), version log `:1216`.
- `crates/rvc/src/startup.rs` — reuse the existing genesis/GVR helpers rather than duplicating them.

**What / why:**
`run_validator` parses the genesis validators root twice with two copies of the error handling. Making
the phase return a single typed `[u8; 32]` (plus its canonical hex, which `main.rs:1631` later needs for
`SlashingProtectionAdapter`) removes the duplication and gives the fail-closed chain-swap gate a
unit-testable home.

**Implementation sketch:**
1. `pub async fn connect_beacon(config: &Config, timeouts: OperationTimeouts)
   -> Result<BeaconHandles, BootstrapError>` returning `{ beacon_client, bn_manager,
   genesis_validators_root: [u8; 32], genesis_validators_root_hex: String, genesis_time }`.
2. Parse the GVR exactly once; the hex form is the canonical lowercase `0x`-prefixed encoding (aligns
   with C8's `CanonicalGvr` from Phase 3 — use it if it has landed).
3. Keep the reachability check and the non-fatal version log inside the phase, with identical messages.
4. Mock-BN-backed unit tests in `crates/rvc` using `wiremock` (already a dev-dependency there or add it).

**Acceptance criteria:**
- [ ] The genesis validators root is parsed in exactly one place
      (`rg 'genesis_validators_root' bin/rvc/src/main.rs` shows no parse).
- [ ] Chain-swap mismatch remains fatal, with the same message and exit path.
- [ ] Beacon unreachable produces the same error as today.
- [ ] RF5-01 smoke tests green, including the mismatch case added there.
- [ ] Workspace green.

**TDD test plan** (RED first):
- `test_connect_beacon_rejects_genesis_root_mismatch` — **RED**: no such function today.
- `test_connect_beacon_parses_gvr_once_into_bytes_and_hex` (hex form equals the lowercase canonical
  encoding of the byte form)
- `test_connect_beacon_reports_unreachable_node`
- `test_connect_beacon_version_log_is_non_fatal_on_error`

**Risks:** `BnManager` construction pulls in the timeouts and multi-node config; keep the signature
`(&Config, OperationTimeouts)` rather than 6 scalars.

---

### Issue RF5-05: `bootstrap::load_signing_keys` phase

- **Points:** 3 · **Scope:** ~1.5–2 days · **Type:** refactor · **Stream:** A
- **Plan item:** F1 · **Findings:** F13 (two `Arc::try_unwrap` ownership dances)
- **Blocked by:** RF5-04 · **Blocks:** RF5-06

**Files to touch:**
- New `crates/rvc/src/bootstrap/keys.rs`.
- `bin/rvc/src/main.rs:1222-1341` — keystore-dir loading (`:1222`, denylist-aware), eager
  secret-provider metrics (`:1237`), cloud-provider loading (`:1240`), the two `Arc::try_unwrap`
  dances (`:1247`, `:1283`), `CompositeSigner` construction (`:1282`), gRPC remote-signer connect and
  key registration (`:1291-1341`).

**What / why:**
The densest phase: two ownership dances exist only because the key manager is shared with the provider
loader and then needs to be consumed. Extracting it into a function whose signature states
"consume the loaders, produce one `Arc<CompositeSigner>`" makes the ownership linear and removes the
`unwrap_or_else(|_| panic!(…))`-adjacent patterns (`main.rs:1283-1285` already uses an anyhow error —
keep that behavior, do not reintroduce a panic).

**Implementation sketch:**
1. `pub async fn load_signing_keys(config: &Config, denylist: &DeletionDenylist)
   -> Result<LoadedKeys, BootstrapError>` returning `{ composite_signer, validator_count,
   local_pubkeys, grpc_signer: Option<…> }`.
2. Build the key manager locally, run the keystore-dir loader and the secret-provider loader against
   it, then construct `CompositeSigner` by value — no `Arc::try_unwrap` needed at all. If a shared
   handle is still required by a provider API, own it inside the phase and unwrap once, returning a
   typed error instead of a panic.
3. Keep the gRPC remote-signer connect non-fatal (lazy connection) with the same v2 contract-version
   check and the same log lines (`:1311-1341`).
4. Eager secret-provider metric initialization (`:1237`) stays inside the phase so `/metrics` output is
   unchanged.

**Acceptance criteria:**
- [ ] `rg 'Arc::try_unwrap' bin/rvc/src/main.rs` returns nothing.
- [ ] No `panic!`/`expect` added; failure modes return `BootstrapError` variants.
- [ ] Denylisted keys are still skipped for both keystore-dir and secret-provider sources (SEC-1b
      regression test moved or duplicated at the phase level).
- [ ] gRPC signer connect failure is still non-fatal and logs identically.
- [ ] `/metrics` still exposes the secret-provider series before any provider call.
- [ ] RF5-01 smoke tests green.

**TDD test plan** (RED first):
- `test_load_signing_keys_skips_denylisted_pubkeys` — **RED**: no phase function exists; today this is
  covered only through the binary.
- `test_load_signing_keys_returns_owned_composite_signer_without_try_unwrap`
- `test_load_signing_keys_grpc_connect_failure_is_non_fatal`
- `test_load_signing_keys_registers_remote_signer_keys_in_composite`
- `test_load_signing_keys_initializes_secret_provider_metrics_eagerly`

**Risks:** the `gcp-secret` feature gates part of this path — build and test with and without it.
Ownership restructuring can subtly change *when* a keystore file handle is dropped; assert the keystore
lock is still held for the whole phase.

---

### Issue RF5-06: `bootstrap::wire_signing_enablement` phase

- **Points:** 3 · **Scope:** ~1.5–2 days · **Type:** refactor · **Stream:** A
- **Plan item:** F1 · **Findings:** F13
- **Blocked by:** RF5-05, and cross-phase E8c (P4) · **Blocks:** RF5-07

**Files to touch:**
- New `crates/rvc/src/bootstrap/enablement.rs`.
- `bin/rvc/src/main.rs:1342-1474` — validator-index resolution (`:1342`), the SEC-2b/2c block
  (`:1346-1430`: monotonic epoch clock `:1359`, index map `:1366`, `ForwardWindowMachine` construction
  and restart-aware safe-skip `:1401-1415`, liveness loop spawn `:1416-1430`), secret-provider refresh
  registration (`:1431-1474`).
- `crates/rvc/src/liveness_loop.rs`, `crates/rvc/src/doppelganger_adapter.rs` — consumed, not changed.

**What / why:**
This is the security-critical phase (SEC-2b/2c): it decides which keys may sign and when. It is also
where the cross-phase locals originate — `epoch_clock` and `forward_window_machine` are created here and
consumed by the keymanager phase (RF5-08). Extracting it with an explicit output struct is what lets
RF5-08 stop reaching into `run_validator`'s locals.

**Implementation sketch:**
1. `pub async fn wire_signing_enablement(config: &Config, keys: &LoadedKeys, beacon: &BeaconHandles,
   slashing_db: &SlashingDb, shutdown: &CancellationToken) -> Result<Enablement, BootstrapError>`
   returning `{ enablement: Arc<dyn SigningEnablement>, forward_window_machine: Option<Arc<…>>,
   epoch_clock: Arc<…>, pubkey_map, liveness_task }`.
2. Preserve exactly: the fail-closed default when the machine is absent, the epoch-0 bypass, the
   restart-aware safe-skip semantics and its warning comment (`:1404-1415`), and the import-strict rule
   for dynamically added keys (`:1465`).
3. The liveness loop keeps going through `bn_manager` (multi-BN failover) and keeps re-resolving indices
   after keymanager import.
4. Unit-test the phase against a mock liveness source rather than the full binary.

**Acceptance criteria:**
- [ ] Doppelganger opt-out still yields an explicit always-enabled enablement, and the default with the
      feature on is still fail-closed for unregistered keys.
- [ ] Epoch-0 bypass and restart safe-skip behavior are unchanged (tests assert both).
- [ ] The liveness loop is spawned with the same cancellation wiring and terminates on shutdown.
- [ ] `BootstrapCtx` gains at most 3 named fields from this phase.
- [ ] RF5-01 smoke tests green.

**TDD test plan** (RED first):
- `test_wire_signing_enablement_returns_fail_closed_machine_by_default` — **RED**: no phase function.
- `test_wire_signing_enablement_optout_yields_always_enabled`
- `test_wire_signing_enablement_preserves_epoch0_bypass`
- `test_wire_signing_enablement_restart_safe_skip_requires_local_history`
- `test_liveness_task_cancels_on_shutdown_token`

**Risks:** highest-consequence phase in the chain — a mis-wire here silently disables the doppelganger
gate. Require that the SEC-2 test suite (`crates/doppelganger/**`, the enablement tests in
`crates/signer`) runs green **and** that a reviewer diffs the enablement construction line by line.
E8c (P4) may already have reshaped `startup.rs:139`; rebase onto it rather than around it.

---

### Issue RF5-07: `bootstrap::build_services` phase

- **Points:** 3 · **Scope:** ~1.5–2 days · **Type:** refactor · **Stream:** A
- **Plan item:** F1 · **Findings:** F13
- **Blocked by:** RF5-06, and cross-phase E7 (P4) · **Blocks:** RF5-08, RF5-09

**Files to touch:**
- New `crates/rvc/src/bootstrap/services.rs`.
- `bin/rvc/src/main.rs:1475-1593` — Step 7 service build (`:1475`), D-3 per-validator registration
  (`:1481-1509`), the fatal fork-compat gate (`:1510-1524`, calling `apply_fork_compatibility_result:1035`),
  proposer `BnManager` (`:1525-1540`), beacon-adapter selection (`:1541-1569`), Step 7b remote signer
  (`:1570-1581`), Step 7b2 attesting toggle (`:1582-1593`).
- `crates/rvc/src/config/builder.rs` — `build_*` methods consumed (post-B2 they are the only bootstrap).

**What / why:**
The remaining pre-orchestrator wiring. After E7 the proposer path goes through `BnManager` failover, so
the awkward "create a new `BeaconClient` from the first proposer endpoint" comment block
(`main.rs:1545-1569`) should already be gone — if E7 has not landed, this issue must not paper over it.

**Implementation sketch:**
1. `pub async fn build_services(config: &Config, ctx: &BootstrapCtx)
   -> Result<Services, BootstrapError>` returning `{ signer, validator_store, beacon_adapter,
   proposer_bn_manager, attesting_enabled, orchestrator_config }`.
2. Keep `apply_fork_compatibility_result` in `bin/rvc` or move it to `crates/rvc` with the phase — but
   **do not change `startup::check_fork_compatibility` itself** (explicit instruction in
   `main.rs:1512`).
3. Preserve D-3: every keystore-loaded validator is registered with the validator store so the
   fail-closed per-validator gate permits them (`:1481-1509`). This is a silent-no-signing footgun if
   dropped — assert it in a test.
4. Keep the attesting toggle `Arc<AtomicBool>` shared with the orchestrator and the keymanager API.

**Acceptance criteria:**
- [ ] Unknown-fork startup is still fatal by default and still opt-out-able via `allow_unsupported_fork`.
- [ ] Every keystore-loaded validator is registered in the validator store (regression test).
- [ ] The proposer path uses the proposer `BnManager` (E7 semantics), not a hand-built client.
- [ ] The attesting toggle is one `Arc<AtomicBool>` shared by orchestrator and keymanager.
- [ ] RF5-01 smoke tests green, including the fork-mismatch case from `MockBn::with_fork`.

**TDD test plan** (RED first):
- `test_build_services_registers_all_loaded_validators` — **RED**: no phase function; the D-3 rule is
  currently only implicit in `run_validator`.
- `test_build_services_fork_mismatch_is_fatal_by_default`
- `test_build_services_fork_mismatch_allowed_with_optout`
- `test_build_services_proposer_path_uses_proposer_bn_manager`
- `test_attesting_toggle_shared_between_orchestrator_and_keymanager`

**Risks:** if E7 slips, this issue inherits the proposer-failover bug and must be re-done. Do not start
it before E7 merges.

---

### Issue RF5-08: `bootstrap::spawn_keymanager_api` phase

- **Points:** 2 · **Scope:** ~1 day · **Type:** refactor · **Stream:** A
- **Plan item:** F5 (F18 half) executed inside the F1 chain · **Findings:** F18, F76
- **Blocked by:** RF5-02 (Stream B), RF5-07, SEC-1 (satisfied — merged `e0b06e0`/`6d77dad`, see P5-A1)
  · **Blocks:** RF5-10

**Files to touch:**
- `crates/rvc/src/keymanager_adapters.rs` — new `pub fn spawn_keymanager_api(...)` (the adapters already
  live here); `scan_and_rearm_gate` is already public here.
- `bin/rvc/src/main.rs:1594-1721` — the whole Step 7c block, including the verbatim-duplicated
  `scan_and_rearm_gate` calls at `:1656-1662` and `:1668-1674`, and the (now struct-based) server
  construction at `:1696-1711`.

**What / why:**
127 inline lines that construct six adapters, choose a doppelganger monitor, and spawn a server — with
the re-arm call copy-pasted into both branches of the monitor selection. It belongs next to the
adapters it builds. Because RF5-02 already replaced the 14 positional arguments, this issue is pure
motion plus the branch hoist.

**Implementation sketch:**
1. `pub fn spawn_keymanager_api(config: &Config, deps: KeymanagerApiDeps) -> anyhow::Result<()>` where
   `KeymanagerApiDeps` carries `composite_signer`, `slashing_db`, `genesis_validators_root_hex`,
   `validator_store`, `beacon_client`, `signer`, `fork_schedule`, `genesis_validators_root`,
   `deletion_denylist`, `attesting_enabled`, `forward_window_machine`, `epoch_clock`.
2. Compute `doppelganger_window` once, select the monitor (`ForwardWindowMonitor` vs
   `DoppelgangerGate`), and call `scan_and_rearm_gate` **once** after the branch, guarded by the same
   `!doppelganger_window.is_zero()` condition.
3. Keep the non-loopback bind warning and the token-file ensure/permission-warn behavior identical.
4. `main.rs` keeps only `if config.keymanager_enabled { rvc::keymanager_adapters::spawn_keymanager_api(&config, deps)?; }`.

**Acceptance criteria:**
- [ ] `scan_and_rearm_gate` is called from exactly one site
      (`rg -c 'scan_and_rearm_gate' bin/rvc/src/main.rs` = 0; one call in `keymanager_adapters.rs`
      outside the definition).
- [ ] Both monitor variants are still selectable and both re-arm on restart.
- [ ] Token ensure + insecure-permission warning + non-loopback warning preserved verbatim.
- [ ] With `keymanager_enabled = false`, nothing is constructed or spawned (test).
- [ ] RF5-01 smoke tests green; add a keymanager-enabled variant.

**TDD test plan** (RED first):
- `test_spawn_keymanager_api_rearms_gate_exactly_once_for_both_monitors` — **RED**: the duplicated call
  currently makes "exactly once per branch" untestable outside the binary.
- `test_spawn_keymanager_api_disabled_constructs_nothing`
- `test_spawn_keymanager_api_warns_on_non_loopback_bind`
- `test_spawn_keymanager_api_uses_forward_window_monitor_when_machine_present`

**Risks:** the deps struct is wide (12 fields); it is a parameter object for one call, not a new
god-object — do not let other phases start reading from it.

---

### Issue RF5-09: `slashing_monitor::spawn` + `SlashedOutcome` enum

- **Points:** 2 · **Scope:** ~1 day · **Type:** refactor · **Stream:** A
- **Plan item:** F1 (slashing-monitor half) · **Findings:** F22
- **Blocked by:** RF5-07 · **Blocks:** RF5-10, RF5-11

**Files to touch:**
- `crates/rvc/src/slashing_monitor.rs:32` — `check_slashed_validators(&watch::Sender<bool>, …)`.
- `bin/rvc/src/main.rs:1751-1811` — Step 8b: the `watch::channel(false)` with an immediately dropped
  receiver (`:1760-1764`), the `*tx.borrow()` poll (`:1787`), the hardcoded
  `Duration::from_secs(12) * 32` (`:1768-1769`), and the inline epoch-tick loop.

**What / why:**
A `watch::Sender` whose receiver is dropped at creation is being used as a shared mutable bool; the
in-file comment even says "We'll re-purpose". The contract ("did this check request shutdown?") should
be the return type. The loop also hardcodes slot/epoch timing that `eth_types::SECONDS_PER_SLOT` /
`SLOTS_PER_EPOCH` already provide and that the same file uses correctly at `:1640-1641`.

**Implementation sketch:**
1. `pub enum SlashedOutcome { NoAction, ShutdownRequested }`; change `check_slashed_validators` to
   return it and drop the `&watch::Sender<bool>` out-parameter.
2. `pub fn spawn(beacon, store, action, shutdown_token) -> JoinHandle<()>` in `slashing_monitor`,
   owning the epoch-tick loop and using `eth_types::SECONDS_PER_SLOT * SLOTS_PER_EPOCH`.
3. `main.rs` keeps one `rvc::slashing_monitor::spawn(...)` call.
4. Leave `SlashedAction`'s stringly `FromStr` alone here — RF5-11 replaces it.

**Acceptance criteria:**
- [ ] No `watch::channel` remains in `bin/rvc/src/main.rs` for the slashing monitor.
- [ ] Epoch tick derives from `eth_types` constants; no `from_secs(12)` literal remains in the loop.
- [ ] `ShutdownRequested` cancels the `CancellationToken` and the main `select!` still exits cleanly.
- [ ] The configured `slashed_validators_action` semantics are unchanged for every value.

**TDD test plan** (RED first):
- `test_check_slashed_validators_returns_shutdown_requested_for_configured_action` — **RED**: the
  function returns `()` today and reports through a channel.
- `test_check_slashed_validators_returns_no_action_when_none_slashed`
- `test_spawn_uses_epoch_tick_from_eth_types_constants`
- `test_spawn_cancels_shutdown_token_on_shutdown_requested`

**Risks:** none material; this is the smallest genuinely behavior-preserving cleanup in the chain.
Verify the `select!` arm ordering in `main.rs` still prefers shutdown.

---

### Issue RF5-10: `bootstrap::spawn_background_tasks` + shutdown; main.rs < 600 lines

- **Points:** 3 · **Scope:** ~1.5–2 days · **Type:** refactor · **Stream:** A
- **Plan item:** F1 (final) · **Findings:** F13, F22
- **Blocked by:** RF5-08, RF5-09 · **Blocks:** RF5-14, RF5-16

**Files to touch:**
- New `crates/rvc/src/bootstrap/tasks.rs`; `crates/rvc/src/bootstrap/mod.rs` gains `pub async fn run(...)`.
- `bin/rvc/src/main.rs:1722-1953` — Step 8 duty loop (`:1722-1750`), metrics bind gate (`:1812-1848`),
  monitoring push task (`:1849-1868`), proposer-config refresh task (`:1869-1900`), broadcast-topic
  logging (`:1901-1939`), logging-guard drop + metrics shutdown (`:1940-1953`).
- `bin/rvc/src/main.rs:1055-1101` — the remaining preamble becomes `bootstrap::run`'s preamble.

**What / why:**
Closes the chain: `run_validator` disappears and `main.rs` becomes CLI parse + logging init + one
library call. The background tasks are the natural last phase because they only consume what earlier
phases produced.

**Implementation sketch:**
1. `pub fn spawn_background_tasks(config: &Config, ctx: &BootstrapCtx, shutdown: &CancellationToken)
   -> BackgroundTasks` — metrics server (with the ISSUE-4.10 non-loopback `InsecureGate`, preserved
   exactly, including the `with_predicate` env-var-only contract documented at `:1817-1822`), gRPC
   health service, monitoring push, proposer-config refresh.
2. `pub async fn run(config, flags, logging_guards) -> anyhow::Result<()>` composes
   `open_slashing_db → connect_beacon → load_signing_keys → wire_signing_enablement → build_services →
   spawn_keymanager_api → slashing_monitor::spawn → spawn_background_tasks`, then owns the `select!`
   and the graceful-shutdown sequence (including the metrics-server shutdown timeout at `:1944-1953`).
3. Logging guards stay owned by `main` and are passed in, so they drop at process scope and flush.
4. `main.rs` retains: clap types, `init_logging`, `load_config`, `build_tracing_config`,
   `build_file_layer_config`, `spawn_log_reload_handler`, `shutdown_signal`, and the dispatch.
5. Add a line-count assertion so the win does not regress.

**Acceptance criteria:**
- [ ] `run_validator` no longer exists; `bin/rvc/src/main.rs` is < 600 lines
      (CI check or a test asserting the count).
- [ ] The metrics non-loopback refusal behaves identically, including the env-var-only contract.
- [ ] Graceful shutdown order is unchanged: tasks cancelled → metrics server drained with timeout →
      logging guards dropped last.
- [ ] RF5-01 smoke tests green with **no change** to the startup-marker constant (any change is
      called out and justified in the PR).
- [ ] Manual mock-BN/devnet boot performed and recorded in the PR (phase-gate requirement).

**TDD test plan** (RED first):
- `test_bootstrap_run_starts_and_stops_cleanly_against_mock_bn` — **RED**: `bootstrap::run` does not
  exist; this is the first in-process (non-subprocess) startup test.
- `test_spawn_background_tasks_refuses_non_loopback_metrics_bind_without_env_optin`
- `test_spawn_background_tasks_all_tasks_cancel_on_shutdown`
- `test_main_rs_under_600_lines`
- `test_shutdown_drains_metrics_server_before_dropping_guards`

**Risks:** the `select!` and shutdown ordering is the last place where a subtle change turns a clean
exit into a hang. Keep the arms in the same order and assert the bounded shutdown in the smoke test.

---

### Issue RF5-11: Typed config enums

- **Points:** 2 · **Scope:** ~1 day · **Type:** refactor · **Stream:** A
- **Plan item:** F3 (part) · **Findings:** F9
- **Blocked by:** RF5-09 (both touch `slashing_monitor.rs`) · **Blocks:** RF5-12

**Files to touch:**
- `crates/rvc/src/config/types.rs:137` (`slashed_validators_action` field), `:515-530` (broadcast
  validation), `:547-555` (slashed-action validation), `:620-643` (`effective_broadcast_topics`),
  `:259-263` (`BeaconNodeEntry.roles`).
- `crates/rvc/src/slashing_monitor.rs:16-30` — `SlashedAction::FromStr`.
- `bin/rvc/src/main.rs` — the re-parse of the already-validated action string.

**What / why:**
Each stringly value has its valid set written twice — once in `Config::validate` and once in a
`FromStr`/match — and the two lists can drift independently. Making them serde enums moves the check to
deserialization and deletes the duplicate arms.

**Implementation sketch:**
1. `#[derive(Deserialize)] #[serde(rename_all = "kebab-case")]` enums: `SlashedAction`,
   `BroadcastTopic`, `TracingExporter`, `BnRole`. `SlashedAction` moves to (or is re-exported from)
   `config::types` so `slashing_monitor` and `main.rs` share one definition.
2. Use them directly as `Config` field types; delete the corresponding arms from `validate()` and the
   literal re-match in `effective_broadcast_topics`. `validate()` keeps only cross-field rules (e.g.
   `none` exclusivity in broadcast topics).
3. Accept the exact strings accepted today (verify each against the current lists) so only the failure
   point and message change.

**Acceptance criteria:**
- [ ] Every value accepted before is accepted now (table-driven test over the current literal lists).
- [ ] An invalid value fails at deserialization with the field named.
- [ ] `Config::validate` no longer contains value lists for these four settings; cross-field rules
      remain.
- [ ] `main.rs` does not re-parse an already-typed action.
- [ ] Release-note item 3 drafted.

**TDD test plan** (RED first):
- `test_invalid_slashed_action_fails_at_deserialization_not_validate` — **RED**: today a bad value
  parses fine and is only caught by `validate()`.
- `test_all_previously_accepted_slashed_actions_still_parse` (table-driven)
- `test_all_previously_accepted_broadcast_topics_still_parse`
- `test_broadcast_none_exclusivity_still_enforced_in_validate`
- `test_bn_role_and_tracing_exporter_round_trip`

**Risks:** a config file with an unknown-but-previously-ignored value now fails to load. Confirm none of
the four fields tolerated unknown values before (they did not — they were validated), and cover it in
the RF5-12 fixture test.

---

### Issue RF5-12: Nested config sub-structs + serde aliases + fixture test

- **Points:** 3 · **Scope:** ~1.5–2 days · **Type:** refactor · **Stream:** A
- **Plan item:** F3 (part) · **Findings:** F4
- **Blocked by:** RF5-11 · **Blocks:** RF5-13

**Files to touch:**
- `crates/rvc/src/config/types.rs:22-231` (the 63-field `Config`), `:338-406` (`Default`),
  `:279-296` (`SecretProviderConfig` — the existing nested precedent to follow).
- New `crates/rvc/tests/config_backward_compat.rs` + a fixture `crates/rvc/tests/fixtures/rvc-v0.6.toml`
  captured from a real production config.

**What / why:**
The 63 flat fields span eight unrelated concerns. Nesting them into `LogfileConfig`, `TracingConfig`,
`KeymanagerConfig`, `GrpcSignerConfig`, `ProposerConfigSource`, `MonitoringConfig`, `BuilderLimits`
(following `SecretProviderConfig`) is what makes RF5-15's generated merge tractable. Existing operator
TOML files use the flat keys, so **`#[serde(alias = "…")]` on every moved key plus a fixture test is the
load-bearing part of this issue** — not the struct surgery.

**Implementation sketch:**
1. Introduce the sub-structs with `#[serde(default)]`, and on each nested field add
   `#[serde(alias = "<old_flat_key>")]` so old TOML keeps loading. Where nesting changes the TOML shape
   (a flat key becoming `[logfile] max_size`), use a `#[serde(flatten)]`-compatible layout or a custom
   `Deserialize` shim — pick the approach that keeps **both** spellings valid and document it.
2. Capture a real pre-phase config as a fixture; assert every field resolves to the same value as
   before (compare against a hand-written expected `Config`).
3. Keep flat accessor methods (`config.tracing_sample_rate()`, `config.keymanager_enabled()`, …)
   delegating to the nested fields so the ~84 existing call sites keep compiling. **These shims are
   temporary and are deleted in RF5-13** — mark them `#[doc(hidden)]` with a `// removed in RF5-13`
   note so they cannot quietly become permanent.
4. `Default` is rebuilt from the sub-structs' own `Default` impls.

**Acceptance criteria:**
- [ ] A pre-phase production `rvc.toml` loads unchanged and produces field-for-field identical values
      (fixture test).
- [ ] Both the old flat key and the new nested key are accepted for every moved setting.
- [ ] `Config::default()` is unchanged in value for every field (assert field-by-field).
- [ ] Every accessor shim carries the RF5-13 removal marker.
- [ ] Workspace green with no call-site changes outside `types.rs`.

**TDD test plan** (RED first):
- `test_production_config_fixture_loads_with_flat_keys` — **RED**: written against the nested structs
  before they exist.
- `test_nested_keys_and_flat_aliases_produce_identical_config`
- `test_default_config_field_values_unchanged`
- `test_unknown_key_behavior_unchanged` (whatever the current policy is — pin it)

**Risks:** TOML shape changes are easy to get subtly wrong for `Option` fields and for tables that were
previously flat keys. If the alias approach cannot cover a specific key, keep that key flat and record
why in the PR — partial nesting is acceptable; a broken operator config is not.

---

### Issue RF5-13: Migrate call sites to nested config; delete the shims

- **Points:** 3 · **Scope:** ~1.5–2 days · **Type:** refactor · **Stream:** A
- **Plan item:** F3 (part) · **Findings:** F4
- **Blocked by:** RF5-12 · **Blocks:** RF5-14

**Files to touch:**
- `bin/rvc/src/main.rs`, `crates/rvc/src/config/builder.rs`, `crates/rvc/src/keymanager_adapters.rs`,
  `crates/rvc/src/orchestrator/coordinator.rs`, `crates/rvc/src/beacon_adapter.rs`,
  `crates/rvc/src/monitoring.rs`, `bin/rvc/tests/tier2_safety.rs`, `bin/rvc/tests/tier3_operations.rs`,
  and the `Config { … }` literals inside `crates/rvc/src/config/types.rs` tests.
- ~84 lines outside `types.rs` name a moved field (P5-A5); most sites use
  `Config { few_fields, ..Config::default() }` and only break if they name a moved field.

**What / why:**
Separating the migration from the introduction keeps both diffs reviewable: RF5-12 is "new types +
compatibility", RF5-13 is "mechanical, compiler-driven sweep". Deleting the shims is what actually
delivers the "one place per knob" property.

**Implementation sketch:**
1. Delete the shims from RF5-12; the compiler enumerates every site.
2. Update each site to the nested path. Prefer constructing sub-structs directly in test literals
   (`Config { keymanager: KeymanagerConfig { enabled: true, ..Default::default() }, ..Config::default() }`).
3. Where a test named five fields across three concerns, consider a small test-local builder rather than
   a deeper literal — but do not add a general-purpose config builder in this issue.
4. Re-run the RF5-12 fixture test unchanged; it must not need edits.

**Acceptance criteria:**
- [ ] No accessor shim remains (`rg 'removed in RF5-13'` is empty).
- [ ] `rg` finds no reference to a moved flat field name outside serde aliases.
- [ ] RF5-12's fixture test passes **without modification**.
- [ ] RF5-01 smoke tests green.
- [ ] Workspace green including `--all-targets`.

**TDD test plan** (RED first):
- `test_no_flat_field_accessors_remain` — **RED**: a source-grep test that fails while the shims exist.
- Existing tier2/tier3 suites pass after migration (they are the real coverage here).
- `test_builder_reads_nested_config_sections` (one representative per sub-struct)

**Risks:** pure churn with a large diff; land it as its own PR with no other change so review can be
"does it still compile and do the suites pass". Coordinate timing with any in-flight Phase 6 work that
touches the same test files.

---

### Issue RF5-14: `Start(StartArgs)` with flattened clap groups

- **Points:** 3 · **Scope:** ~1.5–2 days · **Type:** refactor · **Stream:** A
- **Plan item:** F3 (part) · **Findings:** F14
- **Blocked by:** RF5-10, RF5-13 · **Blocks:** RF5-15

**Files to touch:**
- `bin/rvc/src/main.rs:40` (`#[allow(clippy::large_enum_variant)]`), `:43-391` (the ~90-field inline
  `Start` variant), `:506-582` (the 76-binding destructure), `:628-718` (the hand-written
  `CliOverrides` literal with the repeated `if flag { Some(true) } else { None }` conversions).
- `crates/rvc/src/config/types.rs:946-1016` — `CliOverrides`.

**What / why:**
Adding one flag touches five places. Replacing the inline variant with `Start(StartArgs)` where
`StartArgs` is a `#[derive(clap::Args)]` struct of `#[command(flatten)]` groups deletes the destructure
and the literal outright, and lets the clap groups mirror RF5-12's config sub-structs one-for-one.

**Implementation sketch:**
1. `#[derive(clap::Args)] struct StartArgs` composed of `LoggingArgs`, `TracingArgs`, `KeymanagerArgs`,
   `GrpcSignerArgs`, `ProposerArgs`, `MonitoringArgs`, `BuilderArgs`, `SlashingArgs`, `BeaconArgs` —
   named to match the config sub-structs.
2. `impl From<StartArgs> for CliOverrides` replaces `:628-718`; the bool→`Option<bool>` conversions
   become a helper (`fn flag(b: bool) -> Option<bool>`) or, better, `Option<bool>` clap args where the
   flag genuinely has three states.
3. `Commands::Start(StartArgs)` removes the need for `#[allow(clippy::large_enum_variant)]`.
4. `--help` output must not change: assert the full flag list is preserved (the existing
   `test_start_help` at `integration_test.rs:96` is the seed — extend it to the complete flag set).

**Acceptance criteria:**
- [ ] `#[allow(clippy::large_enum_variant)]` is gone.
- [ ] The destructure block and the `CliOverrides` literal are deleted.
- [ ] Every flag accepted before is still accepted with the same name, short form, default and help
      text (snapshot test over `--help`).
- [ ] Flag precedence over the config file is unchanged for every flag (spot-checked by test).
- [ ] RF5-01 smoke tests green.

**TDD test plan** (RED first):
- `test_start_help_lists_every_flag` — **RED**: extend the existing help test to a complete snapshot
  before restructuring, so any dropped flag fails loudly.
- `test_start_args_convert_to_equivalent_cli_overrides` (build `StartArgs` from an argv vector; compare
  the resulting `CliOverrides` to the pre-change literal's output)
- `test_boolean_flags_absent_yield_none_not_some_false`
- `test_clap_groups_mirror_config_sections`

**Risks:** silently dropping a flag is the failure mode, and it is invisible until an operator's
existing command line breaks. The `--help` snapshot is the guard — write it first and review the
snapshot diff line by line.

---

### Issue RF5-15: Macro-generated merge + `tracing_sample_rate: Option<f64>` + OTEL precedence

- **Points:** 3 · **Scope:** ~1.5–2 days · **Type:** refactor · **Stream:** A
- **Plan item:** F3 (final) · **Findings:** F4, F20
- **Blocked by:** RF5-14 · **Blocks:** none

**Files to touch:**
- `crates/rvc/src/config/types.rs:651-925` — the 275-line `merge_with_cli`.
- `bin/rvc/src/main.rs:942-956` — `build_tracing_config` and the
  `(sample_rate - 0.01).abs() < f64::EPSILON` sentinel; `:943-946` — the
  `OTEL_EXPORTER_OTLP_ENDPOINT` fallback; the `default_value_t = 0.01` clap attribute (in the
  `TracingArgs` group after RF5-14).

**What / why:**
`merge_with_cli` is 275 lines of `if let Some(x) = cli.x { self.x = x }`; a field added to one struct
and forgotten in the merge fails silently. And the sample-rate sentinel means an operator who
explicitly passes `--tracing-sample-rate 0.01` is silently overridden by `OTEL_TRACES_SAMPLER_ARG`,
because "equals the default" is being used as a proxy for "not set".

**Implementation sketch:**
1. A `macro_rules! merge_fields!` taking the field list once, generating the `Option`-overwrite arms per
   sub-struct. The field list lives adjacent to the struct definition so a new field that is not listed
   is a compile error (e.g. via an exhaustive destructure of `CliOverrides` inside the macro expansion).
2. Make `tracing_sample_rate: Option<f64>` end-to-end: drop `default_value_t`, apply the 0.01 fallback
   at resolution time.
3. Move the `OTEL_TRACES_SAMPLER_ARG` and `OTEL_EXPORTER_OTLP_ENDPOINT` fallbacks out of the binary into
   config resolution (or the telemetry crate) so all precedence lives in one place. Precedence:
   explicit CLI > config file > `OTEL_*` env > built-in default.
4. Fold in the small telemetry `anyhow` → `thiserror` rider the plan attaches to this phase
   (§5, F116 first half) **only if** it stays under the point budget; otherwise split it out and say so.

**Acceptance criteria:**
- [ ] `merge_with_cli` is generated from one field list; adding a `CliOverrides` field without listing it
      fails to compile.
- [ ] `--tracing-sample-rate 0.01` survives `OTEL_TRACES_SAMPLER_ARG` being set (the F20 bug fix).
- [ ] With no CLI flag and no config value, `OTEL_TRACES_SAMPLER_ARG` still applies; with neither, the
      default is 0.01.
- [ ] No env-precedence logic remains in `bin/rvc`.
- [ ] Adding a hypothetical flag touches exactly one struct field + one clap attribute — demonstrated in
      the PR description.

**TDD test plan** (RED first):
- `test_explicit_default_sample_rate_survives_env_override` — **RED**: fails today because of the
  `f64::EPSILON` sentinel at `main.rs:948-956`.
- `test_env_sample_rate_applies_when_unset`
- `test_sample_rate_default_is_0_01_when_unset_everywhere`
- `test_merge_covers_every_cli_override_field` (exhaustive destructure; compile-time or reflective)
- `test_otlp_endpoint_precedence_cli_over_file_over_env`

**Risks:** macro-generated merge can hurt readability; keep the macro small and the field list plainly
formatted, and make `cargo expand` output part of the PR discussion if reviewers ask.

---

### Issue RF5-16: `build_signed_exit` shared helper; no `panic!` in exit paths

- **Points:** 3 · **Scope:** ~1.5–2 days · **Type:** refactor · **Stream:** A
- **Plan item:** F6 (part) · **Findings:** F15
- **Blocked by:** RF5-10 · **Blocks:** RF5-17

**Files to touch:**
- `bin/rvc/src/commands/voluntary_exit.rs:24-135` (246 lines total; `Arc::try_unwrap(...).unwrap_or_else(|_| panic!(…))`
  at `:120-121`).
- `bin/rvc/src/commands/prepare_exit.rs:24-135` (212 lines; the same panic at `:103-104`).
- `bin/rvc/src/commands/mod.rs` (or `crates/rvc`) — the new helper.

**What / why:**
Lines 24–135 of both commands are near-verbatim clones: beacon client, pubkey normalization,
validator-index resolution, epoch derivation, `Config` construction, denylist load, key-manager build,
slashing DB open, signer assembly, fork-schedule fetch, `sign_voluntary_exit`. Only the last ~15 lines
differ. Both also panic where `main.rs:1283-1285` handles the same situation with an anyhow error,
violating the CLAUDE.md error-handling convention. The duplicated
`test_pubkey_prefix_normalization` in both files re-implements normalization inline, so it guards
nothing.

**Implementation sketch:**
1. `pub fn normalize_pubkey_hex(raw: &str) -> Result<String>` (or reuse
   `eth_types::canonical::parse_pubkey_hex` if C6 from Phase 3 has landed — prefer that) and delete both
   inline copies plus their tautological tests.
2. `pub async fn build_signed_exit(args: ExitCommonArgs) -> anyhow::Result<(SignedVoluntaryExit, u64)>`
   holding the shared 110 lines.
3. Replace `Arc::try_unwrap(...).unwrap_or_else(|_| panic!(...))` with `?` propagation over a typed
   error, mirroring `main.rs:1283-1285`.
4. Each command becomes ~30 lines: parse args → `build_signed_exit` → submit (with the `--confirm` gate)
   or write to file.

**Acceptance criteria:**
- [ ] Each command file is ≤ ~40 lines of command logic over the shared helper.
- [ ] `rg 'panic!' bin/rvc/src/commands/` returns nothing.
- [ ] Pubkey normalization exists once and its test exercises the shared function.
- [ ] The `--confirm` gate on `voluntary_exit` and the file-write path on `prepare_exit` behave
      identically (tests).
- [ ] Workspace green.

**TDD test plan** (RED first):
- `test_build_signed_exit_returns_error_instead_of_panicking_on_shared_key_manager` — **RED**: today
  this path panics.
- `test_normalize_pubkey_hex_accepts_prefixed_and_bare` (against the shared fn, replacing the two
  inline duplicates)
- `test_voluntary_exit_requires_confirm_flag_before_submit`
- `test_prepare_exit_writes_signed_message_without_submitting`
- `test_both_commands_produce_identical_signed_exit_for_same_inputs`

**Risks:** these commands touch the slashing DB and the signer; make sure the helper opens the DB with
the same flags (no accidental fresh-DB creation) and releases the keystore lock on every path.

---

### Issue RF5-17: Move `prepare_exit.rs` / `submit_exit.rs` next to their consumers

- **Points:** 1 · **Scope:** ~0.5 day · **Type:** refactor · **Stream:** A
- **Plan item:** F6 (part) · **Findings:** F12 (part)
- **Blocked by:** RF5-16 · **Blocks:** none

**Files to touch:**
- `crates/rvc/src/prepare_exit.rs` (193 lines), `crates/rvc/src/submit_exit.rs`,
  `crates/rvc/src/lib.rs` (module declarations), `bin/rvc/src/commands/`.

**What / why:**
Operator-tooling modules live in the orchestrator library crate, where they collide by name with
`bin/rvc/src/commands/prepare_exit.rs`. After RF5-16 the shared logic is in the helper, so these two
modules are thin and belong next to their only consumers.

**Implementation sketch:**
1. Re-verify with `rg` that `crates/rvc/src/{prepare_exit,submit_exit}.rs` have no consumer outside
   `bin/rvc` (if the keymanager `VoluntaryExitManagerAdapter` uses them, keep them in `crates/rvc` and
   instead resolve the name collision by renaming — record the finding and stop).
2. `git mv` into `bin/rvc/src/commands/`, merge with the existing command modules, drop the now-dead
   `pub mod` lines from `crates/rvc/src/lib.rs`.
3. Pure motion: the diff should be recognized by git's move detection.

**Acceptance criteria:**
- [ ] No module-name collision remains between `crates/rvc` and `bin/rvc/src/commands`.
- [ ] `rg` proof of zero external consumers attached to the PR (or the alternative rename path taken,
      with the reason stated).
- [ ] Diff is a pure move plus module declarations.
- [ ] Workspace green.

**TDD test plan** (RED first):
- `test_exit_command_modules_resolve_from_bin_crate` — **RED**: fails to compile before the move (new
  paths do not exist); existing exit tests move with the files and must pass unchanged.

**Risks:** if `crates/rvc`'s keymanager adapter turns out to depend on these modules, the move is wrong —
that is why the `rg` proof is an acceptance criterion, not a step.

---

### Issue RF5-18: rvc-signer — kill cargo-build-in-test; real binary + in-process harness

- **Points:** 2 · **Scope:** ~1 day · **Type:** test · **Stream:** B
- **Plan item:** F2 (guard) · **Findings:** F25
- **Blocked by:** none · **Blocks:** RF5-19

**Files to touch:**
- `bin/rvc-signer/src/integration_polish.rs:20-35` — `bin_path()` runs
  `cargo build -p rvc-signer-bin` from inside a unit test (706 lines in the file).
- New `bin/rvc-signer/tests/common/mod.rs` — shared spawn/PKI helpers.
- `bin/rvc-signer/Cargo.toml` — dev-dependencies as needed.

**What / why:**
A nested `cargo build` under the test runner breaks under `--locked`/offline CI and serializes on the
target-dir lock. `env!("CARGO_BIN_EXE_rvc-signer")` gives the same binary with the same profile and
features, for free — `bin/rvc/tests/integration_test.rs:8-15` already does exactly this and documents
why. This must land before the F2 extraction chain so each step is guarded.

**Implementation sketch:**
1. Replace `bin_path()` with `env!("CARGO_BIN_EXE_rvc-signer")`; move the suite from
   `src/integration_polish.rs` into `tests/` (it is an integration suite living in a source file).
2. Extract the spawn + readiness-poll + shutdown helpers into `tests/common/mod.rs`, including the rcgen
   PKI/mTLS fixture setup the suite needs.
3. Add a `--dry-run` smoke test (rvc-signer already has `dry_run` — `main.rs` `run_serve` prints and
   exits) plus a spawn/SIGTERM/exit-code-0 test, both under `--features dvt` and without.
4. Rename the file by behavior (the plan's H1 note about `integration_polish.rs` naming) — e.g.
   `tests/server_startup.rs`.

**Acceptance criteria:**
- [x] `rg 'cargo build' bin/rvc-signer/` returns nothing under `src/` or `tests/`.
- [x] Tests pass with `--offline` and `--locked`.
- [x] The suite runs under both `--features dvt` and default features.
- [x] A clean start + SIGTERM + exit-code-0 test exists and is not `#[ignore]`d.
- [x] Workspace green.

**TDD test plan** (RED first):
- `test_server_starts_and_shuts_down_cleanly` — **RED**: written against the new `tests/` harness before
  the helper exists.
- `test_dry_run_prints_resolved_config_and_exits_zero`
- `test_binary_path_comes_from_cargo_bin_exe` (guard against reintroducing a nested build)
- Existing `integration_polish` assertions ported one-for-one (test-count diff explained in the PR).

**Risks:** the ported tests may have depended on the nested build's timing; convert sleeps to polling.

---

### Issue RF5-19: `server::run` + `ServerError` skeleton (verbatim body move)

- **Points:** 3 · **Scope:** ~1.5–2 days · **Type:** refactor · **Stream:** B
- **Plan item:** F2 · **Findings:** F25, F111
- **Blocked by:** RF5-18, and cross-phase D4 (P4) · **Blocks:** RF5-20, RF5-23

**Files to touch:**
- `bin/rvc-signer/src/main.rs:359-830` (`run_serve`), `:889-965` (`build_dvt_backend`),
  `:1031-1044` (`load_serve_password`), `:1045-1051` (`shutdown_signal`).
- `bin/rvc-signer/src/lib.rs` (51 lines) — new `pub mod server;`.
- New `bin/rvc-signer/src/server/mod.rs` and `bin/rvc-signer/src/error.rs`.

**What / why:**
`run_serve` is a 472-line god function outside the lib target, so nothing in it is reachable from tests
except by spawning the binary. This issue does the **move only** — body verbatim, one new thiserror
type — so the decomposition issues that follow have small, reviewable diffs. Error handling throughout
is `Box<dyn Error>` with `format!(…).into()`, contrary to CLAUDE.md; `ServerError` starts fixing that at
the boundary.

**Implementation sketch:**
1. `#[derive(thiserror::Error)] pub enum ServerError` with variants for the real failure classes
   (`SlashingDb`, `Backend`, `Tls`, `Bind`, `Config`, `Io`) each carrying `#[source]`.
2. `pub async fn server::run(resolved: ResolvedConfig, shutdown: CancellationToken) -> Result<(), ServerError>`
   containing the moved body; `build_dvt_backend` and `load_serve_password` move with it.
3. `main.rs` keeps CLI parse, `init_logging`, `resolve_config` (moved in RF5-23), and the
   `server::run` call, mapping `ServerError` to an exit code.
4. Convert only the `format!(…).into()` errors that cross the new boundary; leave interior ones for
   RF5-20/21 so this diff stays a move.

**Acceptance criteria:**
- [x] `server::run` is callable from a test in the lib target (a test calls it directly and shuts it
      down via the token).
- [x] `main.rs` no longer contains server assembly.
- [x] `ServerError` is a thiserror enum; the process exit code for each failure class is unchanged.
- [x] Both feature sets build; RF5-18 tests green.
- [x] The diff is dominated by moved lines (git move detection).

**TDD test plan** (RED first):
- `test_server_run_returns_slashing_db_error_variant_on_missing_db` — **RED**: `server::run` does not
  exist; today this is only observable as a process exit code.
- `test_server_run_shuts_down_on_cancellation_token`
- `test_server_run_is_callable_in_process` (no subprocess)
- `test_exit_codes_unchanged_for_each_failure_class`

**Risks:** the DVT tuple gymnastics at `main.rs:396-462` are feature-gated and awkward to move; keep
them verbatim here and clean them in RF5-20.

---

### Issue RF5-20: Decompose into `open_slashing_db` + `build_backend`

- **Points:** 3 · **Scope:** ~1.5–2 days · **Type:** refactor · **Stream:** B
- **Plan item:** F2 · **Findings:** F25
- **Blocked by:** RF5-19 · **Blocks:** RF5-21

**Files to touch:**
- `bin/rvc-signer/src/server/mod.rs` (post-RF5-19), splitting out `server/slashing.rs` and
  `server/backend.rs`.
- Original anchors: the ~75-line slashing-DB open/TOCTOU policy at `main.rs:535-611` (fail-closed on
  missing path without `--init-slashing-db`; the TOCTOU re-check at `:595`), backend construction with
  the dvt arms at `:396-462`, the allow-list single-read hoist at `:400-424` (ISSUE-4.1 / L-1),
  crypto-provider install at `:363`.

**What / why:**
Two independently testable units with real security semantics: the slashing-DB gate (which refuses to
start without protection unless both `--disable-slashing-protection` **and** `RVC_ALLOW_INSECURE=true`)
and backend construction (including the once-only allow-list read that closes a TOCTOU double-read).

**Implementation sketch:**
1. `fn open_slashing_db(resolved: &ResolvedConfig) -> Result<Option<Arc<SlashingDb>>, ServerError>`
   preserving: the two-condition insecure gate, SEC-3 fail-closed on missing path, always-reject on
   0-byte/corrupt header, and the TOCTOU re-check.
2. `async fn build_backend(resolved: &ResolvedConfig, metrics: &SignerMetrics)
   -> Result<(Backend, Option<ShareMap>, Option<Arc<AllowList>>), ServerError>` absorbing
   `build_dvt_backend` and keeping the allow-list read exactly once.
3. Keep the crypto-provider install idempotent and first, with its ADR-006 comment intact.

**Acceptance criteria:**
- [ ] The insecure gate still requires **both** the CLI flag and the env var (test both single
      conditions).
- [ ] Missing DB path without `--init-slashing-db` fails closed; corrupt header always fails.
- [ ] The CN allow-list file is read exactly once per startup (assert via a counting fixture or a
      read-once wrapper).
- [ ] DVT and non-DVT builds both green; DVT backend construction is covered by a test.
- [ ] RF5-18 tests green.

**TDD test plan** (RED first):
- `test_open_slashing_db_refuses_without_both_insecure_conditions` — **RED**: no such function; today
  only reachable through the binary.
- `test_open_slashing_db_fails_closed_on_missing_path`
- `test_open_slashing_db_rejects_corrupt_header_even_with_init_flag`
- `test_build_backend_reads_allow_list_exactly_once`
- `test_build_dvt_backend_shares_allow_list_with_peer_service` (dvt feature)

**Risks:** the TOCTOU policy is subtle; port it line-for-line and have the reviewer diff it against
`main.rs:535-611` from the pre-RF5-19 revision.

---

### Issue RF5-21: Decompose into `build_grpc_router` + `spawn_http_api`

- **Points:** 3 · **Scope:** ~1.5–2 days · **Type:** refactor · **Stream:** B
- **Plan item:** F2 · **Findings:** F25
- **Blocked by:** RF5-20 · **Blocks:** RF5-22

**Files to touch:**
- New `server/grpc.rs` and `server/http.rs`.
- Original anchors: v2 service build `main.rs:613-628`, CN allow-list `:628-658`, DVT peer service
  `:659-681`, hardened server builder `:682-697` (concurrency 32 / streams 64 / 10s timeout),
  H-9 insecure gate `:698-715`, HTTP listener `:716-779` (fail-closed without the shared gate at
  `:725`, shared `SignerMetrics` at `:756`, CN allow-list parity at `:759`), 1 MiB decode cap `:780-790`,
  SIGHUP log-reload wiring and shutdown sequencing at the tail of `run_serve`.

**What / why:**
The last two big blocks of `run_serve`. The load-bearing invariant is that **both** transports share
one `Arc<SigningGate>` (ADR-003 / FR-26) and one `SignerMetrics` registry — a refactor that
accidentally builds two gates reintroduces a double-signing path across transports.

**Implementation sketch:**
1. `fn build_grpc_router(deps) -> Result<Router, ServerError>` — hardened builder settings, per-service
   1 MiB decode cap, the H-9 insecure gate in Refuse mode, TLS from the (soon-renamed) `grpc_tls`
   module.
2. `fn spawn_http_api(deps, shutdown) -> Result<Option<JoinHandle<()>>, ServerError>` — fail-closed
   without the gate, same backend label, same metrics registry, same CN allow-list.
3. Both take the **same** `Arc<SigningGate>` by parameter; `server::run` constructs it once.
4. Preserve the SIGHUP log-reload wiring and the shutdown ordering exactly.

**Acceptance criteria:**
- [ ] One `SigningGate` instance is shared by gRPC and HTTP (test asserts pointer equality via
      `Arc::ptr_eq`).
- [ ] One `SignerMetrics` registry serves both transports (one scrape shows both series).
- [ ] HTTP API without a gate refuses at startup, as today.
- [ ] Hardened-builder limits and the 1 MiB decode cap are unchanged (assert the configured values).
- [ ] The H-9 gate still requires env var + loopback and runs in Refuse mode.

**TDD test plan** (RED first):
- `test_grpc_and_http_share_one_signing_gate` — **RED**: not expressible today, since neither builder
  function exists and the gate is a local in `run_serve`.
- `test_http_api_refuses_startup_without_gate`
- `test_insecure_flag_requires_env_and_loopback`
- `test_grpc_router_applies_decode_cap_and_concurrency_limits`
- `test_both_transports_emit_to_one_metrics_registry`

**Risks:** the highest-value invariant in this chain is the shared gate; make `Arc::ptr_eq` a permanent
test, not a one-off check.

---

### Issue RF5-22: TLS split (`tls_config.rs` + `accept_loop.rs`); `src/tls` → `grpc_tls`

- **Points:** 3 · **Scope:** ~1.5–2 days · **Type:** refactor · **Stream:** B
- **Plan item:** F2 (TLS half) · **Findings:** F34
- **Blocked by:** RF5-21 · **Blocks:** RF5-25

**Files to touch:**
- `bin/rvc-signer/src/http_api/tls.rs` (1097 lines: `audit_cn:94-98`, ServerConfig build `:168-212`,
  `read_certs`/`read_key` `:235-254`, hardened HTTPS accept loop `:278-413`,
  `install_crypto_provider:424`, ~660 lines of tests).
- `bin/rvc-signer/src/tls/mod.rs:35-39` — the copy-pasted doc comment claiming
  `to_client_tls_config` builds a **server** mTLS config.
- `bin/rvc-signer/src/audit/` — destination for `audit_cn`.

**What / why:**
Two different modules are both called `tls`, and the HTTP one is a grab-bag of five concerns. The doc
comment at `tls/mod.rs:35-39` actively misleads: it describes the server builder on the client builder,
in a security-critical mTLS path.

**Implementation sketch:**
1. Split `http_api/tls.rs` into `http_api/tls_config.rs` (crypto-provider install, PEM→DER loading,
   `ServerConfig`/verifier build) and `http_api/accept_loop.rs` (`serve_https`/`serve_one`, semaphore,
   drain, handshake timeout).
2. Move `audit_cn` next to `audit::cn`.
3. `git mv src/tls → src/grpc_tls` and update imports.
4. Fix the `to_client_tls_config` doc comment to describe the client builder.
5. Unify the read-file-with-path-in-error pattern (`TlsError::ReadCert` vs `HttpTlsError::Read`) into
   one shared helper or one error type — state which and why.
6. Tests move with their subject (this is Phase 6's H1 pattern applied early because the file is being
   split anyway).

**Acceptance criteria:**
- [ ] No two modules named `tls`; the gRPC one is `grpc_tls`.
- [ ] `to_client_tls_config`'s doc comment describes the client config (and a doc test or review note
      confirms mTLS client behavior).
- [ ] Accept-loop hardening (semaphore limit, drain, handshake timeout) is behaviorally unchanged —
      assert the configured values.
- [ ] File-read errors carry the path through one shared representation.
- [ ] All ~660 lines of existing TLS tests still run (test-count diff explained).

**TDD test plan** (RED first):
- `test_accept_loop_rejects_beyond_semaphore_limit` — **RED** if not already covered; write it against
  the new `accept_loop` module before moving code.
- `test_handshake_timeout_closes_connection`
- `test_read_cert_error_includes_path`
- `test_client_tls_config_requires_server_cert_validation` (pins the behavior the wrong doc comment
  described)

**Risks:** TLS is security-critical and the move is large. Land it as a pure split first if the diff
grows beyond ~600 changed lines; behavior changes belong in a separate commit within the PR.

---

### Issue RF5-23: rvc-signer config — `Option<T>` args, `*_is_default` heuristics deleted

- **Points:** 3 · **Scope:** ~1.5–2 days · **Type:** bugfix · **Stream:** B
- **Plan item:** F4 · **Findings:** F31
- **Blocked by:** RF5-19 · **Blocks:** RF5-24

**Files to touch:**
- `bin/rvc-signer/src/main.rs:68-238` (`ServeArgs`), `:966-1030` (`resolve_config` and its six
  `*_is_default` string/value comparisons, including the `cfg(dvt)` permutations at `:982-990`).
- `bin/rvc-signer/src/config.rs:133-165` (the 30+-field `CliOverrides` mirror), `:175`
  (`merge_with_cli`).

**What / why:**
`resolve_config` infers "the user did not pass this flag" by comparing the parsed value to the default
(`has_config && args.listen_address == DEFAULT_LISTEN_ADDRESS`). An operator who explicitly passes
`--listen-address 127.0.0.1:50052` — the default value — has their flag silently overridden by the
config file. Making the args `Option<T>` makes "not passed" representable and deletes every heuristic
plus the mirror struct.

**Implementation sketch:**
1. Drop `default_value`/`default_value_t` from `ServeArgs`; make each field `Option<T>`. Keep defaults
   visible in `--help` via `default_value` documentation text or clap's `value_source` if `--help`
   parity matters — decide and state it (recommended: move the defaults into `merge_with_cli` and note
   them in the help text).
2. Move `ServeArgs` into the lib's `config.rs` so `merge_with_cli(file_config, &ServeArgs)` can take it
   directly; delete `CliOverrides` and all `*_is_default` flags.
3. Defaults live in exactly one place: the merge function (or `SignerConfig::default()`).
4. Cover the dvt/non-dvt permutations in both directions.

**Acceptance criteria:**
- [ ] `rg '_is_default' bin/rvc-signer/` returns nothing.
- [ ] `config::CliOverrides` is deleted.
- [ ] An explicitly passed value equal to the default beats the config file (the F31 bug fix).
- [ ] An unpassed flag falls back to file, then to the built-in default.
- [ ] `--help` still shows every flag; if default text changed, the diff is shown in the PR.
- [ ] Both feature sets green; release-note item 1 drafted.

**TDD test plan** (RED first):
- `test_explicit_cli_value_equal_to_default_beats_config_file` — **RED**: fails today; this is the bug.
- `test_unset_flag_falls_back_to_config_file`
- `test_unset_flag_and_no_file_uses_builtin_default`
- `test_dvt_flags_resolve_under_both_feature_sets`
- `test_defaults_defined_in_exactly_one_place` (a source-level or table-driven pin)

**Risks:** `--help` output changes if defaults stop being clap-visible; operators read that. Prefer
keeping the default text and only changing the resolution logic.

---

### Issue RF5-24: `Backend` stays an enum through `ResolvedConfig`

- **Points:** 2 · **Scope:** ~1 day · **Type:** refactor · **Stream:** B
- **Plan item:** F4 · **Findings:** F31
- **Blocked by:** RF5-23 · **Blocks:** RF5-25

**Files to touch:**
- `bin/rvc-signer/src/config.rs` — `ResolvedConfig.backend: String`.
- `bin/rvc-signer/src/main.rs:1052-1061` (`parse_backend`), the raw comparison
  `resolved.backend == "dvt"` (`:479` pre-move; inside `server::build_backend` after RF5-19/20).

**What / why:**
The backend round-trips `Backend` → `Display` → `String` → `parse_backend` → `Backend`, with raw string
comparisons in between. A typo in a comparison is a runtime bug the compiler could have caught.

**Implementation sketch:**
1. `ResolvedConfig.backend: Backend`; derive `Deserialize` on `Backend` (kebab-case) so the TOML value
   parses directly.
2. Delete `parse_backend` and every `== "dvt"` / `== "basic"` comparison in favour of `match`.
3. Keep `Display` for logging and metric labels only.

**Acceptance criteria:**
- [ ] `rg 'parse_backend|== "dvt"|== "basic"' bin/rvc-signer/` returns nothing.
- [ ] `ResolvedConfig.backend` is `Backend`; matches on it are exhaustive.
- [ ] Metric/audit labels still emit the same strings.
- [ ] An invalid backend in TOML fails at deserialization with a clear message.

**TDD test plan** (RED first):
- `test_backend_deserializes_from_toml_as_enum` — **RED**: the field is a `String` today.
- `test_invalid_backend_value_rejected_at_deserialization`
- `test_backend_label_strings_unchanged_in_metrics`
- `test_dvt_backend_selected_by_enum_match` (dvt feature)

**Risks:** metric label strings are an external contract; assert them.

---

### Issue RF5-25: Promote the lib to `crates/signer-server`

- **Points:** 3 · **Scope:** ~1.5–2 days · **Type:** refactor · **Stream:** B
- **Plan item:** F2 (final) · **Findings:** F111, F25
- **Blocked by:** RF5-22, RF5-24 · **Blocks:** none

**Files to touch:**
- New `crates/signer-server/` receiving `http_api/`, `dvt/`, `grpc_tls/`, `audit/`, `backend/`,
  `server/`, `config.rs`, `metrics.rs` from `bin/rvc-signer/src/`.
- `bin/rvc-signer/` reduced to `main.rs` (CLI parse + logging + `signer_server::server::run`).
- `crates/architecture-tests/` — the new crate's allowed edges.
- Workspace `Cargo.toml`, and `crates/grpc-signer`'s dev-dependencies (its integration tests can now
  spin up a real in-process server instead of re-creating rcgen PKI fixtures).

**What / why:**
15.6k LOC of library code lives under `bin/`, invisible to the architecture-tests layer policy and
unusable by other crates' tests. This is the first time that code meets the layering gates — expect it
to surface real edges, not just a table entry. It also resolves the `rvc-signer` lib/bin package-name
awkwardness noted in D7.

**Implementation sketch:**
1. `git mv` the subsystems; keep module paths identical inside the new crate so the diff is a move.
2. Add the crate to the workspace and to `architecture-tests`' known-crates list with its allowed
   dependency edges.
3. Run the acyclicity/forbidden-edge checks; **any violation is either fixed here or split into a
   follow-up issue that names the violating edge** — do not widen the policy to make it pass.
4. Point `bin/rvc-signer/src/main.rs` and `crates/grpc-signer`'s tests at the new crate; delete the
   duplicated PKI fixtures in grpc-signer if the server helpers now cover them.

**Acceptance criteria:**
- [ ] `bin/rvc-signer/src/` contains `main.rs` (and nothing that is a library).
- [ ] `crates/signer-server` is covered by `crates/architecture-tests`; the allowed-edge table names it
      explicitly.
- [ ] Any layering violation surfaced is fixed in-issue or filed with the specific edge named in the PR.
- [ ] `crates/grpc-signer` integration tests use the library server (or a follow-up is filed).
- [ ] Diff is dominated by moves; `cargo build --release` still produces the same binary name.

**TDD test plan** (RED first):
- `test_signer_server_crate_edges_conform_to_layer_policy` — **RED**: the crate is unknown to
  architecture-tests before the move.
- `test_bin_rvc_signer_contains_only_cli` (source-level assertion on the module list)
- Existing rvc-signer suites pass from their new location (test-count diff explained).

**Risks:** the largest single move in the phase; do it when Stream B has no other in-flight PR touching
`bin/rvc-signer`. Feature flags (`dvt`) must be re-declared on the new crate and re-plumbed from the bin.

---

### Issue RF5-26: `DoppelgangerLifecycle` component owns the KM-2 invariant

- **Points:** 3 · **Scope:** ~1.5–2 days · **Type:** refactor · **Stream:** B
- **Plan item:** F5 · **Findings:** F71, F69 (partial — this issue plus RF5-27/RF5-28 remove the
  lifecycle, error-mapping and exit duplication from the 4,181-line `handlers.rs`; the remaining
  `handlers/` module tree and router-test relocation are **H1 in Phase 6**, per the appendix
  disposition "F69 → F5 (P5) + H1 (P6)")
- **Blocked by:** RF5-02, SEC-1 (satisfied — merged `e0b06e0`/`6d77dad`, see P5-A1), and cross-phase
  E8c (P4) · **Blocks:** RF5-27

**Files to touch:**
- `crates/keymanager-api/src/handlers.rs:32-96` (`AppState`: `cancel_tokens`,
  `doppelganger_state_lock`, `doppelganger_window` plus 60+ lines of lock-ordering invariants),
  `:139-318` (`import_keystores`, with ~95 inline lines of token displacement + `tokio::spawn` +
  `select!` enable logic), `:319-457` (`delete_keystores`, repeating the lock/cancel discipline),
  `:474-565` (`import_remote_keys`, which only calls `start_monitoring` — the asymmetry).
- `crates/keymanager-api/src/gate.rs` — already owns the window concept.
- `crates/keymanager-api/tests/km2_cancel_token_race.rs` (661 lines) — retargeted at the component.

**What / why:**
A concurrency-critical state machine (KM-2, SF-3) is enforced purely by convention across three inline
copies, and the local vs remote import paths have already diverged despite a comment claiming they use
"the same enablement gate". The race tests must drive the full HTTP stack to reach it. Encapsulating
window + cancel tokens + state lock in one type makes the invariant enforceable and directly testable.

**Implementation sketch:**
1. `pub struct DoppelgangerLifecycle` owning `window`, `cancel_tokens`, `state_lock`, and the monitor
   handle; API: `on_import(pubkey, kind: ImportKind)`, `on_delete(pubkey)`, and the internal background
   enable task. `ImportKind::{Local, Remote}` carries the one genuine difference (ValidatorManager
   registration).
2. Move the token-displacement + `select!` logic inside; the spawned task re-checks cancellation under
   the same lock, exactly as today (`handlers.rs` spawned task).
3. Handlers become request/response mapping calling `lifecycle.on_import(...)` / `.on_delete(...)`.
4. Retarget `km2_cancel_token_race.rs` at the component (no HTTP stack); keep **one** end-to-end HTTP
   test so the wiring itself stays covered.
5. Preserve the existing lock-ordering documentation by moving it onto the component type.

**Acceptance criteria:**
- [ ] Local and remote import go through one code path, differing only by `ImportKind`.
- [ ] The KM-2 invariant (token displacement + cancel under the state lock) exists in exactly one place.
- [ ] `km2_cancel_token_race` tests target the component; at least one HTTP-level test remains.
- [ ] No behavior change: an import during an in-flight enable task still cancels the prior token; a
      delete during the window still cancels.
- [ ] Existing doppelganger and keymanager suites green.

**TDD test plan** (RED first):
- `test_remote_import_registers_with_lifecycle_like_local` — **RED**: today `import_remote_keys` only
  calls `start_monitoring`; this is the divergence F71 names.
- `test_second_import_displaces_first_cancel_token_under_lock`
- `test_delete_during_window_cancels_enable_task`
- `test_enable_task_rechecks_cancellation_under_state_lock`
- `test_lifecycle_window_zero_enables_immediately`

**Risks:** this is a live race-condition surface; the "no behavior change" criterion is doing real work.
Require that the existing 661-line race suite passes **before** it is retargeted (run it against the new
component through the HTTP stack once, then convert).

---

### Issue RF5-27: thiserror enums for keymanager traits; one central mapper

- **Points:** 3 · **Scope:** ~1.5–2 days · **Type:** refactor · **Stream:** B
- **Plan item:** F5 · **Findings:** F75, F69 (partial — see RF5-26)
- **Blocked by:** RF5-26 · **Blocks:** RF5-28

**Files to touch:**
- `crates/keymanager-api/src/traits.rs:39` (`SlashingProtection::import_interchange`/`export_interchange`
  → `Result<_, String>`), `:80` (`ImportRemoteKeyError::Other(String)` /
  `DeleteRemoteKeyError::Other(String)` passthroughs).
- `crates/keymanager-api/src/url_validator.rs:3` — `Result<url::Url, String>`.
- `crates/keymanager-api/src/handlers.rs:606-610` (the M-8 sanitize warning comment), `:815`
  (`sanitize_internal`), `:824` (`sanitize_item_err`), and every scattered call site.
- `crates/rvc/src/keymanager_adapters.rs` — the adapters implementing these traits.

**What / why:**
Opaque `String` error payloads may carry paths, sockets and internal names, so handlers compensate with
`sanitize_*` sprinkled at each site — a policy enforced by vigilance. Real thiserror enums let one
`IntoResponse` mapper decide exposure by variant, which is both safer and less code. CLAUDE.md
prescribes thiserror for library error types.

**Implementation sketch:**
1. `SlashingProtectionError { NotFound, InvalidInterchange(..), Backend(#[source] ..) }`;
   `ImportRemoteKeyError`/`DeleteRemoteKeyError` gain real variants instead of `Other(String)`;
   `UrlValidationError` with an "is client-safe" notion.
2. One central mapper: client-safe variants render their message; `Backend`/internal variants render a
   generic message and log the detail at `warn`/`error` with the existing redaction helpers.
3. Delete the scattered `sanitize_internal`/`sanitize_item_err` calls; keep the functions only if the
   mapper uses them internally.
4. Update the adapters in `crates/rvc` to produce typed variants.

**Acceptance criteria:**
- [ ] No `Result<_, String>` remains in `crates/keymanager-api/src/traits.rs` or `url_validator.rs`.
- [ ] No internal detail (path, socket, hostname) appears in any HTTP response body — assert with a
      test that feeds a backend error containing a filesystem path.
- [ ] `sanitize_*` is called from at most one place.
- [ ] HTTP status codes and response shapes for every existing error case are unchanged (table-driven
      test against the OpenAPI spec in `docs/keymanager-api.openapi.yaml`).
- [ ] Workspace green.

**TDD test plan** (RED first):
- `test_backend_error_containing_path_is_not_leaked_in_response` — **RED**: today a
  `DeleteRemoteKeyError::Other(String)` passthrough can leak whatever the backend put in it if a
  `sanitize_*` call is missing.
- `test_not_found_variant_maps_to_404_with_safe_message`
- `test_invalid_interchange_maps_to_400`
- `test_error_status_codes_match_openapi_spec` (table-driven)
- `test_url_validation_error_is_client_safe`

**Risks:** response-body text changes could break a consumer parsing messages. Pin status codes and the
documented shape; treat free-text message changes as acceptable and note them in the PR.

---

### Issue RF5-28: Collapse the two exit handlers into one `handle_exit`

- **Points:** 1 · **Scope:** ~0.5 day · **Type:** refactor · **Stream:** B
- **Plan item:** F5 · **Findings:** F77, F69 (partial — see RF5-26)
- **Blocked by:** RF5-27 · **Blocks:** none

**Files to touch:**
- `crates/keymanager-api/src/handlers.rs:745-771` (`sign_voluntary_exit`), `:772-794` (`prepare_exit`) —
  byte-identical bodies differing only in a log line.
- `crates/keymanager-api/src/server.rs:117-118` — the two routes.
- `crates/keymanager-api/src/traits.rs` — `VoluntaryExitManager` documentation.

**What / why:**
`prepare_exit`'s doc says "returns it without submitting", but it invokes the same trait method as
`sign_voluntary_exit`, whose route carries a "THIS IS IRREVERSIBLE" warning log. Either both are
sign-only (making the warning misleading) or the difference lives behind a shared call where it cannot
differ. One function plus an explicit intent parameter makes the answer visible in the code.

**Implementation sketch:**
1. `async fn handle_exit(state, pubkey_hex, query, intent: ExitIntent)` with the two routes as thin
   wrappers passing `ExitIntent::{SignAndSubmit, SignOnly}`.
2. Document on the `VoluntaryExitManager` trait whether signing implies submission. If the two endpoints
   genuinely behave identically today, say so in both route docs and in
   `docs/keymanager-api.openapi.yaml` — **do not** invent a submit path in this issue.
3. Keep the differing log line, driven by `intent`.

**Acceptance criteria:**
- [ ] One handler body; two routes.
- [ ] The `VoluntaryExitManager` trait documents the submit semantics explicitly.
- [ ] Both endpoints return exactly what they returned before (response-shape test).
- [ ] The OpenAPI description matches actual behavior.

**TDD test plan** (RED first):
- `test_both_exit_routes_return_identical_response_for_same_input` — **RED**: written first to pin the
  (surprising) current behavior before collapsing.
- `test_exit_intent_selects_log_line`
- `test_exit_route_docs_match_openapi_description`

**Risks:** if the intended behavior was that `/eth/v1` submits, this issue surfaces a real bug — file it
rather than fixing it here (submission is a behavior change, not a refactor).

---

### Issue RF5-29: validator-store shared `parse_config`

- **Points:** 1 · **Scope:** ~0.5 day · **Type:** refactor · **Stream:** B
- **Plan item:** F7 · **Findings:** F78
- **Blocked by:** none · **Blocks:** RF5-30

**Files to touch:**
- `crates/validator-store/src/store.rs:88-138` (`load_from_config`), `:362-415` (`reload_config`) — both
  read the file, parse `TomlConfig`, then repeat the same ~25-line block of fallback defaults
  (`fee_recipient = [0u8; 20]`, `gas_limit = 30_000_000`) and the per-validator parse loop.

**What / why:**
The fallback constants appear twice; a new `[defaults]` field added to one path silently misses the
other, undermining `reload_config`'s parse-first/apply-second guarantee. Doing this before RF5-30 means
the lock refactor operates on one parse path, not two.

**Implementation sketch:**
1. `const DEFAULT_FEE_RECIPIENT: [u8; 20] = [0u8; 20];` and `const DEFAULT_GAS_LIMIT: u64 = 30_000_000;`
   defined once.
2. `fn parse_config(content: &str) -> Result<(ValidatorDefaults, Vec<ValidatorConfig>), ValidatorStoreError>`
   consumed by both: `load_from_config` constructs `Self`; `reload_config` applies under the write
   locks (unchanged in this issue).
3. Pure deduplication; no locking change.

**Acceptance criteria:**
- [x] The fallback constants are declared once.
- [x] Both paths call `parse_config`; neither re-implements parsing.
- [x] `reload_config` still parses fully before mutating any state.
- [x] Existing validator-store tests pass unchanged.

**TDD test plan** (RED first):
- `test_load_and_reload_produce_identical_defaults_and_validators` — **RED**: written against
  `parse_config` before it exists; it is also the regression guard for the drift F78 describes.
- `test_parse_config_applies_declared_fallback_constants`
- `test_reload_rejects_invalid_toml_without_mutating_state`

**Risks:** none material.

---

### Issue RF5-30: validator-store single lock + atomic reload

- **Points:** 3 · **Scope:** ~1.5–2 days · **Type:** bugfix · **Stream:** B
- **Plan item:** F7 · **Findings:** F128 (partially stale — see P5-A3)
- **Blocked by:** RF5-29 · **Blocks:** none

**Files to touch:**
- `crates/validator-store/src/store.rs:60-66` — the struct: `validators: RwLock<HashMap<…>>` (`:61`),
  `defaults: RwLock<ValidatorDefaults>` (`:62`), a `Mutex` (`:63`),
  `global_block_selection_mode: RwLock<BlockSelectionMode>` (`:64`).
- `:156-168` (`effective_config`: validators → defaults), `:306-360` (`save_config`: defaults `:316` →
  validators `:317` — the opposite order), `:362-415` (`reload_config`: writes defaults `:399` then
  validators `:405`, non-atomically), plus every accessor at `:142-302`.

**What / why:**
`effective_config` and `save_config` acquire two locks in opposite orders. The file is already on
`parking_lot` (so F128's "panics on poison" sub-claim is stale, and the struct has **three** RwLocks,
not two — the refactor must absorb all of them), but parking_lot's write-preferring fairness means a
writer queued between `effective_config`'s two reads makes this a real deadlock, not a theoretical one.
`reload_config` also swaps defaults and validators in two steps, so a reader can observe a half-applied
config.

**Implementation sketch:**
1. `struct StoreState { validators: HashMap<[u8;48], ValidatorConfig>, defaults: ValidatorDefaults,
   global_block_selection_mode: BlockSelectionMode }` behind **one** `RwLock<StoreState>`. Keep the
   separate `Mutex` only if it guards something genuinely unrelated (e.g. file writes); document it.
2. Every accessor (`:142-302`) takes one guard. `effective_config` reads validators and defaults under
   a single read guard — the deadlock becomes unrepresentable.
3. `reload_config` parses via RF5-29's `parse_config`, builds a complete new `StoreState`, then swaps it
   under one write guard: `*state.write() = new_state`.
4. Watch hot-path cost: `effective_config` is called per duty. A single `RwLock` still allows concurrent
   readers; confirm no accessor now holds the write lock longer than before.

**Acceptance criteria:**
- [x] Exactly one `RwLock` over the store state; opposite-order acquisition is impossible by
      construction.
- [x] `reload_config` is atomic: a concurrent reader observes either the old or the new config, never a
      mix (stress test).
- [x] A parse failure during reload leaves the previous state fully intact.
- [x] No accessor regresses from a read guard to a write guard.
- [x] Existing validator-store and orchestrator tests green.

**TDD test plan** (RED first):
- `test_reader_never_observes_half_applied_reload` — **RED**: a stress test spawning readers against a
  concurrent `reload_config` that changes both defaults and validators; fails today because `:399` and
  `:405` are separate write acquisitions.
- `test_effective_config_and_save_config_cannot_deadlock` (stress: N readers calling
  `effective_config` against a writer calling `save_config`; times out today under adverse scheduling)
- `test_reload_failure_leaves_previous_state_intact`
- `test_all_accessors_use_single_state_lock` (source-level or API-level pin)

**Risks:** deadlock tests are inherently timing-dependent; run the stress loop for a bounded number of
iterations with a hard timeout rather than relying on chance. `loom` is optional and likely overkill
here — note it as a follow-up if the stress test proves flaky.

---

### Issue RF5-31: rvc-keygen `write_new_0600` helper

- **Points:** 2 · **Scope:** ~1 day · **Type:** bugfix · **Stream:** B
- **Plan item:** F6 (part) · **Findings:** F21
- **Blocked by:** none · **Blocks:** RF5-32

**Files to touch:**
- `bin/rvc-keygen/src/new_mnemonic.rs:19-52` (`write_mnemonic_backup`, `create_new` at `:29`/`:44`),
  `:258-283` (`write_with_permissions`, `create_new` at `:265`/`:276`).
- `bin/rvc-keygen/src/bls_to_execution.rs:77-98` (`create_new` at `:85`; **non-unix arm at `:94-98`
  falls back to plain `fs::write`**).
- `bin/rvc-keygen/src/exit.rs:52-73` (`create_new` at `:60`; **non-unix arm at `:69-73` falls back to
  plain `fs::write`**).
- Test re-duplications at `exit.rs:255-269` and `bls_to_execution.rs:311-324`.
- New `bin/rvc-keygen/src/fs_util.rs`.

**What / why:**
The `cfg(unix)`/`cfg(not(unix))` "create-new file with mode 0o600" block is copy-pasted four times and
has already diverged: on non-unix, `new_mnemonic` refuses to clobber while `bls_to_execution` and
`exit` silently overwrite an existing signed message. Two tests re-duplicate the block a fifth and sixth
time with the comment "Use the same write logic as run()" — proof the logic is untestably inlined.

**Implementation sketch:**
1. `pub fn write_new_0600(path: &Path, bytes: &[u8]) -> Result<()>` in `fs_util.rs`: `create_new(true)`
   on **all** platforms; `mode(0o600)` under `cfg(unix)`; context-rich errors including the path.
2. Replace all four call sites; delete the two test re-duplications and test the helper directly.
3. Behavior change on non-unix: refusing to overwrite instead of clobbering — release-note item 2.

**Acceptance criteria:**
- [x] One implementation; `rg 'create_new' bin/rvc-keygen/src/` shows it only in `fs_util.rs`.
- [x] `create_new` semantics on all platforms; `0o600` on unix.
- [x] Existing-file writes fail with a clear, path-bearing error on every platform.
- [x] The two test re-duplications are gone; the helper has its own tests.
- [x] Release-note item 2 drafted.

**TDD test plan** (RED first):
- `test_write_new_0600_refuses_existing_file` — **RED**: the helper does not exist, and the behavior it
  pins is currently wrong on non-unix.
- `test_write_new_0600_sets_owner_only_permissions` (unix)
- `test_write_new_0600_error_includes_path`
- `test_exit_command_refuses_to_overwrite_existing_output`
- `test_bls_to_execution_refuses_to_overwrite_existing_output`

**Risks:** a Windows CI job is needed to actually exercise the changed arm; if none exists, gate the
assertion behind `cfg(not(unix))` and note that it is compile-checked but not run.

---

### Issue RF5-32: rvc-keygen `GenerateArgs` struct

- **Points:** 2 · **Scope:** ~1 day · **Type:** refactor · **Stream:** B
- **Plan item:** F6 (part) · **Findings:** F24
- **Blocked by:** RF5-31 · **Blocks:** none

**Files to touch:**
- `bin/rvc-keygen/src/new_mnemonic.rs:61-62` (`run`, 10 params under
  `#[allow(clippy::too_many_arguments)]`), `:115-116` (`generate_from_seed`, 9 params),
  `existing_mnemonic.rs:11-12` (`run`), and the ~20 test call sites.
- Convention to follow: `bls_to_execution.rs:15` (`BlsToExecutionArgs`), `exit.rs:13` (`ExitArgs`).

**What / why:**
Call sites read `..., true, &password, false)` where `pbkdf2` and `dry_run` are indistinguishable
without counting positions, and the same binary already uses Args structs for its two other
subcommands — two conventions for one problem.

**Implementation sketch:**
1. `pub struct GenerateArgs { network, output_dir, num_validators, start_index, withdrawal_address,
   kdf: EncryptionKdf, dry_run }` shared by `new_mnemonic::run` and `existing_mnemonic::run`.
2. Replace the `pbkdf2: bool` with the existing `EncryptionKdf` enum from `crypto`.
3. `generate_from_seed` takes `&GenerateArgs` plus the seed; drop both
   `#[allow(clippy::too_many_arguments)]`.
4. Update the ~20 test call sites to named-field construction.
5. Scope discipline: the plan explicitly defers "further keygen UX changes" (§5) — **only** the
   Args-struct conversion is in scope.

**Acceptance criteria:**
- [x] No `#[allow(clippy::too_many_arguments)]` remains in `new_mnemonic.rs` or `existing_mnemonic.rs`.
- [x] `pbkdf2: bool` is replaced by `EncryptionKdf`; the produced keystore KDF is unchanged for both
      values (test).
- [x] Both subcommands share `GenerateArgs`.
- [x] Generated output is byte-identical for the same inputs (fixture comparison with a fixed seed).
- [x] No CLI-visible change.

**TDD test plan** (RED first):
- `test_generate_args_kdf_enum_selects_same_kdf_as_bool` — **RED**: `GenerateArgs` does not exist; this
  pins the bool→enum mapping in both directions.
- `test_new_mnemonic_output_unchanged_for_fixed_seed`
- `test_existing_mnemonic_shares_generate_args`
- `test_dry_run_writes_nothing`

**Risks:** keystore output is a durable artifact; the fixed-seed byte-identity test is the guard against
an accidental KDF or parameter change.

---

## Validation Strategy (per plan §6.6)

- **Every PR:** `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo nextest run --workspace`, `crates/architecture-tests`.
- **Binary-level smoke tests** (RF5-01 for `bin/rvc`, RF5-18 for `bin/rvc-signer`) run on every issue in
  the F1 and F2 chains. A change to the startup-marker constant requires an explicit PR note.
- **Config backward compatibility:** RF5-12's fixture test must pass **unmodified** through RF5-13,
  RF5-14 and RF5-15.
- **Feature matrix:** the rvc-signer chain builds and tests under `--features dvt` and default; the
  `bin/rvc` chain under `gcp-secret` and default.
- **Manual devnet/mock-BN boot** before RF5-10 merges (explicit phase-gate requirement).
- **Move-shaped diffs** (RF5-17, RF5-19, RF5-22, RF5-25) are reviewed with git move detection; a
  test-count diff accompanies any PR that relocates tests.
