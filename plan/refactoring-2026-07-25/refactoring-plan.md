# rvc Workspace Refactoring Plan

Synthesized 2026-07-25 from 11 parallel analyzer reports (131 findings, raw data in `refactoring-findings.json`; findings referenced below as F1..F131 in JSON array order), then hardened by an adversarial completeness review whose six corrections are folded in below (fail-closed D2 timeout semantics, B5 pre-committed to wiring, A4 doppelganger gate, A7/D4 metrics continuity, B7 KAT re-homing order, E8 split into per-crate items).

---

## 1. Executive Summary

The rvc workspace (~135k LOC, 26 crates) is **fundamentally healthy**: workspace dependency management is disciplined, error handling is consistently thiserror-in-libs / anyhow-in-bins (one exception: `crates/telemetry`), the `crates/architecture-tests` CI gate is a real strength, panic surface in production code is low (~210 unwrap/expect, mostly justified), and test volume is enormous. The debt is almost entirely **structural**, and it clusters into three systemic patterns:

1. **"Built but never wired."** Whole subsystems exist, are tested, and are dead in production: `crates/sync-service`'s `SyncService` (reimplemented inline in the orchestrator, F2/F92), `crates/timing`'s `AttestationTimer` (F94), `ServiceBuilder::build_all` (a second, drifted composition root, F3/F13), the slashing watermark/prune subsystem (F52), the runtime key-import → orchestrator notification channel (F1), the proposer-nodes BnManager (built then discarded, F19), and gRPC sign metrics registered but never recorded (F29). The most dangerous instance: **the EIP-3076 watermark-equality fix (commit 40b6c1e) landed in the two dead slashing check paths but NOT in the production `stage_*` path** — and the conformance/property suites certify the dead path (F48/F50). Prior audits flagged this exact pattern twice (F118).
2. **Consensus-critical logic duplicated until it drifts.** Domain/signing-root derivation exists in 3+ live copies, the EIP-7044 Capella cap in 4 (F38); EIP-3076 rules in 3 (F48); the rvc-signer type→domain→root policy in 3 transports with a real builder-fork-version divergence (F28); the Web3Signer wire protocol mirrored by comment between client and server (F45/F106); network presets (GVR, fork versions) in two incompatible formats (F16/F107); two safe-signing stacks with disjoint safety features — the VC path has metrics but no sign timeout, the remote-signer path has the timeout but no metrics (F37).
3. **God files, god traits, god config.** `coordinator.rs` 5,711 lines (F5), `slashing/db.rs` 5,466 (F51), `keymanager-api/handlers.rs` 4,181 (F69), `beacon/client.rs` 5,357 (F60), `signer/lib.rs` 3,008 (F40) — in each case 60–85% inline test modules. The 51-method `BeaconNodeClient` trait forces 16 hand-rolled mocks (F104/F59/F7). Adding one CLI flag touches 5 places across two crates (F14/F4); adding one beacon endpoint touches 5+ sites (F63).

**Top risks to maintainability:** (a) the drifted slashing production path — a live correctness gap in the most safety-critical code, masked by tests aimed at dead code; (b) the next fork rollout (Fulu/Gloas) — four parallel fork representations (F82), dual SSZ universes (F80), and per-fork match arms in three crates make every fork a multi-crate, compiler-unassisted edit; (c) the mock/test-organization burden, which actively discourages extending traits and hides real coverage gaps (no pipeline-level double-vote rejection test exists, F124).

The plan below runs six phases: fix the safety-critical drift and add the missing safety-net tests first; purge dead twins second (so later phases don't refactor code slated for deletion); extract shared foundations third; consolidate the signing/slashing/beacon cores fourth; rebuild the composition roots and config plumbing fifth; and do file splits, test relocation, and doc regeneration last. Every phase leaves the workspace green (`cargo test`, `cargo clippy`, architecture-tests) and is decomposed into independently landable PRs.

**Coordination note:** two remediation efforts are already in flight — `plan/security-2026-07-18/` (SEC-1..SEC-6: keymanager tracked_keys, doppelganger wiring, slashing DB fail-closed open, unwrap DoS, typed SSZ bodies) and `docs/issues/` (test-audit phases 1–3). This plan deliberately does **not** duplicate those tracked security fixes (F117, F119, F125 are pointers, not work items here); where a refactor touches the same files, the phase notes call out the dependency.

---

## 2. Cross-Reference: Overlapping Findings

Independent analyzers converged on the same problems; convergence raises priority.

| Merged work item | Findings (analyzer count) |
|---|---|
| BeaconNodeClient god-trait + 16 hand-rolled mocks | F7 (rvc), F59 (beacon), F97/F103 (duty crates), F104 (cross-cutting) — **4 analyzers** |
| sync-service dead twin of orchestrator sync logic | F2 (rvc), F92 + F99 + F102 (duty crates) — **2 analyzers** |
| Dead `ServiceBuilder::build_all` / run_validator god-function | F3 (rvc), F13 (bin) — **2 analyzers** |
| crypto as god-crate / logging commons | F39 (crypto), F105 (cross-cutting) — **2 analyzers** |
| Web3Signer wire types mirrored client↔server | F45 (crypto), F106 (cross-cutting) — **2 analyzers** |
| Network presets duplicated in two formats | F16 (bin), F107 (cross-cutting) — **2 analyzers** |
| Slashing watermark/prune dead + dormant M-1 bug | F52 (slashing), F127 (prior corpus) — **2 analyzers** |
| Conformance suite aimed at non-production path | F50 (slashing), F126 (prior corpus) — **2 analyzers** |
| Pubkey-hex parsing re-implemented 6–15× | F73 (km), F88 (eth-types), F116 (cross-cutting), F6/F10 (rvc `format!("0x{}")` ×58) — **4 analyzers** |
| rvc-signer needs a real library crate | F25 (rvc-signer), F111 (cross-cutting) — **2 analyzers** |
| Coordinator god file | F5 (rvc), F121 (prior corpus) — **2 analyzers** |
| Config sprawl (Config/CliOverrides/clap ×5 sites) | F4 (rvc), F14 + F20 (bin) — **2 analyzers** |
| HTTP retry duplication / scatter | F58 (beacon), F108 + F131 (cross-cutting, prior) — **3 analyzers** |
| Doppelganger dual implementations | F93 (duty crates), F118 (prior corpus), F3 (legacy path in build_all) — **3 analyzers** |
| Fork representation sprawl | F82 + F85 + F89 (eth-types), F74 (grpc-signer) — **2 analyzers** |
| grpc-signer/rvc-signer double proto compilation + v1 surface | F32, F35, F79 — **2 analyzers** |
| Shared test-support gap (keystore/PKI/signer fixtures) | F46 (signer), F95 (block-service), F113 (cross-cutting), F110 (empty test-utils feature) — **3 analyzers** |
| Signing-root/domain derivation duplication | F38 (crypto/signer), F28 + F27 (rvc-signer), F70 (grpc-signer) — **3 analyzers** |

---

## 3. Themes

### Theme A — Safety-critical correctness & safety-net tests
**Motivation:** Before any consolidation, fix the one live rule divergence and add the tests that make later refactoring safe. These are the items where "refactoring debt" is already a correctness bug.

| Item | Files | Impact / Effort |
|---|---|---|
| A1. Port watermark-equality fix (`<` → `<=`) to production stage path; add stage-path watermark tests | `crates/slashing/src/stage.rs:356`, `stage.rs:506`; new tests in `crates/slashing/tests/stage.rs` | high / S (F48 partial, F127) |
| A2. Retarget EIP-3076 conformance + proptest suites at `stage_*` + commit/discard | `crates/slashing/tests/conformance.rs:104,134`, `tests/proptest_slashing.rs:49`; drive real watermark code instead of test-local HashMaps (`conformance.rs:158`) | high / M (F50, F126) |
| A3. Pipeline-level slashing tests: double-vote rejection across two `process_slot` calls, conflicting-data concurrent-signer test, fail-closed DB-error propagation | `crates/rvc/src/orchestrator/coordinator.rs` tests, `crates/signer/src/lib.rs:1977` | high / M (F124) |
| A4. Wire runtime key-import to orchestrator: make `pubkey_map` + `key_gen_tx` required ctor params of `KeystoreManagerAdapter`/`RemoteKeyManagerAdapter`; collapse the 3 stacked `DutyOrchestrator` ctors into one taking `OrchestratorDeps` | `crates/rvc/src/keymanager_adapters.rs:73,399,775`, `orchestrator/coordinator.rs:149,184,321`, `bin/rvc/src/main.rs:1627` | high / M (F1) |
| A5. Fix builder test UB (unsafe pointer downcast → Arc clone); consider `unsafe_code = "deny"` workspace lint | `crates/builder/src/service.rs:669` | med / S (F100) |
| A6. `--password-dir`: implement per-keystore passwords or delete the flag; make missing-password an explicit startup error | `bin/rvc-signer/src/main.rs:82,1031`, `config.rs:58` | med / S (F30) |
| A7. Record (not delete) gRPC sign metrics in v2 handlers, mirroring HTTP labels; remove dead `metrics` field if decision is delete | `bin/rvc-signer/src/metrics.rs:20,193`, `service.rs:123,210` | med / S (F29) |

### Theme B — Dead-code purge (delete the twins)
**Motivation:** Several later refactors would otherwise waste effort restructuring code that should not exist. Deleting first shrinks the surface all other phases operate on. Every deletion below was verified caller-free by the analyzers via rg; re-verify before each PR.

| Item | Files | Impact / Effort |
|---|---|---|
| B1. Delete `sync_service::SyncService`/`SyncSigner`/`SyncBeaconClient`; shrink crate to `is_sync_committee_aggregator`, subnet mapping, error type (constants move in D3) | `crates/sync-service/src/lib.rs:97,115,192`; fix ARCHITECTURE.md; delete dead `OrchestratorError::SyncService` (`crates/rvc/src/orchestrator/error.rs:44`) | high / M (F2, F92; F102 resolves itself) |
| B2. Delete `ServiceBuilder::build_all`, `BuiltServices`, `orchestrator_factory`, `build_doppelganger_service`; port their unit tests to individual `build_*` methods | `crates/rvc/src/config/builder.rs:126,269,703` | high / M (F3, half of F13) |
| B3. Delete `timing::timer.rs` (AttestationTimer, run_slot_loop), its 3 self-registered metrics, `TimingError::SlotNotStarted/Cancelled`, unused BPS constants | `crates/timing/src/timer.rs`, `error.rs:11`, `lib.rs:32-58` | high / S (F94) |
| B4. Delete slashing API generations 1–2 after A2: `is_safe_to_sign/propose` + `record_*` deleted or `pub(crate)`; `check_and_record_*` becomes thin `stage+commit` wrapper or is deleted; drop `_client_cn` param and duplicated doc block | `crates/slashing/src/db.rs:805,934,1227,1257,1341,1523` | high / M (F49, F127) |
| B5. Watermark subsystem: **wire it** (decision pre-committed; deletion is off the table because Phase 1's A1/A2 test-pin stage-path watermark semantics and the 38 minimal-strategy conformance cases depend on watermark maxima — deleting would invalidate those tests and weaken minimal-format EIP-3076 interchange import safety): set watermarks from interchange maxima on import, add `rvc slashing prune` subcommand (or periodic task) | `crates/slashing/src/db.rs:1832-2031`, `error.rs:50` | med / M (F52) |
| B6. Delete `eth-types/src/insecure.rs` + its test file; fix stale comment in `bin/rvc-signer/src/service.rs:452` | `crates/eth-types/src/insecure.rs`, `tests/insecure_gate.rs` | med / S (F84) |
| B7. Delete crypto free `sign_*` functions + `RawSigner` + shadowed `DOMAIN_BEACON_ATTESTER`; keep `compute_domain/compute_signing_root`, `is_aggregator`, one voluntary-exit helper for rvc-keygen; migrate their KATs onto the surviving `compute_domain`/`compute_signing_root` helpers now (they re-home onto `signing_root_for` when D1 lands in Phase 4) | `crates/crypto/src/signing.rs:8`, `block_signing.rs`, `sync_signing.rs`, `aggregation_signing.rs`, `builder_signing.rs`, `typed_signer.rs:32` | med / M (F42) |
| B8. Delete `load_from_directory_with_tracker` + `DecryptionAttemptTracker` (or fold rate-limiting into the single filtered loader); correct ARCHITECTURE.md | `crates/crypto/src/key_manager.rs:110,376,437`, `decryption_tracker.rs` | med / S–M (F43) |
| B9. bn-manager dead config: delete `BnSelectionStrategy`/`selection_strategy`, fix/drop `head_slot`, unify SSE cap constant, drop dead `BnOutcome.latency` | `crates/bn-manager/src/traits.rs:200,232`, `manager.rs:194`, `beacon/src/http_caps.rs:18`, `broadcast.rs:10` | med / S (F64) |
| B10. v1 proto retirement: implement v2 `ListPublicKeys` in `GrpcRemoteSigner::connect` (ISSUE-1.9), then delete v1 `SignerService` impl, lib re-exports, v1 tests, audit compat re-exports, and v1 proto compilation in both build.rs | `crates/grpc-signer/src/client.rs:117`, `lib.rs:18`, `bin/rvc-signer/src/service.rs:459`, both `build.rs` | med / M (F35, F79, prereq for D4) |
| B11. Micro-deletions: `OrchestratorError::{Shutdown,InvalidPubkey,BeaconTimeout}` (F12), `SlashingError::MigrationError` (F56), `SlashingDbReader` full-fetch max → delegate to `last_signed_attestation_epoch` (F57) | `crates/rvc/src/orchestrator/error.rs:31`, `crates/slashing/src/error.rs:13`, `reader.rs:80` | low / S |

### Theme C — Foundation & crate topology (enablers)
**Motivation:** Give shared logic a home *below* the crates that duplicate it, so Theme E/F consolidation has somewhere to point. Also restores the documented layering.

| Item | Files | Impact / Effort |
|---|---|---|
| C1. Extract `crates/observability` (or `rvc-logging`) from crypto: `logging.rs`, `hex.rs`, `pubkey.rs` (CanonicalPubkey); repoint ~20 dependents; drop crypto dep where logging was the only use; pin in architecture-tests ZERO_OUT_EDGE list; delete private `redact_url` in remote_signer.rs | `crates/crypto/src/logging.rs`, `hex.rs`, `pubkey.rs`, `crates/beacon/src/client.rs:7`, `crates/architecture-tests/Cargo.toml` | high / M (F39, F105) |
| C2. `NetworkPreset` table in eth-types (name, genesis_fork_version, GVR, capella_fork_version, genesis_time as typed `[u8;4]`/`[u8;32]` + hex accessors); keygen `KeygenNetwork` and rvc `Network` become thin delegates; cross-check test byte-form == hex-form | new `crates/eth-types/src/networks.rs`; `bin/rvc-keygen/src/network.rs:12`, `crates/rvc/src/config/network.rs:17`, mainnet literal at `config/builder.rs:1063` | high / S–M (F16, F107) |
| C3. ForkName as single fork source: `FromStr` (replaces `body_fork_layout` string match), `id()/try_from(u32)` (replaces `validate_fork_id` + grpc-signer byte-match), `body_layout()`; `ForkSchedule::entries()` table so from_epoch/fork_version/activation_epoch iterate one list; grpc-signer carries ForkName in SignContext (no silent `_ => Deneb`); fix `ssz_helpers` Electra dispatch (decode ElectraAttestation for fork_id ≥ 5 or reject explicitly) | `crates/eth-types/src/fork.rs`, `block.rs:56`, `ssz_helpers.rs:52,128,238`, `crates/grpc-signer/src/client.rs:216`, `bin/rvc-signer/src/service.rs:750` | high / M (F82, F85, F89, F74) |
| C4. `crates/signer-proto`: compile signer.v2.proto once (client + server stubs behind features); both bin/rvc-signer and grpc-signer depend on it (after B10 removes v1) | new crate; `bin/rvc-signer/build.rs`, `crates/grpc-signer/build.rs` | med / M (F32) |
| C5. Shared Web3Signer wire module (`web3signer-wire` crate or module in signer-proto): Serialize+Deserialize on one type set; serde round-trip conformance test; split `remote_signer.rs` into wire.rs + client.rs | `crates/crypto/src/remote_signer.rs:130,194`, `bin/rvc-signer/src/http_api/request.rs:30,80` | high / M (F45, F106) |
| C6. Canonical pubkey/hex parsing: route the 6+ hand-rolled parse sites through `eth_types::canonical::parse_pubkey_hex`; make `canonical` the engine under `hex_fixed` and `serde_signature`; type `SyncCommitteeDuty.pubkey` as `[u8;48]` | `crates/keymanager-api/src/handlers.rs:831`, `crates/validator-store/src/store.rs:47`, `crates/secret-provider/src/key_source_manager.rs:121`, `refresh.rs:79`, `crates/eth-types/src/hex_fixed.rs`, `serde_signature.rs`, `sync_committee.rs:22` | med / S–M (F73, F88, F116) |
| C7. Dependency hygiene: remove unused deps (crypto ssz_derive/tree_hash_derive, metrics serde_json, grpc-signer thiserror); populate or delete crypto's empty `test-utils` flag; promote futures/rcgen/hyper/http-body-util to `[workspace.dependencies]`; standardize feature name `test-utils` | listed Cargo.tomls (F110) | med / S |
| C8. `CanonicalGvr` newtype in slashing: parse once at boundary, one canonical 0x-lowercase encoding for metadata, rows, interchange comparison | `crates/slashing/src/db.rs:1136,1148,1804`, `crates/rvc/src/startup.rs:116` | med / M (F53) |

### Theme D — Signing-stack consolidation (one signing core)
**Motivation:** The highest concentration of consensus-critical duplication. Goal: each policy (domain derivation, EIP-7044 cap, timeout, slashing-gate flow, error taxonomy, sanitization) exists exactly once.

| Item | Files | Impact / Effort |
|---|---|---|
| D1. Per-duty signing-root module in crypto: `signing_root_for(duty, ctx)` with the Capella cap applied inside; consumers: SignerService's 10 methods, LocalSigner TypedSigner impls, Web3Signer request builders, grpc-signer, test mocks; delete `capella_capped_fork_version` call sites + caller-obligation doc; unify sign_attestation on ForkSchedule (L-11); re-home the KATs migrated in B7 onto `signing_root_for` | `crates/signer/src/lib.rs:262,928`, `crates/crypto/src/typed_signer.rs:171,330`, `remote_signer.rs:326`, `voluntary_exit_signing.rs:15`, `bin/rvc-keygen/src/exit.rs:127` | high / M (F38, part F128-adjacent L-11 from F127) |
| D2. Merge the two safe-signing stacks: extract `sign_slashable(stage_fn, root, pubkey, hooks)` core owning spawn_blocking + timeout + commit/discard + metrics hooks; SignerService delegates to it (gains sign timeout + PubkeyScopedDb auditing); SigningGate keeps it (gains metrics + re-check-enablement-under-lock); add `sign_nonslashable` helper to SignerService mirroring gate.rs:529 so 7 methods become 3-line wrappers. **Timeout semantics are backend-dependent and fail-closed:** SigningGate's discard-staged-row-on-timeout (gate.rs:292-299, the BUG-003 fix) is only safe for in-process backends, where dropping the future guarantees no signature was produced. Against SignerService's REMOTE backends (Web3Signer/gRPC) the request may have already reached the signer when the timeout fires, so the shared core must retain/commit the staged row on timeout — or restrict post-timeout retries to the same signing root via D3's `CommitFailed` taxonomy — never discard-and-allow-conflicting-retry | `crates/signer/src/lib.rs:124,238,473,627`, `gate.rs:225,292,371,529` | high / L (F37, F40 partial) |
| D3. Error taxonomy convergence: one signing error enum distinguishing `SlashingBlocked` (never retry) vs `CommitFailed` (same-root retry safe) with `#[source] SlashingError`; fix SignerService commit-failure arms; move `SigningError` into `crypto/src/error.rs`; shared `classify(SigningGateError) -> GateErrClass` consumed by both rvc-signer transport mappers | `crates/signer/src/lib.rs:48,395,558`, `error.rs:32`, `crates/crypto/src/signer_trait.rs:9`, `bin/rvc-signer/src/service.rs:399`, `http_api/response.rs:59,81` | high / M (F41, F36) |
| D4. rvc-signer transport unification: promote `dispatch.rs` SignPlan engine to a transport-neutral module used by gRPC + HTTP + DVT; `sign_prelude`/`RequestCtx` helper + `dispatch_non_slashable` for the 10 v2 handlers; `grpc_common` module for the 5 duplicated validators + proto decode blocks; resolve builder-fork-version divergence (thread network genesis fork version through both transports — deliberate behavior fix) | `bin/rvc-signer/src/http_api/dispatch.rs:45,82`, `service.rs:490-1086,324`, `dvt/peer_service.rs:104,236,336` | high / M–L (F26, F27, F28) |
| D5. grpc-signer `sign_rpc` helper collapsing 10× ~55-line pipelines; dedupe `connect()` TLS/non-TLS channel build | `crates/grpc-signer/src/client.rs:117,264,717` | high / M (F70) |
| D6. `ValidatorSigner` returns `crypto::Signature`; implement trait directly on SignerService, delete 200-line delegation impl; evaluate dropping `?Send` | `crates/signer/src/traits.rs:17`, `lib.rs:1137` | med / M (F44) |
| D7. Naming cleanup: delete `slashable.rs`/`non_slashable.rs` re-export modules; resolve rvc-signer lib/bin package-name collision; add signer-hierarchy doc in crypto | `crates/signer/src/slashable.rs`, `non_slashable.rs`, Cargo.tomls | low / S (F47) |

### Theme E — Slashing & beacon access-layer mechanics
**Motivation:** Single rule engine for EIP-3076; single retry engine and narrow traits for beacon access. Adding an endpoint should touch 2 sites, not 5; a rule fix should touch 1 site, not 3.

| Item | Files | Impact / Effort |
|---|---|---|
| E1. Extract `crates/slashing/src/rules.rs`: pure `check_attestation(rows, watermarks, candidate)` / `check_block(...)`; all surviving entry points (stage_* after B4) delegate; `WatermarkKind` enum + `read_watermark`/`raise_watermark` helpers collapse 15 SQL literals | `crates/slashing/src/db.rs:934-1714`, `stage.rs:315,348,452` | high / L (F48, F55) |
| E2. Split `db.rs` into `db/` module dir: open.rs (preflight/pragmas/permissions), migrations.rs (absorb migration.rs + migrate_to_v2, share `read_schema_version`), interchange.rs, watermarks.rs, rules delegation; move test clusters alongside. Pure code motion | `crates/slashing/src/db.rs`, `migration.rs:25` | med / L (F51) |
| E3. Targeted SQL for per-sign checks: unique-index double-vote lookup, EXISTS for surround/surrounded, MIN(target_epoch) — replaces full-history scan under the signing mutex | `crates/slashing/src/stage.rs:514`, `db.rs:977,1598` | med / M (F54) |
| E4. Beacon single retry engine: `execute_with_retry_raw` becomes the one loop; `execute_with_retry`, `post_empty_with_headers`, `submit_attestation` (400-partial-failure hook) rebuild on it; add URL-encoding via `Url::query_pairs_mut`, jitter, uniform 429/Retry-After; `traced()` helper replaces 7 header-injection copies; rvc/monitoring `push_with_retry` consumes the shared policy | `crates/beacon/src/client.rs:759,902,1035,1163,129-1049,187`, `crates/rvc/src/monitoring.rs:170` | high / M (F58, F66, F108, F131) |
| E5. BeaconNodeClient split + shared mock: role traits (DutiesProvider, BlockProducer, AttestationApi, SyncCommitteeApi, LivenessApi, NodeStatusApi) with blanket impl; `test-utils` feature on bn-manager exporting one erroring-by-default configurable mock; delete the 16 hand mocks; remove `post_validator_liveness` error-returning default impl; passthrough impl generated by macro/`delegate` | `crates/bn-manager/src/traits.rs:22,156,525`, `manager.rs:1238`, all mock sites (F7/F104 lists) | high / L (F59, F104, F7, F63) |
| E6. BnManager `submit()` helper for the 5 broadcast-vs-query_first blocks; batched health-tracker updates (`record_outcomes`) in query_best/fallback_unsynced | `crates/bn-manager/src/manager.rs:920-1188,567,634` | med / S (F61, F68) |
| E7. Proposer failover fix: `BeaconBlockAdapter` accepts `Arc<dyn BeaconNodeClient>`; proposer BnManager actually used for block production; document retries=0-under-failover policy in one place; narrow `build_beacon` to exit tooling | `bin/rvc/src/main.rs:1526,1542`, `crates/rvc/src/config/builder.rs:208,245`, `beacon_adapter.rs` | med / M (F19, F62) |
| E8a. builder seam: 2-method `BuilderBeaconClient` + 1-method registration signer trait (deletes ~250 mock lines) | `crates/builder/src/service.rs:32,339` | med / M (F97 part) |
| E8b. duty-tracker: `from_response` cache constructors; `clear_cache` extended to cover the sync cache | `crates/duty-tracker/src/tracker.rs:114-398,299` | med / S (F96) |
| E8c. doppelganger: single `MonotonicEpochClock` + shared restart-skip predicate; legacy `DoppelgangerService` retired from the startup path — **gated on SEC-2**, with its own lifecycle tests (imported/restarted key does not attest until its window clears) | `crates/doppelganger/src/service.rs:31,96`, `epoch_clock.rs:23`, `forward_window.rs:128`, `crates/rvc/src/startup.rs:139` | med / M (F93, coord SEC-2) |
| E8d. timing: SlotClock derived methods become default trait methods; per-impl duplicated slot math deleted | `crates/timing/src/clock.rs:57,176` | low / S (F98) |
| E9. Secret-provider shared pipeline: one instrumented `fetch_provider_keys(provider, denylist, timeout)` owning hex precheck, timeout, concurrency, metrics, spans — used by boot and refresh (closes the refresh observability gap and the boot no-timeout gap) | `crates/secret-provider/src/key_source_manager.rs:117-137`, `refresh.rs:51-91` | high / M (F72) |

### Theme F — Composition roots & configuration plumbing
**Motivation:** One real, testable bootstrap per binary; config that can be extended by touching one place.

| Item | Files | Impact / Effort |
|---|---|---|
| F1. Extract `run_validator` into a `crates/rvc` bootstrap module of phase functions (`open_slashing_db`, `load_signing_keys`, `wire_signing_enablement`, `spawn_background_tasks`…); main.rs shrinks to CLI parse + logging + one library call; dedupe GVR parse; slashing-monitor loop moves into `rvc::slashing_monitor::spawn` returning `SlashedOutcome` enum | `bin/rvc/src/main.rs:1055-1953,1752`, `crates/rvc/src/slashing_monitor.rs:32` | high / L (F13, F22) |
| F2. rvc-signer server into the lib: `server::run(resolved, shutdown) -> Result<(), ServerError>` (thiserror) decomposed into open_slashing_db/build_backend/build_grpc_router/spawn_http_api; then promote lib to `crates/signer-server`; replace cargo-build-in-test with `CARGO_BIN_EXE` or direct `server::run` calls; TLS module split (tls_config.rs + accept_loop.rs, rename src/tls → grpc_tls, fix wrong doc comment) | `bin/rvc-signer/src/main.rs:359-1058`, `integration_polish.rs:20`, `tls/mod.rs:35`, `http_api/tls.rs` | high / L (F25, F111, F34) |
| F3. rvc config restructure: nested sub-structs (Logfile/Tracing/Keymanager/GrpcSigner/ProposerSource/Monitoring/BuilderLimits per the SecretProviderConfig precedent); `Start(StartArgs)` with `#[command(flatten)]` groups + `From<StartArgs> for CliOverrides`; macro-generated merge; typed config enums (SlashedAction, BroadcastTopic, TracingExporter, BnRole); `tracing_sample_rate: Option<f64>` end-to-end with OTEL env precedence in one place | `crates/rvc/src/config/types.rs:22,338,651,946,137,515-638`, `bin/rvc/src/main.rs:43,506,628,948` | high / L (F4, F14, F9, F20) |
| F4. rvc-signer config: CLI args become `Option<T>` (kills every `*_is_default` heuristic and the explicit-default-override bug); ServeArgs moves into lib config.rs, CliOverrides mirror deleted; `Backend` stays an enum through ResolvedConfig | `bin/rvc-signer/src/main.rs:966-1058`, `config.rs:133,175` | med / M (F31) |
| F5. Keymanager server assembly: `spawn_keymanager_api(config, deps)` in crates/rvc; `KeymanagerServer::new(deps, settings)` structs replace 14 positional args; `scan_and_rearm_gate` hoisted above the branch; DoppelgangerLifecycle component encapsulating window/cancel_tokens/state-lock (KM-2 invariant in one type, local+remote import share one path); thiserror enums for SlashingProtection/remote-key traits so sanitize_* collapses to one mapper; exit handlers collapse to one `handle_exit` | `bin/rvc/src/main.rs:1595-1720`, `crates/keymanager-api/src/server.rs:34`, `handlers.rs:32-96,198-293,377,513,745,772`, `traits.rs:39,80`, `url_validator.rs:3` | high / L (F18, F71, F75, F76, F77) — coordinate with SEC-1 tracked_keys work (F119) |
| F6. Exit commands: shared `build_signed_exit(args)` helper; panicking `Arc::try_unwrap` → `?`; move `prepare_exit.rs`/`submit_exit.rs` next to their bin/rvc consumers; keygen `write_new_0600` helper (create_new on all platforms) ×4 sites; `GenerateArgs` struct for new/existing_mnemonic | `bin/rvc/src/commands/voluntary_exit.rs:24`, `prepare_exit.rs:24`, `bin/rvc-keygen/src/new_mnemonic.rs:19,62,258`, `bls_to_execution.rs:77`, `exit.rs:52`, `crates/rvc/src/prepare_exit.rs` | med / M (F15, F21, F24, part F12) |
| F7. Validator-store: single lock over one state struct (fixes opposite-order acquisition + non-atomic reload); shared `parse_config` with fallback consts defined once | `crates/validator-store/src/store.rs:88,131,272,362` | med / M (F128, F78) |

### Theme G — eth-types fork/SSZ hygiene
**Motivation:** Reduce the cost/risk of the next fork. **Coordinate every item with in-flight SEC-6 typed-SSZ work (F117) — do not race it.**

| Item | Files | Impact / Effort |
|---|---|---|
| G1. Single-field-list `ssz_container!` macro (struct + Encode/Decode from one list) — makes field-order divergence unrepresentable | `crates/eth-types/src/block_body.rs:108-675` | high / M (F81) |
| G2. `impl_container_tree_hash!` macro for the 10 hand-written TreeHash impls (ordered leaf list stated once per type) | `crates/eth-types/src/aggregation.rs`, `attestation.rs:18`, `sync_committee.rs`, `block.rs:458,520` | med / M (F83) |
| G3. Dual-SSZ mitigation short of unification: stop exposing block_body twins publicly (`pub(crate)` or `Wire*` prefix) + module-level twin table; full unification deferred until ssz_types/ethereum_ssz versions align (see Deferred) | `crates/eth-types/src/block_body.rs:259-412`, `lib.rs:95` | high / S mitigation (F80) |
| G4. `extract_blob_kzg_commitments` on typed decoders; `Result` signature so malformed ≠ empty; delete duplicated offset constants | `crates/eth-types/src/block.rs:23,86` | med / M (F87) |
| G5. Gate test fixtures behind `test-fixtures` feature in `pub mod fixtures`; consumers move them to dev-deps | `crates/eth-types/src/block_body.rs:893`, `block.rs:354`, `lib.rs:28` | med / S (F86) |
| G6. Delete constant-echo tests; keep uniqueness/size invariants; one table-driven spec-pin test | `crates/eth-types/src/domains.rs:20`, `lib.rs:197,337` | low / S (F90) |
| G7. Sync-committee constants + `subcommittee_index` + `is_sync_committee_aggregator` move to eth-types; both former copies delete (pairs with B1) | `crates/sync-service/src/lib.rs:23,211`, `crates/rvc/src/orchestrator/sync_committee.rs:20,170` | med / S (F99) |

### Theme H — Test organization, fidelity & docs
**Motivation:** Make the 60–85%-test files navigable, end mock copy-paste, aim tests at production paths, and stop ARCHITECTURE.md rot.

| Item | Files | Impact / Effort |
|---|---|---|
| H1. Move wiremock/integration suites out of source files: beacon client.rs → `tests/client_http.rs`; bn-manager manager.rs → `tests/manager_strategies.rs`; coordinator's 5k-line module → per-topic test files; slashing db.rs tests move with E2; block-service test module split + 3 beacon mocks merged; keymanager handlers.rs router tests → tests/ with one shared TestApp harness; rvc-signer routes.rs/tls.rs suites → submodule/tests files; rename `integration_polish.rs`/issue-ID test files by behavior | listed god-files (F60, F5, F95, F69, F33) | high / L |
| H2. Shared test support: `rvc-test-support` dev-only crate (rcgen PKI + mTLS harness), `create_test_keystore` behind crypto `test-utils`, signer `tests/common/mod.rs` fixture + enablement mocks, stub ValidatorSigner behind signer test-utils; duty-tracker tests move to in-memory mocks (keep 1–2 wiremock round-trips) | F113/F46/F95/F103 sites | med / M |
| H3. Relocate bin/rvc tier suites to the library crates they exercise; prune tautological cases; add real CLI-level tests (assert_cmd / CARGO_BIN_EXE) for flag parsing + startup exit codes; move telemetry-parity tests to crates/telemetry; delete vacuous test + duplicate SharedBuf | `bin/rvc/tests/tier2-4*.rs`, `integration_test.rs`, `bin/rvc/src/main.rs:2097-2712` | med / M (F17, F23) |
| H4. Mock fidelity (docs/issues phase-2 alignment): capture full args/payloads in block/sync mocks; assert content not counts | `crates/block-service/src/service.rs:690`, `crates/sync-service/src/lib.rs:328` | med / M (F123) |
| H5. KAT-first policy: every signing/container root test anchored to reference-client vectors; forbid self-consistency-only assertions (adopt as review convention + note in CLAUDE.md/ARCHITECTURE.md) | F122 sites | high / policy |
| H6. ARCHITECTURE.md regenerated from `cargo metadata` with a doc==generated test in architecture-tests; add crate count fix + meta-crates; record shutdown-idiom and fail-closed conventions; topology: fold propagator into bn-manager `submit` module, break block-service→builder edge (local CircuitBreakerState), add no-domain→domain-edge rule | `ARCHITECTURE.md`, `crates/architecture-tests/tests/architecture_no_cycles.rs`, `crates/propagator/src/lib.rs:27`, `crates/block-service/src/service.rs:3`, `crates/builder/src/circuit_breaker.rs:11` | med / M (F109, F112, F67) |
| H7. Structural splits inside crates/rvc: keymanager_adapters/ module dir with `KeyChangeNotifier`; coordinator `wait_for`/`phase_deadline` helpers + epoch-boundary extraction (+ evaluate BlockProposalService extraction per REVIEW.md); aggregation `produce_one_aggregate`/`submit_versioned`/`timed()` combinator; attestation inner-`Result` fn; `duty_tracker` module rename to `grpc_health`; monitoring/config_url under background_tasks; PubkeyMap re-keyed by `[u8;48]` + shared pubkey→index registry | F6, F5/F121, F8, F11, F12, F10 sites | med / L |

---

## 4. Phased Plan

Ordering logic: Phase 1 fixes live correctness drift and installs the safety nets later phases rely on. Phase 2 deletes dead twins so no later phase restructures doomed code. Phase 3 builds the shared foundations that Phase 4's consolidations point at. Phase 5 rebuilds composition roots on top of the consolidated cores. Phase 6 is code motion, test relocation, and doc regeneration — deliberately last because file splits create merge conflicts with every earlier phase.

### Phase 1 — Correctness fixes & safety nets (Theme A) — total effort M, risk LOW-MEDIUM
**Goal:** production slashing path matches EIP-3076; the tests that would catch a botched later refactor exist; the key-import path works.

| Work item | Acceptance criteria | Effort | Risk / mitigation |
|---|---|---|---|
| A1 stage.rs watermark `<=` | `stage.rs:356/506` use `<=`; new tests in `crates/slashing/tests/stage.rs` prove equality blocking on block-slot and att-target watermarks | S | Intentional behavior change (bug fix). TDD: write failing watermark-equality stage tests first; conformance suite (after A2) must pass |
| A2 conformance/proptest retarget | `tests/conformance.rs` + `proptest_slashing.rs` drive `stage_* → commit/discard`; all 76 conformance cases green on the production path; interchange watermark simulation uses real DB watermark code | M | If cases fail, that is signal — triage each divergence before changing production code |
| A3 pipeline slashing tests | New test: two `process_slot` calls with conflicting AttestationData → second blocked; concurrent-signer test uses conflicting data; DB-error → fail-closed test | M | Additive only |
| A4 key-import wiring | `with_pubkey_map` builder methods deleted; adapters require notifier at construction; single `DutyOrchestrator` ctor w/ `OrchestratorDeps`; integration test: import key via keymanager adapter → orchestrator duty cache cleared (`key_gen_rx` fires); doppelganger gate test: a newly imported key produces no attestations until its doppelganger window/enablement gate clears | M | Constructor churn across bin/rvc + tests; compile errors are the point. Keep `#[allow(too_many_arguments)]` removal in same PR. Coordinate with SEC-2: A4 lands four phases before the DoppelgangerLifecycle consolidation (F5/E8c), so the gate test is the interim guard |
| A5 builder unsafe fix | unsafe block gone; workspace `unsafe_code = "deny"` (allow-listed where truly needed) | S | none |
| A6 --password-dir | flag either works per docs (per-keystore files) or is removed; empty-password fallback replaced by startup error | S | Deployment-visible: release-note it |
| A7 gRPC sign metrics | one shared recording helper (not per-handler inline code) called by all 10 v2 handlers; `sign_total`/`sign_duration_seconds`/`sign_errors_total` with type×outcome labels; scrape test asserts non-zero after a sign | S | D4 (P4) rewrites these handlers into the SignPlan dispatcher — the helper is what D4 absorbs; the scrape test must stay green through that unification |

**Phase gate:** `cargo test --workspace`, `cargo clippy --workspace`, architecture-tests green; slashing conformance suite green **on the stage path**.

### Phase 2 — Dead-code purge (Theme B) — total effort M-L, risk LOW
**Goal:** every later phase operates on code that is actually alive. Mostly deletions; each PR re-verifies zero callers via `rg` before deleting.

| Work item | Acceptance criteria | Effort |
|---|---|---|
| B1 sync-service twin deletion | crate exports only `is_sync_committee_aggregator` + subnet helper + error; orchestrator unchanged behaviorally; ARCHITECTURE.md corrected | M |
| B2 build_all deletion | `builder.rs` has no `build_all`/`BuiltServices`/`build_doppelganger_service`; former unit tests ported to `build_*` methods | M |
| B3 timing timer deletion | `timer.rs` gone; no `rvc_slot_timing_*` metrics registered; crate = SlotClock + constants only | S |
| B4 slashing API gen-1/2 removal | public surface = `stage_*` (+ optional thin `check_and_record` wrapper delegating to stage); `_client_cn` gone; affected tests ported (depends on A2) | M |
| B5 watermark wiring | Interchange import sets watermarks from interchange maxima; `rvc slashing prune` subcommand + prune metric live; the wire (not delete) decision recorded in ARCHITECTURE.md with the A1/A2 dependency as rationale | M |
| B6 eth-types insecure deletion | module + test file gone; stale comment fixed | S |
| B7 crypto free-fn deletion | free `sign_*`/`RawSigner` gone; KATs migrated to the surviving `compute_domain`/`compute_signing_root` helpers (re-homed onto `signing_root_for` by D1 in Phase 4); `no_direct_composite_signer` guard still green | M |
| B8 tracker loader deletion | one directory-scan loop remains (with traversal check + pubkey verification + truncated logging); ARCHITECTURE.md corrected | S-M |
| B9 bn-manager dead config | `selection_strategy` gone from config; per-op strategy documented on BnManager | S |
| B10 v1 proto retirement | grpc-signer connect uses v2 ListPublicKeys; v1 impl/exports/tests/proto compilation deleted in both crates | M |
| B11 micro-deletions | dead error variants gone; reader delegates to SQL MAX | S |

**Phase gate:** full workspace green; `cargo build --release` binary size/deps sanity; grep-based dead-symbol audit attached to PRs.

### Phase 3 — Foundations (Theme C + G quick wins) — total effort L, risk LOW-MEDIUM
**Goal:** shared homes exist for logging, network presets, fork identity, wire contracts, pubkey parsing — so Phase 4 consolidation has targets. Wide but mechanical changes.

| Work item | Acceptance criteria | Effort | Risk / mitigation |
|---|---|---|---|
| C1 observability crate | beacon/bn-manager/slashing/etc. no longer depend on crypto for logging; architecture-tests updated (new sink pinned); crypto Cargo.toml loses no-longer-needed re-exports; redaction conformance CI test passes against new crate | M | Touches ~20 Cargo.tomls; land as one PR with only `use`-path changes |
| C2 NetworkPreset table | both binaries delegate; cross-check test (byte vs hex forms) green; mainnet GVR literal appears exactly once in the workspace | S-M | KAT-style: assert current literals unchanged |
| C3 ForkName single source | `FromStr`/`id()`/`try_from(u32)`/`body_layout()` exist; `body_fork_layout` string match, `validate_fork_id`, grpc-signer byte-match all delegate; ssz_helpers Electra decode either dispatches or rejects with a typed error (test proves Electra-shaped aggregate is not silently misparsed); `ForkSchedule::entries()` drives from_epoch/fork_version/activation_epoch | M | Consensus-adjacent: KATs for every fork mapping before/after; exhaustive-match compile checks |
| C4 signer-proto crate | one tonic_build invocation in the workspace; both consumers use it (after B10) | M | Generated-type paths change; mechanical |
| C5 web3signer-wire module | one type set with Serialize+Deserialize; serde round-trip test; client and server import it; `remote_signer.rs` split into wire.rs/client.rs | M | Contract-frozen: round-trip test uses recorded production JSON bodies |
| C6 canonical pubkey parsing | the six listed parse sites call `eth_types::canonical`; behavior test: `0X` prefix + mixed case accepted uniformly (or uniformly rejected — one documented policy) | S-M | Policy unification is a small behavior change; enumerate call sites in PR |
| C7 dependency hygiene | `cargo udeps`/machete clean for listed crates; single `test-utils` feature name | S | none |
| C8 CanonicalGvr | slashing import/export/set_gvr take typed value; import of interchange with `0x`-vs-bare GVR no longer spuriously rejects (test) | M | DB-visible: migration not needed (TEXT stays), but add row-encoding normalization test |
| G5/G6/G7 eth-types quick wins | fixtures behind `test-fixtures`; constant-echo tests deleted; sync constants moved (pairs with B1) | S | none |

**Phase gate:** workspace green; architecture-tests layer policy updated and green; `cargo tree` diff reviewed (crypto's dependents shrink).

### Phase 4 — Core consolidation (Themes D + E) — total effort XL, risk MEDIUM-HIGH (highest-value phase)
**Goal:** exactly one implementation each of: EIP-3076 rules, signing-root derivation, safe-signing flow, gate error taxonomy, rvc-signer sign policy, grpc RPC pipeline, beacon retry loop, beacon mock. Phase 1's tests are the guardrails.

| Work item | Acceptance criteria | Effort | Risk / mitigation |
|---|---|---|---|
| E1+E2 slashing rules core + db/ split | `rules.rs` pure functions; stage delegates; conformance (production-path, from A2) + proptests green; db/ split is pure code motion (diff = moves) | L | Highest-stakes refactor; conformance suite is the oracle; land rules extraction and file split as separate PRs |
| E3 targeted SQL checks | EXISTS/MIN queries replace full-history scan; proptest equivalence run old-vs-new on random histories; timing test shows bounded per-sign work | M | Keep old path behind cfg(test) comparison harness for one release |
| D1 signing-root module | one `signing_root_for`; EIP-7044 cap in exactly one place (grep proves); existing fork-boundary KATs pass against the shared helper | M | KATs migrated before deleting old sites |
| D2 safe-signing merge | SignerService + SigningGate share `sign_slashable`/`sign_nonslashable` cores; both paths have timeout + metrics + enablement re-check (feature-parity table in PR); 4 slashable methods → 2 thin wrappers; timeout is fail-closed for remote backends (staged row retained/committed on expiry, or retries restricted to the same signing root via D3 — never discarded); late-completion test: timeout fires, remote sign completes late, a subsequent conflicting sign for the same slot/epoch is blocked | L | The in-process discard-on-timeout semantics (gate.rs:292-299, BUG-003 fix) must NOT be ported verbatim to remote backends — that is a double-sign path, not an upgrade; A3 pipeline tests must stay green |
| D3 error taxonomy | `CommitFailed` distinguishable from `SlashingBlocked` at VC call sites (test asserts retry semantics); one `classify()` for both rvc-signer mappers | M | Callers matching on old variants updated in same PR |
| D4 rvc-signer SignPlan unification | gRPC/HTTP/DVT consume one plan engine; builder fork-version divergence resolved (cross-transport test: identical request → identical signature); `grpc_common` validators shared; A7's metrics recording helper absorbed into the dispatcher with its scrape test still green | M-L | Cross-transport signature-equality test is the oracle; fork-version fix is a deliberate behavior change on non-mainnet — release-note |
| D5 grpc-signer sign_rpc | 10 methods shrink to request-construction + one call; wire-level integration test (against in-process server once F2 lands, else existing harness) green | M | none beyond diff size |
| D6 ValidatorSigner returns Signature | delegation impl deleted; consumers call `.to_bytes()` at wire boundary only | M | Mechanical, compiler-driven |
| E4 beacon retry engine | one loop; 400-partial-failure preserved (wiremock tests); URL-encoding + jitter added; monitoring push uses shared policy | M | Wiremock suite (moved or in place) is the oracle |
| E5 BeaconNodeClient split + shared mock | role traits + blanket impl compile all existing call sites; one configurable mock in bn-manager test-utils; 16 hand mocks deleted (`rg "impl BeaconNodeClient for" | wc -l` = 3: BnManager, BeaconClient, shared mock); default-impl footgun removed | L | Blanket impl keeps `Arc<dyn BeaconNodeClient>` users compiling; delete mocks incrementally per crate |
| E6/E7 BnManager submit + proposer failover | 5 dispatch blocks → 1 helper; proposer path goes through BnManager failover (integration test: first proposer node down → second used) | M | Proposer change is behavior-visible: flag in release notes |
| E8a builder seam | builder tests stub the 2-method trait, not 25 methods; ~250 hand-rolled mock lines deleted | M | none |
| E8b duty-tracker cache | `from_response` constructors in place; test proves `clear_cache` clears the sync cache | S | none |
| E8c doppelganger consolidation | single clock + single restart-skip predicate; legacy `DoppelgangerService` retired from startup path; lifecycle test: imported/restarted key does not attest until window clears | M | Gated on SEC-2; keep legacy service until forward-window wiring confirmed in production |
| E8d timing default methods | derived slot math as SlotClock default trait methods; per-impl duplicates deleted | S | Mechanical, compiler-driven |
| E9 secret-provider pipeline | boot and refresh share one instrumented fetch fn; refresh emits RVC_SECRET_PROVIDER_* metrics (test); boot has timeout (test with hung mock provider) | M | none |

**Phase gate:** full workspace green; slashing conformance + proptests + A3 pipeline tests green; D2 late-completion double-sign test green; cross-transport signature-equality test green; signing KATs green; manual metric-scrape smoke test.

### Phase 5 — Composition roots & config (Theme F) — total effort XL, risk MEDIUM
**Goal:** each binary is CLI-parse + one library call; adding a config knob touches one place.

| Work item | Acceptance criteria | Effort | Risk / mitigation |
|---|---|---|---|
| F1 run_validator extraction | main.rs < ~600 lines; bootstrap phase fns unit-tested in crates/rvc; startup behavior byte-for-byte (same log lines/ordering where feasible); new CLI-level smoke test spawns binary and asserts clean startup+shutdown against mock BN | L | Biggest wiring risk in the plan. Extract one phase fn per PR; H3's CLI tests (pull forward the startup smoke test) guard each step |
| F2 rvc-signer server extraction | `server::run` in lib (then `crates/signer-server`); `integration_polish` no longer shells to cargo; tests use CARGO_BIN_EXE or in-process server; ServerError thiserror | L | Same PR-per-subsystem discipline; existing tests/ suites are the oracle |
| F3 rvc config restructure | Config = nested sub-structs; StartArgs flatten groups; merge generated (one field list); typed enums deserialize directly; `--tracing-sample-rate 0.01` explicit value survives env (test); adding a hypothetical flag = 1 struct field + 1 clap attr (demonstrated in PR description) | L | Config-file compat: serde aliases for old flat TOML keys + fixture test loading an existing config file |
| F4 rvc-signer config Option-ification | `*_is_default` heuristics gone; explicit-default CLI value wins over file (test) | M | Behavior fix — release-note |
| F5 keymanager assembly + lifecycle | `spawn_keymanager_api` in crates/rvc; `new(deps, settings)`; DoppelgangerLifecycle owns KM-2 invariant (km2 race tests target component directly, no HTTP stack needed); local+remote import share one path; trait errors are thiserror enums, sanitize_* collapsed | L | Coordinate with SEC-1 (tracked_keys) — land SEC-1 first or in same series to avoid double-touching handlers.rs |
| F6 exit-command dedup + keygen fs helper | both exit commands ≤ ~40 lines each over `build_signed_exit`; no `panic!` in command paths; `write_new_0600` single implementation, create_new on all platforms (behavior fix for non-unix overwrite) | M | none |
| F7 validator-store single lock | one lock; deadlock scenario impossible by construction; reload atomic (test: reader never observes half-applied config) | M | Concurrency tests with loom or stress harness optional |

**Phase gate:** workspace green; new CLI smoke tests green; run an actual `rvc start --dry-run`-style boot against a devnet/mock BN before merge of F1.

### Phase 6 — Structure, tests & docs (Themes G remainder + H) — total effort L-XL (parallelizable), risk LOW
**Goal:** navigable files, one mock per concept, docs that regenerate instead of rot.

| Work item | Acceptance criteria | Effort |
|---|---|---|
| G1/G2 eth-types macros | single-field-list container macro; TreeHash macro; KATs unchanged (byte-identical roots proven by existing vectors); coordinate/serialize with SEC-6 typed-body work | M |
| G3 dual-SSZ mitigation | block_body twins not publicly ambiguous (pub(crate) or Wire* rename); twin table documented | S |
| G4 blob-commitments on typed decoders | Result-returning; malformed-body test distinguishes error from empty | M |
| H1 test relocation | client.rs/manager.rs/coordinator.rs/db.rs/service.rs/handlers.rs/routes.rs each < ~40% test lines; wiremock suites in tests/; no test deleted without a ported equivalent (CI test-count diff reviewed) | L |
| H2 shared test support | rvc-test-support crate (PKI/mTLS); keystore fixtures in crypto test-utils; signer tests/common; duty-tracker in-memory mocks | M |
| H3 bin/rvc test relocation + CLI tests | tier suites live next to code they test; tautological tests pruned; assert_cmd coverage for flag parsing/exit codes | M |
| H4 mock fidelity | block/sync mocks capture and assert full payloads (aligns docs/issues phase-2) | M |
| H5 KAT policy | convention documented; new-code review checklist item | S |
| H6 ARCHITECTURE.md regeneration + topology | doc==generated CI test; propagator folded into bn-manager submit module; block-service→builder edge gone; no-domain→domain rule in FORBIDDEN table | M |
| H7 crates/rvc structural splits | keymanager_adapters/ dir; coordinator helpers + (optional) BlockProposalService; aggregation/attestation refactors; PubkeyMap re-key + shared index registry (perf test: prepare_proposers no longer O(v×64×duties)) | L |

**Phase gate:** workspace green; architecture doc test green; line-count report for the former god-files.

---

## 5. Deliberately Deferred (excluded, with reasons)

- **Full dual-SSZ-universe unification (F80 full fix):** blocked on upstream `ssz_types`/`ethereum_ssz` version alignment; only the exposure mitigation (G3) is in scope now.
- **Typed SSZ / opaque `Vec<u8>` body replacement (F117):** already tracked and in flight as SEC-6a-d in `plan/security-2026-07-18/`; this plan only coordinates (G1/G2/G4 land after or with it).
- **Keymanager tracked_keys single-source-of-truth (F119) and fail-open sweep (F125):** tracked as SEC-1/SEC-2/SEC-3 in the security plan; F5 keymanager work sequences after SEC-1.
- **Workspace-wide unwrap/expect campaign (F120):** XL, and the two analyzers disagree by 16× on the count (210 vs ~3,450 — re-measure first); hot-path DoS instance is tracked as SEC-5. Do instead: `clippy::unwrap_used/expect_used` deny in slashing/signer/crypto after Phase 4.
- **Signature `[u8;96]` newtype migration (F91):** L effort, low impact; natural follow-up to SEC-6/G-work, not before.
- **Full beacon stringly-typed struct migration (F65):** L effort; duties endpoints may piggyback on E5/E8, the rest deferred — parsing pain shrinks anyway once duty types are typed.
- **Shutdown idiom unification (F114):** opportunistic only — adopt CancellationToken in code Phase 5 already touches; a dedicated migration is churn without user-visible value.
- **Metrics registry injection + register_metric! consolidation (F115, F129):** low impact; revisit after Phase 6; deleting never-used metric definitions rides along with B3/A7.
- **Fuzz/property coverage for untrusted input (F130):** valuable but owned by the test-audit plan (docs/issues 3.x); not a refactoring work item.
- **Propagator extension to all submission types (F67 option 1):** we chose the fold-in direction (H6) instead; extending a pass-through layer adds indirection without need.
- **new_mnemonic GenerateArgs beyond the struct swap (F24 deep rework):** only the Args-struct conversion is in scope (F6); further keygen UX changes are product work.
- **Telemetry anyhow→thiserror (F116 first half):** S, kept — folded into F2/F3 phase gates as a rider; listed here so it isn't double-counted as its own item.

---

## 6. Validation Strategy

Per the repo's TDD convention (CLAUDE.md RED→GREEN→REFACTOR), every consolidation lands as: (1) characterization/KAT tests against the *current* production path, (2) the refactor, (3) tests still green — plus:

1. **Always-on gates (every PR, every phase):** `cargo fmt --check`, `cargo clippy --workspace` (warnings addressed), `cargo test --workspace`, `crates/architecture-tests` (acyclicity, forbidden/required edges, zero-out sinks — updated in C1/H6 as crates move).
2. **Phase 1:** the new stage-path conformance run is the master oracle for all later slashing work; pipeline double-vote test guards orchestrator→signer→slashing wiring for Phases 4–5.
3. **Phase 2 (deletions):** `rg` zero-caller proof attached per PR; test-count diff must be explained (ported vs deleted-with-the-dead-code).
4. **Phase 3 (foundations):** KAT pinning — network presets, fork mappings, wire-contract round-trips asserted equal to current literals/bodies before repointing consumers.
5. **Phase 4 (consolidation):** oracles per item — conformance+proptests (slashing), signing KATs incl. fork boundaries + EIP-7044 (signing root), cross-transport signature-equality (rvc-signer), wiremock suites (beacon retry), old-vs-new SQL equivalence proptest (E3). Deliberate behavior changes (VC sign timeout — fail-closed per D2's remote-backend semantics, gate metrics, builder fork version, proposer failover) each get an explicit test + release note.
6. **Phase 5 (composition):** binary-level smoke tests (assert_cmd/CARGO_BIN_EXE): clean start, flag precedence, exit codes; config-file backward-compat fixture tests; manual devnet boot for F1.
7. **Phase 6 (code motion):** diffs reviewed as pure moves (git move detection); test-count and line-count reports; ARCHITECTURE.md doc==generated test becomes a permanent gate.

---

## 7. Appendix — Full Findings Disposition Table

Scope keys: **rvc** = crates/rvc · **bin** = bin/rvc + bin/rvc-keygen · **sgnbin** = bin/rvc-signer · **cry/sgn** = crates/crypto + crates/signer · **slash** = crates/slashing · **bcn** = beacon/bn-manager/propagator · **km5** = keymanager-api/validator-store/secret-provider/grpc-signer/signer-registry · **eth** = crates/eth-types · **duty** = per-duty service crates · **xcut** = cross-cutting · **prior** = prior review/audit corpus. Disposition = theme item (phase).

| F# | Finding (short) | Scope | Category | Imp | Eff | Disposition |
|---|---|---|---|---|---|---|
| F1 | Key-import wiring optional, never connected | rvc | api-design | high | M | A4 (P1) |
| F2 | sync-service dead; orchestrator reimplements | rvc | duplication | high | L | B1 (P2) |
| F3 | build_all/BuiltServices test-only scaffolding | rvc | dead-code | high | L | B2 (P2) |
| F4 | Config sprawl: 60+ fields + 275-line merge | rvc | config | high | L | F3 (P5) |
| F5 | coordinator.rs run() dup + 5k-line test module | rvc | structure | med | M | H1+H7 (P6) |
| F6 | keymanager_adapters.rs 3k-line 8-adapter file | rvc | structure | med | M | H7 (P6) |
| F7 | 7+ hand-rolled BeaconNodeClient mocks in rvc | rvc | testing | med | M | E5 (P4) |
| F8 | maybe_produce_aggregations 415-line mirrored fn | rvc | duplication | med | M | H7 (P6) |
| F9 | Stringly config enums validated twice | rvc | error-handling | med | S | F3 (P5) |
| F10 | PubkeyMap stringly-keyed, O(n) scans | rvc | performance | med | M | H7 (P6) |
| F11 | process_attestation_duty 12 early-return copies | rvc | structure | low | S | H7 (P6) |
| F12 | Ops modules in orchestrator crate + name collision | rvc | structure | low | S | H7/F6 (P5-6) |
| F13 | run_validator ~900-line god fn + dead build_all | bin | structure | high | L | B2 (P2) + F1 (P5) |
| F14 | CLI flag touches 5 places | bin | config | high | L | F3 (P5) |
| F15 | voluntary_exit/prepare_exit ~110-line clones + panic | bin | duplication | high | M | F6 (P5) |
| F16 | Network presets duplicated keygen vs rvc | bin | duplication | med | M | C2 (P3) |
| F17 | bin/rvc tier suites test library crates | bin | testing | med | M | H3 (P6) |
| F18 | Keymanager assembly inline + 14-arg ctor call | bin | structure | med | M | F5 (P5) |
| F19 | Proposer BnManager built then discarded | bin | dead-code | med | M | E7 (P4) |
| F20 | Tracing sample-rate float sentinel | bin | config | med | S | F3 (P5) |
| F21 | keygen 0o600 write block ×4, divergent overwrite | bin | duplication | med | S | F6 (P5) |
| F22 | Slashing monitor watch::Sender as mutable bool | bin | api-design | low | S | F1 (P5) |
| F23 | 615-line bin test module tests telemetry crate | bin | testing | low | S | H3 (P6) |
| F24 | new/existing_mnemonic 9-10 positional args | bin | api-design | low | S | F6 (P5) |
| F25 | run_serve composition root outside lib | sgnbin | structure | high | L | F2 (P5) |
| F26 | 10 v2 handlers repeat prelude + dispatch | sgnbin | duplication | high | M | D4 (P4) |
| F27 | Validators/decode copy-pasted service↔peer_service | sgnbin | duplication | high | S | D4 (P4) |
| F28 | Sign policy ×3 transports, builder-fork divergence | sgnbin | duplication | high | M | D4 (P4) |
| F29 | gRPC sign metrics registered, never recorded | sgnbin | dead-code | med | S | A7 (P1) |
| F30 | --password-dir cannot work as documented | sgnbin | error-handling | med | S | A6 (P1) |
| F31 | Config plumbing ×6 + *_is_default mis-resolution | sgnbin | config | med | M | F4 (P5) |
| F32 | Double proto compilation | sgnbin | dependency | med | M | C4 (P3) |
| F33 | routes.rs 82% tests; opaque test-module names | sgnbin | testing | med | M | H1 (P6) |
| F34 | TLS split across two same-named modules | sgnbin | structure | med | M | F2 (P5) |
| F35 | v1 SignerService kept fully compiled | sgnbin | dead-code | low | S | B10 (P2) |
| F36 | Gate-error sanitization duplicated gRPC/HTTP | sgnbin | duplication | low | S | D3 (P4) |
| F37 | Two safe-signing stacks, divergent safety features | cry/sgn | duplication | high | L | D2 (P4) |
| F38 | Signing-root derivation ×3; EIP-7044 cap ×4 | cry/sgn | duplication | high | M | D1 (P4) |
| F39 | crypto god-crate: logging drags BLS stack into 20 crates | cry/sgn | structure | high | M | C1 (P3) |
| F40 | signer lib.rs 3,008-line god-file | cry/sgn | structure | high | M | D2 (P4) + H1 (P6) |
| F41 | Error taxonomy fragmented; commit≠blocked conflated | cry/sgn | error-handling | high | M | D3 (P4) |
| F42 | Legacy free sign_* fns + RawSigner dead | cry/sgn | dead-code | med | M | B7 (P2) |
| F43 | Two directory loaders, tracker variant dead+weaker | cry/sgn | duplication | med | M | B8 (P2) |
| F44 | ValidatorSigner returns Vec<u8>, 200-line delegation | cry/sgn | api-design | med | M | D6 (P4) |
| F45 | Web3Signer wire types hand-mirrored | cry/sgn | duplication | med | M | C5 (P3) |
| F46 | 13 signer test files re-implement fixtures | cry/sgn | testing | med | S | H2 (P6) |
| F47 | Re-export modules + rvc-signer name collision | cry/sgn | naming | low | S | D7 (P4) |
| F48 | EIP-3076 rules ×3, stage missed watermark fix | slash | duplication | high | L | A1 (P1) + E1 (P4) |
| F49 | Two dead check/record API generations | slash | dead-code | high | M | B4 (P2) |
| F50 | Conformance/proptests aim at non-production path | slash | testing | high | M | A2 (P1) |
| F51 | db.rs 5,466-line god-file, split migrations | slash | structure | med | L | E2 (P4) |
| F52 | Watermark/prune subsystem unreachable | slash | dead-code | med | M | B5 (P2) |
| F53 | GVR stringly-typed, 3 encodings | slash | api-design | med | M | C8 (P3) |
| F54 | Per-sign full-history scan, unbounded growth | slash | performance | med | M | E3 (P4) |
| F55 | Watermark SQL literal ×15, magic strings | slash | duplication | low | S | E1 (P4) |
| F56 | MigrationError dead duplicate variant | slash | error-handling | low | S | B11 (P2) |
| F57 | Reader re-implements MAX over full fetch | slash | duplication | low | S | B11 (P2) |
| F58 | Four copy-pasted retry loops (~500 lines) | bcn | duplication | high | M | E4 (P4) |
| F59 | 26-method god-trait, ~11 mocks, default-impl footgun | bcn | api-design | high | L | E5 (P4) |
| F60 | client.rs 75% / manager.rs 62% inline tests | bcn | testing | high | M | H1 (P6) |
| F61 | Broadcast-vs-query_first dispatch ×5 | bcn | duplication | med | S | E6 (P4) |
| F62 | Fallback semantics scattered; proposer bypasses failover | bcn | config | med | M | E7 (P4) |
| F63 | 165-line manual passthrough impl | bcn | duplication | med | S | E5 (P4) |
| F64 | Dead bn-manager config (selection_strategy etc.) | bcn | dead-code | med | S | B9 (P2) |
| F65 | Stringly beacon API structs duplicate eth-types | bcn | api-design | med | L | Deferred (duties subset may ride E5/E8) |
| F66 | Trace-header injection ×7 | bcn | duplication | low | S | E4 (P4) |
| F67 | Propagator covers only plain attestations | bcn | structure | low | M | H6 (P6, fold into bn-manager) |
| F68 | Per-result write-lock churn in query_best | bcn | performance | low | S | E6 (P4) |
| F69 | handlers.rs 4,181-line monolith | km5 | structure | high | L | F5 (P5) + H1 (P6) |
| F70 | grpc-signer 10× ~55-line RPC boilerplate | km5 | duplication | high | M | D5 (P4) |
| F71 | Doppelganger lifecycle inlined in HTTP handlers | km5 | structure | high | M | F5 (P5) |
| F72 | secret-provider boot vs refresh divergence | km5 | duplication | high | M | E9 (P4) |
| F73 | Pubkey-hex parsing ×6, canonical helper unused | km5 | duplication | med | S | C6 (P3) |
| F74 | grpc-signer fork_id defaults unknown nets to Deneb | km5 | config | med | M | C3 (P3) |
| F75 | Stringly error contracts in keymanager traits | km5 | error-handling | med | M | F5 (P5) |
| F76 | KeymanagerServer::new 14 positional args | km5 | api-design | med | S | F5 (P5) |
| F77 | Exit handlers copy-paste identical | km5 | duplication | med | S | F5 (P5) |
| F78 | validator-store load/reload TOML dup | km5 | duplication | low | S | F7 (P5) |
| F79 | grpc-signer re-exports removed v1 client | km5 | dead-code | low | S | B10 (P2) |
| F80 | Dual SSZ stacks: 7 duplicate public types | eth | duplication | high | L | G3 mitigation (P6); full fix deferred (upstream) |
| F81 | impl_ssz_container! field list written twice | eth | duplication | high | M | G1 (P6, coord SEC-6) |
| F82 | Four parallel fork representations | eth | api-design | high | M | C3 (P3) |
| F83 | Hand-written TreeHash ×10 | eth | duplication | med | M | G2 (P6, coord SEC-6) |
| F84 | eth-types insecure module dead | eth | dead-code | med | S | B6 (P2) |
| F85 | ssz_helpers fork_id no-op; Electra misparse | eth | api-design | med | M | C3 (P3) |
| F86 | Test fixtures exported from production API | eth | structure | med | S | G5 (P3) |
| F87 | extract_blob_kzg_commitments: malformed = empty | eth | error-handling | med | M | G4 (P6) |
| F88 | Two hex stacks + three pubkey representations | eth | duplication | med | M | C6 (P3) |
| F89 | ForkSchedule 13 fields, 3 hand matches | eth | structure | low | M | C3 (P3) |
| F90 | Constant-echo tests | eth | testing | low | S | G6 (P3) |
| F91 | Signature = Vec<u8> alias | eth | api-design | low | L | Deferred (post-SEC-6) |
| F92 | SyncService production-dead duplicate | duty | duplication | high | M | B1 (P2) |
| F93 | Doppelganger dual impls + clock ×3 | duty | duplication | high | M | E8c (P4, coord SEC-2) |
| F94 | timing AttestationTimer dead + dead metrics | duty | dead-code | high | S | B3 (P2) |
| F95 | block-service service.rs 85% tests, 3 mocks | duty | testing | med | M | H1+H2 (P6) |
| F96 | DutyTracker parse loop ×4; clear_cache misses sync | duty | duplication | med | S | E8b (P4) |
| F97 | Inconsistent signer/beacon seams across duty crates | duty | api-design | med | L | E8a–E8d (P4) |
| F98 | SlotClock impls duplicate ~90 lines slot math | duty | duplication | med | M | E8d (P4) |
| F99 | Sync-committee constants duplicated | duty | duplication | med | S | G7 (P3) |
| F100 | Builder test unsafe pointer downcast | duty | testing | med | S | A5 (P1) |
| F101 | propose_block_with_mode public validation bypass | duty | api-design | med | S | E8a rider (P4): demote pub(crate), extend symbol-grep guard |
| F102 | sync-service Vec<u8> aliases + parallel arrays | duty | api-design | low | S | Resolved by B1 (P2) |
| F103 | DutyTracker wiremock unit tests | duty | testing | low | M | H2 (P6) |
| F104 | BeaconNodeClient 51-method god-trait, 16 mocks | xcut | api-design | high | L | E5 (P4) |
| F105 | crypto = workspace logging registry | xcut | structure | high | M | C1 (P3) |
| F106 | Web3Signer wire duplicated client/server | xcut | duplication | high | M | C5 (P3) |
| F107 | Network constants duplicated, 2 formats | xcut | duplication | high | S | C2 (P3) |
| F108 | Three divergent HTTP retries; signing path none | xcut | duplication | med | M | E4 (P4) |
| F109 | ARCHITECTURE.md graph drifted; not CI-checked | xcut | structure | med | S | H6 (P6) |
| F110 | Dep hygiene: unused deps, dead feature, stray pins | xcut | dependency | med | S | C7 (P3) |
| F111 | rvc-signer 15.6k-LOC app crate hides 6 libraries | xcut | structure | med | L | F2 (P5) |
| F112 | Topology: propagator pass-through; bs→builder edge | xcut | structure | med | M | H6 (P6) |
| F113 | No shared test-support crate | xcut | testing | med | M | H2 (P6) |
| F114 | Two shutdown idioms (watch vs CancellationToken) | xcut | async | low | M | Deferred (opportunistic in P5) |
| F115 | Metrics: four registration patterns | xcut | duplication | low | M | Deferred |
| F116 | telemetry anyhow; scattered 0x handling | xcut | error-handling | low | S | C6 (P3) + telemetry thiserror rider (P5) |
| F117 | Hand-rolled SSZ / opaque Vec<u8> body | prior | structure | high | XL | Deferred — tracked SEC-6 (in flight); G items coordinate |
| F118 | Safety mechanisms built but never wired (pattern) | prior | dead-code | high | L | Covered by A4/B5/E7/E8 + SEC-2; wiring-proof test convention in H5 |
| F119 | Keymanager tracked_keys diverges from registry | prior | api-design | high | M | Deferred — tracked SEC-1; F5 sequences after it |
| F120 | Widespread unwrap/expect in hot paths | prior | error-handling | high | XL | Deferred — re-measure; clippy deny rider on slashing/signer/crypto after P4; SEC-5 owns the DoS case |
| F121 | Coordinator still a god object | prior | structure | med | L | H7 (P6, incl. optional BlockProposalService) |
| F122 | Tests encode wrong spec assumptions | prior | testing | high | M | H5 (P6 policy) + A2 (P1) |
| F123 | Low-fidelity mocks discard arguments | prior | testing | med | M | H4 (P6, aligns docs/issues phase-2) |
| F124 | No pipeline slashing-block integration test | prior | testing | high | M | A3 (P1) |
| F125 | Fail-open at security-critical edges (pattern) | prior | error-handling | high | M | Deferred — tracked SEC-2/SEC-3; convention noted in H6 docs |
| F126 | Conformance runner re-implements watermarks | prior | duplication | low | S | A2 (P1) |
| F127 | Inconsistent signer/slashing surfaces (L-11/M-26/L-16) | prior | api-design | med | M | A1/B4/B5 (P1-2) + D1 ForkSchedule unification (P4) |
| F128 | validator-store lock ordering / non-atomic reload | prior | async | med | M | F7 (P5) |
| F129 | Global lazy_static metrics registry | prior | config | low | S | Deferred |
| F130 | No fuzz coverage for untrusted input | prior | testing | med | M | Deferred — owned by test-audit plan (docs/issues 3.x) |
| F131 | Beacon request hygiene: URL encoding, backoff | prior | error-handling | med | S | E4 (P4) |

*131 findings dispositioned: 7 in Phase 1, 15 in Phase 2, 12 in Phase 3, ~30 in Phase 4, ~20 in Phase 5, ~25 in Phase 6, 12 deferred (each with reason), 5 delegated to in-flight security/test plans.*
