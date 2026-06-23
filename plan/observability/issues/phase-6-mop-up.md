# Phase 6: Remaining Crates + Bins

**Goal:** Close the retrofit matrix (architecture §1.5) on crates/bins not covered by the hot
path or external-surface phases.
**Total points:** 9
**Total issues:** 5
**Depends on:** Phase 1 (helpers), Phase 3 (ratchet), Phase 4 preferred so orchestrator root span
shape is stable
**Unblocks:** Phase 7 (test-harness retrofit assumes all crates are at target state), Phase 8

Scope comes straight from architecture §1.5 retrofit matrix for crates not touched in Phases 4–5:
`bin/rvc`, `bin/rvc-keygen`, `bin/rvc-signer` self-instrumentation beyond 5.4, `crates/metrics`,
`crates/timing`, `crates/telemetry` self-instrumentation sanity pass, `crates/eth-types` no-change
verification.

Phase 6 also does one cleanup: remove the deprecated `crates/crypto/src/logging.rs` re-export
entirely after Phase 2 Issue 2.3 converted every importer.

---

## Issue 6.1: `bin/rvc` — CLI flag + env for `RVC_LOG_FORMAT` + telemetry init wiring

- **Points:** 2
- **Depends on:** 1.4 (resource attrs + banner), 1.5 (LogFormat), Phase 4 complete (orchestrator
  slot-root verified stable)
- **Files touched:**
  - `bin/rvc/src/main.rs`
  - `bin/rvc/src/commands/mod.rs` (if CLI definition lives there — otherwise wherever `clap`
    derive is applied)
- **Summary:** Wire `--log-format text|json` CLI flag + `RVC_LOG_FORMAT` env fallback (CLI wins
  when both are set, per PRD Gate §5 decision). Populate
  `TelemetryConfig::{instance_id, deployment_env, file_sink_enabled}` from config / hostname.
  Also verify the existing `rvc.orchestrator.process_slot` root span is the slot-scoped parent
  for duty children from Phase 4 (sanity grep — no code change expected).
- **Acceptance criteria:**
  - [ ] `bin/rvc` `clap` definition has `#[arg(long, env = "RVC_LOG_FORMAT", value_enum)]
        log_format: Option<LogFormat>` (or equivalent — CLI arg uses the `LogFormat` enum from
        Issue 1.5).
  - [ ] CLI flag value wins over env value when both are provided — add a unit test.
  - [ ] Telemetry init populates `instance_id` from config, falling back to `hostname::get()`
        (add `hostname` dep if not present — architecture allows; otherwise read
        `gethostname` crate or `std::env::var("HOSTNAME")`).
  - [ ] Telemetry init populates `deployment_env` from config; default `"dev"` if absent.
  - [ ] `file_sink_enabled` is set true when the file appender is configured; banner from Issue
        1.4 reflects the effective value.
  - [ ] Grep verifies `rvc.orchestrator.process_slot` exists and carries `rvc.slot`, `rvc.epoch`
        entry fields.
- **Tests:**
  - `bin/rvc/tests/log_format_cli.rs::test_cli_flag_overrides_env` — set env
    `RVC_LOG_FORMAT=text`, pass `--log-format json`; assert the resolved `LogFormat` is `Json`.
  - `bin/rvc/tests/log_format_cli.rs::test_env_used_when_no_cli` — set env only; assert env
    value applied.
  - `bin/rvc/tests/log_format_cli.rs::test_default_is_text` — neither set; default `Text`.
  - `bin/rvc/tests/telemetry_init.rs::test_instance_id_fallback_to_hostname` — config with
    empty `instance_id`; assert it is populated with a non-empty fallback.
- **Non-goals:**
  - Changing orchestrator loop structure.
  - Slot-tick event (Phase 8).

---

## Issue 6.2: `bin/rvc-keygen` — `#[instrument]` on subcommand entries

- **Points:** 2
- **Depends on:** Phase 3 complete, 1.1
- **Files touched:**
  - `bin/rvc-keygen/src/main.rs`
  - `bin/rvc-keygen/src/new_mnemonic.rs`
  - `bin/rvc-keygen/src/existing_mnemonic.rs`
  - `bin/rvc-keygen/src/bls_to_execution.rs`
  - `bin/rvc-keygen/src/exit.rs`
- **Summary:** Instrument each subcommand's `run` entry with `#[tracing::instrument(skip_all,
  name = "rvc.keygen.<subcommand>", fields(rvc.keygen.operation = "<subcommand>", rvc.outcome =
  Empty, rvc.duration_ms = Empty, error.type = Empty))]`. Not hot-path; thin logging per
  architecture §1.5. `skip_all` is mandatory because mnemonic / keystore args are in scope (Phase
  3 rule `INSTRUMENT_NO_SKIPALL`).
- **Acceptance criteria:**
  - [ ] `new_mnemonic::run`, `existing_mnemonic::run`, `bls_to_execution::run`, `exit::run`
        each have the `#[instrument]` attribute above.
  - [ ] Any fn whose signature mentions `Mnemonic`, `SecretKey`, `Zeroizing`, or `SignRequest`
        has `skip_all`. (Phase 3 rule catches violations.)
  - [ ] No `?mnemonic`, `?sk`, `?secret`, `?password`, `?passphrase` in any log macro.
  - [ ] `RedactedKeystore` used anywhere keystore metadata is logged.
  - [ ] `info!` at each subcommand entry and `info!("<subcommand> completed", rvc.outcome =
        "success")` (or `error!` on failure) at close.
- **Tests:**
  - `bin/rvc-keygen/tests/keygen_span.rs::test_new_mnemonic_emits_root_span` — drive
    `new_mnemonic::run` with a tmp output dir; `TestTracingGuard` asserts root
    `rvc.keygen.new_mnemonic` with `rvc.outcome = "success"` and no mnemonic appears in any
    captured event or field.
  - `bin/rvc-keygen/tests/keygen_span.rs::test_exit_error_records_error_type` — drive
    `exit::run` with a missing input file; assert `rvc.outcome = "error"`, `error.type`
    classifier.
- **Non-goals:**
  - Instrumenting helper fns (`password.rs`, `verify.rs`) unless they exceed the `?secret` /
    `?password` bar flagged by Phase 3.

---

## Issue 6.3: `bin/rvc-signer` — self-instrumentation mop-up + metrics crate minimal

- **Points:** 2
- **Depends on:** Phase 5 Issue 5.4 (handler-level instrumentation already landed)
- **Files touched:**
  - `bin/rvc-signer/src/main.rs` (startup logs)
  - `bin/rvc-signer/src/reload.rs` (reload pathway)
  - `bin/rvc-signer/src/dvt/bridge.rs` (helpers not covered by 5.4)
  - `bin/rvc-signer/src/dvt/peer_service.rs` (helpers not covered by 5.4)
  - `bin/rvc-signer/src/dvt/peer_client.rs` (helpers not covered by 5.4)
  - `bin/rvc-signer/src/integration_polish.rs`
  - `crates/metrics/src/server.rs` (one `info!` on `MetricsServer` startup per architecture §1.5)
- **Summary:** Fill gaps not covered by Issue 5.4. `bin/rvc-signer` startup gets the telemetry
  banner (already wired via Issue 1.4 if telemetry init is shared — verify). Reload path gets
  `rvc.signer.reload` span. DVT helpers used from 5.4's hot path get `debug`-level spans where
  they add diagnostic value. `crates/metrics` gets one `info!` on `MetricsServer::start` with
  `http.route = "/metrics"`, `server.address`, `server.port`; no per-request span (architecture
  §1.5 explicitly says skip).
- **Acceptance criteria:**
  - [ ] `bin/rvc-signer/src/main.rs` calls `telemetry::init_tracing` with populated
        `instance_id` / `deployment_env` and emits the Issue 1.4 banner.
  - [ ] `reload.rs` has a `rvc.signer.reload` root span with parse-first / apply-second
        pattern mirroring Issue 5.10.
  - [ ] DVT helper fns that currently have no span but handle `SignRequest`/`SigningRequest`
        args gain `#[instrument(skip_all, name = "rvc.signer.dvt.<helper>")]` to satisfy the
        Phase 3 `INSTRUMENT_NO_SKIPALL` rule. If the current tree has zero violations, this
        bullet is trivially met.
  - [ ] `integration_polish.rs` — one pass to replace any `{:?}` on a BLS type with
        `%TruncatedSignature` / `%TruncatedPubkeyBytes`.
  - [ ] `crates/metrics/src/server.rs::MetricsServer::start` emits one `info!` on bind with
        `server.address`, `server.port`, `http.route = "/metrics"`, no per-request span.
  - [ ] `/metrics` and `/healthz` handlers remain un-instrumented (architecture §1.5).
- **Tests:**
  - `bin/rvc-signer/tests/reload_span.rs::test_reload_emits_parse_then_apply` — mirror of
    Issue 5.10's test, specialized to rvc-signer's reload.
  - `crates/metrics/tests/server_span.rs::test_start_emits_info_on_bind` — start the
    MetricsServer on a random port; assert one `info!` event with the expected fields.
- **Non-goals:**
  - Instrumenting `/metrics` and `/healthz` handlers.
  - Changing DVT protocol.

---

## Issue 6.4: Remove `crates/crypto/src/logging.rs` after grace period

- **Points:** 1
- **Depends on:** Phase 2 Issue 2.3 (all importers flipped to `telemetry::`), Phase 3 Issue 3.1
  (ratchet won't regress on the deletion)
- **Files touched:**
  - `crates/crypto/src/logging.rs` (delete)
  - `crates/crypto/src/lib.rs` (remove `pub mod logging;` export)
- **Summary:** Architecture §1.2 says the re-export file is removed in Phase 5; the project plan
  Phase 6 "long tail" owns it for calendar reasons. Deletion is safe because Issue 2.3
  guaranteed no new importers since Phase 2.
- **Acceptance criteria:**
  - [ ] `crates/crypto/src/logging.rs` is deleted.
  - [ ] `crates/crypto/src/lib.rs` no longer exports the `logging` module.
  - [ ] `cargo build --workspace` and `cargo clippy --workspace --all-targets -- -D warnings`
        clean.
  - [ ] `grep -rn "crypto::logging" crates/ bin/` returns no matches.
- **Tests:**
  - `cargo test --workspace` passes.
- **Non-goals:**
  - Any behavior change.

---

## Issue 6.5: Retrofit-matrix verification sweep — `eth-types`, `timing`, `telemetry`

- **Points:** 2
- **Depends on:** 6.1, 6.2, 6.3, 6.4
- **Files touched:**
  - No code changes expected — verification-only. Document findings in issue comments / PR
    description.
- **Summary:** Final gate for the phase. Walk the architecture §1.5 matrix row by row and
  assert each crate's retrofit state matches "target". `eth-types` must remain untouched per
  architecture §1.5 "No change" (if any drive-by violations surfaced, fix them). `timing` same.
  `telemetry` self-instrumentation is the Issue 1.4 banner — verify.
- **Acceptance criteria:**
  - [ ] Every row in architecture §1.5 retrofit matrix has been verified against the current
        tree. Produce a checklist in the PR description:
        - `bin/rvc` ✅ (Issue 6.1)
        - `bin/rvc-keygen` ✅ (Issue 6.2)
        - `bin/rvc-signer` ✅ (Issues 5.4, 6.3)
        - `crates/rvc` ✅ (Phase 4)
        - `crates/beacon` ✅ (Issue 5.1)
        - `crates/bn-manager` ✅ (Issue 5.2)
        - `crates/builder` ✅ (Issue 4.6)
        - `crates/doppelganger` ✅ (Issue 5.11)
        - `crates/eth-types` ✅ (no change confirmed)
        - `crates/crypto` ✅ (Issues 2.2, 4.10, 5.6)
        - `crates/grpc-signer` ✅ (Issue 5.3)
        - `crates/keymanager-api` ✅ (Issue 5.8)
        - `crates/metrics` ✅ (Issue 6.3)
        - `crates/propagator` ✅ (Issue 4.8)
        - `crates/secret-provider` ✅ (Issue 5.7)
        - `crates/signer` ✅ (Issue 4.7)
        - `crates/slashing` ✅ (Issue 5.9)
        - `crates/sync-service` ✅ (Issue 4.5)
        - `crates/block-service` ✅ (Issue 4.4)
        - `crates/duty-tracker` ✅ (Issue 4.9)
        - `crates/validator-store` ✅ (Issue 5.10)
        - `crates/timing` ✅ (no change confirmed)
        - `crates/telemetry` ✅ (Phase 1)
  - [ ] `cargo clippy --workspace --all-targets -- -D warnings` clean (PRD acceptance #3).
  - [ ] `cargo test --workspace --no-fail-fast` runs to completion — zero failures aside from
        any that are explicitly marked `#[ignore]` for long-running (which there should be none
        new in this initiative).
  - [ ] `cargo test --test forbidden_log_patterns` green.
  - [ ] One `info!` (JSON output when `--log-format json`) from the running `bin/rvc --help` (or
        a probe run) is JSON-parseable via `jq`.
- **Tests:**
  - No new tests. The gate is workspace-wide green across clippy, tests, and the ratchet.
- **Non-goals:**
  - Any new instrumentation work (if gaps surface, file follow-ups).
