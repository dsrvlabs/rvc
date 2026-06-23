# Phase 8: P1 Polish

**Goal:** Complete PRD P1 items — error-display audit, metrics cross-references, resource
attribute wiring, slot-tick event.
**Total points:** 5
**Total issues:** 3
**Depends on:** Phase 1 (TelemetryConfig fields), Phase 4 (orchestrator hot path stable), Phase 7
(doc exists to patch)
**Unblocks:** none (terminal phase)

All P1 items are independent and individually revertable. Exit gates PRD acceptance #6 (zero
`ERROR`/`WARN` in clean `cargo test --workspace` run outside explicit error-path tests).

---

## Issue 8.1: P1-1 + P1-2 — error-display audit + metrics cross-reference annotations

- **Points:** 2
- **Depends on:** Phase 7 Issue 7.3 (doc exists so the metrics-cross-ref section can be added)
- **Files touched:**
  - Every `crates/*/src/error.rs` — expected: 14+ files based on the glob earlier (one per crate
    that defines its own error enum)
  - `docs/observability.md` (append "Metrics cross-reference" section paragraph with the
    convention)
- **Summary:** Two related P1 items bundled because both concern the shape of log lines at
  sites where an error is reported:
  - **P1-1 error-display audit:** Walk every `thiserror`-derived error enum and verify
    `#[error("...")]` on each variant carries enough context that `error = %e` is actionable
    without needing `Debug`. Add correlation keys (endpoint name, pubkey short form, operation)
    where a variant is terse.
  - **P1-2 metrics cross-reference:** At sites where a metric exists (search
    `crates/metrics/src/definitions.rs` for metric names), add a one-line comment next to the
    log call referencing the metric name, like `// metric: slashing_checks_total` above the
    `info!`/`error!`. Convention documented in `docs/observability.md`.
- **Acceptance criteria:**
  - [ ] Every `thiserror` variant across `crates/*/src/error.rs` has a `Display` string that:
        - Includes at least one correlation key when one is available (endpoint, pubkey short
          form, slot, validator index, operation name).
        - Avoids bare text like "operation failed"; prefer "operation <op> on endpoint <url>
          failed: <cause>".
  - [ ] At every `error!` / `warn!` call site where a matching Prometheus metric exists (from
        `crates/metrics/src/definitions.rs`), a single comment `// metric:
        <metric_name>` precedes the macro.
  - [ ] `docs/observability.md` has a "Metrics cross-reference" section documenting the
        convention (one paragraph + one code-block example).
  - [ ] `cargo clippy --workspace --all-targets -- -D warnings` clean.
  - [ ] Review discipline: diff stays under ~500 LOC per PRD constraint. If the audit surfaces
        a large refactor, defer to a follow-up issue and document.
- **Tests:**
  - `crates/<crate>/src/error.rs::tests::display_contains_context_for_each_variant` — one per
    error module (optional, scope-permitting): for each variant, format a representative
    instance and assert the string contains at least one of the expected correlation tokens.
    Use a small table-driven test; skip variants that legitimately lack a correlation key
    (e.g. `ConfigTomlParseError` — a parse error has no validator context).
- **Non-goals:**
  - Restructuring error enums (variant renames, split into sub-enums) — out of scope per PRD
    §Risks; defer refactors to follow-up.
  - Adding new metrics — architect-level decision.

---

## Issue 8.2: P1-3 — wire `service.instance.id` + `deployment.environment` from config/hostname

- **Points:** 1
- **Depends on:** Phase 1 Issue 1.4 (fields added to TelemetryConfig), Phase 6 Issue 6.1 (
  `bin/rvc` CLI wiring)
- **Files touched:**
  - `bin/rvc/src/main.rs` (populate `TelemetryConfig::instance_id` from config, falling back to
    `hostname::get()` or equivalent; populate `deployment_env` from config)
  - `bin/rvc/src/config/types.rs` (add optional `instance_id` and `deployment_env` fields to
    the config struct, with serde defaults)
  - `bin/rvc-signer/src/main.rs` + `bin/rvc-signer/src/config.rs` (mirror the wiring)
  - `Cargo.toml` (workspace — add `hostname = "0.4"` dependency if not present; architecture
    §8 does not mandate a specific crate; `hostname = "0.4"` is the conventional choice)
- **Summary:** Phase 1 added the `TelemetryConfig` fields but did not populate them. This issue
  closes the loop so the exported OTel resource actually carries the values. Hostname fallback
  makes the default useful without operator config.
- **Acceptance criteria:**
  - [ ] `bin/rvc` populates `TelemetryConfig::instance_id` from
        `config.instance_id.unwrap_or_else(|| hostname::get().to_string_lossy().into())`.
  - [ ] `deployment_env` populated from `config.deployment_env.unwrap_or("dev".into())`.
  - [ ] `bin/rvc-signer` mirrors the same wiring.
  - [ ] `docs/observability.md` "Resource attributes" section lists both keys with their
        defaults and override paths.
  - [ ] `cargo clippy --workspace --all-targets -- -D warnings` clean.
- **Tests:**
  - `bin/rvc/tests/telemetry_init.rs::test_instance_id_from_config_overrides_hostname` —
    config with explicit `instance_id = "explicit-id"`; assert the built resource carries
    `"explicit-id"`.
  - `bin/rvc/tests/telemetry_init.rs::test_instance_id_fallback_to_hostname` — empty config
    `instance_id`; assert the built resource carries a non-empty value equal to
    `hostname::get()`.
  - `bin/rvc/tests/telemetry_init.rs::test_deployment_env_default` — missing config value
    resolves to `"dev"`.
- **Non-goals:**
  - OTel collector config changes (architecture §5; ops artifact).
  - Adding further resource attributes.

---

## Issue 8.3: P1-4 — slot-tick `info!` event

- **Points:** 2
- **Depends on:** Phase 4 Issue 4.3 (coordinator.rs is stable), Phase 7 Issue 7.3 (doc exists
  to patch with the new event convention)
- **Files touched:**
  - `crates/rvc/src/orchestrator/coordinator.rs` (where the slot loop sits — confirm via grep
    for `process_slot` call site)
  - Possibly `crates/timing/src/lib.rs` (read drift source; no instrumentation changes per
    architecture §1.5 "no change")
  - `docs/observability.md` (add the slot-tick event to the level-policy / field table)
- **Summary:** One `info!` per slot boundary at the top of the orchestrator loop, so a log-only
  reader can establish the slot timeline without needing metric timestamps. Fields: `rvc.slot`,
  `rvc.epoch`, `rvc.wall_clock_drift_ms` (the delta between intended slot start and actual tick
  time — compute from `timing`'s slot-clock + `SystemTime::now()`).
- **Acceptance criteria:**
  - [ ] Exactly one `info!` event per slot at the top of the `process_slot` loop (or its
        caller) with fields: `rvc.slot` (u64), `rvc.epoch` (u64), `rvc.wall_clock_drift_ms`
        (i64, can be negative for early ticks).
  - [ ] Event message is concise: `"slot tick"` or `"slot started"`.
  - [ ] `rvc.wall_clock_drift_ms` computation uses `std::time::SystemTime::now()` vs the
        slot-clock's intended start wall time; document the sign convention in
        `docs/observability.md` (positive = tick late, negative = tick early).
  - [ ] `docs/observability.md` updated: a one-line entry in the mandatory-fields-per-duty-
        type table referencing the slot-tick event.
  - [ ] Event does NOT fire from within `rvc.orchestrator.process_slot` span to avoid
        double-counting — it fires once per iteration of the outer loop, as a standalone event
        before the per-slot span opens. (Level-policy coherence: it's a state transition, not
        a duty milestone.)
- **Tests:**
  - `crates/rvc/tests/slot_tick.rs::test_one_info_event_per_slot` — drive the orchestrator for
    N simulated slots under a `TestTracingGuard`; assert exactly N `info!` events with target
    matching the slot-tick event fire per N slots.
  - `crates/rvc/tests/slot_tick.rs::test_slot_tick_fields_present` — assert `rvc.slot`,
    `rvc.epoch`, `rvc.wall_clock_drift_ms` are all present on the event.
  - `crates/rvc/tests/slot_tick.rs::test_zero_errors_warns_on_clean_run` — PRD acceptance #6
    sanity: drive N slots of happy-path duty work; assert `guard.events_at(Level::ERROR).
    len() == 0` and `guard.events_at(Level::WARN).len() == 0`.
- **Non-goals:**
  - Adding new metrics for drift (metrics team owns).
  - Changing slot clock semantics.
