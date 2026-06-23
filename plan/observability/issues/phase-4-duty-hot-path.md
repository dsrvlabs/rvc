# Phase 4: Duty Hot-Path Retrofit

**Goal:** Apply the span hierarchy (architecture §3 table) and field standard to every duty-path
file so the oncall runbook walkthrough succeeds on a synthetic duty failure.
**Total points:** 21
**Total issues:** 11
**Depends on:** Phase 3 (ratchet live so retrofit edits cannot regress)
**Unblocks:** Phase 7 (integration-test retrofit assumes duty-path spans are present), Phase 8
(slot-tick event sits on this surface)

Reference material the code-writer must open alongside each issue:

- Architecture §3 — span hierarchy table (mandatory fields per duty family). **All field lists
  below are abbreviated; use §3 as the authoritative set.**
- Architecture §4 — level policy (root spans `info`, sub-operations `debug`, etc.).
- PRD §P0-4 — coverage list.
- Research summary #4 and PRD §Technical Considerations — async-trait fallback pattern:
  use `.instrument(info_span!(...))` inside the method body when `#[instrument]` breaks `Send`.

All retrofit issues share the same style constraint: every `#[instrument]` uses `skip_all`,
explicit `name = "rvc..."`, and `fields(...)` allowlisted to architecture §3 keys. No `err` / `ret`
attributes. Outcome and duration are deferred via `Span::record` at close.

---

## Issue 4.1: Retrofit `orchestrator/attestation.rs` — root span + iteration children

- **Points:** 2
- **Depends on:** Phase 3 complete
- **Files touched:**
  - `crates/rvc/src/orchestrator/attestation.rs`
- **Summary:** Wrap the attestation duty path in `rvc.attestation.produce` per architecture §3.
  Every `pub(crate) async fn` gets `#[tracing::instrument(skip_all, name = "rvc.attestation.X",
  fields(...))]` with entry fields and `tracing::field::Empty` placeholders for
  `rvc.outcome` / `rvc.duration_ms` (and `rvc.slashing.result` / `error.type` where applicable).
  The per-validator loop opens a child span `rvc.attestation.produce` with
  `rvc.validator_index`, `rvc.pubkey = %TruncatedPubkey::new(&hex)`. At close, call
  `Span::current().record("rvc.outcome", outcome_str)` and
  `Span::current().record("rvc.duration_ms", start.elapsed().as_millis() as u64)`.
- **Acceptance criteria:**
  - [ ] Every `pub(crate) async fn` in `attestation.rs` has `#[tracing::instrument(skip_all,
        name = "rvc.attestation.*", fields(...))]` with at minimum the mandatory entry fields
        from architecture §3 for the Attestation duty family (`rvc.slot`, `rvc.validator_index`,
        `rvc.pubkey`, `rvc.operation = "attestation"`).
  - [ ] Root `rvc.attestation.produce` span records `rvc.outcome` (one of
        `"success"|"rejected"|"error"|"timeout"`) and `rvc.duration_ms` at close via
        `Span::record`.
  - [ ] On error paths, `error.type` is recorded with a short classifier (e.g. `"timeout"`,
        `"slashing_db"`, `"beacon_5xx"`) — not the full error message. The full message goes to
        the log line as `error = %e`.
  - [ ] Public fn signatures are unchanged (PRD constraint). Any async-trait method that rejects
        `#[instrument]` via `Send`-bound is instrumented instead as
        `async { ... }.instrument(info_span!(...))` inside the body.
  - [ ] No `err` or `ret` on `#[instrument]` anywhere in the file.
- **Tests:**
  - `crates/rvc/tests/attestation_span.rs` (new, or extend existing) — RED→GREEN→REFACTOR using
    `TestTracingGuard`:
    - `test_attestation_success_records_outcome` — drive a happy-path attestation, assert the
      root span `rvc.attestation.produce` exists with
      `rvc.slot`, `rvc.validator_index`, `rvc.pubkey` set at entry, and
      `rvc.outcome = "success"`, `rvc.duration_ms` set after close. Declare the guard with
      `let _g = telemetry::test_capture();` so the drop-printing-on-panic behavior surfaces
      diffs when fields are missing.
    - `test_attestation_error_records_error_type` — inject a failure (e.g. fake propagator
      returns error), assert `rvc.outcome = "error"` and `error.type` is a non-empty short
      classifier string.
- **Non-goals:**
  - Propagator or signer retrofit (separate issues).
  - Changing the public async fn signatures.
  - Touching `aggregation.rs` or `sync_committee.rs` (Issue 4.2).

---

## Issue 4.2: Retrofit `orchestrator/aggregation.rs` + `sync_committee.rs`

- **Points:** 2
- **Depends on:** 4.1 (pattern established — especially the outcome/duration record helper if
  extracted to `orchestrator/utils.rs`)
- **Files touched:**
  - `crates/rvc/src/orchestrator/aggregation.rs`
  - `crates/rvc/src/orchestrator/sync_committee.rs`
- **Summary:** Mirror Issue 4.1 for the aggregation and sync-committee duty families. Root spans
  `rvc.aggregation.produce`, `rvc.sync.message`, `rvc.sync.contribution` per architecture §3.
  Aggregation adds `rvc.committee_index`; sync contribution adds `rvc.sync.subnet`.
- **Acceptance criteria:**
  - [ ] Every `pub(crate) async fn` in both files has `#[tracing::instrument(skip_all, name =
        "rvc.aggregation.*" | "rvc.sync.*", fields(...))]` per architecture §3.
  - [ ] Root span `rvc.aggregation.produce` carries `rvc.slot`, `rvc.validator_index`,
        `rvc.pubkey`, `rvc.committee_index`, `rvc.operation = "aggregate"` at entry; records
        `rvc.outcome` and `rvc.duration_ms` at close.
  - [ ] Root span `rvc.sync.message` carries `rvc.slot`, `rvc.validator_index`, `rvc.pubkey`,
        `rvc.operation = "sync_message"`.
  - [ ] Root span `rvc.sync.contribution` adds `rvc.sync.subnet`,
        `rvc.operation = "sync_contribution"`.
  - [ ] Per-validator loops emit child spans `debug`-level per architecture §4.
  - [ ] No public signature changes.
- **Tests:**
  - `crates/rvc/tests/aggregation_span.rs::test_aggregation_happy_path_fields_match_§3` —
    `TestTracingGuard` asserts the full architecture-§3 entry field set is present.
  - `crates/rvc/tests/aggregation_span.rs::test_aggregation_error_records_error_type` — inject
    failure, assert `rvc.outcome = "error"` + short `error.type`.
  - `crates/rvc/tests/sync_committee_span.rs::test_sync_message_success` — assert fields.
  - `crates/rvc/tests/sync_committee_span.rs::test_sync_contribution_includes_subnet` — assert
    `rvc.sync.subnet` present on the root span entry fields.
- **Non-goals:**
  - Beacon or propagator-level spans under these duty roots (they're siblings owned by Phase 5
    for beacon and Issue 4.8 for propagator).

---

## Issue 4.3: Retrofit `orchestrator/duty_management.rs` + `coordinator.rs` + `utils.rs`

- **Points:** 2
- **Depends on:** 4.1
- **Files touched:**
  - `crates/rvc/src/orchestrator/duty_management.rs`
  - `crates/rvc/src/orchestrator/coordinator.rs`
  - `crates/rvc/src/orchestrator/utils.rs`
- **Summary:** Duty-management pub(crate) async fns gain `rvc.duty.fetch_*` root spans per
  architecture §3 "Duty fetch" row; `coordinator.rs` owns `rvc.orchestrator.process_slot` (already
  exists — verify it passes its `rvc.slot` / `rvc.epoch` entry fields into child duty spans
  without re-parenting) and any `process_epoch` style wrapper. `utils.rs` is the natural home for
  a small helper `record_outcome(span, outcome, start: Instant)` used by Issues 4.1–4.3 (and
  reused in 4.8).
- **Acceptance criteria:**
  - [ ] `duty_management.rs` — every `pub(crate) async fn` has
        `#[tracing::instrument(skip_all, name = "rvc.duty.fetch_*", fields(rvc.epoch, rvc.count =
        Empty, rvc.outcome = Empty, rvc.duration_ms = Empty, error.type = Empty))]` per §3.
  - [ ] `coordinator.rs` — `rvc.orchestrator.process_slot` exists (verify with `grep`); if
        missing, add. Carries `rvc.slot`, `rvc.epoch` entry fields.
  - [ ] `utils.rs` — new `pub(crate) fn record_outcome(span: &tracing::Span, outcome: &str,
        start: std::time::Instant)` helper that records `rvc.outcome` and `rvc.duration_ms` in
        one call. Private helper — not part of the telemetry crate API.
  - [ ] `record_outcome` is used at close of every root duty span in Issues 4.1–4.3 and 4.8
        (cross-check during review).
- **Tests:**
  - `crates/rvc/tests/duty_management_span.rs::test_fetch_attester_records_count_and_outcome` —
    assert the root span carries `rvc.epoch` at entry and `rvc.count`, `rvc.outcome`,
    `rvc.duration_ms` at close.
  - `crates/rvc/tests/duty_management_span.rs::test_fetch_returns_error_records_error_type` —
    assert `rvc.outcome = "error"` + `error.type`.
  - `crates/rvc/src/orchestrator/utils.rs::tests::record_outcome_sets_both_fields` — create a
    span with `rvc.outcome` / `rvc.duration_ms` empty, call `record_outcome`, assert both are
    populated via a `TestTracingGuard`.
- **Non-goals:**
  - Moving `record_outcome` to `crates/telemetry` (keep it local until other crates need it).

---

## Issue 4.4: Retrofit `crates/block-service/src/service.rs`

- **Points:** 2
- **Depends on:** Phase 3 complete
- **Files touched:**
  - `crates/block-service/src/service.rs`
- **Summary:** Expand from the existing one `#[instrument]` site to root span `rvc.block.propose`
  on the public block-proposal method, with child spans
  `rvc.block.sign_randao`, `rvc.block.produce_block` (child of `rvc.beacon.produce_block`),
  `rvc.block.sign_block`, `rvc.block.publish_block` per architecture §3. Root carries
  `rvc.slot`, `rvc.validator_index`, `rvc.pubkey`, `rvc.block.blinded` (bool),
  `rvc.operation = "block"`; records `rvc.outcome`, `rvc.duration_ms`, `rvc.block.slot`,
  `rvc.slashing.result`, `error.type` at close.
- **Acceptance criteria:**
  - [ ] Every `pub async fn` on `BlockService` has `#[tracing::instrument(skip_all, name =
        "rvc.block.*", fields(...))]` with §3 entry fields.
  - [ ] Root span `rvc.block.propose` records the deferred fields listed above.
  - [ ] `rvc.block.blinded` is set at entry based on the code path (MEV-aware vs. local
        production) — not deferred.
  - [ ] Sub-operation spans at `debug` level per architecture §4.
- **Tests:**
  - `crates/block-service/tests/block_span.rs::test_block_propose_happy_path` — `TestTracingGuard`
    asserts the parent-child tree matches §3 (`rvc.block.propose` → `rvc.block.sign_randao` →
    `rvc.block.produce_block` → `rvc.block.sign_block` → `rvc.block.publish_block`), all entry
    fields present on root, `rvc.outcome = "success"`, `rvc.duration_ms` set.
  - `crates/block-service/tests/block_span.rs::test_block_propose_sign_error` — inject a signer
    failure, assert `rvc.outcome = "error"` and `error.type = "sign_error"` (or similar
    classifier).
- **Non-goals:**
  - Changing block-proposal business logic.
  - Slashing-level assertions (landed in Phase 5 Issue 5.8).

---

## Issue 4.5: Retrofit `crates/sync-service/src/lib.rs`

- **Points:** 1
- **Depends on:** Phase 3 complete
- **Files touched:**
  - `crates/sync-service/src/lib.rs`
- **Summary:** Two existing `#[instrument]` sites. Verify both (and add if missing) for
  `produce_sync_messages`, `produce_contributions`, `compute_selection_proof`. All gain
  architecture §3 "Sync committee msg" / "Sync contribution" entry fields and deferred outcome /
  duration. `rvc.sync.subnet` added where applicable.
- **Acceptance criteria:**
  - [ ] `produce_sync_messages` has `#[tracing::instrument(skip_all, name = "rvc.sync.message",
        fields(rvc.slot, rvc.validator_index, rvc.pubkey, rvc.operation = "sync_message",
        rvc.outcome = Empty, rvc.duration_ms = Empty, error.type = Empty))]`.
  - [ ] `produce_contributions` — analog for `rvc.sync.contribution` with `rvc.sync.subnet`.
  - [ ] `compute_selection_proof` — child span `rvc.sign.selection_proof` (architecture §3
        "Sync contribution" children).
  - [ ] Existing sites that already have `#[instrument]` are audited for `skip_all` and correct
        field list.
- **Tests:**
  - `crates/sync-service/tests/sync_span.rs::test_sync_message_success_fields` — assertions as
    per 4.2 analogue, but owned by sync-service.
  - `crates/sync-service/tests/sync_span.rs::test_sync_contribution_includes_subnet` —
    `rvc.sync.subnet` present.
  - `crates/sync-service/tests/sync_span.rs::test_sync_message_error_records_error_type` —
    failure-path counterpart.
- **Non-goals:**
  - Beacon submission span (Phase 5).

---

## Issue 4.6: Retrofit `crates/builder/src/service.rs`

- **Points:** 1
- **Depends on:** Phase 3 complete
- **Files touched:**
  - `crates/builder/src/service.rs`
- **Summary:** Instrument `register_validators`, `prepare_proposers`, and any retry helper. Root
  spans `rvc.builder.register`, `rvc.builder.prepare_proposers`. Jitter sleep becomes a sibling
  span `rvc.builder.jitter_wait` at `debug` level. Per architecture §3 "Builder registration"
  pattern fields: `rvc.slot` (when slot-bound), `rvc.validator_index`, `rvc.pubkey`.
- **Acceptance criteria:**
  - [ ] `register_validators` has `#[tracing::instrument(skip_all, name =
        "rvc.builder.register", fields(rvc.count, rvc.outcome = Empty, rvc.duration_ms = Empty,
        error.type = Empty))]`.
  - [ ] `prepare_proposers` has analog `rvc.builder.prepare_proposers`.
  - [ ] Any retry helper carries `rvc.attempt` field (u32) incrementing per retry.
  - [ ] Jitter sleep is wrapped in `debug_span!("rvc.builder.jitter_wait", rvc.duration_ms =
        Empty)` with `Span::record` on wake.
- **Tests:**
  - `crates/builder/tests/builder_span.rs::test_register_validators_success` — assertions.
  - `crates/builder/tests/builder_span.rs::test_register_validators_retry_records_attempt` —
    fake BN returns 503 once then 200; assert two attempts recorded, second with
    `rvc.attempt = 1`.
  - `crates/builder/tests/builder_span.rs::test_register_validators_exhausted_records_error` —
    all attempts fail, assert `rvc.outcome = "error"` and `error.type = "all_retries_exhausted"`
    (or similar).
- **Non-goals:**
  - Circuit-breaker instrumentation (sibling file `circuit_breaker.rs`, handled as part of
    Phase 6 mop-up if not already covered).

---

## Issue 4.7: Retrofit `crates/signer/src/lib.rs` — audit 11 existing `#[instrument]` sites

- **Points:** 2
- **Depends on:** Phase 3 complete
- **Files touched:**
  - `crates/signer/src/lib.rs`
- **Summary:** Architecture §1.5 reports ~11 existing `#[instrument]` sites. Audit each for
  `skip_all` presence and correct architecture §3 "Signer request" field set. Add
  `rvc.outcome` / `rvc.duration_ms` via `Span::record`. After slashing check, record
  `rvc.slashing.result`.
- **Acceptance criteria:**
  - [ ] Every `sign_*` async fn in the crate has `#[tracing::instrument(skip_all, name =
        "rvc.sign.{attestation|block|sync|aggregation|randao|voluntary_exit|builder}",
        fields(rvc.pubkey, rvc.operation, rvc.slashing.result = Empty, rvc.outcome = Empty,
        rvc.duration_ms = Empty, error.type = Empty))]`.
  - [ ] Slashing check result is recorded as `rvc.slashing.result` (one of
        `safe|double_vote|surrounding|surrounded|double_proposal|db_error`) immediately after the
        slashing-protection call.
  - [ ] `skip_all` present on every one of the 11 sites; any missing `skip_all` is added.
  - [ ] No `err` / `ret` on any `#[instrument]`.
- **Tests:**
  - `crates/signer/tests/signer_span.rs::test_sign_attestation_success_records_slashing_result`
    — assert `rvc.slashing.result = "safe"` on happy path.
  - `crates/signer/tests/signer_span.rs::test_sign_attestation_double_vote_records_result` —
    fake slashing DB returns double-vote, assert `rvc.slashing.result = "double_vote"`,
    `rvc.outcome = "rejected"` (per architecture §4: slashing reject is `warn!` / `rejected`,
    not `error`).
  - `crates/signer/tests/signer_span.rs::test_sign_error_records_error_type` — BLS error;
    assert `rvc.outcome = "error"` and `error.type` classifier.
- **Non-goals:**
  - Moving slashing-protection into the signer span tree (it already sits correctly; this issue
    only records results).

---

## Issue 4.8: Retrofit `crates/propagator/src/lib.rs`

- **Points:** 2
- **Depends on:** Phase 3 complete
- **Files touched:**
  - `crates/propagator/src/lib.rs`
- **Summary:** Root span per submit call per architecture §3 "Propagation" row:
  `rvc.propagator.submit_attestations` and `rvc.propagator.submit_aggregate_attestations`. Entry
  fields `rvc.slot`, `rvc.count`. Deferred `rvc.outcome`, `rvc.duration_ms`, `rvc.bn_endpoint`,
  `error.type`. One child span `rvc.beacon.submit_*` per BN attempt (the beacon call itself is
  owned by `crates/beacon` in Phase 5; propagator just routes).
- **Acceptance criteria:**
  - [ ] `submit_attestations` has `#[tracing::instrument(skip_all, name =
        "rvc.propagator.submit_attestations", fields(rvc.slot, rvc.count, rvc.outcome = Empty,
        rvc.duration_ms = Empty, rvc.bn_endpoint = Empty, error.type = Empty))]`.
  - [ ] `submit_aggregate_attestations` has analog
        `rvc.propagator.submit_aggregate_attestations`.
  - [ ] `rvc.bn_endpoint` recorded with `%RedactedUrl(&endpoint)` at the point the specific BN
        is picked.
  - [ ] `rvc.outcome` recorded at close.
- **Tests:**
  - `crates/propagator/tests/propagator_span.rs::test_submit_attestations_success` — happy path,
    all fields populated, `rvc.count` matches number of attestations submitted.
  - `crates/propagator/tests/propagator_span.rs::test_submit_attestations_beacon_error` — fake
    beacon returns 500, assert `rvc.outcome = "error"`, `error.type = "beacon_5xx"` (or similar
    classifier), `rvc.bn_endpoint` matches redacted form of the target endpoint.
- **Non-goals:**
  - Beacon client instrumentation (Phase 5 Issue 5.1).
  - Aggregation selection logic.

---

## Issue 4.9: Retrofit `crates/duty-tracker/src/tracker.rs` — fill 6-site gap audit

- **Points:** 2
- **Depends on:** Phase 3 complete
- **Files touched:**
  - `crates/duty-tracker/src/tracker.rs`
- **Summary:** Architecture §1.5 reports 6 existing `#[instrument]` sites. Audit all `fetch_*`,
  `check_and_refetch_*`, `evict_*` functions and fill any gap. Each carries `rvc.epoch` or
  `rvc.committee_period` per architecture §3 "Duty fetch".
- **Acceptance criteria:**
  - [ ] Every `pub async fn` or `pub(crate) async fn` prefixed `fetch_`, `check_and_refetch_`,
        or `evict_` has `#[tracing::instrument(skip_all, name = "rvc.duty.*", fields(rvc.epoch
        OR rvc.committee_period, rvc.operation, rvc.count = Empty, rvc.outcome = Empty,
        rvc.duration_ms = Empty, rvc.duty.dependent_root = Empty, error.type = Empty))]`.
  - [ ] `rvc.duty.dependent_root` recorded as `%TruncatedPubkeyBytes(&root.0)` (the
        dependent-root is a 32-byte hash, not a pubkey, but the short-form helper works on any
        `&[u8]`).
  - [ ] Cache hit/miss emits a `debug!` event on the current span (architecture §4).
  - [ ] Evict logs at `info!` with count of evicted entries.
- **Tests:**
  - `crates/duty-tracker/tests/tracker_span.rs::test_fetch_attester_duties_success_fields` —
    assert `rvc.epoch`, `rvc.count`, `rvc.duty.dependent_root` are present; outcome success.
  - `crates/duty-tracker/tests/tracker_span.rs::test_fetch_attester_duties_beacon_error` —
    assert error-path classifier.
  - `crates/duty-tracker/tests/tracker_span.rs::test_evict_records_count` — evict N entries;
    assert the `info!` event has `rvc.count = N`.
- **Non-goals:**
  - Changing caching policy.
  - Beacon client instrumentation (Phase 5).

---

## Issue 4.10: Audit `crates/crypto/src/*_signing.rs` helper signing files

- **Points:** 2
- **Depends on:** 4.7
- **Files touched:**
  - `crates/crypto/src/signing.rs`
  - `crates/crypto/src/block_signing.rs`
  - `crates/crypto/src/sync_signing.rs`
  - `crates/crypto/src/aggregation_signing.rs`
  - `crates/crypto/src/voluntary_exit_signing.rs`
  - `crates/crypto/src/builder_signing.rs`
- **Summary:** Architecture §1.5 reports ~11 already-instrumented sites across these six helper
  files. This issue is a batched audit: verify `skip_all` on every site, verify field lists match
  the Signer family shape in architecture §3, verify `rvc.pubkey` is `%TruncatedPubkey` or
  `%TruncatedPubkeyBytes` (never `%pk.to_string()` or `?pk`), verify no `err` / `ret` on any
  attribute. Sites that reference `SecretKey`, `SigningRequest`, or `SignRequest` in their
  signature MUST have `skip_all` — Phase 3 Issue 3.1's `INSTRUMENT_NO_SKIPALL` rule will catch
  any that don't.
- **Acceptance criteria:**
  - [ ] Every `#[instrument]` site in these six files carries `skip_all` + explicit `name` +
        `fields(...)`.
  - [ ] No `%pubkey` is a full-hex formatting; every mention uses `TruncatedPubkey` or
        `TruncatedPubkeyBytes`.
  - [ ] No `?sig` or `?signature` appears in any log macro or attribute field list.
  - [ ] `cargo test -p crypto` green.
- **Tests:**
  - `crates/crypto/tests/signing_span_audit.rs` (new) — one `#[test]` per file that
    grep-verifies via `include_str!` + `regex::Regex` that every `#[tracing::instrument` is
    followed by `skip_all` before the closing paren. Cheap static test; runs in <100 ms.
  - `crates/crypto/tests/signing_span_audit.rs::bls_signing_logs_short_pubkey` — drive one sign
    call under `TestTracingGuard`, assert any emitted event with a pubkey field matches the
    `TruncatedPubkey` short-form regex (not full 96-hex).
- **Non-goals:**
  - Adding new spans to sites that currently have none (not needed per PRD P0-4 list).
  - Expanding to `composite_signer.rs` or `key_manager.rs` (not on the P0-4 hot-path list; Phase
    6 covers if needed).

---

## Issue 4.11: Phase 4 integration — runbook walkthrough gate

- **Points:** 3
- **Depends on:** 4.1–4.10
- **Files touched:**
  - `crates/rvc/tests/duty_lifecycle.rs` (new) — end-to-end integration test that drives a full
    attestation lifecycle against mocked BN + mocked slashing DB and captures the entire trace
  - No production files changed.
- **Summary:** Acceptance gate for the phase. Stands up a synthetic integration rig (mock BN
  via `wiremock`, real `crates/slashing` with a temp-file DB, real `crates/signer` with a test
  key) and asserts the full span tree + field set match architecture §3 end-to-end. Also seeds the
  runbook walkthrough (Phase 7 will reference this test from `docs/observability.md`).
- **Acceptance criteria:**
  - [ ] Test drives one happy-path attestation duty from
        `rvc.orchestrator.process_slot` through `rvc.attestation.produce` through
        `rvc.sign.attestation` through `rvc.propagator.submit_attestations` through
        `rvc.beacon.submit_*` — all under one trace id.
  - [ ] `TestTracingGuard` captures the full tree; assertion set:
        - Every root-span-level field in architecture §3 is present on its respective span.
        - Every root span has `rvc.outcome = "success"` at close.
        - Every root span has a non-zero `rvc.duration_ms`.
        - All children chain to the parent via `parent_id`.
  - [ ] A second test drives a failure path (fake BN returns 500 on propagation); asserts the
        propagator's `rvc.outcome = "error"`, `error.type` is populated.
  - [ ] Oncall runbook text (drafted as a comment block in the test file, formalized in Phase 7
        `docs/observability.md`): "given (slot, validator pubkey) → grep traces for `rvc.slot =
        {slot}` AND `rvc.pubkey` short-form; walk children in order."
  - [ ] `cargo clippy --workspace --all-targets -- -D warnings` green.
  - [ ] Perf guard: test runtime under 3 seconds on developer hardware (loose bound; the
        100-validator load test is owned by infra — PRD §Risks — and is not in this issue).
- **Tests:**
  - `crates/rvc/tests/duty_lifecycle.rs::test_attestation_full_lifecycle_happy_path` — per
    acceptance.
  - `crates/rvc/tests/duty_lifecycle.rs::test_attestation_full_lifecycle_beacon_failure` — per
    acceptance.
- **Non-goals:**
  - Block / sync / aggregation lifecycles (attestation is the runbook canonical case; other
    families are covered by per-issue tests 4.2–4.8).
  - 100-validator load-test (infra task outside this initiative's test budget).
  - Writing the runbook doc itself (Phase 7 Issue 7.3).
