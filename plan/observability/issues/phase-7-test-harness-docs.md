# Phase 7: Test-Harness Adoption + Conventions Doc

**Goal:** Retrofit integration tests to use `TestTracingGuard` with drop-printing-on-panic;
publish `docs/observability.md`; prove a failing test prints the span tree by default with no
`RUST_LOG` or `--nocapture`.
**Total points:** 9
**Total issues:** 5
**Depends on:** Phase 1 (`TestTracingGuard`), Phase 4 (hot-path spans to capture), Phase 5
(cross-crate trace context for end-to-end continuity)
**Unblocks:** Phase 8

Per-test retrofit is light (~1 line per test body). Per-crate issue for readability and
reviewability. The conventions doc lands last in the phase so the runbook snippet can reference
the PRD acceptance gate tests landed in Phase 4.

---

## Issue 7.1: Adopt `TestTracingGuard` in integration tests — duty path crates

- **Points:** 2
- **Depends on:** 1.2, Phase 4 complete
- **Files touched:**
  - `crates/rvc/tests/**/*.rs`
  - `crates/signer/tests/**/*.rs`
  - `crates/block-service/tests/**/*.rs`
  - `crates/sync-service/tests/**/*.rs`
- **Summary:** Add `let _g = telemetry::test_capture();` at the top of every test body that
  exercises production spans. Retrofit is one line per test. Keep existing `wiremock` / tokio
  fixtures untouched. TDD loop for retrofit: verify a test passes, add the guard, re-run and
  confirm no regression, then intentionally break one assertion to confirm the guard
  prints-on-panic behavior appears in the default `cargo test` output (then revert the break).
- **Acceptance criteria:**
  - [ ] Every `#[tokio::test]` or `#[test]` across the listed crates that exercises a span from
        the production path has `let _g = telemetry::test_capture();` as the first line (before
        any fixture setup).
  - [ ] Tests that explicitly install their own subscriber (e.g.
        `crates/secret-provider/tests/tracing_hierarchy.rs`) are left alone — the guard is
        opt-in.
  - [ ] `cargo test --workspace --no-fail-fast` passes.
  - [ ] Running one specific test with `cargo test -p rvc -- test_attestation_full_lifecycle_
        happy_path --nocapture` shows span captures in the output (baseline: guard emits nothing
        on success; guard is exercised).
  - [ ] No test regresses; test counts match pre-retrofit counts.
- **Tests:**
  - No new tests. The change is mechanical.
  - Review notes should include one example diff showing the before/after for a representative
    test.
- **Non-goals:**
  - Adding new integration tests (those come from Phase 4 / Phase 5 per-issue tests).
  - Touching unit tests (`#[cfg(test)] mod tests { ... }` at the bottom of source files) — they
    are narrow-scope and rarely need span capture.
  - Retrofitting `crates/secret-provider/tests/tracing_hierarchy.rs` (already installs its own
    subscriber — explicitly left alone).

---

## Issue 7.2: Adopt `TestTracingGuard` in integration tests — propagator / duty-tracker / slashing

- **Points:** 2
- **Depends on:** 1.2, Phase 4 complete, Phase 5 Issue 5.9 (slashing fields land)
- **Files touched:**
  - `crates/propagator/tests/**/*.rs`
  - `crates/duty-tracker/tests/**/*.rs`
  - `crates/slashing/tests/**/*.rs`
- **Summary:** Second batch of integration-test retrofits. Same pattern as Issue 7.1. Phase 5's
  slashing acceptance test (Issue 5.9 `test_double_vote_records_result_and_epochs`) must run
  under the guard so the PRD P0-6 acceptance observation is asserted from captured spans, not
  from global subscriber output.
- **Acceptance criteria:**
  - [ ] `let _g = telemetry::test_capture();` at the top of every relevant test body across
        the three crates.
  - [ ] `crates/slashing/tests/slashing_span.rs` tests from Issue 5.9 are verified to surface
        the correct span fields via the guard (not via global subscriber).
  - [ ] `cargo test --workspace --no-fail-fast` passes.
- **Tests:**
  - None new.
- **Non-goals:**
  - Rewriting any test's assertions — only adding the guard line.

---

## Issue 7.3: Publish `docs/observability.md` — conventions doc

- **Points:** 3
- **Depends on:** 7.1, 7.2 (so runbook can reference landed tests), Phase 4 Issue 4.11 (runbook
  test is the reference); Phase 5 Issue 5.5 (gRPC round-trip test for the propagation section)
- **Files touched:**
  - `docs/observability.md` (new)
  - `CLAUDE.md` (add a reference line pointing to `docs/observability.md` per PRD P0-1
    acceptance)
- **Summary:** Write the canonical conventions doc per PRD P0-1. Do not re-invent content —
  reference architecture §2–§6 and link. Goals: single place a developer opens when they want to
  know "how do I instrument this new function?" and an oncall opens when they want the runbook.
  Doc examples compile as `///` doc tests where applicable.
- **Acceptance criteria:**
  - [ ] `docs/observability.md` exists with these sections (drawn from architecture §2–§6 +
        PRD P0-1 + PRD UX/Design Notes):
        1. **Span naming** — `rvc.{domain}.{operation}` scheme. Table of canonical root spans
           per architecture §3.
        2. **Field keys** — standard `rvc.*` table from PRD P0-1 + architecture §3.
        3. **Level policy** — architecture §4 table copy.
        4. **`#[instrument]` style** — always `skip_all`, always explicit `name`, fields
           allowlisted.
        5. **Error-logging style** — `error = %e` not `error = ?e`. Attach `error.type`
           classifier.
        6. **Redaction helpers reference** — `TruncatedPubkey` / `TruncatedPubkeyBytes` /
           `TruncatedSignature` / `RedactedUrl` / `RedactedKeystore` / `RedactedSecret`.
        7. **Forbidden patterns** — copy the regex table from architecture §2.3 + the allowlist
           syntax.
        8. **gRPC propagation** — client interceptor + server `attach_server_parent` (reference
           architecture §2.4). Point to Issue 5.5 round-trip test as the canonical example.
        9. **Long-running spans** — fresh-root-per-iteration rule (architecture §6).
        10. **Runbook** — step-by-step "given a slot and validator pubkey, reconstruct the duty
           lifecycle from logs". Point to Phase 4 Issue 4.11 test
           (`crates/rvc/tests/duty_lifecycle.rs`) as the canonical trace shape.
        11. **File sink + `RVC_LOG_FORMAT`** — architecture §2.6 behavior; default is text in
           dev/test, json in prod.
        12. **Test-capture** — doc snippet: `let _g = telemetry::test_capture();`. Reference
           drop-printing-on-panic behavior.
        13. **Collector tail-sampling** — a pointer to architecture §5. Note this is an ops
           artifact, not a rs-vc artifact.
        14. **Resource attributes** — `service.name`, `service.version`, `network.name`,
           `service.instance.id`, `deployment.environment`.
        15. **Metrics cross-reference** — one-line convention: if a log event has a
           corresponding Prometheus metric, include the metric name in the event message.
  - [ ] `CLAUDE.md` has a new entry under `## Observability` (or a logical home) with a link:
        "Conventions: [docs/observability.md](docs/observability.md). All new tracing /
        logging code must follow this doc."
  - [ ] Doc examples that appear in Rust code blocks compile under `cargo test --doc -p
        telemetry` (use `/// ```` / `/// ```no_run` fencing appropriately).
  - [ ] Table of contents at the top linking to each section.
- **Tests:**
  - `cargo test --doc -p telemetry` passes; any doc examples embedded in `crates/telemetry`
    that mirror the `docs/observability.md` snippets compile.
- **Non-goals:**
  - Re-documenting span hierarchy details that already live in architecture §3 — link to
    `plan/observability/architecture.md` §3 instead.
  - Writing a migration guide (no migration — this is greenfield conventions).

---

## Issue 7.4: Demo failing test — span-tree-on-panic proof

- **Points:** 1
- **Depends on:** 1.2, Phase 4 (so real spans exist to capture)
- **Files touched:**
  - `crates/duty-tracker/tests/intentional_failure_demo.rs` (new) — gated behind
    `#[cfg(feature = "demo-fail")]` or `#[ignore]` so normal CI does not fail
- **Summary:** One test that:
  1. Installs `TestTracingGuard`.
  2. Drives a real duty-path call that emits spans.
  3. Panics (e.g. `panic!("intentional — demonstrates on-panic span tree print")`).
  When run with `cargo test -p duty-tracker -- --ignored`, the captured span tree appears in
  stdout (cargo captures stdout on failure by default, so the test output is visible).
- **Acceptance criteria:**
  - [ ] Test is marked `#[ignore = "demo for span-tree-on-panic behavior"]` so it does not
        fail CI.
  - [ ] Running `cargo test -p duty-tracker -- --ignored
        test_demo_span_tree_on_panic --nocapture` produces stdout output containing `SPAN `
        and `EVENT ` tokens from the `SpanTreeFormatter` (PRD UX/Design Notes shape).
  - [ ] Test file top-of-file comment explains the purpose: demonstrating PRD acceptance #2
        without actually failing CI on every run.
  - [ ] A second check, in `docs/observability.md` "Test-capture" section, references this
        test with a copy-paste command: `cargo test -p duty-tracker -- --ignored
        test_demo_span_tree_on_panic --nocapture`.
- **Tests:**
  - The demo test itself. Reviewed manually — the reviewer runs the command and confirms the
    output shape. No automated assertion because the test is designed to panic.
- **Non-goals:**
  - Making the demo run in CI (would fail every build).
  - Cross-crate demos — one crate is enough.

---

## Issue 7.5: PRD acceptance #2 — "synthesize a failure, read output" dual exercise

- **Points:** 1
- **Depends on:** 7.1, 7.3, 7.4
- **Files touched:**
  - No source files. Document the exercise in the PR description for the reviewer.
- **Summary:** PRD §Goals #2 requires at least two "synthesize a failure, read output" exercises
  during review. This issue is a review-gate, not a code change — the reviewer picks two tests
  (say, one from `crates/rvc/tests` and one from `crates/signer/tests`), introduces a forced
  assertion failure, confirms the span-tree output in default `cargo test` captured stdout
  identifies the root cause in ≤ 30 seconds of reading, then reverts.
- **Acceptance criteria:**
  - [ ] Reviewer performs the exercise on two distinct tests across two distinct crates,
        records brief notes in the PR description:
        - Test name + crate
        - Forced-failure diff (one line)
        - Root-cause inference time (seconds)
        - Revert confirmation
  - [ ] Both exercises succeed in identifying the root cause from captured output alone, no
        `RUST_LOG`, no `--nocapture` needed (cargo default captures test stdout and surfaces on
        failure).
  - [ ] If either exercise fails the "identify in ≤ 30 s" bar, file a follow-up to tighten the
        guard's output or to add more fields — but do NOT gate this issue on the follow-up.
- **Tests:**
  - None new. This is a review-validated acceptance.
- **Non-goals:**
  - Automating the exercise (would be fragile).
  - Writing a dedicated tool — the `TestTracingGuard` already does the job.
