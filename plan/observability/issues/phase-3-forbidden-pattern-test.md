# Phase 3: Forbidden-Pattern Test (Ratchet)

**Goal:** Land `tests/forbidden_log_patterns.rs` green on the current tree; from this phase forward
no new banned logging pattern can enter the codebase.
**Total points:** 5
**Total issues:** 3
**Depends on:** Phase 1 (dev-deps `walkdir`, `regex`), Phase 2 (`bls.rs` Debug fix removes the
primary `BAD_SIG_DEBUG` source)
**Unblocks:** Phase 4, Phase 5, Phase 6, Phase 7, Phase 8

The ratchet is the PRD P0-2 enforcement mechanism. Regex set is verbatim from architecture §2.3 —
do not modify the patterns without a documented review. The test is an integration test at the
workspace root (`tests/forbidden_log_patterns.rs`), not a clippy lint, because it needs to inspect
macro arguments and format-string contents that clippy does not expose.

---

## Issue 3.1: Implement the workspace-root scanner + allowlist parser

- **Points:** 3
- **Depends on:** 1.6 (dev-deps), 2.2 (bls.rs Debug fix so `BAD_SIG_DEBUG` does not mass-fire)
- **Files touched:**
  - `tests/forbidden_log_patterns.rs` (new, workspace root)
  - `Cargo.toml` (workspace root — already has `[workspace.dev-dependencies]` entries from 1.6;
    verify `walkdir` and `regex` are reachable from the root test target — for a root `tests/`
    integration test, these may need `[dev-dependencies]` on the root binary or a small
    `[[test]]` declaration)
- **Summary:** Hand-rolled scanner: `walkdir` over the workspace minus the exclusion list in
  architecture §2.3 (`target/`, `tests/conformance/`, `plan/`, `docs/`, `OUT_DIR` generated
  files, the test file itself). Per-file regex match against the six rules from architecture §2.3
  (`BAD_FIELD`, `BAD_FMT`, `BAD_ZEROIZING`, `BAD_SIG_DEBUG`, `INSTRUMENT_NO_SKIPALL`,
  `BAD_GLOBAL_DEFAULT`). Allowlist comment syntax `// observability: allow <non-empty reason>`
  directly above the offending line.
  TDD cycle: RED with a failing assertion via a seeded fixture file (Issue 3.2), GREEN with the
  scanner+parser, REFACTOR to tidy the rule table.
- **Acceptance criteria:**
  - [ ] `tests/forbidden_log_patterns.rs` compiles and contains a single `#[test] fn
        forbidden_log_patterns_workspace_clean()` (matching architecture §2.3 sketch).
  - [ ] On the retrofitted current tree (post-Phase 2), the test passes.
  - [ ] Six regex rules match exactly the architecture §2.3 table — `BAD_FIELD`, `BAD_FMT`,
        `BAD_ZEROIZING`, `BAD_SIG_DEBUG`, `INSTRUMENT_NO_SKIPALL`, `BAD_GLOBAL_DEFAULT`.
  - [ ] `Violation { file, line, rule }` struct prints as `"{file}:{line}: {rule}"` on failure.
  - [ ] Exclusions honored: `target/`, `tests/conformance/`, `plan/`, `docs/`, `OUT_DIR`
        generated protos, and the test file itself are skipped.
  - [ ] Allowlist parser `is_allowlisted(source, match_offset)` returns true only if the
        immediately-preceding non-empty line matches
        `^\s*//\s*observability:\s*allow\s+\S.+$` (non-empty reason required).
  - [ ] An empty-reason allowlist (`// observability: allow`) does NOT suppress detection.
  - [ ] Runtime on the current tree is under 5 seconds (research baseline: ~500 ms). Add a
        `println!` at the end of the test reporting elapsed time for monitoring.
- **Tests:**
  - The primary test IS the integration test itself, run as `cargo test --test
    forbidden_log_patterns`. Passes on the current tree.
  - Fixture-based sub-assertions land in Issue 3.2.
- **Non-goals:**
  - Rewriting the rule regexes — copy from architecture §2.3 verbatim. If a rule misfires,
    reopen the rule, do not silently edit.
  - Implementing the test as an `xtask` or a build-script (PRD explicitly picks workspace-test).
  - Integration with CI (happens in Issue 3.3 for visibility; test itself runs under standard
    `cargo test --workspace`).

---

## Issue 3.2: Seeded-violation fixtures + self-test

- **Points:** 1
- **Depends on:** 3.1
- **Files touched:**
  - `tests/fixtures/forbidden_log_patterns/` (new directory)
  - `tests/fixtures/forbidden_log_patterns/bad_field.rs.txt`
  - `tests/fixtures/forbidden_log_patterns/bad_fmt.rs.txt`
  - `tests/fixtures/forbidden_log_patterns/bad_zeroizing.rs.txt`
  - `tests/fixtures/forbidden_log_patterns/bad_sig_debug.rs.txt`
  - `tests/fixtures/forbidden_log_patterns/instrument_no_skipall.rs.txt`
  - `tests/fixtures/forbidden_log_patterns/bad_global_default.rs.txt`
  - `tests/fixtures/forbidden_log_patterns/allowlist_with_reason.rs.txt`
  - `tests/fixtures/forbidden_log_patterns/allowlist_empty_reason.rs.txt`
  - `tests/forbidden_log_patterns.rs` (add `#[test] fn fixtures_trigger_expected_rules()` that
    invokes the scanner against the fixture dir and asserts one violation per rule file, plus two
    allowlist cases)
- **Summary:** Each fixture is a `.rs.txt` file (not a real `.rs`, so the compiler ignores it) that
  contains one planted violation. The self-test scans the fixture directory and asserts detection.
- **Acceptance criteria:**
  - [ ] Six rule-specific fixtures exist; each plants exactly one violation of its rule.
  - [ ] `allowlist_with_reason.rs.txt` contains a single violation preceded by
        `// observability: allow testing fixture`; the scanner should NOT report it.
  - [ ] `allowlist_empty_reason.rs.txt` contains a single violation preceded by
        `// observability: allow`; the scanner MUST still report it.
  - [ ] `fixtures_trigger_expected_rules` scans the fixture directory and asserts the rule names
        returned match exactly the expected set (`BAD_FIELD`, `BAD_FMT`, `BAD_ZEROIZING`,
        `BAD_SIG_DEBUG`, `INSTRUMENT_NO_SKIPALL`, `BAD_GLOBAL_DEFAULT`, plus the empty-reason
        allowlist site — 7 total).
  - [ ] `.rs.txt` extension keeps rustc from trying to compile the fixtures; fixture parent dir
        is explicitly whitelisted into the scanner for the self-test and excluded from the main
        `workspace_clean` test.
- **Tests:**
  - `tests/forbidden_log_patterns.rs::fixtures_trigger_expected_rules` (new) — asserts described
    above.
- **Non-goals:**
  - Making the fixtures real `.rs` files (would require `#[cfg(never)]` gymnastics and risks
    surfacing in the main scan).
  - Testing the scanner via `cargo fuzz` / property tests.

---

## Issue 3.3: Seed allowlist for pre-existing violations + CI wiring

- **Points:** 1
- **Depends on:** 3.1, 3.2
- **Files touched:**
  - Any source file that surfaces a violation once 3.1 is run — expected sites (based on
    architecture §1.5 "already has skip_all" audit): none after 2.2 lands, but verify. Likely
    candidates to audit: `crates/secret-provider/src/key_source_manager.rs`,
    `crates/crypto/src/keystore.rs`, and any file using `?signature` / `?sig`.
  - `.github/workflows/*.yml` OR `Makefile` OR existing CI config (whatever the repo uses — quick
    `ls .github/workflows` discovery)
- **Summary:** Run `cargo test --test forbidden_log_patterns` on the current tree. For each
  reported violation that is not already fixed by Phase 2, add an allowlist comment with a
  concrete reason (examples: "exercises error path in unit test", "test harness sets up capture
  subscriber before our API"). Then ensure CI runs this test — typically it is already picked up
  by `cargo test --workspace`, but double-check the CI command.
- **Acceptance criteria:**
  - [ ] `cargo test --test forbidden_log_patterns` passes on the branch head.
  - [ ] Every allowlist comment in the tree follows
        `// observability: allow <non-empty reason>` and each has a reviewer-approved reason
        (not `// observability: allow tmp` or similar placeholder).
  - [ ] The repo's CI config runs `cargo test --workspace` in a job that fails if the new test
        fails (no new ignore wiring).
  - [ ] A planted violation (temporarily) in any `crates/<any>/src/**/*.rs` fails the test —
        verified by the reviewer during code review, then reverted.
  - [ ] Documentation: a short README paragraph in `tests/forbidden_log_patterns.rs` top-of-file
        comment describes the allowlist syntax so future contributors do not need to dig into
        source.
- **Tests:**
  - Exit criterion is the same test passing. No new tests.
- **Non-goals:**
  - Expanding the regex rule set.
  - Adding a blanket allowlist on any file or crate. Every allowlist entry is line-specific.
  - Bypass mechanism (e.g. `#[cfg(observability_off)]`) — not needed.
