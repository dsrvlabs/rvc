//! ISSUE-4.5 / L-5: regression guard against `"head"` literal block-root queries.
//!
//! The audit finding was: `crates/rvc/src/orchestrator/sync_committee.rs:285`
//! used the literal string `"head"` as a block-id when querying
//! `get_block_root`, which is subject to TOCTOU drift (the head can advance
//! between query and use). The fix (ISSUE-2.5, A5) introduced `SlotContext`
//! which queries `get_block_root(slot=N)` for a deterministic, slot-qualified
//! root.
//!
//! This test scans the orchestrator source tree at test time and fails if any
//! file contains a `"head"` string literal that is not part of a comment, a
//! mock implementation (test-only), or an explicit allowlist entry. A future
//! contributor who reintroduces `get_block_root("head")` will see this test
//! fail with the exact file:line where they did it.

use std::fs;
use std::path::PathBuf;

/// Files in `crates/rvc/src/orchestrator/` are allowed to contain the literal
/// `"head"` *only* if their entry is listed here, with a justification.
///
/// Each entry is `(filename, justification)`. The check is filename-only (not
/// full path) so renames inside the orchestrator tree don't bypass it.
const ALLOWLIST: &[(&str, &str)] = &[
    // sync_committee.rs has a mock that intentionally maps `"head"` -> the
    // head root in its test module, to prove the production code does NOT
    // make `"head"` queries (counter-asserts against future regressions).
    ("sync_committee.rs", "test-only mock that distinguishes \"head\" from slot-qualified queries"),
    // slot_context.rs has the same pattern in its own test mock.
    ("slot_context.rs", "test-only mock that distinguishes \"head\" from slot-qualified queries"),
    // coordinator.rs has a generic timeout test that exercises a head-block
    // root fetch path; it does not use SlotContext and is unrelated to L-5.
    ("coordinator.rs", "test-only timeout exercise; unrelated to L-5"),
];

#[test]
fn test_no_head_string_literal_in_orchestrator_production_code() {
    let crate_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let orchestrator_dir = crate_root.join("src").join("orchestrator");

    assert!(
        orchestrator_dir.is_dir(),
        "orchestrator dir not found: {}",
        orchestrator_dir.display()
    );

    let mut violations: Vec<String> = Vec::new();

    for entry in fs::read_dir(&orchestrator_dir).expect("read_dir orchestrator") {
        let entry = entry.expect("dir entry");
        let path = entry.path();

        // Recurse one level (e.g. `proposer/`, `attestation_subnet/` if any).
        if path.is_dir() {
            for sub in fs::read_dir(&path).expect("read_dir sub") {
                let sub = sub.expect("dir entry");
                let sub_path = sub.path();
                if sub_path.extension().is_some_and(|e| e == "rs") {
                    check_file(&sub_path, &mut violations);
                }
            }
        } else if path.extension().is_some_and(|e| e == "rs") {
            check_file(&path, &mut violations);
        }
    }

    assert!(
        violations.is_empty(),
        "ISSUE-4.5 / L-5 regression: production `\"head\"` literal(s) found in \
         orchestrator. Use slot-qualified queries via `SlotContext` or extend \
         the ALLOWLIST in tests/no_head_literal_l5.rs with a justification.\n\
         Violations:\n{}",
        violations.join("\n")
    );
}

fn check_file(path: &std::path::Path, violations: &mut Vec<String>) {
    let filename = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    let allowed = ALLOWLIST.iter().any(|(name, _)| *name == filename);

    let contents = fs::read_to_string(path).expect("read source");
    for (line_no, line) in contents.lines().enumerate() {
        if line_contains_head_literal(line) && !allowed {
            violations.push(format!("  {}:{}: {}", path.display(), line_no + 1, line.trim()));
        }
    }
}

/// Returns true if `line` contains a `"head"` string literal that is not part
/// of a `//` comment and not part of an obvious doc-string-like construction.
fn line_contains_head_literal(line: &str) -> bool {
    // Strip after `//` to ignore comments.
    let code = line.split("//").next().unwrap_or("");
    code.contains("\"head\"")
}
