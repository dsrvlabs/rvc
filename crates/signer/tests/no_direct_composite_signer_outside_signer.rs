//! Standing CI gate: no direct BLS signing outside `crates/signer/src`.
//!
//! # Purpose
//!
//! Every BLS signing call that produces a slashable or consensus-significant
//! signature MUST route through `SigningGate` (or `SignerService`), which
//! enforces the doppelganger gate and slashing protection.  A direct call to
//! `CompositeSigner::sign` in orchestrator/application code would bypass these
//! checks.
//!
//! This test enumerates workspace crates via `cargo metadata` (serde_json; no
//! new external deps added) and greps PRODUCTION source files for the patterns
//! that would indicate a bypass.  Test code (`#[cfg(test)]` modules, `tests/`
//! directories) is excluded because orchestrator test mocks legitimately
//! construct `CompositeSigner` for wiring up in-process test harnesses.
//!
//! # Allow-listed paths (source roots that MAY call `.sign()` directly)
//!
//! - `crates/signer/src/`  — the gate's own implementation.
//! - `crates/crypto/src/`  — cryptographic primitives layer; `.sign()` on
//!   `SecretKey`/BLS objects is an implementation detail here.
//!
//! # Excluded code (not checked)
//!
//! - Files under `tests/` or `examples/` subdirectories of any crate.
//! - Lines inside `#[cfg(test)]` or `mod tests { … }` blocks.
//!
//! # Patterns checked (substrings in production source lines)
//!
//! - `CompositeSigner::sign` — direct type-qualified method call.
//! - `composite.sign(`       — method call on a `composite` variable.
//! - `composite_signer.sign(` — method call on a `composite_signer` variable.

use std::path::{Path, PathBuf};
use std::process::Command;

// ---------------------------------------------------------------------------
// Policy tables
// ---------------------------------------------------------------------------

/// Source path prefixes (relative to workspace root) allowed to call
/// sign primitives directly.
const ALLOWED_PATH_PREFIXES: &[&str] = &["crates/signer/src/", "crates/crypto/src/"];

/// Patterns that indicate a direct BLS signing bypass outside the gate.
const BYPASS_PATTERNS: &[&str] =
    &["CompositeSigner::sign", "composite.sign(", "composite_signer.sign("];

// ---------------------------------------------------------------------------
// Helper: recursively collect *.rs production files (exclude tests/ examples/).
// ---------------------------------------------------------------------------

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let read_dir = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(_) => return,
    };
    for entry in read_dir.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let dir_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            // Skip test / example directories.
            if dir_name == "tests" || dir_name == "examples" {
                continue;
            }
            collect_rs_files(&path, out);
        } else if path.is_file() && path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

// ---------------------------------------------------------------------------
// Helper: strip `#[cfg(test)]` / `mod tests { … }` blocks.
//
// Returns the production lines of a Rust source — lines NOT inside a test
// block.  Uses a simple brace-depth counter; conservative (may include a few
// extra lines near block boundaries) but will never misclassify production
// orchestrator code as test code.
// ---------------------------------------------------------------------------

fn strip_test_blocks(source: &str) -> String {
    let mut out = Vec::new();
    let mut depth: i64 = 0;
    let mut in_test_block = false;
    let mut cfg_test_pending = false;

    for line in source.lines() {
        let trimmed = line.trim();

        // Detect #[cfg(test)].
        if trimmed.contains("#[cfg(test)]") {
            cfg_test_pending = true;
            // Don't emit the cfg(test) attribute line either.
            continue;
        }

        // Detect start of test block: `mod tests` or block following cfg(test).
        let starts_test =
            trimmed.starts_with("mod tests") || (cfg_test_pending && trimmed.ends_with('{'));

        if starts_test && !in_test_block {
            in_test_block = true;
            cfg_test_pending = false;
            // Count braces on this line.
            for ch in trimmed.chars() {
                match ch {
                    '{' => depth += 1,
                    '}' => depth -= 1,
                    _ => {}
                }
            }
            continue; // skip the `mod tests {` line itself
        }

        if in_test_block {
            for ch in trimmed.chars() {
                match ch {
                    '{' => depth += 1,
                    '}' => depth -= 1,
                    _ => {}
                }
            }
            if depth <= 0 {
                in_test_block = false;
                depth = 0;
            }
            continue; // skip test block contents
        }

        // Not in a test block — emit the line.
        cfg_test_pending = false;
        out.push(line);
    }

    out.join("\n")
}

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

#[test]
fn no_direct_composite_signer_outside_signer() {
    // ── 1. cargo metadata ────────────────────────────────────────────────────
    // CARGO_MANIFEST_DIR is crates/signer; walk up two levels to workspace root.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let workspace_root = Path::new(manifest_dir)
        .parent() // crates/
        .and_then(|p| p.parent()) // workspace root
        .expect("could not determine workspace root from CARGO_MANIFEST_DIR");

    let output = Command::new("cargo")
        .args(["metadata", "--format-version=1", "--no-deps"])
        .current_dir(manifest_dir)
        .output()
        .expect("cargo metadata must run; cargo must be on PATH");

    assert!(
        output.status.success(),
        "cargo metadata exited non-zero: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let metadata: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("cargo metadata must be valid JSON");

    let packages = metadata["packages"].as_array().expect("metadata 'packages' must be an array");

    // ── 2. Resolve allow-listed absolute paths ───────────────────────────────
    let allowed_abs: Vec<PathBuf> =
        ALLOWED_PATH_PREFIXES.iter().map(|p| workspace_root.join(p)).collect();

    // ── 3. Grep production source of every workspace crate ──────────────────
    let mut violations: Vec<String> = Vec::new();

    for pkg in packages {
        let manifest_path_str = match pkg["manifest_path"].as_str() {
            Some(p) => p,
            None => continue,
        };
        let crate_root = match Path::new(manifest_path_str).parent() {
            Some(p) => p.to_path_buf(),
            None => continue,
        };
        let src_dir = crate_root.join("src");
        if !src_dir.is_dir() {
            continue;
        }

        let mut files = Vec::new();
        collect_rs_files(&src_dir, &mut files);

        for file_path in files {
            // Skip allow-listed paths.
            if allowed_abs.iter().any(|a| file_path.starts_with(a)) {
                continue;
            }

            let source = match std::fs::read_to_string(&file_path) {
                Ok(s) => s,
                Err(_) => continue,
            };

            let production = strip_test_blocks(&source);

            for pattern in BYPASS_PATTERNS {
                if production.contains(pattern) {
                    for (line_no, line) in production.lines().enumerate() {
                        if line.contains(pattern) {
                            violations.push(format!(
                                "{}:{}: bypass pattern {:?} found: {}",
                                file_path.display(),
                                line_no + 1,
                                pattern,
                                line.trim()
                            ));
                        }
                    }
                }
            }
        }
    }

    // ── 4. Assert no violations ─────────────────────────────────────────────
    assert!(
        violations.is_empty(),
        "D-3 standing gate (Issue 2.10b): direct BLS signing outside \
         crates/signer/src or crates/crypto/src detected in production code.\n\
         All signing MUST route through SigningGate / SignerService.\n\
         Test code (#[cfg(test)] / mod tests / tests/ dirs) is excluded.\n\
         \n\
         Violations:\n{}",
        violations.join("\n")
    );
}
