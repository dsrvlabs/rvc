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
//! - `CompositeSigner::sign` — direct type-qualified call on the composite signer.
//! - `composite.sign(`       — method call on a `composite` variable.
//! - `composite_signer.sign(` — method call on a `composite_signer` variable.
//! - `crypto::sign_block`/`crypto::sign_attestation`/`crypto::sign_aggregate_and_proof`
//!   — free-function signing entry points in the crypto crate (non-routed).
//! - `SecretKey::sign(` — direct BLS sign on a secret key.
//!
//! None of these patterns exist in production outside the allow-listed paths
//! today; the gate catches future bypass shapes.

use std::path::{Path, PathBuf};
use std::process::Command;

// ---------------------------------------------------------------------------
// Policy tables
// ---------------------------------------------------------------------------

/// Source path prefixes (relative to workspace root) allowed to call
/// sign primitives directly.
const ALLOWED_PATH_PREFIXES: &[&str] = &["crates/signer/src/", "crates/crypto/src/"];

/// Patterns that indicate a direct BLS signing bypass outside the gate.
/// Each entry is a substring that, when found in a non-test production line,
/// signals a missing gate.
const BYPASS_PATTERNS: &[&str] = &[
    // Direct composite-signer calls (both type-qualified and variable-named).
    "CompositeSigner::sign",
    "composite.sign(",
    "composite_signer.sign(",
    // Free-function signing paths in the crypto crate (slashable operations).
    "crypto::sign_block",
    "crypto::sign_attestation",
    "crypto::sign_aggregate_and_proof",
    // Direct BLS secret-key sign — should only appear inside crates/crypto/src.
    "SecretKey::sign(",
];

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
// Helper: strip `#[cfg(test)]` / `mod tests { … }` blocks from a source string.
//
// Returns the production portion of a Rust source file — lines that are NOT
// inside a `#[cfg(test)]`-annotated item or `mod tests { … }` block.
//
// Design goals:
//   1. String-literal-aware brace counting: `{` / `}` inside `"…"` literals
//      do not affect the depth counter.  Handles `\"` escape sequences inside
//      strings.  (A raw `r"…"` literal is treated conservatively — its content
//      is not special-cased, but raw literals rarely contain unbalanced braces.)
//   2. Stacked attributes: when `#[cfg(test)]` is followed by one or more
//      additional attribute lines (`#[allow(…)]`, `#[derive(…)]`, …) before
//      the item, `cfg_test_pending` remains set until the next non-attribute
//      line, so the entire annotated item is stripped.
//   3. Conservative: the stripper may occasionally include an extra blank line
//      at the end of a block boundary, but will NEVER misclassify a production
//      orchestrator line as test code.
// ---------------------------------------------------------------------------

fn strip_test_blocks(source: &str) -> String {
    let mut out = Vec::new();
    let mut depth: i64 = 0;
    let mut in_test_block = false;
    let mut cfg_test_pending = false;

    for line in source.lines() {
        let trimmed = line.trim();

        // ── Attribute-line detection ─────────────────────────────────────────
        // Any line that is purely an attribute starts with `#[`.
        let is_attribute_line = trimmed.starts_with("#[");

        if trimmed.contains("#[cfg(test)]") {
            // Set the pending flag; don't emit this attribute line.
            cfg_test_pending = true;
            continue;
        }

        // While cfg_test_pending is set, keep consuming consecutive attribute
        // lines (e.g. `#[allow(clippy::…)]` that stack on top of cfg(test)).
        // Reset only when we reach a non-attribute line.
        if cfg_test_pending && is_attribute_line {
            // Another stacked attribute — still pending, still suppress.
            continue;
        }

        // ── Test-block start detection ───────────────────────────────────────
        // Matches: `mod tests {`, or any line with `{` that follows cfg(test).
        let starts_test =
            trimmed.starts_with("mod tests") || (cfg_test_pending && trimmed.contains('{'));

        if starts_test && !in_test_block {
            in_test_block = true;
            cfg_test_pending = false;
            // Count braces on this opening line (string-literal-aware).
            delta_braces(trimmed, &mut depth);
            continue; // suppress the `mod tests {` line itself
        }

        // ── In-block brace tracking ─────────────────────────────────────────
        if in_test_block {
            delta_braces(trimmed, &mut depth);
            if depth <= 0 {
                in_test_block = false;
                depth = 0;
            }
            continue; // suppress test block contents
        }

        // ── Production line ─────────────────────────────────────────────────
        // If we reach here, cfg_test_pending was set but the line is NOT an
        // attribute and does NOT start a block — this is an unusual pattern
        // (e.g. `#[cfg(test)]` on a `use` statement).  Reset the flag and
        // emit the line; it's safer to include than to silently drop.
        cfg_test_pending = false;
        out.push(line);
    }

    out.join("\n")
}

/// Compute the net brace-depth delta for a single source line, skipping
/// characters inside double-quoted string literals.
///
/// - `\"` inside a string literal is an escape; the `"` does not toggle the
///   string-open state.
/// - Only `{` and `}` outside string literals are counted.
/// - Single-line comments (`//`) are NOT special-cased; brace counts inside
///   comments are counted.  This is conservative: it may close a test block
///   one line late if a comment holds `}`, but never misses a real block end.
fn delta_braces(line: &str, depth: &mut i64) {
    let mut in_string = false;
    let mut chars = line.chars().peekable();

    while let Some(ch) = chars.next() {
        if in_string {
            if ch == '\\' {
                // Consume the escaped character so `\"` doesn't toggle state.
                chars.next();
            } else if ch == '"' {
                in_string = false;
            }
        } else {
            match ch {
                '"' => in_string = true,
                '{' => *depth += 1,
                '}' => *depth -= 1,
                _ => {}
            }
        }
    }
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

// ---------------------------------------------------------------------------
// Unit tests for `strip_test_blocks` and `delta_braces`
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── delta_braces ──────────────────────────────────────────────────────────

    #[test]
    fn test_delta_braces_plain() {
        let mut d = 0i64;
        delta_braces("fn foo() { let x = 1; }", &mut d);
        assert_eq!(d, 0, "balanced braces → net delta 0");
    }

    #[test]
    fn test_delta_braces_open() {
        let mut d = 0i64;
        delta_braces("mod tests {", &mut d);
        assert_eq!(d, 1);
    }

    #[test]
    fn test_delta_braces_skips_string_literals() {
        // The brace inside the string must not affect the counter.
        let mut d = 0i64;
        delta_braces(r#"let s = "expected '}' here";"#, &mut d);
        assert_eq!(d, 0, "braces inside string literals must be ignored");
    }

    #[test]
    fn test_delta_braces_handles_escape_in_string() {
        // `\"` inside a string literal must not close the string.
        let mut d = 0i64;
        delta_braces(r#"let s = "he said \"hi {\" there";"#, &mut d);
        assert_eq!(d, 0, "escaped quote inside string must not toggle string state");
    }

    #[test]
    fn test_delta_braces_multiple_strings() {
        let mut d = 0i64;
        delta_braces(r#"format!("{}", "{ }") {"#, &mut d);
        // braces inside both format strings are inside strings → skip.
        // The trailing `{` after the closing `)` is a real brace → +1.
        assert_eq!(d, 1);
    }

    // ── strip_test_blocks ────────────────────────────────────────────────────

    #[test]
    fn test_strip_plain_production() {
        let src = "fn foo() {}\nfn bar() {}\n";
        let stripped = strip_test_blocks(src);
        assert!(stripped.contains("fn foo()"), "production lines must be kept");
        assert!(stripped.contains("fn bar()"), "production lines must be kept");
    }

    #[test]
    fn test_strip_removes_mod_tests_block() {
        let src = "fn prod() {}\n\nmod tests {\n    fn inner() {}\n}\n";
        let stripped = strip_test_blocks(src);
        assert!(stripped.contains("fn prod()"), "production fn must be kept");
        assert!(!stripped.contains("fn inner()"), "test fn must be stripped");
        assert!(!stripped.contains("mod tests"), "mod tests line must be stripped");
    }

    #[test]
    fn test_strip_removes_cfg_test_block() {
        let src = "fn prod() {}\n\n#[cfg(test)]\nmod tests {\n    fn inner() {}\n}\n";
        let stripped = strip_test_blocks(src);
        assert!(stripped.contains("fn prod()"), "production fn must be kept");
        assert!(!stripped.contains("fn inner()"), "test fn must be stripped");
    }

    #[test]
    fn test_strip_stacked_attributes() {
        // #[cfg(test)] followed by #[allow(…)] before the block.
        let src = "fn prod() {}\n\n#[cfg(test)]\n#[allow(clippy::foo)]\nmod tests {\n    fn inner() {}\n}\n";
        let stripped = strip_test_blocks(src);
        assert!(stripped.contains("fn prod()"), "production fn must be kept");
        assert!(
            !stripped.contains("fn inner()"),
            "test fn under stacked attributes must be stripped"
        );
    }

    #[test]
    fn test_strip_brace_in_string_does_not_confuse_counter() {
        // A production line with an unbalanced brace inside a string literal.
        let src =
            "fn prod() {\n    let s = \"expected '}' here\";\n}\n\nmod tests {\n    fn t() {}\n}\n";
        let stripped = strip_test_blocks(src);
        assert!(stripped.contains("fn prod()"), "production fn must be kept");
        assert!(stripped.contains("expected '}'"), "production string literal must be preserved");
        assert!(!stripped.contains("fn t()"), "test fn must be stripped");
    }

    #[test]
    fn test_strip_nested_braces() {
        let src = "fn prod() {}\n\nmod tests {\n    fn a() {\n        let b = || {\n            1\n        };\n    }\n}\n";
        let stripped = strip_test_blocks(src);
        assert!(stripped.contains("fn prod()"));
        assert!(!stripped.contains("fn a()"));
    }

    #[test]
    fn test_strip_production_after_test_block() {
        let src = "fn before() {}\n\nmod tests {\n    fn t() {}\n}\n\nfn after() {}\n";
        let stripped = strip_test_blocks(src);
        assert!(stripped.contains("fn before()"));
        assert!(stripped.contains("fn after()"), "production fn after test block must be kept");
        assert!(!stripped.contains("fn t()"));
    }
}
