//! Standing CI gate: no `rvc.`-prefixed span names or field keys in production logging.
//!
//! Phase 4 of the structured-logging initiative normalizes the legacy `rvc.` tracing
//! namespace to the canonical registry (`crypto::logging::fields`) so OTLP dashboards group
//! on `slot`, not `rvc.slot`. This gate scans production `*.rs` source under `crates/*/src`
//! and `bin/*/src` and fails if an `rvc.`-prefixed tracing span name or field key appears in
//! a file that is neither permanently `EXCLUDE`d (non-key fixtures) nor on the temporary
//! `KNOWN_REMAINING` allow-list. Each normalization issue removes its file(s) from
//! `KNOWN_REMAINING`; issue 4.12b tightens it to empty (the workspace-wide zero-`rvc.`
//! invariant).
//!
//! No external dependency (Phase-1 rule P6): a tiny hand-rolled matcher, not `regex`.

use std::path::{Path, PathBuf};

/// Files whose only `rvc.` occurrences are NON-key fixtures (test data or the product's log
/// filename), not production tracing keys. Permanent — these are never normalized away, so
/// they are excluded outright rather than tracked in `KNOWN_REMAINING`.
const EXCLUDE: &[&str] = &[
    // Conformance helper's test inputs ("rvc.slot", "rvc.foo") exercising the Gate-5 diff.
    "crates/crypto/src/logging.rs",
    // The product's rotating log file is literally named "rvc.log" (a filename, not a key).
    "crates/telemetry/src/file_appender.rs",
    // Likewise: bin/rvc's only rvc. hit is the default `"rvc.log"` log filename.
    "bin/rvc/src/main.rs",
];

/// Production files still carrying `rvc.`-prefixed tracing keys, pending their normalization
/// issue. Tightened to EMPTY by issue 4.12b. Paths are workspace-relative, `/`-separated.
const KNOWN_REMAINING: &[&str] = &[
    // Planned per-crate normalization issues (4.6–4.11):
    "crates/propagator/src/lib.rs",                     // 4.9
    "crates/bn-manager/src/manager.rs",                 // 4.10a
    "crates/slashing/src/db.rs",                        // 4.10b
    "crates/slashing/src/audit.rs",                     // 4.10b
    "crates/secret-provider/src/gcp.rs",                // 4.10c
    "crates/secret-provider/src/key_source_manager.rs", // 4.10c
    "crates/beacon/src/client.rs",                      // 4.11
    "crates/grpc-signer/src/client.rs",                 // 4.11
    "crates/rvc/src/orchestrator/coordinator.rs", // 4.12a (Phase-2 2.9 left a beacon test ref)
    // Stragglers not named in the plan's issue list — real rvc. keys the census missed.
    // Absorbed by 4.12b (whose job is to empty this list); see its task notes.
    "crates/crypto/src/signing.rs",
    "crates/crypto/src/aggregation_signing.rs",
    "crates/crypto/src/block_signing.rs",
    "crates/crypto/src/builder_signing.rs",
    "crates/crypto/src/sync_signing.rs",
    "crates/crypto/src/voluntary_exit_signing.rs",
    "crates/crypto/src/remote_signer.rs",
    "crates/keymanager-api/src/handlers.rs",
    "crates/sync-service/src/lib.rs",
    "bin/rvc-signer/src/service.rs",          // 4.12b
    "bin/rvc-signer/src/dvt/peer_service.rs", // 4.12b
    "bin/rvc-signer/src/backend/dvt.rs",      // 4.12b
];

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is `<root>/crates/architecture-tests`; the workspace root is two up.
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().to_path_buf()
}

fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs(&path, out);
        } else if path.extension().map(|x| x == "rs").unwrap_or(false) {
            out.push(path);
        }
    }
}

/// All production source files: `crates/*/src/**.rs` + `bin/*/src/**.rs`. Integration tests
/// under `crates/*/tests` / `bin/*/tests` are intentionally not scanned.
fn production_rs_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for base in ["crates", "bin"] {
        let Ok(entries) = std::fs::read_dir(root.join(base)) else { continue };
        for entry in entries.flatten() {
            let src = entry.path().join("src");
            if src.is_dir() {
                collect_rs(&src, &mut out);
            }
        }
    }
    out
}

/// True if the (comment-stripped) line uses an `rvc.`-prefixed tracing span name or field
/// key. Matches `"rvc.<key>"` (a quoted span name) and `rvc.<dotted_key> =` (a field key),
/// while ignoring `rvc::` module paths, `self.rvc.` field access, and prose mentions.
fn rvc_key_in_line(code: &str) -> bool {
    let bytes = code.as_bytes();
    let mut from = 0;
    while let Some(rel) = code[from..].find("rvc.") {
        let at = from + rel;
        let before = at.checked_sub(1).map(|i| bytes[i]);
        let after = &code[at + 4..];
        let next_is_lower = after.chars().next().map(|c| c.is_ascii_lowercase()).unwrap_or(false);

        // Quoted span name: `"rvc.<lower>` (e.g. name = "rvc.sign.attestation").
        if before == Some(b'"') && next_is_lower {
            return true;
        }

        // Field key: a non-identifier char (or line start) precedes `rvc.`, the key is a
        // dotted lowercase ident, and it is immediately assigned (`=`, not `==`/`=>`).
        let before_breaks_ident =
            before.map(|b| !(b.is_ascii_alphanumeric() || b == b'_' || b == b'.')).unwrap_or(true);
        if before_breaks_ident && next_is_lower {
            let key_end = after
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.'))
                .unwrap_or(after.len());
            let rest = after[key_end..].trim_start();
            if rest.starts_with('=') && !rest.starts_with("==") && !rest.starts_with("=>") {
                return true;
            }
        }

        from = at + 4;
    }
    false
}

/// Returns the code portion of a line with any trailing `//` line/doc comment removed.
/// The `//` is only treated as a comment when it is **outside** a string literal, so a
/// key on a URL-bearing line (e.g. `debug!(target = "http://bn", rvc.bn_url = %u)`) is not
/// truncated away before the matcher sees it. A best-effort scanner (escape-aware `"`
/// toggling); raw strings with embedded backslashes are a rare edge it doesn't model.
fn strip_line_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    let mut in_string = false;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' if in_string => {
                i += 2; // skip the escaped char (e.g. \")
                continue;
            }
            b'"' => in_string = !in_string,
            b'/' if !in_string && bytes.get(i + 1) == Some(&b'/') => return &line[..i],
            _ => {}
        }
        i += 1;
    }
    line
}

/// True if any production line in `src` carries an `rvc.`-prefixed tracing key (comments
/// stripped first so doc/line comments mentioning `rvc.slot` don't trip the gate).
fn file_has_rvc_key(src: &str) -> bool {
    src.lines().any(|raw| rvc_key_in_line(strip_line_comment(raw)))
}

#[test]
fn no_rvc_prefixed_keys_outside_allow_lists() {
    let root = workspace_root();
    let files = production_rs_files(&root);
    // Floor against a vacuous pass if directory enumeration ever silently fails.
    assert!(files.len() > 100, "scanned only {} files; workspace walk likely broke", files.len());
    let mut offenders: Vec<String> = Vec::new();
    for file in files {
        let rel = file.strip_prefix(&root).unwrap().to_string_lossy().replace('\\', "/");
        if EXCLUDE.contains(&rel.as_str()) || KNOWN_REMAINING.contains(&rel.as_str()) {
            continue;
        }
        if file_has_rvc_key(&std::fs::read_to_string(&file).unwrap_or_default()) {
            offenders.push(rel);
        }
    }
    offenders.sort();
    assert!(
        offenders.is_empty(),
        "rvc.-prefixed tracing keys found in files not on EXCLUDE/KNOWN_REMAINING.\n\
         Normalize them to crypto::logging::fields, or (if the `rvc.` is a non-key fixture) \
         add the file to EXCLUDE:\n  {}",
        offenders.join("\n  ")
    );
}

#[test]
fn matcher_flags_keys_and_ignores_non_keys() {
    // Real span names and field keys are flagged:
    assert!(rvc_key_in_line(r#"    name = "rvc.sign.attestation","#));
    assert!(rvc_key_in_line(r#"    fields(rvc.operation = "attestation")"#));
    assert!(rvc_key_in_line("        rvc.slot = slot,"));
    assert!(rvc_key_in_line("        rvc.doppelganger.detected_count = n,"));
    // Non-keys are ignored:
    assert!(!rvc_key_in_line("use rvc::logging;")); // module path (no dot)
    assert!(!rvc_key_in_line("let x = self.rvc.inner;")); // struct field access
    assert!(!rvc_key_in_line(r#"let s = "see rvc.slot in the docs";"#)); // prose, not a key

    // A quoted filename like "rvc.log" DOES match (indistinguishable from a span name) — that
    // is why such files (e.g. telemetry/file_appender.rs) are handled via EXCLUDE, not here.
    assert!(rvc_key_in_line(r#"    filename: "rvc.log".to_string(),"#));
}

#[test]
fn comment_strip_is_string_literal_aware() {
    // A `//` inside a string literal (a URL) must NOT hide a real key after it on the same
    // line — exactly the co-location 4.11/4.12b create when normalizing rvc.bn_url/rvc.head.
    assert!(file_has_rvc_key(r#"    warn!(target = "https://bn", rvc.bn_url = %u);"#));
    assert!(file_has_rvc_key(r#"    let u = "http://x"; debug!(rvc.slot = s);"#));
    // A genuine trailing line comment / doc comment mentioning a key is still stripped.
    assert!(!file_has_rvc_key("    let x = 1; // see rvc.epoch in the registry"));
    assert!(!file_has_rvc_key("/// emits rvc.slot on the span"));
}
