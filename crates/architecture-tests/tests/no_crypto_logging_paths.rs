//! RF3-02: no `crypto::logging` / `crypto::hex` / `crypto::pubkey` paths remain.
//!
//! After the observability repoint, production sources under `crates/*/src` and
//! `bin/*/src` must import logging/hex/pubkey only via `observability::…`.
//! This gate is a hand-rolled scanner (no new dependency; same style as
//! `no_rvc_prefix.rs`) so the sweep is complete rather than approximate.

use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().to_path_buf()
}

fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name == "target" || name.starts_with('.') {
                continue;
            }
            collect_rs(&path, out);
        } else if path.extension().map(|x| x == "rs").unwrap_or(false) {
            out.push(path);
        }
    }
}

/// Production source files: `crates/*/src/**.rs` + `bin/*/src/**.rs`.
fn production_rs_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for base in ["crates", "bin"] {
        let Ok(entries) = std::fs::read_dir(root.join(base)) else {
            continue;
        };
        for entry in entries.flatten() {
            let src = entry.path().join("src");
            if src.is_dir() {
                collect_rs(&src, &mut out);
            }
        }
    }
    out
}

/// True if `code` contains a forbidden `crypto::{logging,hex,pubkey}` path.
///
/// Matches the path forms `crypto::logging`, `crypto::hex`, `crypto::pubkey`
/// (and brace-import fragments are covered because those still spell the
/// module name after `::`). Does not match unrelated identifiers like
/// `crypto::PublicKey` or comments that only say "logging" without the path.
fn has_crypto_observability_path(src: &str) -> bool {
    src.contains("crypto::logging")
        || src.contains("crypto::hex")
        || src.contains("crypto::pubkey")
        || src.contains("crypto::{logging")
        || src.contains("crypto::{hex")
        || src.contains("crypto::{pubkey")
        // Brace form: use crypto::{…, logging::…, …}
        || src.contains("logging::") && src.lines().any(|line| {
            let t = line.trim_start();
            t.starts_with("use crypto::{") && t.contains("logging::")
        })
        || src.lines().any(|line| {
            let t = line.trim_start();
            t.starts_with("use crypto::{")
                && (t.contains("hex::") || t.contains("pubkey::") || t.contains(" logging") || t.contains("{logging"))
        })
}

#[test]
fn no_crypto_logging_paths_remain() {
    let root = workspace_root();
    let files = production_rs_files(&root);
    assert!(files.len() > 100, "scanned only {} files; workspace walk likely broke", files.len());

    let mut offenders: Vec<String> = Vec::new();
    for file in files {
        let rel = file.strip_prefix(&root).unwrap().to_string_lossy().replace('\\', "/");
        let src = std::fs::read_to_string(&file).unwrap_or_default();
        if has_crypto_observability_path(&src) {
            offenders.push(rel);
        }
    }
    offenders.sort();
    assert!(
        offenders.is_empty(),
        "crypto::logging / crypto::hex / crypto::pubkey paths remain (RF3-02).\n\
         Repoint to observability::…:\n  {}",
        offenders.join("\n  ")
    );
}

#[test]
fn matcher_flags_crypto_paths_and_ignores_real_crypto() {
    assert!(has_crypto_observability_path("use crypto::logging::TruncatedPubkey;"));
    assert!(has_crypto_observability_path("use crypto::hex::{strip_prefix_strict, HexError};"));
    assert!(has_crypto_observability_path("pubkey.parse::<crypto::pubkey::CanonicalPubkey>()"));
    assert!(has_crypto_observability_path(
        "use crypto::{logging::TruncatedPubkey, CompositeSigner};"
    ));
    // Real crypto symbols are fine:
    assert!(!has_crypto_observability_path("use crypto::{PublicKey, SecretKey};"));
    assert!(!has_crypto_observability_path("use observability::logging::TruncatedPubkey;"));
}
