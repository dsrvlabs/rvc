//! Regression tests for M-5 (ISSUE-3.4): `TruncatedPubkey` in audit logs.
//!
//! # What M-5 fixes
//!
//! Before this fix:
//! - `audit::log::log_audit` logged the full 96-char BLS pubkey hex.
//! - `backend::basic::BasicSigner::load` also logged the full pubkey.
//!
//! After the fix both log sites use `crypto::logging::TruncatedPubkey` which
//! renders as `0x{first-10}…{last-8}` — 23 characters — instead of the full
//! 98-character hex string.
//!
//! ## Test strategy
//!
//! We capture the tracing output emitted during a call to `log_audit` /
//! `BasicSigner::load` using a custom `MakeWriter` that writes into a shared
//! `Arc<Mutex<Vec<u8>>>` buffer.  After the call we assert that:
//! - The captured line contains the truncation marker `...`.
//! - The middle section of the full pubkey hex does NOT appear.
//!
//! These assertions are RED before the fix (full hex → no `...`) and GREEN
//! after (TruncatedPubkey → contains `...`).

use std::sync::{Arc, Mutex};

use crypto::{EncryptionKdf, Keystore, SecretKey};
use rvc_signer_bin::{
    audit::log::{log_audit, AuditEntry, TruncatedPubkey},
    backend::basic::BasicSigner,
};
use tempfile::TempDir;
use zeroize::Zeroizing;

// ── log capture infrastructure ────────────────────────────────────────────────

/// A `Write` impl that appends to a shared byte buffer.
struct CaptureWriter(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for CaptureWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A `MakeWriter` that hands out `CaptureWriter` instances sharing one buffer.
struct MakeCapture(Arc<Mutex<Vec<u8>>>);

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for MakeCapture {
    type Writer = CaptureWriter;

    fn make_writer(&'a self) -> Self::Writer {
        CaptureWriter(Arc::clone(&self.0))
    }
}

/// Run `f` inside a tracing subscriber that captures all log output and return
/// the captured string.
fn capture_logs<F: FnOnce()>(f: F) -> String {
    let buf = Arc::new(Mutex::new(Vec::<u8>::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_writer(MakeCapture(Arc::clone(&buf)))
        .with_ansi(false)
        .with_level(true)
        .finish();

    tracing::subscriber::with_default(subscriber, f);

    let captured = buf.lock().unwrap().clone();
    String::from_utf8(captured).unwrap_or_default()
}

// ── TruncatedPubkey format contract (used by both sites) ─────────────────────

/// Full BLS pubkey (48 bytes = 96 hex chars + "0x" prefix = 98 chars total).
const FULL_PUBKEY: &str = "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a";

/// Middle section of the full pubkey — must NOT appear in truncated output.
const PUBKEY_MIDDLE: &str = "abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489";

// ── M-5 / audit::log ─────────────────────────────────────────────────────────

/// `log_audit` must render the pubkey with `TruncatedPubkey`, not as raw hex.
///
/// RED (before fix): the captured line contains `FULL_PUBKEY` → no `...` in
///   the pubkey field → assertion `contains("...")` fails.
/// GREEN (after fix): TruncatedPubkey shortens the field → `...` is present
///   and the middle section is absent.
#[test]
fn test_pubkey_truncated_in_audit_log() {
    let output = capture_logs(|| {
        let entry = AuditEntry {
            timestamp: "2026-05-01T00:00:00Z".to_string(),
            pubkey_hex: FULL_PUBKEY.to_string(),
            client_cn: "test-client".to_string(),
            backend: "basic".to_string(),
            result: "success".to_string(),
            duration_ms: 1,
            rpc: Some("sign_beacon_block".to_string()),
        };
        log_audit(&entry);
    });

    assert!(
        output.contains("..."),
        "expected truncated pubkey (containing '...') in log output, got:\n{}",
        output
    );
    assert!(
        !output.contains(PUBKEY_MIDDLE),
        "full pubkey middle must not appear in log output, got:\n{}",
        output
    );
}

/// The expected truncated format is `0x{first-10}...{last-8}` = 23 chars.
#[test]
fn test_truncated_pubkey_format_contract() {
    let rendered = TruncatedPubkey::new(FULL_PUBKEY).to_string();
    assert_eq!(rendered, "0x93247f2209...611df74a");
}

// ── M-5 / backend::basic ─────────────────────────────────────────────────────

/// Helper: create a keystore JSON in `dir` and return the pubkey bytes.
fn write_test_keystore(dir: &std::path::Path, password: &str) -> [u8; 48] {
    let sk = SecretKey::generate();
    let pubkey = sk.public_key().to_bytes();
    let ks = Keystore::encrypt(&sk, password.as_bytes(), "", EncryptionKdf::Pbkdf2)
        .expect("encrypt keystore");
    let json = ks.to_json().expect("serialize keystore");
    let path = dir.join(format!("{}.json", hex::encode(pubkey)));
    std::fs::write(path, json).expect("write keystore");
    pubkey
}

/// `BasicSigner::load` must log each loaded key with `TruncatedPubkey`.
///
/// RED (before fix): the log line shows `pubkey=<full-96-char-hex>` → no `...`
///   after the `pubkey=` field → assertion fails.
/// GREEN (after fix): TruncatedPubkey is applied → the `pubkey=` field contains
///   `...` and is only 23 chars (`0x{10}...{8}`).
#[tokio::test]
async fn test_pubkey_truncated_in_basic_backend_log() {
    let dir = TempDir::new().unwrap();
    let password = "integration-test-pass";
    let pubkey = write_test_keystore(dir.path(), password);

    // Build the expected truncated prefix: "pubkey=0x{first-10-hex-chars}..."
    let full_hex = hex::encode(pubkey);
    let expected_prefix = format!("pubkey=0x{}...", &full_hex[..10]);

    let output = capture_logs(|| {
        let pw = Zeroizing::new(password.to_string());
        BasicSigner::load(dir.path(), &pw).expect("load signer");
    });

    // The "Loaded keystore" line must contain the truncated pubkey field.
    assert!(
        output.contains(&expected_prefix),
        "expected '{}' in BasicSigner::load log, got:\n{}",
        expected_prefix,
        output
    );

    // The full 96-char hex must NOT appear as the `pubkey` field value.
    // We check for `pubkey=<full>` explicitly (the path field may still carry
    // the hex as a filename, so we scope the check to the field name prefix).
    let full_pubkey_field = format!("pubkey={}", full_hex);
    assert!(
        !output.contains(&full_pubkey_field),
        "full pubkey as 'pubkey=' field must not appear in load log, got:\n{}",
        output
    );
}
