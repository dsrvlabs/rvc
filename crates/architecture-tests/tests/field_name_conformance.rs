//! Advisory Gate 5: canonical field-name conformance over a curated event set.
//!
//! Captures the structured field keys of a small, representative set of hot-path events and
//! reports (via `eprintln!`, never a hard `assert!` on real keys) any that are not in the
//! canonical registry (`crypto::logging::conformance`). It is **advisory** in Phase 4 — issue
//! 4.13 grows the curated set with real hot-path events; issue 5.2 escalates it to a blocking
//! gate. The implicit `message` event field is excluded (it is the log message, not a
//! structured key).

use std::sync::{Arc, Mutex};

use tracing::field::{Field, Visit};
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::prelude::*;

#[derive(Clone, Default)]
struct KeyCapture(Arc<Mutex<Vec<String>>>);

struct KeyVisitor<'a>(&'a mut Vec<String>);

impl Visit for KeyVisitor<'_> {
    // Every typed `record_*` defaults to `record_debug`, so capturing here records the names
    // of all field types (u64/str/bool/…).
    fn record_debug(&mut self, field: &Field, _: &dyn std::fmt::Debug) {
        if field.name() != "message" {
            self.0.push(field.name().to_string());
        }
    }
}

impl<S: tracing::Subscriber> Layer<S> for KeyCapture {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        if let Ok(mut keys) = self.0.lock() {
            event.record(&mut KeyVisitor(&mut keys));
        }
    }
}

#[test]
fn field_names_advisory_conformance() {
    let cap = KeyCapture::default();
    let subscriber = tracing_subscriber::registry().with(cap.clone());

    tracing::subscriber::with_default(subscriber, || {
        // Curated representative hot-path events with canonical fields (grown by 4.13).
        tracing::info!(slot = 1u64, epoch = 0u64, committee_index = 3u64, "attestation published");
        tracing::debug!(validator_index = 7u64, pubkey = "0xtrunc", "duty cache hit");
        tracing::info!(bn_url = "redacted", "beacon node selected");
        tracing::info!(slot = 1u64, block_root = "0xtrunc", "block proposed");
        // A deliberately NON-canonical key, proving the advisory diff detects drift.
        tracing::warn!(val_idx = 9u64, "synthetic non-canonical fixture");
    });

    let observed = cap.0.lock().unwrap();
    let keys: Vec<&str> = observed.iter().map(String::as_str).collect();
    let flagged = crypto::logging::conformance::non_canonical_keys(keys);

    // Harness self-test: capture works and the diff catches the planted drift.
    assert!(observed.iter().any(|k| k == "slot"), "field capture failed (no `slot` seen)");
    assert!(
        flagged.contains(&"val_idx"),
        "advisory diff failed to flag the planted non-canonical key: {flagged:?}"
    );

    // ADVISORY: never fail the build on a real non-canonical key (5.2 makes it blocking).
    let real_flagged: Vec<&str> = flagged.iter().copied().filter(|k| *k != "val_idx").collect();
    if !real_flagged.is_empty() {
        eprintln!(
            "Gate 5 (advisory) — non-canonical field keys on the curated set: {real_flagged:?}"
        );
    }
}
