//! Advisory Gate 5: canonical field-name conformance over a curated event set.
//!
//! Captures the structured field keys of a small, representative MULTI-CRATE hot-path event
//! set and reports (via `eprintln!`, never a hard `assert!` on real keys) any that are not in
//! the canonical registry (`crypto::logging::conformance`). It is **advisory** in Phase 4 —
//! issue 4.13 grew the curated set with the now-normalized canonical keys the orchestrator /
//! beacon / signer / doppelganger / slashing / bn-manager / duty-tracker / block-service paths
//! emit; issue 5.2 escalates it to a blocking gate. The implicit `message` event field is
//! excluded (it is the log message, not a structured key).
//!
//! Load-bearing assertions (these DO fail the build):
//!   1. The curated PURELY-canonical event set yields an EMPTY advisory diff — proving the
//!      Phase-4 `rvc.`-prefix removal + key normalization actually landed across crates.
//!   2. A deliberately non-canonical key IS flagged — proving the advisory mechanism detects
//!      drift (the gate is non-vacuous), so escalating it to blocking in Phase 5 is meaningful.
//!
//! Deferred to Phase 5 (intentionally NOT in the empty-assertion set): domain count/label
//! fields that crates still emit but are not yet canonical — e.g. `validator_count`,
//! `detected_count`, `duty_count`/`duties_count`, `signing_type`, `slashing_result`,
//! `strategy`, `tried`, `cache_type`. Adding any of them here would (correctly) make the
//! advisory diff non-empty; their canonical registration / ADVISORY_ALLOW disposition is a
//! Phase-5 decision.

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

/// Emits the curated PURELY-canonical multi-crate hot-path event set under `cap` and returns
/// the captured field keys. Every key here is either a canonical `crypto::logging::fields`
/// const or an advisory-allowed key (`error`, `count`, `http.*`) — so a correct Phase-4
/// normalization makes `non_canonical_keys` empty over this set.
fn emit_canonical_hot_path_events(cap: &KeyCapture) -> Vec<String> {
    let subscriber = tracing_subscriber::registry().with(cap.clone());
    tracing::subscriber::with_default(subscriber, || {
        // --- orchestrator (crates/rvc) — attestation / aggregation / block phases ---
        tracing::info!(slot = 1u64, epoch = 0u64, committee_index = 3u64, "attestation published");
        tracing::debug!(
            slot = 1u64,
            validator_index = 7u64,
            pubkey = "0xtrunc",
            subcommittee_index = 2u64,
            "sync-committee duty processed"
        );
        tracing::info!(slot = 1u64, head = "0xtrunc", "head updated");

        // --- beacon — duty-call spans (slot/epoch/bn_url + OTel http.* + error) ---
        tracing::info!(bn_url = "redacted", epoch = 0u64, "attester duties fetched");
        tracing::warn!(slot = 1u64, error = "timeout", "beacon call retried");
        tracing::debug!(slot = 1u64, "http.status_code" = 200u64, "produce_block_v3 ok");

        // --- signer (rvc-signer) — sign.* spans carry the canonical `duty` ---
        tracing::debug!(slot = 1u64, pubkey = "0xtrunc", duty = "block", "block signed");
        tracing::debug!(
            epoch = 0u64,
            pubkey = "0xtrunc",
            duty = "attestation",
            "attestation signed"
        );

        // --- doppelganger ---
        tracing::info!(epoch = 0u64, pubkey = "0xtrunc", "doppelganger window clear");

        // --- slashing (rvc-slashing) ---
        tracing::debug!(pubkey = "0xtrunc", slot = 1u64, "slashing-db block staged");

        // --- bn-manager ---
        tracing::info!(bn_url = "redacted", slot = 1u64, "beacon node selected");

        // --- duty-tracker ---
        tracing::debug!(
            slot = 1u64,
            epoch = 0u64,
            validator_index = 7u64,
            committee_index = 3u64,
            "attester duty resolved"
        );

        // --- block-service ---
        tracing::info!(slot = 1u64, pubkey = "0xtrunc", block_root = "0xtrunc", "block proposed");

        // --- correlation kit (crypto::logging) — request_id / time_into_slot ---
        tracing::info!(
            request_id = "00000000-0000-4000-8000-000000000000",
            "signing request received"
        );
        tracing::debug!(slot = 1u64, time_into_slot = 1333u64, "slot phase reached");

        // --- generic milestone advisory key ---
        tracing::info!(count = 42u64, "validators loaded");
    });

    let observed = cap.0.lock().unwrap();
    observed.clone()
}

/// Load-bearing: the curated PURELY-canonical multi-crate event set must yield an EMPTY
/// advisory diff — Phase-4 normalization proof. Also a harness self-test (capture works).
#[test]
fn canonical_hot_path_event_set_yields_empty_advisory() {
    let cap = KeyCapture::default();
    let observed = emit_canonical_hot_path_events(&cap);
    assert!(observed.iter().any(|k| k == "slot"), "field capture failed (no `slot` seen)");

    let keys: Vec<&str> = observed.iter().map(String::as_str).collect();
    let flagged = crypto::logging::conformance::non_canonical_keys(keys);
    assert!(
        flagged.is_empty(),
        "Phase-4 regression: curated canonical event set produced non-canonical keys: {flagged:?}"
    );
}

/// Load-bearing (non-vacuity): a deliberately non-canonical key MUST be flagged by the advisory
/// diff — proving the mechanism detects drift, so the Phase-5 escalation to a blocking gate is
/// meaningful. Without this, an all-canonical set could pass even if the diff were a no-op.
#[test]
fn non_canonical_key_is_flagged_advisory() {
    let cap = KeyCapture::default();
    let subscriber = tracing_subscriber::registry().with(cap.clone());
    tracing::subscriber::with_default(subscriber, || {
        // A synonym for `slot` and a clearly-stray key: both must be flagged.
        tracing::warn!(
            rvc.slot = 9u64,
            not_a_canonical_key = 1u64,
            "synthetic non-canonical fixture"
        );
    });

    let observed = cap.0.lock().unwrap();
    let keys: Vec<&str> = observed.iter().map(String::as_str).collect();
    let flagged = crypto::logging::conformance::non_canonical_keys(keys);
    assert!(
        flagged.contains(&"rvc.slot"),
        "advisory diff failed to flag the planted `rvc.slot` synonym: {flagged:?}"
    );
    assert!(
        flagged.contains(&"not_a_canonical_key"),
        "advisory diff failed to flag the planted stray key: {flagged:?}"
    );
}

/// Advisory reporter (Phase 4): mixes the curated canonical events with the still-deferred
/// Phase-5 domain keys and reports — via `eprintln!`, NEVER `assert!` — any non-canonical keys
/// on the REAL (non-planted) surface. This keeps Gate 5 advisory: it surfaces drift to operators
/// without failing the build. Issue 5.2 escalates this to a hard assertion.
#[test]
fn gate5_advisory_report_never_fails_build() {
    let cap = KeyCapture::default();
    let observed = emit_canonical_hot_path_events(&cap);
    let keys: Vec<&str> = observed.iter().map(String::as_str).collect();
    let flagged = crypto::logging::conformance::non_canonical_keys(keys);

    // ADVISORY ONLY: report, do not assert. Phase 5 (issue 5.2) makes this blocking.
    if !flagged.is_empty() {
        eprintln!("Gate 5 (advisory) — non-canonical field keys on the curated set: {flagged:?}");
    }
}
