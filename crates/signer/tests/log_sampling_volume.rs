//! Issue 5.3 — log-event sampling, the **volume-bound** half.
//!
//! With the sampled site's level ENABLED, N calls produce ≈N/rate emitted events under a
//! captured subscriber — proving the 1-in-N sampler actually bounds log volume.
//!
//! Reproduces the EXACT guard shape used at the production call site in
//! `crates/signer/src/lib.rs` (the per-validator-per-slot attestation-stage trace):
//!
//!   if tracing::enabled!(tracing::Level::TRACE)
//!       && crypto::logging::should_log_sampled(&CTR, N) { tracing::trace!(...); }
//!
//! **One test per binary, by design.** Tracing's max-level hint and callsite-interest
//! cache are PROCESS-global; the disabled half lives in a SEPARATE binary
//! (`log_sampling_disabled.rs`) so a TRACE subscriber here can never poison the INFO-only
//! disabled test (the same determinism rule the Gate-4 `zero_alloc.rs` follows).

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use crypto::logging::should_log_sampled;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::Layer;

/// Counts every event that passes the subscriber's level filter.
struct CountEvents;

static EMITTED: AtomicUsize = AtomicUsize::new(0);

impl<S: tracing::Subscriber> Layer<S> for CountEvents {
    fn on_event(&self, _event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        EMITTED.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn sampled_site_emits_one_in_n_when_enabled() {
    let subscriber = tracing_subscriber::registry().with(LevelFilter::TRACE).with(CountEvents);
    let _guard = tracing::subscriber::set_default(subscriber);

    let ctr = AtomicU64::new(0);
    let n = 16u64;
    let windows = 100u64;
    let calls = n * windows;

    EMITTED.store(0, Ordering::SeqCst);
    for _ in 0..calls {
        // Identical guard shape to the production call site.
        if tracing::enabled!(tracing::Level::TRACE) && should_log_sampled(&ctr, n) {
            tracing::trace!("staging attestation slashing-protection record (sampled)");
        }
    }

    let emitted = EMITTED.load(Ordering::SeqCst) as u64;
    assert_eq!(
        emitted, windows,
        "1-in-{n} over {windows} windows must emit exactly {windows} events"
    );
    assert!(emitted < calls, "sampling must reduce volume below the raw call count ({calls})");
    // Level was enabled, so every call consulted the sampler exactly once.
    assert_eq!(
        ctr.load(Ordering::Relaxed),
        calls,
        "every enabled call advances the per-site counter"
    );
}
