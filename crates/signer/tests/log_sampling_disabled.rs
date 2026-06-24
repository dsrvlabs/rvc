//! Issue 5.3 — log-event sampling, the **zero-cost-when-disabled** half.
//!
//! With the sampled site's level DISABLED (subscriber max level `info`, TRACE off), the
//! `tracing::enabled!` guard short-circuits (Rust `&&`), so `should_log_sampled` is NEVER
//! called and the per-site `AtomicU64` counter is unchanged after the calls. This proves
//! the guard ORDERING: a disabled hot site does no sampling work and pays nothing — the
//! same R1 / Gate-4 invariant `zero_alloc.rs` guards via the allocator, here observed
//! directly on the counter.
//!
//! **One test, info-only, in its own binary.** Tracing's max-level hint and
//! callsite-interest cache are PROCESS-global; keeping the disabled scenario alone here
//! (never a TRACE subscriber in this binary) makes the `enabled!` short-circuit
//! deterministic under `cargo test`, `--test-threads=N`, and `nextest`.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use crypto::logging::should_log_sampled;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::Layer;

struct CountEvents;

static EMITTED: AtomicUsize = AtomicUsize::new(0);

impl<S: tracing::Subscriber> Layer<S> for CountEvents {
    fn on_event(&self, _event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        EMITTED.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn disabled_site_never_consults_sampler() {
    // TRACE off: the only dispatcher this binary ever installs is info-level.
    let subscriber = tracing_subscriber::registry().with(LevelFilter::INFO).with(CountEvents);
    let _guard = tracing::subscriber::set_default(subscriber);

    let ctr = AtomicU64::new(0);

    EMITTED.store(0, Ordering::SeqCst);
    for _ in 0..10_000u64 {
        // Identical guard shape to the production call site.
        if tracing::enabled!(tracing::Level::TRACE) && should_log_sampled(&ctr, 16) {
            tracing::trace!("staging attestation slashing-protection record (sampled)");
        }
    }

    assert_eq!(
        ctr.load(Ordering::Relaxed),
        0,
        "a DISABLED trace site must NOT consult the sampler (counter must stay 0)"
    );
    assert_eq!(EMITTED.load(Ordering::SeqCst), 0, "no events emitted while TRACE is disabled");
}
