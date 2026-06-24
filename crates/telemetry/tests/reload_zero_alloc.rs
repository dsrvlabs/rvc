//! Gate 4 (P0-6) for the issue-5.4 reload layer.
//!
//! Wrapping the reconciled `EnvFilter` in `reload::Layer` must NOT make a
//! disabled `debug!`/`trace!` allocate at the default `info` level. The reload
//! layer's `register_callsite` delegates to the inner `EnvFilter`, which reports
//! `Interest::never()` for a callsite no directive could enable; the `tracing`
//! macro then short-circuits *before* dispatch, so the reload layer's `RwLock`
//! read is never reached on the disabled hot path. This binary proves that with a
//! dependency-free counting global allocator — the same technique as the
//! per-crate `zero_alloc.rs` gates — so the always-on reload layer is shown free
//! at the default path, independent of whether the SIGHUP trigger is enabled.
//!
//! Determinism mirrors the other Gate-4 binaries: ONE `#[test]`, an `info`-only
//! subscriber (never a `trace` one), so the process-global max-level hint and
//! callsite-interest cache are not raced. Non-vacuity is proven in-test: an
//! ENABLED `info!` over the same consuming layer DOES allocate.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use rvc_telemetry::reloadable_env_filter;
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::Layer;

struct CountingAllocator;

static ALLOCS: AtomicUsize = AtomicUsize::new(0);
static COUNTING: AtomicBool = AtomicBool::new(false);

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if COUNTING.load(Ordering::Relaxed) {
            ALLOCS.fetch_add(1, Ordering::Relaxed);
        }
        System.alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if COUNTING.load(Ordering::Relaxed) {
            ALLOCS.fetch_add(1, Ordering::Relaxed);
        }
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

/// A consuming layer that formats every event it receives into a heap `String`.
/// An ENABLED event allocates here; a DISABLED one never reaches it.
struct FormatOnEvent;

impl<S: tracing::Subscriber> Layer<S> for FormatOnEvent {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        struct V(String);
        impl tracing::field::Visit for V {
            fn record_debug(&mut self, f: &tracing::field::Field, v: &dyn std::fmt::Debug) {
                self.0.push_str(&format!("{}={v:?} ", f.name()));
            }
        }
        let mut v = V(String::new());
        event.record(&mut v);
        std::hint::black_box(v.0);
    }
}

fn allocs_during<F: FnOnce()>(f: F) -> usize {
    COUNTING.store(true, Ordering::SeqCst);
    let before = ALLOCS.load(Ordering::SeqCst);
    f();
    let count = ALLOCS.load(Ordering::SeqCst) - before;
    COUNTING.store(false, Ordering::SeqCst);
    count
}

#[test]
fn disabled_debug_through_reload_layer_is_zero_alloc() {
    // Default-`info` startup path: ensure RUST_LOG doesn't raise the floor.
    // (Set inside the test process only; nextest isolates each test.)
    unsafe { std::env::remove_var("RUST_LOG") };

    // Compose exactly as the binaries do: the reload-wrapped filter is the OUTER
    // global filter over a consuming layer. Effective level is `info`.
    let (reload_layer, _handle) = reloadable_env_filter("info");
    let subscriber = tracing_subscriber::registry().with(FormatOnEvent).with(reload_layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    let replay = || {
        tracing::debug!(field = "x", "disabled debug through reload layer");
        tracing::trace!(field = "y", "disabled trace through reload layer");
    };

    // Sanity: the counting allocator is live.
    assert!(
        allocs_during(|| {
            let v = std::hint::black_box(vec![1u8, 2, 3]);
            drop(v);
        }) > 0,
        "counting allocator must observe heap allocations"
    );

    // Non-vacuity: an ENABLED info! over the same consuming layer DOES allocate.
    assert!(
        allocs_during(|| tracing::info!(field = "z", "non-vacuity probe")) > 0,
        "an ENABLED info! over the consuming layer (behind reload) must allocate"
    );

    // Warm up callsite registration (one-time, cached), then measure steady state.
    let _ = allocs_during(replay);
    let n = allocs_during(replay);
    assert_eq!(n, 0, "disabled debug!/trace! through the reload layer must not allocate (got {n})");
}
