// ISSUE-3.3 (M-3): circuit-breaker atomic ordering regression test
//
// NOTE: This is a best-effort runtime test for read-after-write visibility on
// the circuit-breaker atomics.
//
// On x86/x86_64, TSO (Total Store Order) provides stronger-than-specified
// ordering guarantees, so Ordering::Relaxed atomics already behave like
// Release/Acquire in practice. This means the test may also pass with the
// *unfixed* Relaxed code on x86. The semantic bug (stale reads) would manifest
// on ARM/RISC-V weak-memory-order architectures.
//
// The `Barrier` used below internally relies on `Mutex`/`Condvar`. The
// pthread_mutex_lock/unlock implementations these wrap emit a full memory
// fence (dmb ish on ARM, MFENCE-equivalent on x86) at every wait/release.
// That fence drains the writer's store buffer and makes its prior atomic
// stores visible to the reader — independently of whether a per-atomic
// release-acquire chain has been formed (the barrier mutex is a different
// object from the counters, so a strict C++/Rust memory-model release-
// acquire pair would not technically chain through it; the fence is what
// actually saves us).
//
// In addition, switching the counter atomics to `AcqRel`/`Acquire`/`Release`
// (rather than `Relaxed`) is what enforces visibility on ARM in the absence
// of the barrier — i.e. in real production use where there is no rendezvous.
// The barrier here is a test scaffolding device; the ordering upgrade is the
// production fix.
//
// A `loom`-based test would provide exhaustive model-checked verification;
// `loom` is not currently a workspace dev-dep (see Cargo.toml).

use rvc_builder::CircuitBreakerState;
use std::sync::{Arc, Barrier};
use std::thread;

/// Thread A calls `record_miss()` until the breaker would trip, then signals
/// via a `Barrier`. Thread B (main) waits on the barrier and then reads
/// `is_tripped()`.
///
/// With `AcqRel` on `fetch_add` and `Acquire` on the load inside
/// `is_tripped()`, the Release in the writer and the Acquire in the reader form
/// a happens-before edge that guarantees visibility of the write on all
/// platforms.
#[test]
fn test_read_after_write_visibility() {
    // consecutive_limit=1 so a single miss trips the breaker.
    let cb = Arc::new(CircuitBreakerState::new(1, 0));
    let barrier = Arc::new(Barrier::new(2));

    let cb_writer = Arc::clone(&cb);
    let barrier_writer = Arc::clone(&barrier);

    let writer = thread::spawn(move || {
        // AcqRel fetch_add: establishes a Release edge visible to
        // any subsequent Acquire load on the same atomic.
        cb_writer.record_miss();
        // Signal the reader that the write is complete.
        barrier_writer.wait();
    });

    // Block until the writer has finished record_miss().
    barrier.wait();

    // Acquire load inside is_tripped() must observe the AcqRel store from
    // the writer thread. On a correct implementation this assertion is
    // guaranteed by the memory model on all architectures.
    assert!(cb.is_tripped(), "is_tripped() must observe the miss recorded by the writer thread");

    writer.join().unwrap();
}

/// Verify that after `record_miss()` calls from one thread, a second thread
/// reading `consecutive_misses()` via the Acquire getter sees the final count.
#[test]
fn test_consecutive_misses_visible_across_threads() {
    const MISS_COUNT: u32 = 5;
    let cb = Arc::new(CircuitBreakerState::new(100, 100)); // high limits, won't trip
    let barrier = Arc::new(Barrier::new(2));

    let cb_w = Arc::clone(&cb);
    let bar_w = Arc::clone(&barrier);

    let writer = thread::spawn(move || {
        for _ in 0..MISS_COUNT {
            cb_w.record_miss();
        }
        bar_w.wait();
    });

    barrier.wait();

    // Both consecutive and epoch counters must be visible.
    assert_eq!(
        cb.consecutive_misses(),
        MISS_COUNT,
        "consecutive_misses() must be visible after writer signals via barrier"
    );
    assert_eq!(
        cb.epoch_misses(),
        MISS_COUNT,
        "epoch_misses() must be visible after writer signals via barrier"
    );

    writer.join().unwrap();
}

/// Verify that `reset_epoch()` zeroing of both counters is visible to a reader
/// that synchronises via a Barrier after the reset.
#[test]
fn test_reset_epoch_zeroes_visible_across_threads() {
    let cb = Arc::new(CircuitBreakerState::new(3, 5));

    // Fill counters in the current thread (no ordering concern yet).
    cb.record_miss();
    cb.record_miss();
    assert_eq!(cb.consecutive_misses(), 2);

    let barrier = Arc::new(Barrier::new(2));

    let cb_w = Arc::clone(&cb);
    let bar_w = Arc::clone(&barrier);

    let resetter = thread::spawn(move || {
        cb_w.reset_epoch(1); // AcqRel swap + Release stores
        bar_w.wait();
    });

    barrier.wait();

    // Reader must see zeroed counters (Release from resetter, Acquire from reader).
    assert_eq!(
        cb.consecutive_misses(),
        0,
        "consecutive_misses must be 0 after reset_epoch visible via barrier"
    );
    assert_eq!(
        cb.epoch_misses(),
        0,
        "epoch_misses must be 0 after reset_epoch visible via barrier"
    );
    assert!(!cb.is_tripped(), "breaker must not be tripped after epoch reset");

    resetter.join().unwrap();
}

/// Verify that `record_success()` resetting the consecutive counter is visible
/// to a reader that synchronises via a Barrier.
#[test]
fn test_record_success_visible_across_threads() {
    let cb = Arc::new(CircuitBreakerState::new(3, 10));

    // Pre-fill consecutive counter.
    cb.record_miss();
    cb.record_miss();
    assert_eq!(cb.consecutive_misses(), 2);

    let barrier = Arc::new(Barrier::new(2));

    let cb_w = Arc::clone(&cb);
    let bar_w = Arc::clone(&barrier);

    let succeeder = thread::spawn(move || {
        cb_w.record_success(); // Release store
        bar_w.wait();
    });

    barrier.wait();

    assert_eq!(
        cb.consecutive_misses(),
        0,
        "record_success() must be visible: consecutive_misses should be 0"
    );
    // epoch_misses unaffected by record_success.
    assert_eq!(cb.epoch_misses(), 2, "epoch_misses should not be reset by record_success");

    succeeder.join().unwrap();
}
