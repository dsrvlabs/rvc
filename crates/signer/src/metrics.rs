//! Signer Prometheus families (ARCH-6h).

use std::sync::LazyLock;

use metrics::{define_histogram_vec, define_int_counter_vec, HistogramVec, IntCounterVec};

pub use metrics::definitions::{attestation_status, slashing_result, tx_hold_kind};

/// Shared attestation counter; `register_metric` de-duplicates the family.
pub static RVC_ATTESTATIONS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    define_int_counter_vec(
        "rvc_attestations_total",
        "Total number of attestation operations",
        &["status"],
    )
});

/// Histogram for signing operation latency in seconds.
pub static RVC_SIGNING_DURATION_SECONDS: LazyLock<HistogramVec> = LazyLock::new(|| {
    define_histogram_vec(
        "rvc_signing_duration_seconds",
        "Duration of signing operations in seconds",
        &[],
        &[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0],
        &[],
    )
});

/// Counter for slashing protection database checks.
/// Labels: result (safe, blocked)
pub static RVC_SLASHING_PROTECTION_CHECKS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    define_int_counter_vec(
        "rvc_slashing_protection_checks_total",
        "Total number of slashing protection checks",
        &["result"],
    )
});

/// Histogram for slashing-DB transaction hold duration in milliseconds.
///
/// Labels: `kind` — either `"attestation"` or `"block"`.
pub static RVC_SIGNER_SLASHING_TX_HOLD_DURATION_MS: LazyLock<HistogramVec> = LazyLock::new(|| {
    define_histogram_vec(
        "rvc_signer_slashing_tx_hold_duration_ms",
        "Duration (ms) that the slashing-DB transaction is held per stage→commit/discard cycle",
        &["kind"],
        &[1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0],
        &[],
    )
});

/// Reserve-transaction-only hold duration in milliseconds (ARCH-5b / X6).
///
/// Labels: `kind` — `"attestation"` or `"block"`.
pub static RVC_SLASHING_RESERVE_TX_HOLD_DURATION_MS: LazyLock<HistogramVec> = LazyLock::new(|| {
    define_histogram_vec(
        "rvc_slashing_reserve_tx_hold_duration_ms",
        "Duration (ms) of the slashing-DB reserve write transaction (mutex acquire → COMMIT)",
        &["kind"],
        &[1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0],
        &[],
    )
});

pub fn init() {
    LazyLock::force(&RVC_ATTESTATIONS_TOTAL);
    LazyLock::force(&RVC_SIGNING_DURATION_SECONDS);
    LazyLock::force(&RVC_SLASHING_PROTECTION_CHECKS_TOTAL);
    LazyLock::force(&RVC_SIGNER_SLASHING_TX_HOLD_DURATION_MS);
    LazyLock::force(&RVC_SLASHING_RESERVE_TX_HOLD_DURATION_MS);
}

#[cfg(test)]
mod tests {
    #[test]
    fn init_twice_does_not_panic() {
        super::init();
        super::init();
    }
}
