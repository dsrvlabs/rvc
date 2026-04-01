//! Core metric definitions for the validator client.
//!
//! This module defines the standard metrics collected by the validator client
//! for monitoring attestations, duties, signing operations, beacon node requests,
//! and slashing protection.

use lazy_static::lazy_static;
use prometheus::{Gauge, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, Opts};

use crate::REGISTRY;

lazy_static! {
    /// Counter for attestation operations.
    /// Labels: status (success, failed, skipped)
    pub static ref RVC_ATTESTATIONS_TOTAL: IntCounterVec = {
        let opts = Opts::new(
            "rvc_attestations_total",
            "Total number of attestation operations"
        );
        let counter = IntCounterVec::new(opts, &["status"])
            .expect("Failed to create rvc_attestations_total metric");
        REGISTRY.register(Box::new(counter.clone()))
            .expect("Failed to register rvc_attestations_total metric");
        counter
    };

    /// Counter for duty fetch operations.
    pub static ref RVC_DUTIES_FETCHED_TOTAL: IntCounterVec = {
        let opts = Opts::new(
            "rvc_duties_fetched_total",
            "Total number of duty fetch operations"
        );
        let counter = IntCounterVec::new(opts, &[])
            .expect("Failed to create rvc_duties_fetched_total metric");
        REGISTRY.register(Box::new(counter.clone()))
            .expect("Failed to register rvc_duties_fetched_total metric");
        counter
    };

    /// Histogram for signing operation latency in seconds.
    pub static ref RVC_SIGNING_DURATION_SECONDS: HistogramVec = {
        let opts = HistogramOpts::new(
            "rvc_signing_duration_seconds",
            "Duration of signing operations in seconds"
        ).buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]);
        let histogram = HistogramVec::new(opts, &[])
            .expect("Failed to create rvc_signing_duration_seconds metric");
        REGISTRY.register(Box::new(histogram.clone()))
            .expect("Failed to register rvc_signing_duration_seconds metric");
        histogram
    };

    /// Counter for slashing protection database checks.
    /// Labels: result (safe, blocked)
    pub static ref RVC_SLASHING_PROTECTION_CHECKS_TOTAL: IntCounterVec = {
        let opts = Opts::new(
            "rvc_slashing_protection_checks_total",
            "Total number of slashing protection checks"
        );
        let counter = IntCounterVec::new(opts, &["result"])
            .expect("Failed to create rvc_slashing_protection_checks_total metric");
        REGISTRY.register(Box::new(counter.clone()))
            .expect("Failed to register rvc_slashing_protection_checks_total metric");
        counter
    };

    /// Counter for slots processed by the orchestrator.
    pub static ref RVC_ORCHESTRATOR_SLOTS_PROCESSED_TOTAL: IntCounterVec = {
        let opts = Opts::new(
            "rvc_orchestrator_slots_processed_total",
            "Total number of slots processed by the orchestrator"
        );
        let counter = IntCounterVec::new(opts, &["result"])
            .expect("Failed to create rvc_orchestrator_slots_processed_total metric");
        REGISTRY.register(Box::new(counter.clone()))
            .expect("Failed to register rvc_orchestrator_slots_processed_total metric");
        counter
    };

    /// Counter for missed slots.
    pub static ref RVC_ORCHESTRATOR_MISSED_SLOTS_TOTAL: IntCounterVec = {
        let opts = Opts::new(
            "rvc_orchestrator_missed_slots_total",
            "Total number of missed attestation slots"
        );
        let counter = IntCounterVec::new(opts, &[])
            .expect("Failed to create rvc_orchestrator_missed_slots_total metric");
        REGISTRY.register(Box::new(counter.clone()))
            .expect("Failed to register rvc_orchestrator_missed_slots_total metric");
        counter
    };

    /// Gauge for currently active attestation tasks.
    pub static ref RVC_ORCHESTRATOR_ACTIVE_ATTESTATIONS: Gauge = {
        let opts = Opts::new(
            "rvc_orchestrator_active_attestations",
            "Number of currently active attestation tasks"
        );
        let gauge = Gauge::with_opts(opts)
            .expect("Failed to create rvc_orchestrator_active_attestations metric");
        REGISTRY.register(Box::new(gauge.clone()))
            .expect("Failed to register rvc_orchestrator_active_attestations metric");
        gauge
    };

    /// Counter for aggregation operations.
    /// Labels: status (success, failed, skipped)
    pub static ref RVC_AGGREGATIONS_TOTAL: IntCounterVec = {
        let opts = Opts::new(
            "rvc_aggregations_total",
            "Total number of attestation aggregation operations"
        );
        let counter = IntCounterVec::new(opts, &["status"])
            .expect("Failed to create rvc_aggregations_total metric");
        REGISTRY.register(Box::new(counter.clone()))
            .expect("Failed to register rvc_aggregations_total metric");
        counter
    };

    /// Histogram for slot processing duration in seconds.
    pub static ref RVC_ORCHESTRATOR_SLOT_PROCESSING_DURATION_SECONDS: HistogramVec = {
        let opts = HistogramOpts::new(
            "rvc_orchestrator_slot_processing_duration_seconds",
            "Duration of slot processing operations in seconds"
        ).buckets(vec![0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 4.0, 8.0, 12.0]);
        let histogram = HistogramVec::new(opts, &[])
            .expect("Failed to create rvc_orchestrator_slot_processing_duration_seconds metric");
        REGISTRY.register(Box::new(histogram.clone()))
            .expect("Failed to register rvc_orchestrator_slot_processing_duration_seconds metric");
        histogram
    };

    /// Counter for slashing DB prune operations.
    /// Labels: type (attestation, block)
    pub static ref RVC_SLASHING_DB_PRUNE_TOTAL: IntCounterVec = {
        let opts = Opts::new(
            "rvc_slashing_db_prune_total",
            "Total number of slashing DB records pruned"
        );
        let counter = IntCounterVec::new(opts, &["type"])
            .expect("Failed to create rvc_slashing_db_prune_total metric");
        REGISTRY.register(Box::new(counter.clone()))
            .expect("Failed to register rvc_slashing_db_prune_total metric");
        counter
    };

    /// Counter for duty reorg detections.
    /// Labels: duty_type (attester, proposer)
    pub static ref RVC_DUTY_REORG_DETECTED_TOTAL: IntCounterVec = {
        let opts = Opts::new(
            "rvc_duty_reorg_detected_total",
            "Total number of duty reorg detections"
        );
        let counter = IntCounterVec::new(opts, &["duty_type"])
            .expect("Failed to create rvc_duty_reorg_detected_total metric");
        REGISTRY.register(Box::new(counter.clone()))
            .expect("Failed to register rvc_duty_reorg_detected_total metric");
        counter
    };

    /// Gauge for attestation enabled state (1=enabled, 0=disabled).
    pub static ref RVC_ATTESTING_ENABLED: Gauge = {
        let opts = Opts::new(
            "rvc_attesting_enabled",
            "Whether attestation duties are enabled (1=enabled, 0=disabled)"
        );
        let gauge = Gauge::with_opts(opts)
            .expect("Failed to create rvc_attesting_enabled metric");
        REGISTRY.register(Box::new(gauge.clone()))
            .expect("Failed to register rvc_attesting_enabled metric");
        gauge
    };

    /// Counter for slashed validators detected.
    pub static ref RVC_VALIDATORS_SLASHED_TOTAL: IntCounter = {
        let opts = Opts::new(
            "rvc_validators_slashed_total",
            "Total number of slashed validators detected"
        );
        let counter = IntCounter::with_opts(opts)
            .expect("Failed to create rvc_validators_slashed_total metric");
        REGISTRY.register(Box::new(counter.clone()))
            .expect("Failed to register rvc_validators_slashed_total metric");
        counter
    };

}

/// Initializes all core metrics by accessing the lazy_static variables.
/// This ensures metrics are registered with the global registry.
pub fn init_metrics() {
    lazy_static::initialize(&RVC_ATTESTATIONS_TOTAL);
    lazy_static::initialize(&RVC_DUTIES_FETCHED_TOTAL);
    lazy_static::initialize(&RVC_SIGNING_DURATION_SECONDS);
    lazy_static::initialize(&RVC_SLASHING_PROTECTION_CHECKS_TOTAL);
    lazy_static::initialize(&RVC_AGGREGATIONS_TOTAL);
    lazy_static::initialize(&RVC_ORCHESTRATOR_SLOTS_PROCESSED_TOTAL);
    lazy_static::initialize(&RVC_ORCHESTRATOR_MISSED_SLOTS_TOTAL);
    lazy_static::initialize(&RVC_ORCHESTRATOR_ACTIVE_ATTESTATIONS);
    lazy_static::initialize(&RVC_ORCHESTRATOR_SLOT_PROCESSING_DURATION_SECONDS);
    lazy_static::initialize(&RVC_SLASHING_DB_PRUNE_TOTAL);
    lazy_static::initialize(&RVC_DUTY_REORG_DETECTED_TOTAL);
    lazy_static::initialize(&RVC_ATTESTING_ENABLED);
    lazy_static::initialize(&RVC_VALIDATORS_SLASHED_TOTAL);
}

/// Attestation status label values.
pub mod attestation_status {
    pub const SUCCESS: &str = "success";
    pub const FAILED: &str = "failed";
    pub const SKIPPED: &str = "skipped";
}

/// Slashing protection result label values.
pub mod slashing_result {
    pub const SAFE: &str = "safe";
    pub const BLOCKED: &str = "blocked";
}

/// Orchestrator slot processing result label values.
pub mod orchestrator_result {
    pub const SUCCESS: &str = "success";
    pub const FAILED: &str = "failed";
    pub const NO_DUTIES: &str = "no_duties";
}

/// Slashing DB prune type label values.
pub mod prune_type {
    pub const ATTESTATION: &str = "attestation";
    pub const BLOCK: &str = "block";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attestations_total_increments() {
        RVC_ATTESTATIONS_TOTAL.with_label_values(&[attestation_status::SUCCESS]).inc();
        let value = RVC_ATTESTATIONS_TOTAL.with_label_values(&[attestation_status::SUCCESS]).get();
        assert!(value >= 1, "Counter should be at least 1 after increment");

        RVC_ATTESTATIONS_TOTAL.with_label_values(&[attestation_status::FAILED]).inc();
        let failed_value =
            RVC_ATTESTATIONS_TOTAL.with_label_values(&[attestation_status::FAILED]).get();
        assert!(failed_value >= 1, "Failed counter should be at least 1 after increment");

        RVC_ATTESTATIONS_TOTAL.with_label_values(&[attestation_status::SKIPPED]).inc();
        let skipped_value =
            RVC_ATTESTATIONS_TOTAL.with_label_values(&[attestation_status::SKIPPED]).get();
        assert!(skipped_value >= 1, "Skipped counter should be at least 1 after increment");
    }

    #[test]
    fn test_duties_fetched_total_increments() {
        RVC_DUTIES_FETCHED_TOTAL.with_label_values(&[] as &[&str]).inc();
        let value = RVC_DUTIES_FETCHED_TOTAL.with_label_values(&[] as &[&str]).get();
        assert!(value >= 1, "Counter should be at least 1 after increment");
    }

    #[test]
    fn test_signing_duration_observes() {
        RVC_SIGNING_DURATION_SECONDS.with_label_values(&[] as &[&str]).observe(0.05);
        let count =
            RVC_SIGNING_DURATION_SECONDS.with_label_values(&[] as &[&str]).get_sample_count();
        assert!(count >= 1, "Histogram should have at least 1 observation");
    }

    #[test]
    fn test_slashing_protection_checks_total_increments() {
        RVC_SLASHING_PROTECTION_CHECKS_TOTAL.with_label_values(&[slashing_result::SAFE]).inc();
        let safe_value =
            RVC_SLASHING_PROTECTION_CHECKS_TOTAL.with_label_values(&[slashing_result::SAFE]).get();
        assert!(safe_value >= 1, "Safe counter should be at least 1 after increment");

        RVC_SLASHING_PROTECTION_CHECKS_TOTAL.with_label_values(&[slashing_result::BLOCKED]).inc();
        let blocked_value = RVC_SLASHING_PROTECTION_CHECKS_TOTAL
            .with_label_values(&[slashing_result::BLOCKED])
            .get();
        assert!(blocked_value >= 1, "Blocked counter should be at least 1 after increment");
    }

    #[test]
    fn test_duty_reorg_detected_total_increments() {
        RVC_DUTY_REORG_DETECTED_TOTAL.with_label_values(&["attester"]).inc();
        let attester_value = RVC_DUTY_REORG_DETECTED_TOTAL.with_label_values(&["attester"]).get();
        assert!(attester_value >= 1, "Attester reorg counter should be at least 1");

        RVC_DUTY_REORG_DETECTED_TOTAL.with_label_values(&["proposer"]).inc();
        let proposer_value = RVC_DUTY_REORG_DETECTED_TOTAL.with_label_values(&["proposer"]).get();
        assert!(proposer_value >= 1, "Proposer reorg counter should be at least 1");
    }

    #[test]
    fn test_init_metrics_registers_all() {
        init_metrics();

        RVC_ATTESTATIONS_TOTAL.with_label_values(&[attestation_status::SUCCESS]).inc();
        RVC_DUTIES_FETCHED_TOTAL.with_label_values(&[] as &[&str]).inc();
        RVC_SIGNING_DURATION_SECONDS.with_label_values(&[] as &[&str]).observe(0.001);
        RVC_SLASHING_PROTECTION_CHECKS_TOTAL.with_label_values(&[slashing_result::SAFE]).inc();

        let metrics = REGISTRY.gather();
        let metric_names: Vec<&str> = metrics.iter().map(|m| m.name()).collect();

        assert!(
            metric_names.contains(&"rvc_attestations_total"),
            "rvc_attestations_total should be registered"
        );
        assert!(
            metric_names.contains(&"rvc_duties_fetched_total"),
            "rvc_duties_fetched_total should be registered"
        );
        assert!(
            metric_names.contains(&"rvc_signing_duration_seconds"),
            "rvc_signing_duration_seconds should be registered"
        );
        assert!(
            metric_names.contains(&"rvc_slashing_protection_checks_total"),
            "rvc_slashing_protection_checks_total should be registered"
        );
    }

    #[test]
    fn test_circuit_breaker_trips_total_increments() {
        RVC_BUILDER_CIRCUIT_BREAKER_TRIPS_TOTAL.inc();
        let value = RVC_BUILDER_CIRCUIT_BREAKER_TRIPS_TOTAL.get();
        assert!(value >= 1, "Circuit breaker trips counter should be at least 1 after increment");
    }

    #[test]
    fn test_builder_consecutive_misses_gauge() {
        RVC_BUILDER_CONSECUTIVE_MISSES.set(3);
        assert_eq!(RVC_BUILDER_CONSECUTIVE_MISSES.get(), 3);
        RVC_BUILDER_CONSECUTIVE_MISSES.set(0);
        assert_eq!(RVC_BUILDER_CONSECUTIVE_MISSES.get(), 0);
    }

    #[test]
    fn test_builder_epoch_misses_gauge() {
        RVC_BUILDER_EPOCH_MISSES.set(5);
        assert_eq!(RVC_BUILDER_EPOCH_MISSES.get(), 5);
        RVC_BUILDER_EPOCH_MISSES.set(0);
        assert_eq!(RVC_BUILDER_EPOCH_MISSES.get(), 0);
    }
}
