//! Core metric definitions for the validator client.
//!
//! This module defines the standard metrics collected by the validator client
//! for monitoring attestations, duties, signing operations, beacon node requests,
//! and slashing protection.

use lazy_static::lazy_static;
use prometheus::{Gauge, HistogramOpts, HistogramVec, IntCounterVec, Opts};

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

    /// Counter for duty cache operations.
    /// Labels: operation (hit, miss, invalidation)
    pub static ref RVC_DUTY_CACHE_OPERATIONS_TOTAL: IntCounterVec = {
        let opts = Opts::new(
            "rvc_duty_cache_operations_total",
            "Total number of duty cache operations"
        );
        let counter = IntCounterVec::new(opts, &["operation"])
            .expect("Failed to create rvc_duty_cache_operations_total metric");
        REGISTRY.register(Box::new(counter.clone()))
            .expect("Failed to register rvc_duty_cache_operations_total metric");
        counter
    };

    /// Counter for dependent root changes.
    pub static ref RVC_DEPENDENT_ROOT_CHANGES_TOTAL: IntCounterVec = {
        let opts = Opts::new(
            "rvc_dependent_root_changes_total",
            "Total number of dependent root changes detected"
        );
        let counter = IntCounterVec::new(opts, &[])
            .expect("Failed to create rvc_dependent_root_changes_total metric");
        REGISTRY.register(Box::new(counter.clone()))
            .expect("Failed to register rvc_dependent_root_changes_total metric");
        counter
    };

    /// Histogram for duty fetch latency in seconds.
    pub static ref RVC_DUTY_FETCH_DURATION_SECONDS: HistogramVec = {
        let opts = HistogramOpts::new(
            "rvc_duty_fetch_duration_seconds",
            "Duration of duty fetch operations in seconds"
        ).buckets(vec![0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]);
        let histogram = HistogramVec::new(opts, &[])
            .expect("Failed to create rvc_duty_fetch_duration_seconds metric");
        REGISTRY.register(Box::new(histogram.clone()))
            .expect("Failed to register rvc_duty_fetch_duration_seconds metric");
        histogram
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

    /// Counter for beacon node HTTP requests.
    /// Labels: endpoint, status
    pub static ref RVC_BEACON_REQUESTS_TOTAL: IntCounterVec = {
        let opts = Opts::new(
            "rvc_beacon_requests_total",
            "Total number of beacon node HTTP requests"
        );
        let counter = IntCounterVec::new(opts, &["endpoint", "status"])
            .expect("Failed to create rvc_beacon_requests_total metric");
        REGISTRY.register(Box::new(counter.clone()))
            .expect("Failed to register rvc_beacon_requests_total metric");
        counter
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
}

/// Initializes all core metrics by accessing the lazy_static variables.
/// This ensures metrics are registered with the global registry.
pub fn init_metrics() {
    lazy_static::initialize(&RVC_ATTESTATIONS_TOTAL);
    lazy_static::initialize(&RVC_DUTIES_FETCHED_TOTAL);
    lazy_static::initialize(&RVC_DUTY_CACHE_OPERATIONS_TOTAL);
    lazy_static::initialize(&RVC_DEPENDENT_ROOT_CHANGES_TOTAL);
    lazy_static::initialize(&RVC_DUTY_FETCH_DURATION_SECONDS);
    lazy_static::initialize(&RVC_SIGNING_DURATION_SECONDS);
    lazy_static::initialize(&RVC_BEACON_REQUESTS_TOTAL);
    lazy_static::initialize(&RVC_SLASHING_PROTECTION_CHECKS_TOTAL);
    lazy_static::initialize(&RVC_AGGREGATIONS_TOTAL);
    lazy_static::initialize(&RVC_ORCHESTRATOR_SLOTS_PROCESSED_TOTAL);
    lazy_static::initialize(&RVC_ORCHESTRATOR_MISSED_SLOTS_TOTAL);
    lazy_static::initialize(&RVC_ORCHESTRATOR_ACTIVE_ATTESTATIONS);
    lazy_static::initialize(&RVC_ORCHESTRATOR_SLOT_PROCESSING_DURATION_SECONDS);
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

/// HTTP request status label values.
pub mod request_status {
    pub const SUCCESS: &str = "success";
    pub const FAILED: &str = "failed";
}

/// Duty cache operation label values.
pub mod cache_operation {
    pub const HIT: &str = "hit";
    pub const MISS: &str = "miss";
    pub const INVALIDATION: &str = "invalidation";
}

/// Orchestrator slot processing result label values.
pub mod orchestrator_result {
    pub const SUCCESS: &str = "success";
    pub const FAILED: &str = "failed";
    pub const NO_DUTIES: &str = "no_duties";
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
        RVC_DUTIES_FETCHED_TOTAL.with_label_values(&[]).inc();
        let value = RVC_DUTIES_FETCHED_TOTAL.with_label_values(&[]).get();
        assert!(value >= 1, "Counter should be at least 1 after increment");
    }

    #[test]
    fn test_signing_duration_observes() {
        RVC_SIGNING_DURATION_SECONDS.with_label_values(&[]).observe(0.05);
        let count = RVC_SIGNING_DURATION_SECONDS.with_label_values(&[]).get_sample_count();
        assert!(count >= 1, "Histogram should have at least 1 observation");
    }

    #[test]
    fn test_beacon_requests_total_increments() {
        RVC_BEACON_REQUESTS_TOTAL
            .with_label_values(&["/eth/v1/beacon/states/head", request_status::SUCCESS])
            .inc();
        let value = RVC_BEACON_REQUESTS_TOTAL
            .with_label_values(&["/eth/v1/beacon/states/head", request_status::SUCCESS])
            .get();
        assert!(value >= 1, "Counter should be at least 1 after increment");

        RVC_BEACON_REQUESTS_TOTAL
            .with_label_values(&["/eth/v1/validator/duties", request_status::FAILED])
            .inc();
        let failed_value = RVC_BEACON_REQUESTS_TOTAL
            .with_label_values(&["/eth/v1/validator/duties", request_status::FAILED])
            .get();
        assert!(failed_value >= 1, "Failed counter should be at least 1 after increment");
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
    fn test_duty_cache_operations_total_increments() {
        RVC_DUTY_CACHE_OPERATIONS_TOTAL.with_label_values(&[cache_operation::HIT]).inc();
        let hit_value =
            RVC_DUTY_CACHE_OPERATIONS_TOTAL.with_label_values(&[cache_operation::HIT]).get();
        assert!(hit_value >= 1, "Hit counter should be at least 1 after increment");

        RVC_DUTY_CACHE_OPERATIONS_TOTAL.with_label_values(&[cache_operation::MISS]).inc();
        let miss_value =
            RVC_DUTY_CACHE_OPERATIONS_TOTAL.with_label_values(&[cache_operation::MISS]).get();
        assert!(miss_value >= 1, "Miss counter should be at least 1 after increment");

        RVC_DUTY_CACHE_OPERATIONS_TOTAL.with_label_values(&[cache_operation::INVALIDATION]).inc();
        let invalidation_value = RVC_DUTY_CACHE_OPERATIONS_TOTAL
            .with_label_values(&[cache_operation::INVALIDATION])
            .get();
        assert!(
            invalidation_value >= 1,
            "Invalidation counter should be at least 1 after increment"
        );
    }

    #[test]
    fn test_dependent_root_changes_total_increments() {
        RVC_DEPENDENT_ROOT_CHANGES_TOTAL.with_label_values(&[]).inc();
        let value = RVC_DEPENDENT_ROOT_CHANGES_TOTAL.with_label_values(&[]).get();
        assert!(value >= 1, "Counter should be at least 1 after increment");
    }

    #[test]
    fn test_duty_fetch_duration_observes() {
        RVC_DUTY_FETCH_DURATION_SECONDS.with_label_values(&[]).observe(0.1);
        let count = RVC_DUTY_FETCH_DURATION_SECONDS.with_label_values(&[]).get_sample_count();
        assert!(count >= 1, "Histogram should have at least 1 observation");
    }

    #[test]
    fn test_init_metrics_registers_all() {
        init_metrics();

        RVC_ATTESTATIONS_TOTAL.with_label_values(&[attestation_status::SUCCESS]).inc();
        RVC_DUTIES_FETCHED_TOTAL.with_label_values(&[]).inc();
        RVC_DUTY_CACHE_OPERATIONS_TOTAL.with_label_values(&[cache_operation::HIT]).inc();
        RVC_DEPENDENT_ROOT_CHANGES_TOTAL.with_label_values(&[]).inc();
        RVC_DUTY_FETCH_DURATION_SECONDS.with_label_values(&[]).observe(0.001);
        RVC_SIGNING_DURATION_SECONDS.with_label_values(&[]).observe(0.001);
        RVC_BEACON_REQUESTS_TOTAL.with_label_values(&["/test", request_status::SUCCESS]).inc();
        RVC_SLASHING_PROTECTION_CHECKS_TOTAL.with_label_values(&[slashing_result::SAFE]).inc();

        let metrics = REGISTRY.gather();
        let metric_names: Vec<&str> = metrics.iter().map(|m| m.get_name()).collect();

        assert!(
            metric_names.contains(&"rvc_attestations_total"),
            "rvc_attestations_total should be registered"
        );
        assert!(
            metric_names.contains(&"rvc_duties_fetched_total"),
            "rvc_duties_fetched_total should be registered"
        );
        assert!(
            metric_names.contains(&"rvc_duty_cache_operations_total"),
            "rvc_duty_cache_operations_total should be registered"
        );
        assert!(
            metric_names.contains(&"rvc_dependent_root_changes_total"),
            "rvc_dependent_root_changes_total should be registered"
        );
        assert!(
            metric_names.contains(&"rvc_duty_fetch_duration_seconds"),
            "rvc_duty_fetch_duration_seconds should be registered"
        );
        assert!(
            metric_names.contains(&"rvc_signing_duration_seconds"),
            "rvc_signing_duration_seconds should be registered"
        );
        assert!(
            metric_names.contains(&"rvc_beacon_requests_total"),
            "rvc_beacon_requests_total should be registered"
        );
        assert!(
            metric_names.contains(&"rvc_slashing_protection_checks_total"),
            "rvc_slashing_protection_checks_total should be registered"
        );
    }
}
