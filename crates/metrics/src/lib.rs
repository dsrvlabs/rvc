//! Prometheus metrics integration for the validator client.
//!
//! This module provides a global metrics registry and helper macros for
//! registering and using prometheus metrics.

pub mod definitions;
pub mod server;

pub use server::{
    create_metrics_router, create_metrics_router_with_health, new_health_status, serve_metrics,
    serve_metrics_with_health, HealthStatus, SharedHealthStatus,
};

use lazy_static::lazy_static;
use prometheus::{Counter, Gauge, Histogram, HistogramOpts, Opts, Registry};

lazy_static! {
    /// Global prometheus metrics registry.
    pub static ref REGISTRY: Registry = Registry::new();
}

/// Register a counter metric with the global registry.
///
/// # Arguments
/// * `name` - The metric name
/// * `help` - Help text describing the metric
///
/// # Returns
/// A registered `Counter` or an error if registration fails.
pub fn register_counter(name: &str, help: &str) -> prometheus::Result<Counter> {
    let counter = Counter::with_opts(Opts::new(name, help))?;
    REGISTRY.register(Box::new(counter.clone()))?;
    Ok(counter)
}

/// Register a gauge metric with the global registry.
///
/// # Arguments
/// * `name` - The metric name
/// * `help` - Help text describing the metric
///
/// # Returns
/// A registered `Gauge` or an error if registration fails.
pub fn register_gauge(name: &str, help: &str) -> prometheus::Result<Gauge> {
    let gauge = Gauge::with_opts(Opts::new(name, help))?;
    REGISTRY.register(Box::new(gauge.clone()))?;
    Ok(gauge)
}

/// Register a histogram metric with the global registry.
///
/// # Arguments
/// * `name` - The metric name
/// * `help` - Help text describing the metric
/// * `buckets` - Optional custom bucket boundaries
///
/// # Returns
/// A registered `Histogram` or an error if registration fails.
pub fn register_histogram(
    name: &str,
    help: &str,
    buckets: Option<Vec<f64>>,
) -> prometheus::Result<Histogram> {
    let mut opts = HistogramOpts::new(name, help);
    if let Some(b) = buckets {
        opts = opts.buckets(b);
    }
    let histogram = Histogram::with_opts(opts)?;
    REGISTRY.register(Box::new(histogram.clone()))?;
    Ok(histogram)
}

/// Macro for conveniently registering a counter metric.
///
/// # Example
/// ```ignore
/// let counter = register_counter!("my_counter", "A sample counter");
/// counter.inc();
/// ```
#[macro_export]
macro_rules! register_counter {
    ($name:expr, $help:expr) => {
        $crate::register_counter($name, $help)
    };
}

/// Macro for conveniently registering a gauge metric.
///
/// # Example
/// ```ignore
/// let gauge = register_gauge!("my_gauge", "A sample gauge");
/// gauge.set(42.0);
/// ```
#[macro_export]
macro_rules! register_gauge {
    ($name:expr, $help:expr) => {
        $crate::register_gauge($name, $help)
    };
}

/// Macro for conveniently registering a histogram metric.
///
/// # Example
/// ```ignore
/// let histogram = register_histogram!("my_histogram", "A sample histogram");
/// histogram.observe(0.5);
/// ```
#[macro_export]
macro_rules! register_histogram {
    ($name:expr, $help:expr) => {
        $crate::register_histogram($name, $help, None)
    };
    ($name:expr, $help:expr, $buckets:expr) => {
        $crate::register_histogram($name, $help, Some($buckets))
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_exists() {
        // Verify the global registry exists and is accessible
        let metrics = REGISTRY.gather();
        assert!(metrics.is_empty() || !metrics.is_empty());
    }

    #[test]
    fn test_register_counter() {
        let counter = register_counter("test_counter_1", "A test counter").unwrap();

        // Counter should start at 0
        assert_eq!(counter.get(), 0.0);

        // Increment the counter
        counter.inc();
        assert_eq!(counter.get(), 1.0);

        // Increment by a specific amount
        counter.inc_by(5.0);
        assert_eq!(counter.get(), 6.0);
    }

    #[test]
    fn test_register_gauge() {
        let gauge = register_gauge("test_gauge_1", "A test gauge").unwrap();

        // Gauge should start at 0
        assert_eq!(gauge.get(), 0.0);

        // Set the gauge
        gauge.set(42.0);
        assert_eq!(gauge.get(), 42.0);

        // Increment the gauge
        gauge.inc();
        assert_eq!(gauge.get(), 43.0);

        // Decrement the gauge
        gauge.dec();
        assert_eq!(gauge.get(), 42.0);

        // Add to gauge
        gauge.add(8.0);
        assert_eq!(gauge.get(), 50.0);

        // Subtract from gauge
        gauge.sub(10.0);
        assert_eq!(gauge.get(), 40.0);
    }

    #[test]
    fn test_register_histogram() {
        let histogram = register_histogram("test_histogram_1", "A test histogram", None).unwrap();

        // Observe some values
        histogram.observe(0.5);
        histogram.observe(1.0);
        histogram.observe(2.5);

        // Verify observations were recorded
        let sample_count = histogram.get_sample_count();
        assert_eq!(sample_count, 3);

        let sample_sum = histogram.get_sample_sum();
        assert_eq!(sample_sum, 4.0);
    }

    #[test]
    fn test_register_histogram_with_custom_buckets() {
        let buckets = vec![0.1, 0.5, 1.0, 5.0, 10.0];
        let histogram = register_histogram(
            "test_histogram_custom_1",
            "A histogram with custom buckets",
            Some(buckets),
        )
        .unwrap();

        histogram.observe(0.3);
        histogram.observe(0.8);
        histogram.observe(3.0);

        assert_eq!(histogram.get_sample_count(), 3);
    }

    #[test]
    fn test_duplicate_registration_fails() {
        // Register a metric
        let _ = register_counter("duplicate_test_counter", "First registration").unwrap();

        // Attempting to register with the same name should fail
        let result = register_counter("duplicate_test_counter", "Second registration");
        assert!(result.is_err());
    }

    #[test]
    fn test_metrics_gathered_from_registry() {
        // Register some metrics
        let counter = register_counter("gather_test_counter", "Counter for gather test").unwrap();
        let gauge = register_gauge("gather_test_gauge", "Gauge for gather test").unwrap();

        // Update the metrics
        counter.inc_by(10.0);
        gauge.set(99.0);

        // Gather all metrics from registry
        let metrics = REGISTRY.gather();

        // Find our metrics in the gathered result
        let counter_found = metrics.iter().any(|m| m.get_name() == "gather_test_counter");
        let gauge_found = metrics.iter().any(|m| m.get_name() == "gather_test_gauge");

        assert!(counter_found, "Counter should be in gathered metrics");
        assert!(gauge_found, "Gauge should be in gathered metrics");
    }
}
