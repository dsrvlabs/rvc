use lazy_static::lazy_static;
use metrics::REGISTRY;
use prometheus::{GaugeVec, HistogramOpts, HistogramVec, IntCounterVec, Opts};

lazy_static! {
    /// Gauge for the number of keys loaded per secret provider source.
    /// Labels: source (e.g., "gcp", "local")
    pub static ref RVC_SECRET_PROVIDER_KEYS_LOADED: GaugeVec = {
        let opts = Opts::new(
            "rvc_secret_provider_keys_loaded",
            "Number of keys loaded per secret provider source"
        );
        let gauge = GaugeVec::new(opts, &["source"])
            .expect("Failed to create rvc_secret_provider_keys_loaded metric");
        REGISTRY.register(Box::new(gauge.clone()))
            .expect("Failed to register rvc_secret_provider_keys_loaded metric");
        gauge
    };

    /// Counter for errors encountered during secret provider operations.
    /// Labels: source, error_type
    pub static ref RVC_SECRET_PROVIDER_ERRORS_TOTAL: IntCounterVec = {
        let opts = Opts::new(
            "rvc_secret_provider_errors_total",
            "Total number of errors during secret provider operations"
        );
        let counter = IntCounterVec::new(opts, &["source", "error_type"])
            .expect("Failed to create rvc_secret_provider_errors_total metric");
        REGISTRY.register(Box::new(counter.clone()))
            .expect("Failed to register rvc_secret_provider_errors_total metric");
        counter
    };

    /// Histogram for the duration of secret provider load operations.
    /// Labels: source
    pub static ref RVC_SECRET_PROVIDER_LOAD_DURATION_SECONDS: HistogramVec = {
        let opts = HistogramOpts::new(
            "rvc_secret_provider_load_duration_seconds",
            "Duration of secret provider load operations in seconds"
        ).buckets(vec![0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0]);
        let histogram = HistogramVec::new(opts, &["source"])
            .expect("Failed to create rvc_secret_provider_load_duration_seconds metric");
        REGISTRY.register(Box::new(histogram.clone()))
            .expect("Failed to register rvc_secret_provider_load_duration_seconds metric");
        histogram
    };
}

pub fn init_secret_provider_metrics() {
    lazy_static::initialize(&RVC_SECRET_PROVIDER_KEYS_LOADED);
    lazy_static::initialize(&RVC_SECRET_PROVIDER_ERRORS_TOTAL);
    lazy_static::initialize(&RVC_SECRET_PROVIDER_LOAD_DURATION_SECONDS);
}

pub fn classify_error(err: &crate::SecretProviderError) -> &'static str {
    match err {
        crate::SecretProviderError::Auth(_) => "auth",
        crate::SecretProviderError::NotFound(_) => "not_found",
        crate::SecretProviderError::Provider(_) => "provider",
        crate::SecretProviderError::InvalidKeyMaterial(_) => "invalid_key_material",
        crate::SecretProviderError::DecryptionFailed { .. } => "decryption_failed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keys_loaded_gauge_set_and_get() {
        RVC_SECRET_PROVIDER_KEYS_LOADED.with_label_values(&["gcp"]).set(5.0);
        let value = RVC_SECRET_PROVIDER_KEYS_LOADED.with_label_values(&["gcp"]).get();
        assert_eq!(value, 5.0);
    }

    #[test]
    fn test_errors_total_counter_increments() {
        let before = RVC_SECRET_PROVIDER_ERRORS_TOTAL.with_label_values(&["local", "auth"]).get();
        RVC_SECRET_PROVIDER_ERRORS_TOTAL.with_label_values(&["local", "auth"]).inc();
        let after = RVC_SECRET_PROVIDER_ERRORS_TOTAL.with_label_values(&["local", "auth"]).get();
        assert_eq!(after, before + 1);
    }

    #[test]
    fn test_load_duration_histogram_observes() {
        let before = RVC_SECRET_PROVIDER_LOAD_DURATION_SECONDS
            .with_label_values(&["gcp"])
            .get_sample_count();
        RVC_SECRET_PROVIDER_LOAD_DURATION_SECONDS.with_label_values(&["gcp"]).observe(0.5);
        let after = RVC_SECRET_PROVIDER_LOAD_DURATION_SECONDS
            .with_label_values(&["gcp"])
            .get_sample_count();
        assert_eq!(after, before + 1);
    }

    #[test]
    fn test_init_secret_provider_metrics_does_not_panic() {
        init_secret_provider_metrics();
    }

    #[test]
    fn test_metrics_registered_with_registry() {
        init_secret_provider_metrics();
        // Trigger metric creation by accessing them
        RVC_SECRET_PROVIDER_KEYS_LOADED.with_label_values(&["registry_test"]).set(1.0);
        RVC_SECRET_PROVIDER_ERRORS_TOTAL.with_label_values(&["registry_test", "provider"]).inc();
        RVC_SECRET_PROVIDER_LOAD_DURATION_SECONDS
            .with_label_values(&["registry_test"])
            .observe(0.1);

        let gathered = REGISTRY.gather();
        let names: Vec<&str> = gathered.iter().map(|m| m.name()).collect();
        assert!(
            names.contains(&"rvc_secret_provider_keys_loaded"),
            "keys_loaded not in registry: {:?}",
            names
        );
        assert!(
            names.contains(&"rvc_secret_provider_errors_total"),
            "errors_total not in registry: {:?}",
            names
        );
        assert!(
            names.contains(&"rvc_secret_provider_load_duration_seconds"),
            "load_duration not in registry: {:?}",
            names
        );
    }

    #[test]
    fn test_classify_error_variants() {
        assert_eq!(classify_error(&crate::SecretProviderError::Auth("x".into())), "auth");
        assert_eq!(classify_error(&crate::SecretProviderError::NotFound("x".into())), "not_found");
        assert_eq!(classify_error(&crate::SecretProviderError::Provider("x".into())), "provider");
        assert_eq!(
            classify_error(&crate::SecretProviderError::InvalidKeyMaterial("x".into())),
            "invalid_key_material"
        );
        assert_eq!(
            classify_error(&crate::SecretProviderError::DecryptionFailed {
                id: "k".into(),
                reason: "r".into()
            }),
            "decryption_failed"
        );
    }

    #[test]
    fn test_different_sources_independent() {
        RVC_SECRET_PROVIDER_KEYS_LOADED.with_label_values(&["src_a"]).set(10.0);
        RVC_SECRET_PROVIDER_KEYS_LOADED.with_label_values(&["src_b"]).set(20.0);
        assert_eq!(RVC_SECRET_PROVIDER_KEYS_LOADED.with_label_values(&["src_a"]).get(), 10.0);
        assert_eq!(RVC_SECRET_PROVIDER_KEYS_LOADED.with_label_values(&["src_b"]).get(), 20.0);
    }
}
