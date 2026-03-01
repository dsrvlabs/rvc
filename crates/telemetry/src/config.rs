/// Exporter backend for telemetry data.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum ExporterKind {
    /// OpenTelemetry Protocol (OTLP) over HTTP.
    #[default]
    Otlp,
    /// Google Cloud Trace exporter (requires `gcp-trace` feature).
    #[cfg(feature = "gcp-trace")]
    Gcp,
}

/// Configuration for the telemetry subsystem.
#[derive(Debug, Clone)]
pub struct TelemetryConfig {
    /// OTLP collector endpoint URL.
    pub endpoint: String,
    /// Which exporter backend to use.
    pub exporter: ExporterKind,
    /// Trace sampling rate (0.0 to 1.0).
    pub sample_rate: f64,
    /// Ethereum network name (e.g. "mainnet", "hoodi").
    pub network: String,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            endpoint: "http://localhost:4318".to_string(),
            exporter: ExporterKind::default(),
            sample_rate: 1.0,
            network: "mainnet".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_telemetry_config_default() {
        let config = TelemetryConfig::default();
        assert_eq!(config.endpoint, "http://localhost:4318");
        assert_eq!(config.exporter, ExporterKind::Otlp);
        assert_eq!(config.sample_rate, 1.0);
        assert_eq!(config.network, "mainnet");
    }

    #[test]
    fn test_exporter_kind_default_is_otlp() {
        let kind = ExporterKind::default();
        assert_eq!(kind, ExporterKind::Otlp);
    }

    #[test]
    fn test_telemetry_config_custom_values() {
        let config = TelemetryConfig {
            endpoint: "http://collector:4318".to_string(),
            exporter: ExporterKind::Otlp,
            sample_rate: 0.5,
            network: "hoodi".to_string(),
        };
        assert_eq!(config.endpoint, "http://collector:4318");
        assert_eq!(config.sample_rate, 0.5);
        assert_eq!(config.network, "hoodi");
    }

    #[test]
    fn test_telemetry_config_clone() {
        let config = TelemetryConfig::default();
        let cloned = config.clone();
        assert_eq!(cloned.endpoint, config.endpoint);
        assert_eq!(cloned.sample_rate, config.sample_rate);
        assert_eq!(cloned.network, config.network);
    }

    #[test]
    fn test_exporter_kind_debug() {
        let kind = ExporterKind::Otlp;
        let debug = format!("{:?}", kind);
        assert_eq!(debug, "Otlp");
    }
}
