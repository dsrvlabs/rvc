//! Config section structs (clap `Args` groups).
//!
//! ARCH-4f: tracing, keymanager, grpc_signer, monitoring. Later issues add
//! the partial and missing sections.

mod grpc_signer;
mod keymanager;
mod monitoring;
mod tracing;

pub use grpc_signer::{GrpcSignerArgs, GrpcSignerConfig};
pub use keymanager::{KeymanagerArgs, KeymanagerConfig};
pub use monitoring::{MonitoringArgs, MonitoringConfig};
pub use tracing::{TracingArgs, TracingConfig, TracingExporter};

#[cfg(test)]
mod tests {
    use clap::{CommandFactory, Parser};

    use super::*;

    /// Pre-move `rvc start` long flags for the four migrated groups (20 knobs).
    const PRE_MOVE_LONG_FLAGS: &[&str] = &[
        "--allow-insecure-remote-signer",
        "--grpc-signer-tls-ca-cert",
        "--grpc-signer-tls-cert",
        "--grpc-signer-tls-key",
        "--grpc-signer-url",
        "--keymanager-address",
        "--keymanager-body-limit",
        "--keymanager-cors-origins",
        "--keymanager-enabled",
        "--keymanager-token-file",
        "--monitoring-endpoint",
        "--monitoring-endpoint-insecure",
        "--monitoring-interval",
        "--remote-signer-allowed-hosts",
        "--remote-signer-url",
        "--tracing-endpoint",
        "--tracing-exporter",
        "--tracing-max-export-batch-size",
        "--tracing-max-queue-size",
        "--tracing-sample-rate",
    ];

    #[derive(Parser, Debug)]
    #[command(name = "rvc-start-probe", no_binary_name = true)]
    struct MigratedSectionsProbe {
        #[command(flatten)]
        tracing: TracingArgs,
        #[command(flatten)]
        keymanager: KeymanagerArgs,
        #[command(flatten)]
        grpc_signer: GrpcSignerArgs,
        #[command(flatten)]
        monitoring: MonitoringArgs,
    }

    fn probe_long_flags() -> Vec<String> {
        let cmd = MigratedSectionsProbe::command();
        let mut flags: Vec<String> = cmd
            .get_arguments()
            .filter_map(|arg| arg.get_long().map(|l| format!("--{l}")))
            .filter(|f| f != "--help" && f != "--version")
            .collect();
        flags.sort();
        flags.dedup();
        flags
    }

    #[test]
    fn tracing_section_flat_alias_still_parses() {
        let flat: TracingArgs =
            toml::from_str(r#"tracing_endpoint = "http://x""#).expect("flat alias");
        let nested: TracingArgs = toml::from_str(r#"endpoint = "http://x""#).expect("nested name");
        assert_eq!(flat.endpoint.as_deref(), Some("http://x"));
        assert_eq!(flat.endpoint, nested.endpoint);
        assert_eq!(flat, nested);
    }

    #[test]
    fn otel_env_fallback_is_still_config_else_env() {
        let _guard = otel_env_lock();
        std::env::set_var("OTEL_EXPORTER_OTLP_ENDPOINT", "http://env-must-lose:4318");
        std::env::set_var("OTEL_TRACES_SAMPLER_ARG", "0.9");

        let tracing = TracingConfig {
            endpoint: Some("http://config-wins:4318".into()),
            sample_rate: Some(0.25),
            ..Default::default()
        };
        assert_eq!(tracing.resolve_endpoint().as_deref(), Some("http://config-wins:4318"));
        assert!((tracing.resolve_sample_rate() - 0.25).abs() < f64::EPSILON);

        std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT");
        std::env::remove_var("OTEL_TRACES_SAMPLER_ARG");
    }

    #[test]
    fn clap_long_flags_unchanged_for_migrated_sections() {
        // Parse forces clap debug_asserts (unique arg ids across flattened groups).
        MigratedSectionsProbe::try_parse_from(std::iter::empty::<&str>())
            .expect("flattened groups must parse with unique clap ids");
        let flags = probe_long_flags();
        let expected: Vec<&str> = {
            let mut v = PRE_MOVE_LONG_FLAGS.to_vec();
            v.push("--no-keymanager");
            v.sort();
            v
        };
        let actual: Vec<&str> = flags.iter().map(String::as_str).collect();
        for flag in PRE_MOVE_LONG_FLAGS {
            assert!(actual.contains(flag), "migrated section missing pre-move flag {flag}");
        }
        assert_eq!(PRE_MOVE_LONG_FLAGS.len(), 20, "ARCH-4f migrates 20 knobs");
        assert_eq!(actual, expected, "unexpected extra or renamed long flags: {actual:?}");
    }

    #[test]
    fn migrated_section_fields_have_no_clap_default_value() {
        let src = concat!(
            include_str!("tracing.rs"),
            include_str!("keymanager.rs"),
            include_str!("grpc_signer.rs"),
            include_str!("monitoring.rs"),
        );
        for line in src.lines() {
            let t = line.trim();
            assert!(
                !t.contains("default_value =") && !t.contains("default_value_t"),
                "ARCH-4f section clap field must not set default_value: {t}"
            );
        }
    }

    fn otel_env_lock() -> std::sync::MutexGuard<'static, ()> {
        use std::sync::{Mutex, OnceLock};
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap_or_else(|e| e.into_inner())
    }
}
