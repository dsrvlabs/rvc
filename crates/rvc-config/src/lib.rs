//! Operator configuration crate (ADR-008).
//!
//! Scaffold (ARCH-4e): provenance types and the [`Config::load`] signature.
//! Section structs land in ARCH-4f+. No figment; env is not a config layer.

mod error;
pub mod sections;

use std::path::Path;

pub use error::{ConfigError, ConfigSource};

/// CLI overlay accepted by [`Config::load`].
///
/// Placeholder for `bin/rvc`'s `StartArgs`. Real clap groups move here in ARCH-4f+.
/// Declared here so `rvc-config` does not depend on `rvc` / `rvc-bin`.
#[derive(Debug, Default, Clone, clap::Args, serde::Deserialize, serde::Serialize)]
pub struct StartArgs {}

/// Folded operator configuration.
///
/// Scaffold: empty. Operator-visible values still live in `rvc::config` until
/// ARCH-4f+ migrates sections and ARCH-4i implements [`Config::load`].
#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct Config {}

impl Config {
    /// Load config with precedence defaults < file < CLI.
    ///
    /// Scaffold (ARCH-4e): returns [`Config::default`] and does not read `file`
    /// or apply `cli`. Operator-visible values stay in `rvc::config`.
    pub fn load(file: Option<&Path>, cli: StartArgs) -> Result<Self, ConfigError> {
        let _ = (file, cli);
        Ok(Self::default())
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn config_error_names_its_provenance_layer() {
        let err = ConfigError::Invalid {
            field: "metrics.port",
            message: "out of range".into(),
            source_layer: ConfigSource::File(PathBuf::from("/tmp/rvc.toml")),
        };
        let rendered = err.to_string();
        assert!(rendered.contains("metrics.port"), "{rendered}");
        assert!(rendered.contains("/tmp/rvc.toml"), "{rendered}");
    }

    #[test]
    fn empty_config_round_trips_through_toml() {
        let encoded = toml::to_string(&Config::default()).expect("serialize empty Config");
        let decoded: Config = toml::from_str(&encoded).expect("deserialize encoded Config");
        assert_eq!(decoded, Config::default());
        let from_empty: Config = toml::from_str("").expect("deserialize empty document");
        assert_eq!(from_empty, Config::default());
    }
}
