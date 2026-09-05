//! Pre-Gloas duty-deadline knobs. TOML `[timing]` only — no clap group.
//!
//! Defaults stay literals so this crate does not grow an `rvc-timing` edge.

use serde::{Deserialize, Serialize};

fn default_attestation_due_bps() -> u64 {
    3333
}

fn default_aggregate_due_bps() -> u64 {
    6667
}

/// Pre-Gloas attestation / aggregation deadlines as basis points of the slot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TimingConfig {
    #[serde(default = "default_attestation_due_bps")]
    pub attestation_due_bps: u64,
    #[serde(default = "default_aggregate_due_bps")]
    pub aggregate_due_bps: u64,
}

impl Default for TimingConfig {
    fn default() -> Self {
        Self {
            attestation_due_bps: default_attestation_due_bps(),
            aggregate_due_bps: default_aggregate_due_bps(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_table_uses_pre_gloas_defaults() {
        let cfg: TimingConfig = toml::from_str("").expect("empty");
        assert_eq!(cfg.attestation_due_bps, 3333);
        assert_eq!(cfg.aggregate_due_bps, 6667);
    }

    #[test]
    fn toml_round_trip_preserves_values() {
        let cfg: TimingConfig = toml::from_str(
            r#"
attestation_due_bps = 2500
aggregate_due_bps = 4000
"#,
        )
        .expect("parse");
        assert_eq!(cfg.attestation_due_bps, 2500);
        assert_eq!(cfg.aggregate_due_bps, 4000);
        let encoded = toml::to_string(&cfg).expect("serialize");
        let again: TimingConfig = toml::from_str(&encoded).expect("deserialize");
        assert_eq!(cfg, again);
    }
}
