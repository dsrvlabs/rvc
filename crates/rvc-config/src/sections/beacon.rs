//! Beacon-node connection section (ARCH-4h).
//!
//! Invented `[beacon]` table: these knobs were bare top-level Config fields
//! (VD-4.2). Nested tables accept section-relative names only (4f SEC). Flat
//! `beacon_url` / `beacon_nodes` / `beacon_max_body_bytes` stay on `ConfigWire`.
//!
//! Four BN timeout flags stay on this clap group (G-2 `BYPASS`); they are not
//! Config knobs until ARCH-4j. `bn_sync_tolerances` is TOML-only (no clap flag).

use serde::{Deserialize, Serialize};

/// Clap + serde declaration for the `[beacon]` knobs (ADR-008).
///
/// Field names are section-relative; `--flag` strings stay the pre-move longs.
/// No flat-legacy `#[serde(alias)]` here: those would bind inside `[beacon]`.
#[derive(Debug, Clone, PartialEq, Default, clap::Args, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct BeaconArgs {
    /// Beacon node URL (e.g., http://localhost:5052)
    #[arg(id = "beacon_url", long = "beacon-url")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,

    /// Comma-separated list of beacon node URLs for multi-BN support
    #[arg(id = "beacon_nodes", long = "beacon-nodes", value_delimiter = ',')]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nodes: Option<Vec<String>>,

    /// Maximum JSON response body size in bytes from the beacon node.
    ///
    /// Requests whose body (or Content-Length) exceeds this value are rejected
    /// before the full body is allocated.  Raise this only if your beacon node
    /// legitimately returns larger responses.
    ///
    /// Default when unset: 33554432 (32 MiB), from `Config::default()`.
    #[arg(id = "beacon_max_body_bytes", long = "beacon-max-body-bytes")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_body_bytes: Option<usize>,

    /// Block production timeout in seconds (default: 3)
    #[arg(long = "block-production-timeout")]
    #[serde(skip)]
    pub block_production_timeout: Option<u64>,

    /// Attestation fetch timeout in seconds (default: 4)
    #[arg(long = "attestation-timeout")]
    #[serde(skip)]
    pub attestation_timeout: Option<u64>,

    /// Aggregate fetch timeout in seconds (default: 2)
    #[arg(long = "aggregate-timeout")]
    #[serde(skip)]
    pub aggregate_timeout: Option<u64>,

    /// Duty fetch timeout in seconds (default: 10)
    #[arg(long = "duty-fetch-timeout")]
    #[serde(skip)]
    pub duty_fetch_timeout: Option<u64>,
}

impl BeaconArgs {
    /// Fold this declaration into a [`BeaconConfig`].
    ///
    /// Defaults live on `rvc::config::Config`; load overlays Option fields.
    pub fn resolved(&self) -> BeaconConfig {
        BeaconConfig {
            url: self.url.clone(),
            nodes: self.nodes.clone().unwrap_or_default(),
            max_body_bytes: self.max_body_bytes,
            bn_sync_tolerances: None,
        }
    }
}

/// `[beacon]` table (section-relative names only; no flat aliases).
///
/// `bn_sync_tolerances` is TOML-only. `beacon_nodes_config` stays on the rvc
/// wire wrapper because it names `BnRole`.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct BeaconConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nodes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_body_bytes: Option<usize>,
    /// TOML-only sync-tolerance string (no CLI flag).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bn_sync_tolerances: Option<String>,
}
