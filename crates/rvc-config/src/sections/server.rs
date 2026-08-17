//! Metrics HTTP and gRPC bind section (ARCH-4h).
//!
//! Invented `[server]` table. Four ADR-009 fields live here (`metrics_address`,
//! `metrics_port`, `grpc_port`, `grpc_address`) and must not regain clap
//! `default_value`. Nested tables accept section-relative names only (4f SEC).
//! Flat top-level keys stay on `ConfigWire`.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

/// Clap + serde declaration for the `[server]` knobs (ADR-008 / ADR-009).
///
/// Field names match the operator-visible keys. `--flag` strings stay the
/// pre-move longs. No flat-legacy `#[serde(alias)]` here.
#[derive(Debug, Clone, PartialEq, Default, clap::Args, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerArgs {
    /// Bind address for the metrics HTTP server (default: 127.0.0.1)
    #[arg(long = "metrics-address")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metrics_address: Option<IpAddr>,

    /// Port for the metrics HTTP server (default: 8080)
    #[arg(long = "metrics-port")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metrics_port: Option<u16>,

    /// Port for the gRPC server (default: 50051)
    #[arg(long = "grpc-port")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grpc_port: Option<u16>,

    /// Bind address for the gRPC server (default: 127.0.0.1)
    #[arg(long = "grpc-address")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grpc_address: Option<String>,
}

impl ServerArgs {
    /// Fold this declaration into a [`ServerConfig`].
    ///
    /// Unused on today's `Config::from_file` / `merge_with_cli` path (ARCH-4i).
    pub fn resolved(&self) -> ServerConfig {
        ServerConfig {
            metrics_address: self.metrics_address,
            metrics_port: self.metrics_port,
            grpc_port: self.grpc_port,
            grpc_address: self.grpc_address.clone(),
        }
    }
}

/// `[server]` table (section-relative names only; no flat aliases).
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metrics_address: Option<IpAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metrics_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grpc_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grpc_address: Option<String>,
}
