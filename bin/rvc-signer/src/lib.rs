//! Library surface for `rvc-signer` binary.
//!
//! This file is the library entry point. The binary `main.rs` uses the
//! library via `rvc_signer_bin::*`. Integration tests in `tests/` link
//! against this library target.

pub mod audit;
pub mod backend;
#[cfg(feature = "dvt")]
pub mod commands;
pub mod config;
#[cfg(test)]
mod cross_transport;
#[cfg(feature = "dvt")]
pub mod dvt;
pub(crate) mod grpc_common;
pub mod http_api;
pub mod insecure_startup;
#[cfg(test)]
mod integration_polish;
pub mod metrics;
pub mod reload;
pub mod service;
/// Transport-neutral SignPlan engine (RF4-09 / D4).
pub(crate) mod sign_plan;
pub mod slashing;
pub mod tls;

/// Re-export of the shared v2 signer proto bindings (compiled once in `rvc-signer-proto`).
pub mod proto {
    pub use signer_proto::signer_v2;
}

// V2 server exports
pub use proto::signer_v2::signer_service_server::SignerServiceServer as SignerServiceServerV2;

// V2 PeerSignerService client + server (DVT) — RF2-16: client dials v2 only.
#[cfg(feature = "dvt")]
pub use proto::signer_v2::peer_signer_service_client::PeerSignerServiceClient;
#[cfg(feature = "dvt")]
pub use proto::signer_v2::peer_signer_service_server::{
    PeerSignerService as PeerSignerServiceV2, PeerSignerServiceServer as PeerSignerServiceServerV2,
};
