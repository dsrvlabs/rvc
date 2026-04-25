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
#[cfg(feature = "dvt")]
pub mod dvt;
#[cfg(test)]
mod integration_polish;
pub mod metrics;
pub mod reload;
pub mod service;
pub mod slashing;
pub mod tls;

pub mod proto {
    pub mod signer {
        tonic::include_proto!("signer");
    }
    pub mod signer_v2 {
        tonic::include_proto!("signer.v2");
    }
}

#[cfg(feature = "dvt")]
pub use proto::signer::peer_signer_service_client::PeerSignerServiceClient;
pub use proto::signer::peer_signer_service_server::{PeerSignerService, PeerSignerServiceServer};
pub use proto::signer::signer_service_server::{SignerService, SignerServiceServer};
pub use proto::signer::{
    GetStatusRequest, GetStatusResponse, ListPublicKeysRequest, ListPublicKeysResponse,
    PartialSignRequest, PartialSignResponse, SignRequest, SignResponse,
};

// V2 server exports
pub use proto::signer_v2::signer_service_server::SignerServiceServer as SignerServiceServerV2;
