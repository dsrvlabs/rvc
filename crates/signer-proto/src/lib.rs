//! Shared generated bindings for `proto/signer.v2.proto`.
//!
//! This is the single `tonic_build` home for the signer v2 contract (RF3-14).
//! Consumers enable additive features:
//! - `server` — generate server stubs (`*_server` modules)
//! - `client` — generate client stubs (`*_client` modules)
//!
//! Message types are always generated. Cargo feature unification turns both
//! stubs on when `rvc-signer-bin` and `rvc-grpc-signer` share a build graph.

#![allow(clippy::all)]
// Generated prost/tonic code is not clippy-clean; keep the allow at the crate root.

/// Generated package `signer.v2`.
pub mod signer_v2 {
    tonic::include_proto!("signer.v2");
}
