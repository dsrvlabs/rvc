//! Web3Signer-compatible HTTP remote-signing API.
//!
//! Phase 1 lands only the rustls crypto-provider install (`tls`); the HTTP
//! handlers, router, and listener arrive in later phases.

pub mod tls;
