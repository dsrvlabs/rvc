//! Small shared utilities used by multiple domain duty crates.
//!
//! Kept inside `rvc-signer` (not a new crate) so duty services that already
//! depend on the signing stack can share lock-free helpers without taking
//! peer domain edges (e.g. block-service → builder).

mod circuit_breaker;

pub use circuit_breaker::CircuitBreakerState;
