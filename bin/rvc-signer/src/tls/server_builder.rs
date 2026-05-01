//! Hardened Tonic server builder for `rvc-signer`.
//!
//! Centralises the security-critical transport parameters so that
//! every code path that constructs the gRPC server uses the same
//! validated defaults.  See `plan/audit-fix/research/05-tonic-grpc-hardening.md`
//! §"Recommended values" for the full rationale.

use std::time::Duration;

use tonic::transport::Server;

/// Returns a Tonic [`Server`] builder pre-configured with hardening parameters
/// recommended by research/05 §"Recommended values" for a security-sensitive
/// signing RPC:
///
/// | Setting                           | Value     | Rationale                              |
/// |-----------------------------------|-----------|----------------------------------------|
/// | `concurrency_limit_per_connection`| 32        | Tower-level cap; pins attack surface   |
/// | `max_concurrent_streams`          | `Some(64)`| H2 `SETTINGS_MAX_CONCURRENT_STREAMS`;  |
/// |                                   |           | blocks stream-flood DoS                |
/// | `timeout`                         | 10 s      | Sign must finish well within one slot  |
/// |                                   |           | (12 s); 10 s is a generous upper bound |
///
/// **Per-service `max_decoding_message_size`** is NOT set here because Tonic
/// exposes it only on the `ServiceServer` wrapper, not the `Server` builder.
/// Callers **must** set it on every service they add:
///
/// ```rust,ignore
/// hardened_server_builder()
///     .add_service(
///         SignerServiceServer::new(svc).max_decoding_message_size(1 << 20),
///     )
///     .serve_with_shutdown(addr, shutdown_signal())
///     .await?;
/// ```
pub fn hardened_server_builder() -> Server {
    Server::builder()
        .concurrency_limit_per_connection(32)
        .max_concurrent_streams(Some(64))
        .timeout(Duration::from_secs(10))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke-test that `hardened_server_builder()` returns a `Server` without
    /// panicking.  The exact builder field values are validated by the
    /// integration tests in `tests/tonic_limits_m10.rs`.
    #[test]
    fn test_hardened_server_builder_returns_server() {
        let _server = hardened_server_builder();
    }
}
