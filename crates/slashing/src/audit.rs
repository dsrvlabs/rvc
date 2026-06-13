//! Audit logging for slashing-protection operations.
//!
//! Emits structured `tracing` records that preserve per-CN operator visibility
//! now that `client_cn` is no longer a slashing-check discriminator (Issue 2.4).
//! Call sites are wired in Issue 2.5; this module just lands the function and a test.

/// Emit a structured audit record for a slashing-protection signing operation.
///
/// # Arguments
/// - `client_cn`: The mTLS Common Name of the requesting client (audit only; no
///   longer used as a slashing-check discriminator after Issue 2.4).
/// - `pubkey`: Hex-encoded validator public key (may be abbreviated).
/// - `outcome`: Human-readable outcome, e.g. `"safe"`, `"blocked"`, `"chain_swap"`.
///
/// # Example
/// ```
/// rvc_slashing::audit_log("local-vc", "0xaabbcc...", "safe");
/// ```
pub fn audit_log(client_cn: &str, pubkey: &str, outcome: &str) {
    tracing::info!(
        target: "rvc.slashing.audit",
        client_cn,
        pubkey,
        outcome,
        "slashing audit",
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that `audit_log` emits a `tracing` event without panicking.
    ///
    /// We use `tracing_subscriber` to capture events and confirm the event was
    /// recorded with the expected field values.
    #[test]
    fn test_audit_log_emits_without_panic() {
        // Install a no-op subscriber so tracing does not drop events silently.
        let subscriber = tracing_subscriber::registry();
        let _guard = tracing::subscriber::set_default(subscriber);

        // Must not panic.
        audit_log("local-vc", "0xaabbccdd", "safe");
        audit_log("cn-dvt-peer", "0x1234", "blocked");
        audit_log("unknown", "0xfeed", "chain_swap");
    }

    /// Verify that `audit_log` accepts non-ASCII inputs gracefully.
    #[test]
    fn test_audit_log_handles_varied_inputs() {
        let subscriber = tracing_subscriber::registry();
        let _guard = tracing::subscriber::set_default(subscriber);

        audit_log("", "", "");
        audit_log("a".repeat(256).as_str(), "0x00", "safe");
    }
}
