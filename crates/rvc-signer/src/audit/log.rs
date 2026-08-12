//! Structured audit log emission for rvc-signer.
//!
//! This module provides the `log_audit` function and the `AuditEntry` struct
//! used by all signing RPC handlers.  It is a thin wrapper that:
//!
//! - Emits success entries at `info` level.
//! - Emits error entries at `warn` level.
//!
//! `TruncatedPubkey` from `crypto::logging` is re-exported here for use by
//! callers that need a display-safe pubkey string in audit context.

pub use crypto::logging::TruncatedPubkey;

/// Structured audit log entry for a signing request.
///
/// Contains only non-sensitive metadata. No key material (secret keys,
/// signing roots, or signatures) is ever included.
pub struct AuditEntry {
    pub timestamp: String,
    pub pubkey_hex: String,
    pub client_cn: String,
    pub backend: String,
    pub result: String,
    pub duration_ms: u64,
    /// Optional: which RPC was invoked (e.g. "sign_beacon_block").
    pub rpc: Option<String>,
}

/// Emit a structured audit log entry.
///
/// Success entries are logged at `info` level; errors at `warn`.
pub fn log_audit(entry: &AuditEntry) {
    let rpc = entry.rpc.as_deref().unwrap_or("sign");
    let truncated_pubkey = TruncatedPubkey::new(&entry.pubkey_hex);
    if entry.result == "success" {
        tracing::info!(
            audit = true,
            rpc = %rpc,
            timestamp = %entry.timestamp,
            pubkey = %truncated_pubkey,
            client_cn = %entry.client_cn,
            backend = %entry.backend,
            result = %entry.result,
            duration_ms = entry.duration_ms,
            "sign request audit"
        );
    } else {
        tracing::warn!(
            audit = true,
            rpc = %rpc,
            timestamp = %entry.timestamp,
            pubkey = %truncated_pubkey,
            client_cn = %entry.client_cn,
            backend = %entry.backend,
            result = %entry.result,
            duration_ms = entry.duration_ms,
            "sign request audit"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_audit_success_does_not_panic() {
        let entry = AuditEntry {
            timestamp: "2026-04-25T12:00:00Z".to_string(),
            pubkey_hex: "0xabcdef".to_string(),
            client_cn: "test-client".to_string(),
            backend: "basic".to_string(),
            result: "success".to_string(),
            duration_ms: 10,
            rpc: Some("sign_beacon_block".to_string()),
        };
        log_audit(&entry);
    }

    #[test]
    fn test_log_audit_error_does_not_panic() {
        let entry = AuditEntry {
            timestamp: "2026-04-25T12:00:00Z".to_string(),
            pubkey_hex: "0xabcdef".to_string(),
            client_cn: "test-client".to_string(),
            backend: "basic".to_string(),
            result: "double_proposal".to_string(),
            duration_ms: 5,
            rpc: None,
        };
        log_audit(&entry);
    }
}
