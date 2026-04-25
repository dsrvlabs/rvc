//! Per-`(client_cn, genesis_validators_root)` view over the shared `SlashingDb`.
//!
//! # Design
//!
//! `ScopedSlashingDb` is created once per RPC call (cheap — just an `Arc` clone
//! plus two small value copies) and captures the client CN extracted from the
//! mTLS certificate and the `genesis_validators_root` from the request's
//! `ForkInfo`.
//!
//! This avoids threading `(client_cn, gvr)` through every call site.
//!
//! # Public API constraints
//!
//! This type is **internal to `bin/rvc-signer`**.  Do not re-export from any
//! public crate.

use std::sync::Arc;

use eth_types::{Epoch, Root, Slot};
use slashing::{SlashingDb, SlashingError, StagedAttestation, StagedBlock};

/// A per-request view over the shared `SlashingDb` bound to a specific
/// `(client_cn, genesis_validators_root)` pair.
///
/// Created once per RPC; cheap (just an `Arc` clone).
pub struct ScopedSlashingDb {
    db: Arc<SlashingDb>,
    client_cn: String,
    genesis_validators_root: Root,
}

impl ScopedSlashingDb {
    /// Create a new scoped view.
    ///
    /// - `db`: Shared database instance (created at signer startup).
    /// - `client_cn`: The mTLS Common Name of the requesting client.
    ///   Use `"unknown"` when TLS is unavailable (non-production).
    /// - `genesis_validators_root`: Taken from `ForkInfo.genesis_validators_root`
    ///   in the typed RPC request.  Not yet cross-checked against the metadata-
    ///   pinned value — that enforcement lands in ISSUE-3.5 (M-6).
    pub fn new(db: Arc<SlashingDb>, client_cn: String, genesis_validators_root: Root) -> Self {
        Self { db, client_cn, genesis_validators_root }
    }

    /// Begin an immediate transaction, run the EIP-3076 violation check for a
    /// block proposal, and return a `StagedBlock` RAII guard.
    ///
    /// Call `guard.commit()` after a successful sign, or let the guard drop
    /// (or call `guard.discard()`) on any failure — the transaction rolls back.
    ///
    /// # Errors
    ///
    /// Returns `SlashingError::SlashableBlock` if a different signing root has
    /// already been committed for `(client_cn, pubkey, slot)`.
    pub fn stage_block(
        &self,
        pubkey_hex: &str,
        slot: Slot,
        signing_root_hex: Option<String>,
    ) -> Result<StagedBlock<'_>, SlashingError> {
        self.db.stage_block(
            &self.client_cn,
            pubkey_hex,
            slot,
            signing_root_hex,
            &self.genesis_validators_root,
        )
    }

    /// Begin an immediate transaction, run the EIP-3076 violation check for an
    /// attestation, and return a `StagedAttestation` RAII guard.
    pub fn stage_attestation(
        &self,
        pubkey_hex: &str,
        source_epoch: Epoch,
        target_epoch: Epoch,
        signing_root_hex: Option<String>,
    ) -> Result<StagedAttestation<'_>, SlashingError> {
        self.db.stage_attestation(
            &self.client_cn,
            pubkey_hex,
            source_epoch,
            target_epoch,
            signing_root_hex,
            &self.genesis_validators_root,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    fn open_test_db() -> (Arc<SlashingDb>, NamedTempFile) {
        let f = NamedTempFile::new().unwrap();
        let db = Arc::new(SlashingDb::open(f.path()).expect("open test DB"));
        (db, f)
    }

    #[test]
    fn test_stage_block_happy_path() {
        let (db, _f) = open_test_db();
        let scoped = ScopedSlashingDb::new(db, "test-cn".to_string(), [0u8; 32]);

        let staged = scoped
            .stage_block("0xaabbcc", 100, Some("0xdeadbeef".to_string()))
            .expect("stage_block should succeed");
        staged.commit().expect("commit should succeed");
    }

    #[test]
    fn test_stage_block_double_proposal_rejected() {
        let (db, _f) = open_test_db();
        let scoped = ScopedSlashingDb::new(db, "test-cn".to_string(), [0u8; 32]);

        let staged1 = scoped
            .stage_block("0xaabbcc", 100, Some("0xdeadbeef".to_string()))
            .expect("first stage should succeed");
        staged1.commit().expect("first commit");

        // Second stage with different signing root for same (cn, pubkey, slot)
        let result = scoped.stage_block("0xaabbcc", 100, Some("0xcafebabe".to_string()));
        assert!(result.is_err(), "double proposal must be rejected");
    }

    #[test]
    fn test_stage_block_discard_leaves_no_row() {
        let (db, _f) = open_test_db();
        let scoped = ScopedSlashingDb::new(Arc::clone(&db), "test-cn".to_string(), [0u8; 32]);

        let staged = scoped
            .stage_block("0xaabbcc", 200, Some("0xfeedface".to_string()))
            .expect("stage should succeed");
        staged.discard();

        // After discard, a new stage for the same slot should succeed
        let staged2 = scoped
            .stage_block("0xaabbcc", 200, Some("0xfeedface".to_string()))
            .expect("stage after discard should succeed");
        staged2.discard();
    }

    #[test]
    fn test_different_cn_scopes_are_independent() {
        let (db, _f) = open_test_db();

        let scoped_a = ScopedSlashingDb::new(Arc::clone(&db), "cn-a".to_string(), [0u8; 32]);
        let scoped_b = ScopedSlashingDb::new(Arc::clone(&db), "cn-b".to_string(), [0u8; 32]);

        // CN-A stages slot 42
        let staged_a = scoped_a
            .stage_block("0xaabbcc", 42, Some("0x01".to_string()))
            .expect("cn-a stage should succeed");
        staged_a.commit().expect("cn-a commit");

        // CN-B can stage the same (pubkey, slot) independently
        let staged_b = scoped_b
            .stage_block("0xaabbcc", 42, Some("0x01".to_string()))
            .expect("cn-b stage should succeed (different CN namespace)");
        staged_b.commit().expect("cn-b commit");
    }
}
