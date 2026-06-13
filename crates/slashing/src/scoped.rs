//! Pubkey-scoped view over the shared `SlashingDb` (Issue 2.4 / 2.5).
//!
//! `PubkeyScopedDb` binds a fixed `genesis_validators_root` and records a
//! `client_cn` for audit-log purposes only.  It exposes no API that lets the
//! caller key the slashing check by CN — all checks are purely pubkey+gvr scoped.
//!
//! This replaces `bin/rvc-signer::ScopedSlashingDb` as the canonical high-level
//! entry point (Issue 2.5 migration).

use std::sync::Arc;

use eth_types::{Epoch, Root, Slot};

use crate::audit::audit_log;
use crate::error::SlashingError;
use crate::stage::{StagedAttestation, StagedBlock};
use crate::SlashingDb;

/// A pubkey-scoped view over the shared `SlashingDb` bound to a specific
/// `genesis_validators_root`.
///
/// Stores `client_cn` for audit-log emission only; it is never used as a
/// slashing-check discriminator.  pubkey+gvr is the sole uniqueness scope.
///
/// # Example
/// ```ignore
/// use std::sync::Arc;
/// use rvc_slashing::{SlashingDb, PubkeyScopedDb};
///
/// let db = Arc::new(SlashingDb::open_in_memory().unwrap());
/// let gvr: [u8; 32] = [1u8; 32];
/// let scoped = PubkeyScopedDb::new(Arc::clone(&db), "local-vc".to_string(), gvr);
/// ```
pub struct PubkeyScopedDb {
    db: Arc<SlashingDb>,
    /// Audit CN — recorded in `audit_log` calls; never used in slashing checks.
    client_cn: String,
    gvr: Root,
}

impl PubkeyScopedDb {
    /// Create a new pubkey-scoped view.
    ///
    /// - `db`: Shared database instance.
    /// - `client_cn`: The client CN to record in audit-log entries.  Has no
    ///   effect on the slashing check — the check is pubkey+gvr scoped only.
    /// - `gvr`: Genesis validators root for this chain.  Every signing call will
    ///   be validated against the metadata-pinned value via the M-6 GVR check.
    pub fn new(db: Arc<SlashingDb>, client_cn: String, gvr: Root) -> Self {
        Self { db, client_cn, gvr }
    }

    /// Begin an immediate transaction and run the EIP-3076 block-proposal check.
    ///
    /// Delegates to [`SlashingDb::stage_block`].  On success or failure, emits
    /// an [`audit_log`] event with `self.client_cn` for per-CN operator visibility.
    ///
    /// # Errors
    ///
    /// Returns `SlashingError::SlashableBlock` if a different signing root has
    /// already been committed for `(pubkey, slot)` across any CN.
    pub fn stage_block<'db>(
        &'db self,
        pubkey_hex: &str,
        slot: Slot,
        signing_root_hex: Option<String>,
    ) -> Result<StagedBlock<'db>, SlashingError> {
        let result = self.db.stage_block(pubkey_hex, slot, signing_root_hex, &self.gvr);
        let outcome = if result.is_ok() { "staged" } else { "rejected" };
        // NOTE: audit_log fires at STAGE time (before commit), while the returned
        // StagedBlock still holds the parking_lot::MutexGuard on the DB connection.
        // A tracing subscriber that attempts to read the DB would deadlock because
        // parking_lot mutexes are non-reentrant.  A "staged" event may therefore
        // precede a rolled-back sign if the caller subsequently discards the guard.
        audit_log(&self.client_cn, pubkey_hex, outcome);
        result
    }

    /// Begin an immediate transaction and run the EIP-3076 attestation check.
    ///
    /// Delegates to [`SlashingDb::stage_attestation`].  On success or failure,
    /// emits an [`audit_log`] event with `self.client_cn` for per-CN operator visibility.
    ///
    /// # Errors
    ///
    /// Returns `SlashingError::SlashableAttestation` if the new `(source, target)` pair
    /// conflicts with any existing attestation for `pubkey` across any CN.
    pub fn stage_attestation<'db>(
        &'db self,
        pubkey_hex: &str,
        source_epoch: Epoch,
        target_epoch: Epoch,
        signing_root_hex: Option<String>,
    ) -> Result<StagedAttestation<'db>, SlashingError> {
        let result = self.db.stage_attestation(
            pubkey_hex,
            source_epoch,
            target_epoch,
            signing_root_hex,
            &self.gvr,
        );
        let outcome = if result.is_ok() { "staged" } else { "rejected" };
        // NOTE: same timing caveat as stage_block — fires at STAGE time while the
        // StagedAttestation guard holds the DB mutex.  A "staged" event may precede
        // a rolled-back sign.  Do not install a tracing subscriber that reads the DB.
        audit_log(&self.client_cn, pubkey_hex, outcome);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{AttestationSlashingViolation, BlockSlashingViolation};

    const PUBKEY: &str =
        "0xabababababababababababababababababababababababababababababababababababababababababababababababababababab";
    const GVR: Root = [1u8; 32];

    fn open_scoped() -> (Arc<SlashingDb>, PubkeyScopedDb) {
        let db = Arc::new(SlashingDb::open_in_memory().expect("open in-memory"));
        let scoped = PubkeyScopedDb::new(Arc::clone(&db), "local-vc".to_string(), GVR);
        (db, scoped)
    }

    #[test]
    fn test_stage_block_commit_succeeds() {
        let (_db, scoped) = open_scoped();
        scoped
            .stage_block(PUBKEY, 100, Some("0xroot_ok".into()))
            .expect("stage_block must succeed")
            .commit()
            .expect("commit must succeed");
    }

    #[test]
    fn test_stage_block_double_proposal_rejected() {
        let (_db, scoped) = open_scoped();

        scoped
            .stage_block(PUBKEY, 200, Some("0xroot_1".into()))
            .expect("first stage")
            .commit()
            .expect("first commit");

        let err = scoped
            .stage_block(PUBKEY, 200, Some("0xroot_2".into()))
            .expect_err("double proposal must be rejected");

        assert!(
            matches!(
                err,
                SlashingError::SlashableBlock(BlockSlashingViolation::DoubleBlockProposal {
                    slot: 200
                })
            ),
            "expected DoubleBlockProposal at slot 200, got: {err:?}"
        );
    }

    #[test]
    fn test_stage_block_discard_leaves_no_row() {
        let (db, scoped) = open_scoped();
        scoped.stage_block(PUBKEY, 300, Some("0xroot".into())).expect("stage").discard();
        assert!(db.get_blocks(PUBKEY).expect("get_blocks").is_empty());
    }

    #[test]
    fn test_stage_attestation_commit_succeeds() {
        let (_db, scoped) = open_scoped();
        scoped
            .stage_attestation(PUBKEY, 5, 10, Some("0xatt_root".into()))
            .expect("stage_attestation must succeed")
            .commit()
            .expect("commit must succeed");
    }

    #[test]
    fn test_stage_attestation_double_vote_rejected() {
        let (_db, scoped) = open_scoped();

        scoped
            .stage_attestation(PUBKEY, 1, 5, Some("0xatt_1".into()))
            .expect("first stage")
            .commit()
            .expect("first commit");

        let err = scoped
            .stage_attestation(PUBKEY, 1, 5, Some("0xatt_2".into()))
            .expect_err("double vote must be rejected");

        assert!(
            matches!(
                err,
                SlashingError::SlashableAttestation(AttestationSlashingViolation::DoubleVote {
                    target_epoch: 5
                })
            ),
            "expected DoubleVote at target_epoch 5, got: {err:?}"
        );
    }

    #[test]
    fn test_stage_attestation_discard_leaves_no_row() {
        let (db, scoped) = open_scoped();
        scoped
            .stage_attestation(PUBKEY, 10, 20, Some("0xatt_root".into()))
            .expect("stage")
            .discard();
        assert!(db.get_attestations(PUBKEY).expect("get_attestations").is_empty());
    }

    /// PubkeyScopedDb records rows with audit CN = "local-vc".
    #[test]
    fn test_audit_cn_is_local_vc() {
        use rusqlite::Connection;
        use tempfile::tempdir;

        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("audit_cn.db");
        let db = Arc::new(SlashingDb::open(&path).expect("open file db"));
        let scoped = PubkeyScopedDb::new(Arc::clone(&db), "local-vc".to_string(), GVR);

        scoped
            .stage_block(PUBKEY, 400, Some("0xaudit_root".into()))
            .expect("stage")
            .commit()
            .expect("commit");

        drop(scoped);
        drop(db);

        let conn = Connection::open(&path).expect("direct open");
        let cn: String = conn
            .query_row(
                "SELECT client_cn FROM blocks WHERE pubkey = ?1 AND slot = 400",
                [PUBKEY],
                |row| row.get(0),
            )
            .expect("block row must exist");

        assert_eq!(cn, "local-vc", "audit CN must be 'local-vc'");
    }

    /// PubkeyScopedDb with a non-local-vc CN emits audit_log with that CN.
    /// The row in the DB still gets AUDIT_ORIGIN ("local-vc") — the per-CN audit
    /// is in the tracing event only.
    #[test]
    fn test_audit_log_fires_on_stage_block() {
        // Install a no-op subscriber so the audit_log tracing call does not panic.
        let subscriber = tracing_subscriber::registry();
        let _guard = tracing::subscriber::set_default(subscriber);

        let db = Arc::new(SlashingDb::open_in_memory().expect("open in-memory"));
        let scoped = PubkeyScopedDb::new(Arc::clone(&db), "peer-dvt-1".to_string(), GVR);

        // Happy-path stage: audit_log must fire with outcome "staged" (no panic).
        scoped
            .stage_block(PUBKEY, 500, Some("0xaudit_fire_root".into()))
            .expect("stage must succeed")
            .commit()
            .expect("commit must succeed");

        // Rejection path: audit_log must fire with outcome "rejected" (no panic).
        let _err = scoped
            .stage_block(PUBKEY, 500, Some("0xaudit_conflict_root".into()))
            .expect_err("double proposal must be rejected");
    }

    /// Same audit_log coverage for stage_attestation paths.
    #[test]
    fn test_audit_log_fires_on_stage_attestation() {
        let subscriber = tracing_subscriber::registry();
        let _guard = tracing::subscriber::set_default(subscriber);

        let db = Arc::new(SlashingDb::open_in_memory().expect("open in-memory"));
        let scoped = PubkeyScopedDb::new(Arc::clone(&db), "peer-dvt-2".to_string(), GVR);

        // Happy-path: audit_log fires with "staged".
        scoped
            .stage_attestation(PUBKEY, 3, 8, Some("0xatt_fire".into()))
            .expect("stage must succeed")
            .commit()
            .expect("commit must succeed");

        // Rejection path: audit_log fires with "rejected".
        let _err = scoped
            .stage_attestation(PUBKEY, 3, 8, Some("0xatt_conflict".into()))
            .expect_err("double vote must be rejected");
    }
}
