//! Read-only view over slashing-protection history.
//!
//! This module defines the [`SlashingDbReader`] trait — a deliberately narrow, read-only
//! seam that allows consumers (e.g. `doppelganger`) to query signing history without
//! receiving any staging or commit capability.  The absence of mutation methods is what
//! makes the forbidden `slashing → doppelganger` dependency edge impossible: `doppelganger`
//! depends on this trait, not on `SlashingDb` directly, so `slashing` never needs to know
//! that `doppelganger` exists.

use eth_types::Root;

use crate::SlashingDb;

/// A monotonically-increasing attestation target epoch.
///
/// Alias for now; may become a newtype later if stronger type-safety is needed.
pub type TargetEpoch = u64;

/// Read-only view over slashing-protection history.
///
/// This trait deliberately has NO staging, commit, or mutation methods — that is what
/// makes the `slashing → doppelganger` cycle impossible: `doppelganger` consumes this
/// read-only seam without gaining any ability to write to the slashing DB.
pub trait SlashingDbReader: Send + Sync {
    /// The highest target epoch this validator has attested under the DB's pinned GVR,
    /// or `None` if there is no such record (or the DB's pinned GVR differs from `gvr`).
    fn last_signed_attestation(&self, pubkey: &str, gvr: &Root) -> Option<TargetEpoch>;
}

impl SlashingDbReader for SlashingDb {
    /// Returns the maximum target epoch recorded for `pubkey`, scoped to `gvr`.
    ///
    /// # Fail-closed GVR scoping
    ///
    /// `SignedAttestation` carries no per-row GVR field; GVR scoping is therefore enforced
    /// via the DB's single pinned GVR (stored in `metadata.genesis_validators_root`).
    ///
    /// A `Some(epoch)` answer is consumed downstream as an **unlock** signal — the
    /// doppelganger forward-window's restart-aware safe-skip treats "we already have an
    /// attestation under this chain" as grounds to skip monitoring. An answer derived from
    /// an *unidentified* or *different* chain must therefore never be returned: it would
    /// skip doppelganger protection based on foreign signing history (a slashing-bypass
    /// hazard). This method is fail-closed (PRD §6.3): it returns `Some` **only** when the
    /// DB's pinned GVR exactly matches `gvr`. In every other case — GVR mismatch, no pinned
    /// GVR (chain identity unknown), or any I/O error — it returns `None`, which makes the
    /// caller run the full forward window. Missing a safe-skip optimization is harmless; a
    /// spurious unlock is not.
    ///
    /// Per-row GVR filtering (so legacy / cross-chain rows in a single DB cannot inflate the
    /// answer) lands with the Phase 2 DVT-1/CN-1/GVR-1 schema migration; until then this
    /// method relies on the DB's single-pinned-GVR invariant established at stage time.
    fn last_signed_attestation(&self, pubkey: &str, gvr: &Root) -> Option<TargetEpoch> {
        match self.pinned_gvr() {
            // Pinned GVR matches the requested chain — the only path that may answer `Some`.
            Ok(Some(pinned)) if pinned == *gvr => {}
            Ok(Some(pinned)) => {
                tracing::warn!(
                    requested_gvr = ?gvr,
                    pinned_gvr = ?pinned,
                    "SlashingDbReader: GVR mismatch; returning None (fail-closed)"
                );
                return None;
            }
            Ok(None) => {
                tracing::warn!(
                    "SlashingDbReader: DB has no pinned GVR; returning None \
                     (fail-closed — cannot confirm chain identity for safe-skip)"
                );
                return None;
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "SlashingDbReader: pinned_gvr() failed; returning None (fail-closed)"
                );
                return None;
            }
        }

        // Delegate to the SQL MAX query — do not materialise every attestation row.
        match self.last_signed_attestation_epoch(pubkey) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "SlashingDbReader: last_signed_attestation_epoch failed; returning None (fail-closed)"
                );
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SlashingDb;

    const PUBKEY: &str =
        "0xaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd";
    const GVR: Root = [7u8; 32];

    fn open_db_with_gvr() -> (SlashingDb, Root) {
        let db = SlashingDb::open_in_memory().expect("open_in_memory");
        let hex = format!("0x{}", hex::encode(GVR));
        db.set_genesis_validators_root(&hex).expect("set_genesis_validators_root");
        (db, GVR)
    }

    /// Multi-row history: reader answer must match `last_signed_attestation_epoch` (SQL MAX).
    #[test]
    fn last_signed_attestation_matches_sql_max_on_multi_row() {
        let (db, gvr) = open_db_with_gvr();

        db.stage_attestation(PUBKEY, 1, 3, None, &gvr)
            .expect("stage 1")
            .commit()
            .expect("commit 1");
        db.stage_attestation(PUBKEY, 3, 7, None, &gvr)
            .expect("stage 2")
            .commit()
            .expect("commit 2");
        db.stage_attestation(PUBKEY, 7, 12, None, &gvr)
            .expect("stage 3")
            .commit()
            .expect("commit 3");

        let via_reader = db.last_signed_attestation(PUBKEY, &gvr);
        let via_sql = db.last_signed_attestation_epoch(PUBKEY).expect("sql max");
        assert_eq!(via_reader, Some(12));
        assert_eq!(via_reader, via_sql, "reader must delegate to SQL MAX result");
    }

    /// DB error after the GVR gate must fail closed (`None`), not panic or leak.
    #[test]
    fn last_signed_attestation_db_error_returns_none() {
        let (db, gvr) = open_db_with_gvr();

        // Destroy the table so the MAX query returns an error.
        {
            let conn = db.conn.lock();
            conn.execute_batch("DROP TABLE attestations").expect("drop table");
        }

        assert_eq!(
            db.last_signed_attestation(PUBKEY, &gvr),
            None,
            "query failure must yield None (fail-closed)"
        );
    }
}
