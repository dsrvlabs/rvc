//! Watermark helpers and [`SlashingDb`] watermark/prune API.
//!
//! Pure code motion (E2 part 2): absorbs RF4-17's [`WatermarkKind`] / read-raise
//! helpers next to the `watermarks` table and the DB-facing set/get/prune methods.
//!
//! The table is addressed by type string (`block`, `att_source`, `att_target`).
//! Magic string literals at call sites are a fail-open hazard (a typo silently
//! disables a check). [`WatermarkKind`] makes those strings unrepresentable
//! outside this module; [`read_watermark`] / [`raise_watermark`] own the SELECT
//! and the monotonic-raise UPSERT.

use rusqlite::{Connection, OptionalExtension, TransactionBehavior};

use super::{normalize_pubkey, SlashingDb};
use crate::error::SlashingError;
use crate::types::PruneStats;
use eth_types::{Epoch, Slot};
use metrics::definitions as metrics;

/// Discriminant for a row in the `watermarks` table.
///
/// The SQL type column values live only in [`Self::as_sql_str`] so a typo in a
/// call site cannot silently disable a watermark check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WatermarkKind {
    /// Block-proposal floor (`watermark_type = 'block'`).
    Block,
    /// Attestation source-epoch floor (`watermark_type = 'att_source'`).
    AttestationSource,
    /// Attestation target-epoch floor (`watermark_type = 'att_target'`).
    AttestationTarget,
}

impl WatermarkKind {
    /// SQL `watermark_type` column value. Sole definition of the three literals.
    pub const fn as_sql_str(self) -> &'static str {
        match self {
            // These three string literals are the only watermark type values in
            // the crate; every SQL site binds them via a parameter.
            Self::Block => "block",
            Self::AttestationSource => "att_source",
            Self::AttestationTarget => "att_target",
        }
    }

    /// All kinds, in a stable order for round-trip / exhaustiveness tests.
    pub const fn all() -> [Self; 3] {
        [Self::Block, Self::AttestationSource, Self::AttestationTarget]
    }
}

/// Read the watermark value for `(pubkey, kind)`, if present.
///
/// Returns the raw integer stored in the table (slot or epoch, depending on kind).
pub fn read_watermark(
    conn: &Connection,
    pubkey: &str,
    kind: WatermarkKind,
) -> Result<Option<u64>, SlashingError> {
    let result: Option<i64> = conn
        .query_row(
            "SELECT value FROM watermarks WHERE pubkey = ?1 AND watermark_type = ?2",
            (pubkey, kind.as_sql_str()),
            |row| row.get(0),
        )
        .optional()?;
    Ok(result.map(|v| v as u64))
}

/// Raise a watermark monotonically.
///
/// - Missing row → INSERT.
/// - `value >= current` → UPDATE (same value is idempotent).
/// - `value < current` → [`SlashingError::WatermarkLowered`].
///
/// A watermark must never move backwards.
pub fn raise_watermark(
    conn: &Connection,
    pubkey: &str,
    kind: WatermarkKind,
    value: u64,
) -> Result<(), SlashingError> {
    let existing = read_watermark(conn, pubkey, kind)?;

    if let Some(current) = existing {
        if value < current {
            return Err(SlashingError::WatermarkLowered {
                pubkey: pubkey.to_string(),
                watermark_type: kind.as_sql_str().to_string(),
                current,
                attempted: value,
            });
        }
        conn.execute(
            "UPDATE watermarks SET value = ?1 WHERE pubkey = ?2 AND watermark_type = ?3",
            (value as i64, pubkey, kind.as_sql_str()),
        )?;
    } else {
        conn.execute(
            "INSERT INTO watermarks (pubkey, watermark_type, value) VALUES (?1, ?2, ?3)",
            (pubkey, kind.as_sql_str(), value as i64),
        )?;
    }
    Ok(())
}

/// Raise a watermark with `MAX(existing, new)` semantics (silent no-op when lower).
///
/// Used by interchange import so re-importing older maxima never fails and never
/// lowers floors. Prefer [`raise_watermark`] for explicit set APIs that must
/// surface [`SlashingError::WatermarkLowered`].
pub(crate) fn raise_watermark_max(
    conn: &Connection,
    pubkey: &str,
    kind: WatermarkKind,
    value: u64,
) -> Result<(), SlashingError> {
    conn.execute(
        "INSERT INTO watermarks (pubkey, watermark_type, value) VALUES (?1, ?2, ?3)
         ON CONFLICT(pubkey, watermark_type) DO UPDATE
         SET value = MAX(watermarks.value, excluded.value)",
        (pubkey, kind.as_sql_str(), value as i64),
    )?;
    Ok(())
}

// ── SlashingDb watermark / prune API ───────────────────────────────────────

impl SlashingDb {
    /// Set a block watermark for a validator. Blocks below this slot will be rejected and can be pruned.
    ///
    /// Watermarks can only be raised, never lowered. Setting the same value is idempotent.
    pub fn set_block_watermark(&self, pubkey: &str, slot: Slot) -> Result<(), SlashingError> {
        let pubkey = normalize_pubkey(pubkey)?;
        let mut conn = self.conn.lock();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        raise_watermark(&tx, pubkey.as_ref(), WatermarkKind::Block, slot)?;
        tx.commit()?;
        Ok(())
    }

    /// Delete all watermark rows.
    ///
    /// Test-only (`#[cfg(test)]` + `pub(crate)`): production release builds do not
    /// compile this API, so nothing outside the crate's unit tests can wipe the
    /// RF2-12 import floor. The complete-strategy integration harness loads history
    /// via `record_*` instead of calling this.
    #[cfg(test)]
    pub(crate) fn clear_watermarks(&self) -> Result<(), SlashingError> {
        let conn = self.conn.lock();
        conn.execute("DELETE FROM watermarks", [])?;
        Ok(())
    }

    /// Get the block watermark for a validator.
    pub fn get_block_watermark(&self, pubkey: &str) -> Result<Option<Slot>, SlashingError> {
        let pubkey = normalize_pubkey(pubkey)?;
        let conn = self.conn.lock();
        Ok(read_watermark(&conn, pubkey.as_ref(), WatermarkKind::Block)?.map(|v| v as Slot))
    }

    /// Set an attestation watermark for a validator.
    ///
    /// Both source and target epoch watermarks can only be raised, never lowered.
    pub fn set_attestation_watermark(
        &self,
        pubkey: &str,
        source_epoch: Epoch,
        target_epoch: Epoch,
    ) -> Result<(), SlashingError> {
        let pubkey = normalize_pubkey(pubkey)?;
        let mut conn = self.conn.lock();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        raise_watermark(&tx, pubkey.as_ref(), WatermarkKind::AttestationSource, source_epoch)?;
        raise_watermark(&tx, pubkey.as_ref(), WatermarkKind::AttestationTarget, target_epoch)?;
        tx.commit()?;
        Ok(())
    }

    /// Get the attestation watermark for a validator.
    ///
    /// Returns `Some((source_epoch, target_epoch))` if both watermarks are set, `None` otherwise.
    pub fn get_attestation_watermark(
        &self,
        pubkey: &str,
    ) -> Result<Option<(Epoch, Epoch)>, SlashingError> {
        let pubkey = normalize_pubkey(pubkey)?;
        let conn = self.conn.lock();

        let source = read_watermark(&conn, pubkey.as_ref(), WatermarkKind::AttestationSource)?;
        let target = read_watermark(&conn, pubkey.as_ref(), WatermarkKind::AttestationTarget)?;

        match (source, target) {
            (Some(s), Some(t)) => Ok(Some((s as Epoch, t as Epoch))),
            _ => Ok(None),
        }
    }

    /// Delete slashing protection records below all set watermarks.
    ///
    /// Returns an error if no watermarks are set (safety: prevents accidental deletion of all records).
    #[tracing::instrument(name = "slashing.db.prune", skip_all)]
    pub fn prune_below_watermarks(&self) -> Result<PruneStats, SlashingError> {
        let mut conn = self.conn.lock();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

        let watermark_count: i64 =
            tx.query_row("SELECT COUNT(*) FROM watermarks", [], |row| row.get(0))?;

        if watermark_count == 0 {
            return Err(SlashingError::NoWatermarksSet);
        }

        // Delete blocks below each validator's block watermark
        let blocks_deleted = tx.execute(
            "DELETE FROM blocks WHERE EXISTS (
                SELECT 1 FROM watermarks w
                WHERE w.pubkey = blocks.pubkey
                  AND w.watermark_type = ?1
                  AND blocks.slot < w.value
            )",
            [WatermarkKind::Block.as_sql_str()],
        )?;

        // Delete attestations below each validator's target epoch watermark
        let attestations_deleted = tx.execute(
            "DELETE FROM attestations WHERE EXISTS (
                SELECT 1 FROM watermarks w
                WHERE w.pubkey = attestations.pubkey
                  AND w.watermark_type = ?1
                  AND attestations.target_epoch < w.value
            )",
            [WatermarkKind::AttestationTarget.as_sql_str()],
        )?;

        tx.commit()?;

        // Increment prune metrics
        metrics::RVC_SLASHING_DB_PRUNE_TOTAL
            .with_label_values(&[metrics::prune_type::BLOCK])
            .inc_by(blocks_deleted as u64);
        metrics::RVC_SLASHING_DB_PRUNE_TOTAL
            .with_label_values(&[metrics::prune_type::ATTESTATION])
            .inc_by(attestations_deleted as u64);

        let pruned_count = blocks_deleted + attestations_deleted;
        tracing::info!(
            pruned_count,
            blocks_deleted,
            attestations_deleted,
            "slashing DB prune completed"
        );

        Ok(PruneStats {
            attestations_deleted: attestations_deleted as u64,
            blocks_deleted: blocks_deleted as u64,
        })
    }

    /// Count rows that [`Self::prune_below_watermarks`] would delete, without deleting.
    ///
    /// Used by `rvc slashing prune --dry-run`. Same safety gate as prune: errors with
    /// [`SlashingError::NoWatermarksSet`] when no watermarks are present.
    pub fn count_below_watermarks(&self) -> Result<PruneStats, SlashingError> {
        let conn = self.conn.lock();

        let watermark_count: i64 =
            conn.query_row("SELECT COUNT(*) FROM watermarks", [], |row| row.get(0))?;

        if watermark_count == 0 {
            return Err(SlashingError::NoWatermarksSet);
        }

        let blocks_deleted: i64 = conn.query_row(
            "SELECT COUNT(*) FROM blocks WHERE EXISTS (
                SELECT 1 FROM watermarks w
                WHERE w.pubkey = blocks.pubkey
                  AND w.watermark_type = ?1
                  AND blocks.slot < w.value
            )",
            [WatermarkKind::Block.as_sql_str()],
            |row| row.get(0),
        )?;

        let attestations_deleted: i64 = conn.query_row(
            "SELECT COUNT(*) FROM attestations WHERE EXISTS (
                SELECT 1 FROM watermarks w
                WHERE w.pubkey = attestations.pubkey
                  AND w.watermark_type = ?1
                  AND attestations.target_epoch < w.value
            )",
            [WatermarkKind::AttestationTarget.as_sql_str()],
            |row| row.get(0),
        )?;

        Ok(PruneStats {
            attestations_deleted: attestations_deleted as u64,
            blocks_deleted: blocks_deleted as u64,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::SlashingDb;

    fn open() -> SlashingDb {
        SlashingDb::open_in_memory().expect("open_in_memory")
    }

    /// RED → GREEN: raise_watermark must reject a backwards move.
    #[test]
    fn test_raise_watermark_rejects_backwards_move() {
        let db = open();
        let conn = db.conn.lock();
        let pk = "0xabc";

        raise_watermark(&conn, pk, WatermarkKind::Block, 1000).expect("initial raise");
        let err = raise_watermark(&conn, pk, WatermarkKind::Block, 500)
            .expect_err("backwards move must fail");
        match err {
            SlashingError::WatermarkLowered {
                ref pubkey,
                ref watermark_type,
                current,
                attempted,
            } => {
                assert_eq!(pubkey, pk);
                assert_eq!(watermark_type, "block");
                assert_eq!(current, 1000);
                assert_eq!(attempted, 500);
            }
            other => panic!("expected WatermarkLowered, got {other:?}"),
        }
        assert_eq!(read_watermark(&conn, pk, WatermarkKind::Block).unwrap(), Some(1000));
    }

    #[test]
    fn test_raise_watermark_same_value_is_idempotent() {
        let db = open();
        let conn = db.conn.lock();
        let pk = "0xabc";
        raise_watermark(&conn, pk, WatermarkKind::Block, 42).unwrap();
        raise_watermark(&conn, pk, WatermarkKind::Block, 42).unwrap();
        assert_eq!(read_watermark(&conn, pk, WatermarkKind::Block).unwrap(), Some(42));
    }

    #[test]
    fn test_raise_watermark_can_raise() {
        let db = open();
        let conn = db.conn.lock();
        let pk = "0xabc";
        raise_watermark(&conn, pk, WatermarkKind::AttestationSource, 10).unwrap();
        raise_watermark(&conn, pk, WatermarkKind::AttestationSource, 20).unwrap();
        assert_eq!(read_watermark(&conn, pk, WatermarkKind::AttestationSource).unwrap(), Some(20));
    }

    #[test]
    fn test_watermark_kind_round_trips_all_three_kinds() {
        let db = open();
        let conn = db.conn.lock();
        let pk = "0xdead";

        for (i, kind) in WatermarkKind::all().into_iter().enumerate() {
            let value = (i as u64 + 1) * 100;
            raise_watermark(&conn, pk, kind, value).unwrap();
            assert_eq!(read_watermark(&conn, pk, kind).unwrap(), Some(value));
            assert!(!kind.as_sql_str().is_empty());
        }

        assert_eq!(read_watermark(&conn, "0xother", WatermarkKind::Block).unwrap(), None);
    }

    #[test]
    fn test_raise_watermark_max_is_silent_on_lower() {
        let db = open();
        let conn = db.conn.lock();
        let pk = "0xabc";
        raise_watermark_max(&conn, pk, WatermarkKind::Block, 9000).unwrap();
        raise_watermark_max(&conn, pk, WatermarkKind::Block, 100).unwrap();
        assert_eq!(read_watermark(&conn, pk, WatermarkKind::Block).unwrap(), Some(9000));
    }

    /// Grep-style guard: no raw SQL type literals of the form
    /// `watermark_type = '<value>'` remain outside doc comments.
    #[test]
    fn test_no_raw_watermark_type_literals_remain() {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let src_dir = std::path::Path::new(manifest_dir).join("src");
        // Build the needle without embedding the full forbidden pattern as a
        // contiguous string in this file (so this test does not flag itself).
        let needle = format!("watermark_type = {}", "'");
        let mut offenders = Vec::new();

        for path in walkdir_rs(&src_dir) {
            let text = std::fs::read_to_string(&path).expect("read source");
            for (idx, line) in text.lines().enumerate() {
                let trimmed = line.trim_start();
                // Doc/comment lines may mention the SQL form for documentation.
                if trimmed.starts_with("//")
                    || trimmed.starts_with("///")
                    || trimmed.starts_with("//!")
                {
                    continue;
                }
                if line.contains(&needle) {
                    offenders.push(format!("{}:{}: {line}", path.display(), idx + 1));
                }
            }
        }

        assert!(
            offenders.is_empty(),
            "raw watermark type SQL literals must not remain in code; found:\n{}",
            offenders.join("\n")
        );
    }

    fn walkdir_rs(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut out = Vec::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(d) = stack.pop() {
            for entry in std::fs::read_dir(&d).expect("read_dir") {
                let entry = entry.expect("entry");
                let p = entry.path();
                if p.is_dir() {
                    stack.push(p);
                } else if p.extension().and_then(|e| e.to_str()) == Some("rs") {
                    out.push(p);
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod db_api_tests {
    use super::*;
    use crate::db::SlashingDb;
    use eth_types::Root;
    use tempfile::tempdir;

    const TEST_GVR: Root = [0u8; 32];

    #[test]
    fn test_prune_set_and_get_block_watermark() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        assert!(db.get_block_watermark("0x1234").unwrap().is_none());

        db.set_block_watermark("0x1234", 1000).expect("set should succeed");
        assert_eq!(db.get_block_watermark("0x1234").unwrap(), Some(1000));
    }

    #[test]
    fn test_prune_block_watermark_raise_succeeds() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        db.set_block_watermark("0x1234", 1000).expect("set should succeed");
        db.set_block_watermark("0x1234", 2000).expect("raise should succeed");
        assert_eq!(db.get_block_watermark("0x1234").unwrap(), Some(2000));
    }

    #[test]
    fn test_prune_block_watermark_lower_fails() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        db.set_block_watermark("0x1234", 2000).expect("set should succeed");
        let result = db.set_block_watermark("0x1234", 1000);
        assert!(result.is_err());
        match result.unwrap_err() {
            SlashingError::WatermarkLowered { .. } => {}
            other => panic!("expected WatermarkLowered, got: {other:?}"),
        }
        assert_eq!(db.get_block_watermark("0x1234").unwrap(), Some(2000));
    }

    #[test]
    fn test_prune_block_watermark_same_value_succeeds() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        db.set_block_watermark("0x1234", 1000).expect("set should succeed");
        db.set_block_watermark("0x1234", 1000).expect("same value should succeed");
        assert_eq!(db.get_block_watermark("0x1234").unwrap(), Some(1000));
    }

    #[test]
    fn test_prune_set_and_get_attestation_watermark() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        assert!(db.get_attestation_watermark("0x1234").unwrap().is_none());

        db.set_attestation_watermark("0x1234", 100, 101).expect("set should succeed");
        assert_eq!(db.get_attestation_watermark("0x1234").unwrap(), Some((100, 101)));
    }

    #[test]
    fn test_prune_attestation_watermark_raise_succeeds() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        db.set_attestation_watermark("0x1234", 100, 101).expect("set should succeed");
        db.set_attestation_watermark("0x1234", 200, 201).expect("raise should succeed");
        assert_eq!(db.get_attestation_watermark("0x1234").unwrap(), Some((200, 201)));
    }

    #[test]
    fn test_prune_attestation_watermark_lower_source_fails() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        db.set_attestation_watermark("0x1234", 200, 201).expect("set should succeed");
        let result = db.set_attestation_watermark("0x1234", 100, 300);
        assert!(result.is_err());
        match result.unwrap_err() {
            SlashingError::WatermarkLowered { .. } => {}
            other => panic!("expected WatermarkLowered, got: {other:?}"),
        }
    }

    #[test]
    fn test_prune_attestation_watermark_lower_target_fails() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        db.set_attestation_watermark("0x1234", 200, 201).expect("set should succeed");
        let result = db.set_attestation_watermark("0x1234", 300, 100);
        assert!(result.is_err());
        match result.unwrap_err() {
            SlashingError::WatermarkLowered { .. } => {}
            other => panic!("expected WatermarkLowered, got: {other:?}"),
        }
    }

    #[test]
    fn test_prune_attestation_watermark_same_value_succeeds() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        db.set_attestation_watermark("0x1234", 100, 101).expect("set should succeed");
        db.set_attestation_watermark("0x1234", 100, 101).expect("same should succeed");
        assert_eq!(db.get_attestation_watermark("0x1234").unwrap(), Some((100, 101)));
    }

    #[test]
    fn test_prune_watermarks_persist_across_connections() {
        let dir = tempdir().expect("failed to create temp dir");
        let path = dir.path().join("watermarks.db");

        {
            let db = SlashingDb::open(&path).expect("failed to open db");
            db.set_block_watermark("0x1234", 1000).expect("set should succeed");
            db.set_attestation_watermark("0x1234", 100, 101).expect("set should succeed");
        }

        {
            let db = SlashingDb::open(&path).expect("failed to reopen db");
            assert_eq!(db.get_block_watermark("0x1234").unwrap(), Some(1000));
            assert_eq!(db.get_attestation_watermark("0x1234").unwrap(), Some((100, 101)));
        }
    }

    #[test]
    fn test_prune_watermarks_per_validator_isolated() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        db.set_block_watermark("0x1111", 1000).expect("set should succeed");
        db.set_block_watermark("0x2222", 2000).expect("set should succeed");

        assert_eq!(db.get_block_watermark("0x1111").unwrap(), Some(1000));
        assert_eq!(db.get_block_watermark("0x2222").unwrap(), Some(2000));
        assert!(db.get_block_watermark("0x3333").unwrap().is_none());
    }

    #[test]
    fn test_prune_check_and_record_block_rejects_below_watermark() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        db.set_block_watermark("0x1234", 1000).expect("set should succeed");

        let result = db.check_and_record_block("0x1234", 999, None, &[0u8; 32]);
        assert!(result.is_err());
        match result.unwrap_err() {
            SlashingError::BelowBlockWatermark { .. } => {}
            other => panic!("expected BelowBlockWatermark, got: {other:?}"),
        }

        // Should not have recorded anything
        assert!(db.get_blocks("0x1234").unwrap().is_empty());
    }

    #[test]
    fn test_prune_check_and_record_attestation_rejects_below_target_watermark() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        db.set_attestation_watermark("0x1234", 100, 101).expect("set should succeed");

        // source=100 is at source watermark, but target=100 < target watermark=101
        let result = db.check_and_record_attestation("0x1234", 100, 100, None, &[0u8; 32]);
        assert!(result.is_err());
        match result.unwrap_err() {
            SlashingError::BelowAttestationWatermark { .. } => {}
            other => panic!("expected BelowAttestationWatermark, got: {other:?}"),
        }

        assert!(db.get_attestations("0x1234").unwrap().is_empty());
    }

    #[test]
    fn test_prune_check_and_record_attestation_rejects_below_source_watermark() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        db.set_attestation_watermark("0x1234", 20, 20).expect("set should succeed");

        // source=1 is below source watermark=20
        let result = db.check_and_record_attestation("0x1234", 1, 31, None, &[0u8; 32]);
        assert!(result.is_err());
        match result.unwrap_err() {
            SlashingError::BelowAttestationSourceWatermark { .. } => {}
            other => panic!("expected BelowAttestationSourceWatermark, got: {other:?}"),
        }

        // Should not have recorded anything
        assert!(db.get_attestations("0x1234").unwrap().is_empty());
    }

    #[test]
    fn test_prune_below_watermarks_deletes_correct_records() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        // Insert blocks: 100, 200, 300, 400, 500
        for slot in [100, 200, 300, 400, 500] {
            db.seed_block("0x1234", slot, None, &TEST_GVR).expect("record should succeed");
        }

        // Insert attestations: target epochs 10, 20, 30, 40, 50
        for (src, tgt) in [(5, 10), (10, 20), (20, 30), (30, 40), (40, 50)] {
            db.seed_attestation("0x1234", src, tgt, None, &TEST_GVR)
                .expect("record should succeed");
        }

        // Set watermarks: block at 300, attestation at (20, 30)
        db.set_block_watermark("0x1234", 300).expect("set should succeed");
        db.set_attestation_watermark("0x1234", 20, 30).expect("set should succeed");

        let stats = db.prune_below_watermarks().expect("prune should succeed");

        // Blocks below 300: slots 100, 200 → 2 deleted
        assert_eq!(stats.blocks_deleted, 2);
        // Attestations below target 30: target epochs 10, 20 → 2 deleted
        assert_eq!(stats.attestations_deleted, 2);

        // Verify remaining records
        let blocks = db.get_blocks("0x1234").unwrap();
        assert_eq!(blocks.len(), 3);
        assert_eq!(blocks[0].slot, 300);

        let attestations = db.get_attestations("0x1234").unwrap();
        assert_eq!(attestations.len(), 3);
        assert_eq!(attestations[0].target_epoch, 30);
    }

    #[test]
    fn test_prune_without_watermarks_fails() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        // Insert some records but no watermarks
        db.seed_block("0x1234", 100, None, &TEST_GVR).expect("record should succeed");
        db.seed_attestation("0x1234", 5, 10, None, &TEST_GVR).expect("record should succeed");

        let result = db.prune_below_watermarks();
        assert!(result.is_err());
        match result.unwrap_err() {
            SlashingError::NoWatermarksSet => {}
            other => panic!("expected NoWatermarksSet, got: {other:?}"),
        }

        // Records should still be intact
        assert_eq!(db.get_blocks("0x1234").unwrap().len(), 1);
        assert_eq!(db.get_attestations("0x1234").unwrap().len(), 1);
    }

    #[test]
    fn test_prune_multiple_validators() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        // Validator 1: blocks at 100, 200; watermark at 200
        db.seed_block("0x1111", 100, None, &TEST_GVR).expect("record");
        db.seed_block("0x1111", 200, None, &TEST_GVR).expect("record");
        db.set_block_watermark("0x1111", 200).expect("set");

        // Validator 2: blocks at 300, 400; watermark at 350
        db.seed_block("0x2222", 300, None, &TEST_GVR).expect("record");
        db.seed_block("0x2222", 400, None, &TEST_GVR).expect("record");
        db.set_block_watermark("0x2222", 350).expect("set");

        let stats = db.prune_below_watermarks().expect("prune should succeed");

        // V1: slot 100 < 200 → deleted; V2: slot 300 < 350 → deleted
        assert_eq!(stats.blocks_deleted, 2);

        assert_eq!(db.get_blocks("0x1111").unwrap().len(), 1);
        assert_eq!(db.get_blocks("0x2222").unwrap().len(), 1);
    }

    #[test]
    fn test_prune_nothing_to_prune() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        // All records are at or above watermark
        db.seed_block("0x1234", 200, None, &TEST_GVR).expect("record");
        db.seed_block("0x1234", 300, None, &TEST_GVR).expect("record");
        db.set_block_watermark("0x1234", 100).expect("set");

        let stats = db.prune_below_watermarks().expect("prune should succeed");
        assert_eq!(stats.blocks_deleted, 0);
        assert_eq!(stats.attestations_deleted, 0);

        assert_eq!(db.get_blocks("0x1234").unwrap().len(), 2);
    }

    #[test]
    fn test_count_below_watermarks_matches_prune_without_deleting() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        for slot in [100u64, 200, 300, 400, 500] {
            db.seed_block("0x1234", slot, None, &TEST_GVR).expect("record");
        }
        for (src, tgt) in [(5u64, 10), (10, 20), (20, 30), (30, 40), (40, 50)] {
            db.seed_attestation("0x1234", src, tgt, None, &TEST_GVR).expect("record");
        }
        db.set_block_watermark("0x1234", 300).expect("set");
        db.set_attestation_watermark("0x1234", 20, 30).expect("set");

        let counted = db.count_below_watermarks().expect("count");
        assert_eq!(counted.blocks_deleted, 2);
        assert_eq!(counted.attestations_deleted, 2);
        assert_eq!(db.get_blocks("0x1234").unwrap().len(), 5);
        assert_eq!(db.get_attestations("0x1234").unwrap().len(), 5);

        let pruned = db.prune_below_watermarks().expect("prune");
        assert_eq!(pruned, counted);
    }

    #[test]
    fn test_prune_below_watermarks_increments_metric() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        db.seed_block("0x1234", 100, None, &TEST_GVR).expect("record");
        db.seed_block("0x1234", 200, None, &TEST_GVR).expect("record");
        db.set_block_watermark("0x1234", 150).expect("set");

        let before = metrics::RVC_SLASHING_DB_PRUNE_TOTAL
            .with_label_values(&[metrics::prune_type::BLOCK])
            .get();
        let stats = db.prune_below_watermarks().expect("prune");
        assert_eq!(stats.blocks_deleted, 1);
        let after = metrics::RVC_SLASHING_DB_PRUNE_TOTAL
            .with_label_values(&[metrics::prune_type::BLOCK])
            .get();
        assert!(
            after > before,
            "rvc_slashing_db_prune_total{{type=block}} must increase: before={before} after={after}"
        );
    }
}
