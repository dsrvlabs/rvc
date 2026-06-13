//! Schema v3 migration: re-key slashing indices from CN-scoped to pubkey-scoped.
//!
//! # v2 → v3 changes
//!
//! - Drop `idx_attestations_cn_pubkey_target` and `idx_blocks_cn_pubkey_slot`.
//! - Create `idx_attestations_pubkey_gvr_target ON attestations(pubkey, genesis_validators_root, target_epoch)`.
//! - Create `idx_blocks_pubkey_gvr_slot ON blocks(pubkey, genesis_validators_root, slot)`.
//! - Add `slashing_history_marker INTEGER NOT NULL DEFAULT 0` to both tables.
//! - Back-fill `genesis_validators_root` for rows where it is NULL.
//! - Resolve duplicate rows that would violate the new indices BEFORE creating them.
//! - Set `schema_version = '3'`.
//!
//! # Transactional safety
//!
//! The entire migration runs inside a single `BEGIN IMMEDIATE` … `COMMIT` block.
//! Any failure rolls back the transaction, leaving the DB unchanged at v2.

use rusqlite::{Connection, OptionalExtension, TransactionBehavior};

use crate::error::SlashingError;

/// Run the v2 → v3 migration on an already-open connection.
///
/// Gate: if `schema_version >= 3` this is a no-op (idempotent).
pub(crate) fn migrate_to_v3(conn: &mut Connection) -> Result<(), SlashingError> {
    let version: Option<i64> = {
        let sv: Option<String> = conn
            .query_row("SELECT value FROM metadata WHERE key = 'schema_version'", [], |row| {
                row.get(0)
            })
            .optional()?;
        sv.and_then(|s| s.parse().ok())
    };
    if version.unwrap_or(0) >= 3 {
        return Ok(());
    }

    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate).map_err(|e| {
        SlashingError::MigrationFailed(format!("failed to begin v3 migration transaction: {e}"))
    })?;

    let result = run_v3_steps(&tx);

    match result {
        Ok(()) => tx
            .commit()
            .map_err(|e| SlashingError::MigrationFailed(format!("v3 commit failed: {e}"))),
        Err(e) => {
            let _ = tx.rollback();
            Err(e)
        }
    }
}

fn run_v3_steps(tx: &Connection) -> Result<(), SlashingError> {
    add_marker_column_if_missing(tx, "attestations")?;
    add_marker_column_if_missing(tx, "blocks")?;
    backfill_gvr(tx)?;
    resolve_duplicate_blocks(tx)?;
    resolve_duplicate_attestations(tx)?;

    tx.execute_batch(
        "DROP INDEX IF EXISTS idx_attestations_cn_pubkey_target;
         DROP INDEX IF EXISTS idx_blocks_cn_pubkey_slot;",
    )
    .map_err(|e| SlashingError::MigrationFailed(format!("drop CN-keyed indices: {e}")))?;

    tx.execute_batch(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_attestations_pubkey_gvr_target
             ON attestations(pubkey, genesis_validators_root, target_epoch);
         CREATE UNIQUE INDEX IF NOT EXISTS idx_blocks_pubkey_gvr_slot
             ON blocks(pubkey, genesis_validators_root, slot);",
    )
    .map_err(|e| SlashingError::MigrationFailed(format!("create pubkey-scoped indices: {e}")))?;

    let now_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        .to_string();

    tx.execute_batch(&format!(
        "INSERT OR REPLACE INTO metadata (key, value) VALUES ('schema_version', '3');
         INSERT OR REPLACE INTO metadata (key, value) VALUES ('migration_v3_applied_at', '{now_ts}');"
    ))
    .map_err(|e| SlashingError::MigrationFailed(format!("update schema_version to 3: {e}")))?;

    Ok(())
}

fn add_marker_column_if_missing(tx: &Connection, table: &str) -> Result<(), SlashingError> {
    let column_names = query_column_names(tx, table)?;
    if !column_names.iter().any(|n| n == "slashing_history_marker") {
        tx.execute_batch(&format!(
            "ALTER TABLE {table} ADD COLUMN slashing_history_marker INTEGER NOT NULL DEFAULT 0"
        ))
        .map_err(|e| {
            SlashingError::MigrationFailed(format!("ALTER TABLE {table} ADD COLUMN: {e}"))
        })?;
    }
    Ok(())
}

fn query_column_names(tx: &Connection, table: &str) -> Result<Vec<String>, SlashingError> {
    let sql = format!("PRAGMA table_info({table})");
    // Use query_row-style loop to avoid lifetime issues with MappedRows.
    let mut stmt = tx
        .prepare(&sql)
        .map_err(|e| SlashingError::MigrationFailed(format!("PRAGMA table_info: {e}")))?;
    let mut names = Vec::new();
    let mut rows = stmt
        .query([])
        .map_err(|e| SlashingError::MigrationFailed(format!("query table_info: {e}")))?;
    while let Some(row) = rows
        .next()
        .map_err(|e| SlashingError::MigrationFailed(format!("next table_info row: {e}")))?
    {
        let name: String = row
            .get(1)
            .map_err(|e| SlashingError::MigrationFailed(format!("get column name: {e}")))?;
        names.push(name);
    }
    Ok(names)
}

fn backfill_gvr(tx: &Connection) -> Result<(), SlashingError> {
    let null_att: i64 = tx
        .query_row(
            "SELECT COUNT(*) FROM attestations WHERE genesis_validators_root IS NULL",
            [],
            |row| row.get(0),
        )
        .map_err(|e| SlashingError::MigrationFailed(format!("count NULL att gvr: {e}")))?;

    let null_blk: i64 = tx
        .query_row("SELECT COUNT(*) FROM blocks WHERE genesis_validators_root IS NULL", [], |row| {
            row.get(0)
        })
        .map_err(|e| SlashingError::MigrationFailed(format!("count NULL blk gvr: {e}")))?;

    if null_att == 0 && null_blk == 0 {
        return Ok(());
    }

    let pinned_gvr: Option<String> = tx
        .query_row("SELECT value FROM metadata WHERE key = 'genesis_validators_root'", [], |row| {
            row.get(0)
        })
        .optional()
        .map_err(|e| SlashingError::MigrationFailed(format!("read metadata gvr: {e}")))?;

    match pinned_gvr {
        None => Err(SlashingError::MigrationFailed(format!(
            "v3 migration: {null_att} attestation and {null_blk} block rows have NULL \
             genesis_validators_root, but no genesis_validators_root is pinned in metadata. \
             Cannot create pubkey+gvr unique index safely. Pin genesis_validators_root first."
        ))),
        Some(gvr_hex) => {
            // gvr_hex comes from our own metadata; filter to safe chars for interpolation.
            let safe_hex: String =
                gvr_hex.chars().filter(|c| c.is_ascii_hexdigit() || *c == 'x').collect();
            tx.execute(
                "UPDATE attestations SET genesis_validators_root = ?1
                 WHERE genesis_validators_root IS NULL",
                [safe_hex.as_str()],
            )
            .map_err(|e| SlashingError::MigrationFailed(format!("backfill att gvr: {e}")))?;
            tx.execute(
                "UPDATE blocks SET genesis_validators_root = ?1
                 WHERE genesis_validators_root IS NULL",
                [safe_hex.as_str()],
            )
            .map_err(|e| SlashingError::MigrationFailed(format!("backfill blk gvr: {e}")))?;
            Ok(())
        }
    }
}

fn resolve_duplicate_blocks(tx: &Connection) -> Result<(), SlashingError> {
    let groups = query_vec(
        tx,
        "SELECT pubkey, genesis_validators_root, slot
         FROM blocks
         GROUP BY pubkey, genesis_validators_root, slot
         HAVING COUNT(*) > 1",
        [],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, i64>(2)?)),
    )?;

    for (pubkey, gvr, slot) in &groups {
        let rows = query_vec(
            tx,
            "SELECT id, signing_root, client_cn
             FROM blocks
             WHERE pubkey = ?1 AND genesis_validators_root = ?2 AND slot = ?3
             ORDER BY
                 CASE WHEN signing_root IS NULL THEN 1 ELSE 0 END ASC,
                 signing_root ASC,
                 client_cn ASC",
            rusqlite::params![pubkey, gvr, slot],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )?;

        if rows.is_empty() {
            continue;
        }

        let (keeper_id, keeper_root, _) = &rows[0];
        let has_conflict = rows[1..].iter().any(|(_, sr, _)| sr != keeper_root);
        let marker = if has_conflict { 1i64 } else { 0i64 };

        let min_cn =
            rows.iter().map(|(_, _, cn)| cn.as_str()).min().unwrap_or("__legacy__").to_owned();

        // Delete all non-keeper rows FIRST (before updating keeper), because the
        // v2 CN-keyed unique index would fire if we UPDATE the keeper's client_cn
        // while the duplicate rows still exist.
        for (row_id, _, _) in &rows[1..] {
            tx.execute("DELETE FROM blocks WHERE id = ?1", [row_id]).map_err(|e| {
                SlashingError::MigrationFailed(format!("delete dup block {row_id}: {e}"))
            })?;
        }

        tx.execute(
            "UPDATE blocks SET client_cn = ?1, slashing_history_marker = ?2 WHERE id = ?3",
            rusqlite::params![min_cn, marker, keeper_id],
        )
        .map_err(|e| SlashingError::MigrationFailed(format!("update keeper block: {e}")))?;
    }

    Ok(())
}

fn resolve_duplicate_attestations(tx: &Connection) -> Result<(), SlashingError> {
    let groups = query_vec(
        tx,
        "SELECT pubkey, genesis_validators_root, target_epoch
         FROM attestations
         GROUP BY pubkey, genesis_validators_root, target_epoch
         HAVING COUNT(*) > 1",
        [],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, i64>(2)?)),
    )?;

    for (pubkey, gvr, target_epoch) in &groups {
        let rows = query_vec(
            tx,
            "SELECT id, source_epoch, signing_root, client_cn
             FROM attestations
             WHERE pubkey = ?1 AND genesis_validators_root = ?2 AND target_epoch = ?3
             ORDER BY source_epoch DESC, client_cn ASC",
            rusqlite::params![pubkey, gvr, target_epoch],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )?;

        if rows.is_empty() {
            continue;
        }

        let (keeper_id, keeper_source, keeper_root, _) = &rows[0];
        let has_conflict =
            rows[1..].iter().any(|(_, src, root, _)| src != keeper_source || root != keeper_root);
        let marker = if has_conflict { 1i64 } else { 0i64 };

        let min_cn =
            rows.iter().map(|(_, _, _, cn)| cn.as_str()).min().unwrap_or("__legacy__").to_owned();

        // Delete non-keeper rows FIRST before updating keeper's client_cn, to avoid
        // violating the v2 CN-keyed unique constraint (client_cn, pubkey, target_epoch).
        for (row_id, _, _, _) in &rows[1..] {
            tx.execute("DELETE FROM attestations WHERE id = ?1", [row_id]).map_err(|e| {
                SlashingError::MigrationFailed(format!("delete dup att {row_id}: {e}"))
            })?;
        }

        tx.execute(
            "UPDATE attestations SET client_cn = ?1, slashing_history_marker = ?2 WHERE id = ?3",
            rusqlite::params![min_cn, marker, keeper_id],
        )
        .map_err(|e| SlashingError::MigrationFailed(format!("update keeper att: {e}")))?;
    }

    Ok(())
}

/// Execute a query and collect all rows into a Vec using the given row-mapper.
///
/// This helper avoids the rusqlite MappedRows lifetime issue that arises when
/// using `query_map` with a block-local `stmt` — the iterator borrows from `stmt`
/// which cannot escape the block where it is declared.  By collecting eagerly
/// inside the function, the borrow of `stmt` ends before the function returns.
fn query_vec<T, P, F>(
    conn: &Connection,
    sql: &str,
    params: P,
    f: F,
) -> Result<Vec<T>, SlashingError>
where
    P: rusqlite::Params,
    F: Fn(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
{
    let mut stmt =
        conn.prepare(sql).map_err(|e| SlashingError::MigrationFailed(format!("prepare: {e}")))?;
    let mut rows =
        stmt.query(params).map_err(|e| SlashingError::MigrationFailed(format!("query: {e}")))?;
    let mut result = Vec::new();
    while let Some(row) =
        rows.next().map_err(|e| SlashingError::MigrationFailed(format!("next: {e}")))?
    {
        result.push(f(row).map_err(|e| SlashingError::MigrationFailed(format!("map: {e}")))?);
    }
    Ok(result)
}
