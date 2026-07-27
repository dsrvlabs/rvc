//! Schema migrations for [`SlashingDb`] (v1→v2→v3).
//!
//! Absorbs the former top-level `migration.rs` (v3) and the migrate cluster from
//! the monolithic `db.rs`. A single [`read_schema_version`] is shared by all
//! migration paths (E2 part 1).

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension, TransactionBehavior};

use super::SlashingDb;
use crate::error::SlashingError;

/// Read the `schema_version` integer from the `metadata` table.
///
/// Returns `None` if the row is absent (database predates ISSUE-1.2 — treat as v1).
///
/// Shared by v2/v3 migration gates (single reader after E2 part 1 deduplication).
pub(crate) fn read_schema_version(conn: &Connection) -> Result<Option<i64>, SlashingError> {
    let v: Option<String> = conn
        .query_row("SELECT value FROM metadata WHERE key = 'schema_version'", [], |row| row.get(0))
        .optional()?;
    Ok(v.and_then(|s| s.parse().ok()))
}

/// Check whether a column exists in a table using `PRAGMA table_info`.
///
/// Used for idempotent ALTER TABLE: SQLite 3.35 added `ADD COLUMN IF NOT EXISTS`,
/// but we guard with a pragma check for maximum portability.
fn column_exists(conn: &Connection, table: &str, column: &str) -> Result<bool, SlashingError> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let exists = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .any(|r| r.map(|name| name == column).unwrap_or(false));
    Ok(exists)
}

impl SlashingDb {
    /// Create the initial database schema.
    ///
    /// For a **brand-new** database, creates v2 tables directly (with `client_cn` and
    /// `genesis_validators_root` columns and CN-scoped unique indexes). For an existing v1
    /// database, the v1 tables already exist (the CREATE TABLE IF NOT EXISTS is a no-op for
    /// the old-style columns) and `migrate_to_v2` handles the upgrade.
    ///
    /// We use a v2-native CREATE TABLE so that fresh DBs start at v2 without going through
    /// the ALTER TABLE path. The inline `UNIQUE` constraints from v1 are absent here; the
    /// CN-scoped unique indexes are created by `run_v2_migration_transaction`.
    pub(crate) fn migrate(&self) -> Result<(), SlashingError> {
        let conn = self.conn.lock();
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS attestations (
                id INTEGER PRIMARY KEY,
                client_cn TEXT NOT NULL DEFAULT '__legacy__',
                pubkey TEXT NOT NULL,
                source_epoch INTEGER NOT NULL,
                target_epoch INTEGER NOT NULL,
                signing_root TEXT,
                genesis_validators_root TEXT
            );

            CREATE TABLE IF NOT EXISTS blocks (
                id INTEGER PRIMARY KEY,
                client_cn TEXT NOT NULL DEFAULT '__legacy__',
                pubkey TEXT NOT NULL,
                slot INTEGER NOT NULL,
                signing_root TEXT,
                genesis_validators_root TEXT
            );

            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS watermarks (
                pubkey TEXT NOT NULL,
                watermark_type TEXT NOT NULL,
                value INTEGER NOT NULL,
                UNIQUE(pubkey, watermark_type)
            );
            ",
        )?;
        Ok(())
    }

    /// Create an atomic backup of the database file to `<path>.bak.<UNIX_TS>`.
    ///
    /// # Approach
    /// 1. Issue `PRAGMA wal_checkpoint(TRUNCATE)` to flush WAL into the main DB file
    ///    so the backup contains a clean, self-contained snapshot.
    /// 2. Copy `path` to `<path>.bak.<ts>` via a temp file in the same directory
    ///    (atomic on POSIX: write to temp, `sync_all`, rename).
    /// 3. Return the backup path on success.
    ///
    /// The WAL / SHM sidecar files are **not** separately copied: after a full WAL
    /// checkpoint the main file is self-consistent and the sidecars are empty/reset.
    /// Operators who want a byte-for-byte sidecar copy can use `sqlite3 .backup` instead.
    ///
    /// # Errors
    /// Returns `SlashingError::MigrationFailed` if the backup cannot be created.
    ///
    /// # Symlink note
    /// The backup destination uses a UNIX-timestamp suffix that is predictable
    /// to the second. A local attacker who can write to the parent directory
    /// could pre-create that path as a symlink. The temp-then-rename pattern
    /// limits the impact (the main DB file is never truncated), but a future
    /// hardening pass could open with `O_NOFOLLOW`.
    pub(crate) fn backup_before_migrate(
        conn: &Connection,
        path: &Path,
    ) -> Result<PathBuf, SlashingError> {
        // Checkpoint the WAL so the main file is self-consistent.
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;

        let ts = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);

        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| SlashingError::MigrationFailed("DB path has no file name".into()))?;

        let parent = path
            .parent()
            .ok_or_else(|| SlashingError::MigrationFailed("DB path has no parent dir".into()))?;

        let backup_name = format!("{file_name}.bak.{ts}");
        let backup_path = parent.join(&backup_name);

        // Write to a temp file first, then rename (atomic on POSIX). The temp
        // name embeds the same UNIX_TS as the final backup so concurrent
        // migrations on different DB files in the same parent dir cannot
        // collide on the temp path.
        let tmp_name = format!("{file_name}.bak.{ts}.tmp");
        let tmp_path = parent.join(&tmp_name);

        std::fs::copy(path, &tmp_path).map_err(|e| {
            SlashingError::MigrationFailed(format!("failed to copy DB to temp file: {e}"))
        })?;

        // Match the main DB file's 0o600 mode so the backup is not
        // world-readable on hosts with a permissive umask.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600)).map_err(
                |e| {
                    SlashingError::MigrationFailed(format!(
                        "failed to set 0o600 on backup file: {e}"
                    ))
                },
            )?;
        }

        {
            let f = std::fs::OpenOptions::new().write(true).open(&tmp_path).map_err(|e| {
                SlashingError::MigrationFailed(format!("failed to open temp backup for sync: {e}"))
            })?;
            f.sync_all().map_err(|e| {
                SlashingError::MigrationFailed(format!("sync_all on backup failed: {e}"))
            })?;
        }

        std::fs::rename(&tmp_path, &backup_path).map_err(|e| {
            // Clean up temp file on rename failure.
            let _ = std::fs::remove_file(&tmp_path);
            SlashingError::MigrationFailed(format!("failed to rename backup file: {e}"))
        })?;

        tracing::info!(
            backup = %backup_path.display(),
            "slashing DB backup created before schema migration"
        );
        Ok(backup_path)
    }

    /// Migrate the database to schema v2 if it is currently at v1.
    ///
    /// # Decision logic
    /// - `schema_version >= 2`: no-op (already at v2+).
    /// - `schema_version` absent AND `client_cn` column already exists on `attestations`:
    ///   the DB was just created by `migrate()` with the v2-native CREATE TABLE — set
    ///   `schema_version=2` without backing up (no v1 rows to preserve).
    /// - `schema_version` absent AND `client_cn` column **missing**: existing populated v1
    ///   DB — take a backup, run ALTER TABLE batch, set `schema_version=2`.
    ///
    /// Migration order for the v1→v2 path:
    /// 1. Read `schema_version`. If absent, check for `client_cn` column.
    /// 2. Backup `<path>.bak.<UNIX_TS>` (atomic copy + sync_all).
    /// 3. Begin immediate transaction.
    /// 4. Idempotent ALTER TABLE batch (guarded by `PRAGMA table_info`).
    /// 5. Drop old indexes; create CN-scoped ones.
    /// 6. UPSERT `schema_version=2`.
    /// 7. Commit. Any failure → `Err(SlashingError::MigrationFailed)`.
    pub(crate) fn migrate_to_v2(&self, path: &Path) -> Result<(), SlashingError> {
        let (schema_version, has_cn_column) = {
            let conn = self.conn.lock();
            let sv = read_schema_version(&conn)?;
            let has_cn = column_exists(&conn, "attestations", "client_cn")?;
            (sv, has_cn)
        };

        if schema_version.unwrap_or(0) >= 2 {
            // Already at v2 or newer; no migration needed.
            return Ok(());
        }

        if has_cn_column {
            // Fresh DB created by migrate() with v2-native CREATE TABLE.
            // Just set schema_version=2 — no backup needed (no v1 rows to preserve).
            let conn = self.conn.lock();
            conn.execute_batch(
                "INSERT OR REPLACE INTO metadata (key, value) VALUES ('schema_version', '2')",
            )?;
            tracing::debug!(path = %path.display(), "fresh v2 DB: set schema_version=2");
            return Ok(());
        }

        // Existing v1 DB: take a backup, then migrate.
        {
            let conn = self.conn.lock();
            Self::backup_before_migrate(&conn, path)
                .map_err(|e| SlashingError::MigrationFailed(format!("backup failed: {e}")))?;
        }

        // Run migration in a single immediate transaction.
        let result = {
            let mut conn = self.conn.lock();
            Self::run_v2_migration_transaction(&mut conn)
        };

        result.map_err(|e| {
            tracing::error!(error = %e, "schema v2 migration failed; original DB is intact in backup");
            match e {
                SlashingError::MigrationFailed(_) => e,
                other => SlashingError::MigrationFailed(format!("{other}")),
            }
        })?;

        tracing::info!(path = %path.display(), "schema migrated to v2");
        Ok(())
    }

    /// Migrate the database to schema v3 (pubkey-scoped slashing indices).
    ///
    /// Gate: `schema_version >= 3` → no-op (idempotent).
    ///
    /// Delegates to [`migrate_to_v3`] which runs all steps in a
    /// single `IMMEDIATE` transaction.  A failure rolls back completely so the
    /// DB remains at v2 with CN-scoped indices (degraded but safe).
    pub(crate) fn migrate_to_v3(&self) -> Result<(), SlashingError> {
        let mut conn = self.conn.lock();
        migrate_to_v3(&mut conn).map_err(|e| {
            tracing::error!(
                error = %e,
                "schema v3 migration failed; database remains at v2 with CN-scoped indices"
            );
            e
        })
    }

    pub(crate) fn run_v2_migration_transaction(conn: &mut Connection) -> Result<(), SlashingError> {
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

        // Add `client_cn` column to `attestations` if missing.
        if !column_exists(&tx, "attestations", "client_cn")? {
            tx.execute_batch(
                "ALTER TABLE attestations ADD COLUMN client_cn TEXT NOT NULL DEFAULT '__legacy__'",
            )?;
        }

        // Add `genesis_validators_root` column to `attestations` if missing.
        if !column_exists(&tx, "attestations", "genesis_validators_root")? {
            tx.execute_batch("ALTER TABLE attestations ADD COLUMN genesis_validators_root TEXT")?;
        }

        // Add `client_cn` column to `blocks` if missing.
        if !column_exists(&tx, "blocks", "client_cn")? {
            tx.execute_batch(
                "ALTER TABLE blocks ADD COLUMN client_cn TEXT NOT NULL DEFAULT '__legacy__'",
            )?;
        }

        // Add `genesis_validators_root` column to `blocks` if missing.
        if !column_exists(&tx, "blocks", "genesis_validators_root")? {
            tx.execute_batch("ALTER TABLE blocks ADD COLUMN genesis_validators_root TEXT")?;
        }

        // Drop old uniqueness indexes and create new CN-scoped ones.
        // `DROP INDEX IF EXISTS` is always safe.
        tx.execute_batch(
            "
            DROP INDEX IF EXISTS idx_attestations_pubkey_target;
            DROP INDEX IF EXISTS idx_blocks_pubkey_slot;

            CREATE UNIQUE INDEX IF NOT EXISTS idx_attestations_cn_pubkey_target
                ON attestations(client_cn, pubkey, target_epoch);

            CREATE UNIQUE INDEX IF NOT EXISTS idx_blocks_cn_pubkey_slot
                ON blocks(client_cn, pubkey, slot);
            ",
        )?;

        // Upsert schema_version = 2.
        tx.execute_batch(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES ('schema_version', '2')",
        )?;

        tx.commit()?;
        Ok(())
    }
}

// ── v3 migration free functions (absorbed from migration.rs) ──────────────

/// Run the v2 → v3 migration on an already-open connection.
///
/// Gate: if `schema_version >= 3` this is a no-op (idempotent).
pub(crate) fn migrate_to_v3(conn: &mut Connection) -> Result<(), SlashingError> {
    let version = read_schema_version(conn)?;
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

    tx.execute("INSERT OR REPLACE INTO metadata (key, value) VALUES ('schema_version', '3')", [])
        .map_err(|e| SlashingError::MigrationFailed(format!("set schema_version=3: {e}")))?;

    tx.execute(
        "INSERT OR REPLACE INTO metadata (key, value) VALUES ('migration_v3_applied_at', ?1)",
        [now_ts.as_str()],
    )
    .map_err(|e| SlashingError::MigrationFailed(format!("set migration_v3_applied_at: {e}")))?;

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

#[cfg(test)]
mod tests {
    use super::SlashingDb;
    use super::{migrate_to_v3, read_schema_version};
    use tempfile::tempdir;

    #[test]
    fn test_migration_creates_tables() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        let conn = db.conn.lock();
        let table_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('attestations', 'blocks')",
                [],
                |row| row.get(0),
            )
            .expect("failed to query tables");

        assert_eq!(table_count, 2);
    }

    #[test]
    fn test_migration_is_idempotent() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        assert!(db.migrate().is_ok());
        assert!(db.migrate().is_ok());
    }

    #[test]
    fn test_prune_watermarks_table_created_on_migration() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        let conn = db.conn.lock();
        let table_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name = 'watermarks'",
                [],
                |row| row.get(0),
            )
            .expect("failed to query tables");
        assert_eq!(table_count, 1);
    }

    /// Licenses collapsing the former dual schema-version readers (db + migration)
    /// into one shared [`read_schema_version`]. Fresh open yields v3; explicit
    /// metadata writes cover the v1-absent and v2 gates.
    #[test]
    fn test_schema_version_readers_agree() {
        // Fresh DB is migrated to v3 on open — single reader must report 3.
        let db = SlashingDb::open_in_memory().expect("open");
        {
            let conn = db.conn.lock();
            assert_eq!(read_schema_version(&conn).unwrap(), Some(3));
        }

        // Simulate a v2-gated DB: set schema_version=2 and re-read.
        {
            let conn = db.conn.lock();
            conn.execute_batch(
                "INSERT OR REPLACE INTO metadata (key, value) VALUES ('schema_version', '2')",
            )
            .unwrap();
            assert_eq!(read_schema_version(&conn).unwrap(), Some(2));
        }

        // Absent row → None (legacy v1 treatment).
        {
            let conn = db.conn.lock();
            conn.execute("DELETE FROM metadata WHERE key = 'schema_version'", []).unwrap();
            assert_eq!(read_schema_version(&conn).unwrap(), None);
        }

        // Free-function v3 gate uses the same reader (idempotent no-op when already ≥3).
        {
            let mut conn = db.conn.lock();
            conn.execute_batch(
                "INSERT OR REPLACE INTO metadata (key, value) VALUES ('schema_version', '3')",
            )
            .unwrap();
            migrate_to_v3(&mut conn).expect("v3 no-op");
            assert_eq!(read_schema_version(&conn).unwrap(), Some(3));
        }
    }

    /// Re-export / inherent-method audit: public open + permission surface used
    /// by VC/signer must remain callable on [`SlashingDb`] after the split.
    #[test]
    fn test_public_api_surface_unchanged() {
        // Compile-time-ish checklist via callable paths (not just names).
        let dir = tempdir().unwrap();
        let path = dir.path().join("api.db");
        let (db, created) = getashing_open(&path);
        assert!(created);
        let _ = db; // open_with_create_info

        let db = SlashingDb::open(&path).expect("open");
        let _ = SlashingDb::open_in_memory().expect("mem");
        db.check_file_permissions();
        let _ = db.check_file_permissions_strict();
        let _ = db.query_pragma_i64("synchronous");
        db.set_strict_semantics(true);

        // Method presence probes for other pub items still on SlashingDb (mod.rs).
        let _ = db.genesis_validators_root();
        let _ = db.check_integrity();
        let _ = db.get_attestations("0x00");
        let _ = db.get_blocks("0x00");
        let _ = db.get_block_watermark("0x00");
        let _ = db.get_attestation_watermark("0x00");
        let _ = db.count_below_watermarks();
    }

    fn getashing_open(path: &std::path::Path) -> (SlashingDb, bool) {
        SlashingDb::open_with_create_info(path).expect("create")
    }
}
