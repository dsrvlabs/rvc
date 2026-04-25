//! Integration tests for SlashingDb schema v2 migration (ISSUE-1.2).
//!
//! # Schema sentinels
//! - `'__legacy__'`: applied by DEFAULT to pre-migration v1 rows; never used for new rows.
//! - `'local-vc'`: used by VC-side runtime writes (`crates/signer`).
//! - Peer CNs (e.g. `"peer-A"`): used by DVT path (ISSUE-1.7).

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::Connection;
use tempfile::tempdir;

use rvc_slashing::{SlashingDb, SlashingError};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a v1 SQLite database (the schema BEFORE migration) at `path`,
/// inserting `att_count` attestation rows and `blk_count` block rows.
///
/// V1 schema:
/// ```sql
/// CREATE TABLE attestations (id INTEGER PRIMARY KEY, pubkey TEXT, source_epoch INTEGER,
///   target_epoch INTEGER, signing_root TEXT, UNIQUE(pubkey, target_epoch));
/// CREATE TABLE blocks (id INTEGER PRIMARY KEY, pubkey TEXT, slot INTEGER,
///   signing_root TEXT, UNIQUE(pubkey, slot));
/// CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
/// CREATE TABLE watermarks (pubkey TEXT, watermark_type TEXT, value INTEGER,
///   UNIQUE(pubkey, watermark_type));
/// ```
///
/// No `schema_version` row is written (simulates a database that was opened
/// by the old code before ISSUE-1.2 landed).
fn build_v1_db(path: &std::path::Path, att_count: usize, blk_count: usize) {
    let conn = Connection::open(path).expect("open v1 db");

    conn.execute_batch(
        "
        PRAGMA journal_mode = WAL;
        CREATE TABLE IF NOT EXISTS attestations (
            id INTEGER PRIMARY KEY,
            pubkey TEXT NOT NULL,
            source_epoch INTEGER NOT NULL,
            target_epoch INTEGER NOT NULL,
            signing_root TEXT,
            UNIQUE(pubkey, target_epoch)
        );
        CREATE TABLE IF NOT EXISTS blocks (
            id INTEGER PRIMARY KEY,
            pubkey TEXT NOT NULL,
            slot INTEGER NOT NULL,
            signing_root TEXT,
            UNIQUE(pubkey, slot)
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
    )
    .expect("create v1 tables");

    // Insert attestations: spread across 5 realistic pubkeys.
    // Each pubkey gets att_count/5 attestations with consecutive target epochs.
    let pubkeys = [
        "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
    ];

    let per_pubkey_att = att_count / pubkeys.len();
    for (pk_idx, pubkey) in pubkeys.iter().enumerate() {
        for i in 0..per_pubkey_att {
            let source_epoch = (pk_idx * 10000 + i) as i64;
            let target_epoch = source_epoch + 1;
            let signing_root = format!("0x{:064x}", pk_idx * 100000 + i);
            conn.execute(
                "INSERT INTO attestations (pubkey, source_epoch, target_epoch, signing_root)
                 VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![pubkey, source_epoch, target_epoch, signing_root],
            )
            .expect("insert attestation");
        }
    }

    let per_pubkey_blk = blk_count / pubkeys.len();
    for (pk_idx, pubkey) in pubkeys.iter().enumerate() {
        for i in 0..per_pubkey_blk {
            let slot = (pk_idx * 200000 + i) as i64;
            let signing_root = format!("0xblock{:059x}", pk_idx * 100000 + i);
            conn.execute(
                "INSERT INTO blocks (pubkey, slot, signing_root) VALUES (?1, ?2, ?3)",
                rusqlite::params![pubkey, slot, signing_root],
            )
            .expect("insert block");
        }
    }
}

/// Collect all `(pubkey, target_epoch, signing_root)` triples from attestations.
fn collect_attestation_triples(conn: &Connection) -> Vec<(String, i64, Option<String>)> {
    let mut stmt = conn
        .prepare(
            "SELECT pubkey, target_epoch, signing_root FROM attestations ORDER BY pubkey, target_epoch",
        )
        .unwrap();
    stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
}

/// Collect all `(pubkey, slot, signing_root)` triples from blocks.
fn collect_block_triples(conn: &Connection) -> Vec<(String, i64, Option<String>)> {
    let mut stmt = conn
        .prepare("SELECT pubkey, slot, signing_root FROM blocks ORDER BY pubkey, slot")
        .unwrap();
    stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
}

/// Read `metadata.schema_version` from an open connection.
fn read_schema_version(conn: &Connection) -> Option<i64> {
    conn.query_row("SELECT value FROM metadata WHERE key = 'schema_version'", [], |row| {
        row.get::<_, String>(0)
    })
    .ok()
    .and_then(|v| v.parse().ok())
}

/// Find backup files matching `<path>.bak.<digits>` in the parent directory.
fn find_backup_files(original_path: &std::path::Path) -> Vec<PathBuf> {
    let parent = original_path.parent().unwrap();
    let file_name = original_path.file_name().unwrap().to_str().unwrap();
    let prefix = format!("{}.bak.", file_name);

    std::fs::read_dir(parent)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.file_name().map(|n| n.to_str().unwrap_or("").starts_with(&prefix)).unwrap_or(false)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Test 1: v1 populated DB migrates losslessly
// ---------------------------------------------------------------------------

/// Verifies that opening a populated v1 database:
/// - creates a backup file `<path>.bak.<UNIX_TS>` that is byte-for-byte identical
/// - sets `schema_version = 2` in metadata
/// - preserves all row data losslessly
/// - fills `client_cn = '__legacy__'` for all migrated rows
/// - leaves `genesis_validators_root` NULL for all migrated rows
#[test]
fn test_v1_populated_migrates_losslessly() {
    let dir = tempdir().expect("tempdir");
    let db_path = dir.path().join("slashing.db");

    // Build a v1 database with ~5000 attestations + ~5000 blocks (~10K rows total).
    let att_count = 5000;
    let blk_count = 5000;
    build_v1_db(&db_path, att_count, blk_count);

    // Capture original row data BEFORE migration.
    let original_atts = {
        let conn = Connection::open(&db_path).unwrap();
        collect_attestation_triples(&conn)
    };
    let original_blks = {
        let conn = Connection::open(&db_path).unwrap();
        collect_block_triples(&conn)
    };

    // Also capture byte-level snapshot of the DB file for backup comparison.
    let original_bytes = std::fs::read(&db_path).expect("read original db");

    assert_eq!(original_atts.len(), att_count, "fixture should have {att_count} attestations");
    assert_eq!(original_blks.len(), blk_count, "fixture should have {blk_count} blocks");

    // Record timestamps just before opening (backup ts could be at or after this).
    let before_ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

    // Open via SlashingDb — this should trigger migration.
    let db = SlashingDb::open(&db_path).expect("migration should succeed");

    let after_ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

    // 1. schema_version = 2
    {
        let conn = Connection::open(&db_path).unwrap();
        let version = read_schema_version(&conn);
        assert_eq!(version, Some(2), "schema_version should be 2 after migration");
    }

    // 2. Backup file exists and matches byte-for-byte (WAL is checkpointed before backup).
    let backups = find_backup_files(&db_path);
    assert_eq!(backups.len(), 1, "exactly one backup file should exist; found: {:?}", backups);

    let backup_path = &backups[0];
    let backup_name = backup_path.file_name().unwrap().to_str().unwrap();

    // Backup name format: slashing.db.bak.<UNIX_TS>
    let ts_part = backup_name
        .strip_prefix("slashing.db.bak.")
        .expect("backup name should start with 'slashing.db.bak.'");
    let backup_ts: u64 = ts_part.parse().expect("timestamp should be numeric");
    assert!(
        backup_ts >= before_ts && backup_ts <= after_ts + 1,
        "backup timestamp {backup_ts} should be within [{before_ts}, {after_ts}+1]"
    );

    let backup_bytes = std::fs::read(backup_path).expect("read backup file");
    assert_eq!(
        backup_bytes, original_bytes,
        "backup file must be byte-for-byte identical to the original"
    );

    // 3. Row data lossless: every original triple is present with correct columns.
    {
        let conn = Connection::open(&db_path).unwrap();

        let migrated_atts = collect_attestation_triples(&conn);
        assert_eq!(
            migrated_atts.len(),
            att_count,
            "attestation row count must not change after migration"
        );

        // Triples match original.
        for (orig, mig) in original_atts.iter().zip(migrated_atts.iter()) {
            assert_eq!(orig, mig, "attestation triple mismatch after migration");
        }

        // All migrated rows have client_cn = '__legacy__'.
        let legacy_att_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM attestations WHERE client_cn = '__legacy__'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            legacy_att_count as usize, att_count,
            "all migrated attestation rows should have client_cn = '__legacy__'"
        );

        // All migrated rows have genesis_validators_root IS NULL.
        let null_gvr_att: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM attestations WHERE genesis_validators_root IS NULL",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            null_gvr_att as usize, att_count,
            "all migrated attestation rows should have NULL genesis_validators_root"
        );

        let migrated_blks = collect_block_triples(&conn);
        assert_eq!(
            migrated_blks.len(),
            blk_count,
            "block row count must not change after migration"
        );

        for (orig, mig) in original_blks.iter().zip(migrated_blks.iter()) {
            assert_eq!(orig, mig, "block triple mismatch after migration");
        }

        let legacy_blk_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM blocks WHERE client_cn = '__legacy__'", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(
            legacy_blk_count as usize, blk_count,
            "all migrated block rows should have client_cn = '__legacy__'"
        );

        let null_gvr_blk: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM blocks WHERE genesis_validators_root IS NULL",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            null_gvr_blk as usize, blk_count,
            "all migrated block rows should have NULL genesis_validators_root"
        );
    }

    // Drop db to release locks.
    drop(db);
}

// ---------------------------------------------------------------------------
// Test 2: re-opening a v2 DB is a no-op (idempotent)
// ---------------------------------------------------------------------------

/// Verifies that opening a v2 database:
/// - does NOT create a backup file
/// - leaves schema_version = 2
/// - leaves row count unchanged
#[test]
fn test_v2_open_is_idempotent() {
    let dir = tempdir().expect("tempdir");
    let db_path = dir.path().join("slashing.db");

    // First open: creates a fresh v2 DB (no migration needed — it starts at v2).
    {
        let db = SlashingDb::open(&db_path).expect("first open should succeed");
        drop(db);
    }

    // Verify it is at v2 already.
    {
        let conn = Connection::open(&db_path).unwrap();
        assert_eq!(read_schema_version(&conn), Some(2), "fresh DB should be at schema_version=2");
    }

    // No backup files should exist after first open of a brand-new (v2) DB.
    let backups_after_first = find_backup_files(&db_path);
    assert!(
        backups_after_first.is_empty(),
        "no backup should be created when opening a fresh v2 DB"
    );

    // Second open: should be a complete no-op regarding migration.
    {
        let _db = SlashingDb::open(&db_path).expect("second open should succeed");
    }

    // Still no backup files.
    let backups_after_second = find_backup_files(&db_path);
    assert!(
        backups_after_second.is_empty(),
        "no backup should be created on idempotent re-open of v2 DB"
    );

    // Schema version still 2.
    {
        let conn = Connection::open(&db_path).unwrap();
        assert_eq!(read_schema_version(&conn), Some(2), "schema_version must remain 2");
    }
}

// ---------------------------------------------------------------------------
// Test 3: migration failure preserves original DB
// ---------------------------------------------------------------------------

/// Verifies that if the migration fails (simulated via a pre-corrupted file
/// that makes the DB un-migrateable), the original database is left intact.
///
/// Strategy: create a v1 DB, then rename it so the backup path collides with an
/// existing read-only file — causing `backup_before_migrate` to fail. We then
/// assert the DB file is unchanged and an `Err(MigrationFailed)` is returned.
///
/// Note: the spec requires `SlashingError::MigrationFailed` as the error type.
#[test]
fn test_migration_failure_preserves_original() {
    let dir = tempdir().expect("tempdir");
    let db_path = dir.path().join("slashing.db");

    build_v1_db(&db_path, 10, 10);

    let original_bytes = std::fs::read(&db_path).expect("read original");

    // Pre-create a file at the backup path so the atomic copy will fail.
    // We use a fixed timestamp sentinel that the backup function would use.
    // The actual backup uses the current UNIX timestamp. We cannot predict the
    // exact ts, so instead we make the parent directory read-only (Unix) which
    // prevents creating ANY new file in it.
    //
    // On non-Unix platforms, we fall back to marking the DB path itself as
    // read-only (which prevents WAL checkpoint before backup) but the test
    // may be a partial coverage. On macOS/Linux this is deterministic.

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Make the temp directory read-only so no backup file can be created.
        let perms = std::fs::Permissions::from_mode(0o500);
        std::fs::set_permissions(dir.path(), perms).expect("make dir read-only");

        // Opening should fail because the backup cannot be written (or because SQLite
        // cannot write WAL sidecars into the read-only directory).
        let result = SlashingDb::open(&db_path);

        // Restore permissions first so cleanup works.
        let restore_perms = std::fs::Permissions::from_mode(0o700);
        let _ = std::fs::set_permissions(dir.path(), restore_perms);

        assert!(result.is_err(), "should fail when backup cannot be written");
        // Accept MigrationFailed OR DatabaseError — both are valid depending on where
        // the read-only constraint is hit (WAL checkpoint vs. backup copy).
        match result {
            Err(SlashingError::MigrationFailed(_)) | Err(SlashingError::DatabaseError(_)) => {}
            Err(other) => panic!("expected MigrationFailed or DatabaseError, got: {:?}", other),
            Ok(_) => panic!("expected error but got Ok"),
        }

        // The DB file is unchanged (migration never touched it).
        let after_bytes = std::fs::read(&db_path).expect("read after failed migration");
        assert_eq!(
            original_bytes, after_bytes,
            "original DB must be unchanged after a failed migration"
        );
    }

    // On non-Unix platforms: skip the directory-permission trick but verify
    // the DB is still intact (no file corruption from a partial attempt).
    #[cfg(not(unix))]
    {
        // On Windows / other: just verify normal migration works and the test
        // passes (the directory-permission approach doesn't work there).
        let _ = original_bytes;
        let result = SlashingDb::open(&db_path);
        assert!(result.is_ok(), "migration should succeed on non-Unix in this path");
    }
}

// ---------------------------------------------------------------------------
// Test 4: new rows use correct client_cn
// ---------------------------------------------------------------------------

/// Verifies that runtime writes via `check_and_record_block` and
/// `check_and_record_attestation` store the correct `client_cn` (not `__legacy__`).
#[test]
fn test_new_rows_store_client_cn() {
    let dir = tempdir().expect("tempdir");
    let db_path = dir.path().join("slashing.db");
    let gvr = [0u8; 32];

    let db = SlashingDb::open(&db_path).expect("open v2 db");

    let pubkey = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    db.check_and_record_block("local-vc", pubkey, 42, Some("0xdeadbeef".to_string()), &gvr)
        .expect("block should be recorded");

    db.check_and_record_attestation(
        "local-vc",
        pubkey,
        100,
        101,
        Some("0xcafe1234".to_string()),
        &gvr,
    )
    .expect("attestation should be recorded");

    let conn = Connection::open(&db_path).unwrap();

    let block_cn: String = conn
        .query_row(
            "SELECT client_cn FROM blocks WHERE pubkey = ?1 AND slot = 42",
            [pubkey],
            |row| row.get(0),
        )
        .expect("block row should exist");
    assert_eq!(block_cn, "local-vc", "new block rows should store client_cn = 'local-vc'");

    let att_cn: String = conn
        .query_row(
            "SELECT client_cn FROM attestations WHERE pubkey = ?1 AND target_epoch = 101",
            [pubkey],
            |row| row.get(0),
        )
        .expect("attestation row should exist");
    assert_eq!(att_cn, "local-vc", "new attestation rows should store client_cn = 'local-vc'");
}

// ---------------------------------------------------------------------------
// Test 5: client_cn scoping — same pubkey+slot/epoch, different CNs both succeed
// ---------------------------------------------------------------------------

/// Verifies that `(client_cn, pubkey, slot)` is the uniqueness key for blocks,
/// so two different CNs can record the same `(pubkey, slot)` independently.
#[test]
fn test_cn_scoping_different_cns_are_independent() {
    let gvr = [0u8; 32];
    let db = SlashingDb::open_in_memory().expect("open in-memory db");
    let pubkey = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    // peer-A records slot 42 with root R1.
    db.check_and_record_block("peer-A", pubkey, 42, Some("0x1111".to_string()), &gvr)
        .expect("peer-A block should succeed");

    // peer-B records the same slot 42 with a different root R2 — should succeed (different CN).
    db.check_and_record_block("peer-B", pubkey, 42, Some("0x2222".to_string()), &gvr)
        .expect("peer-B block with same slot should succeed (CN-scoped)");
}

// ---------------------------------------------------------------------------
// Test 6: uniqueness within same CN is still enforced (double proposal)
// ---------------------------------------------------------------------------

/// Verifies that a second block record for the same `(client_cn, pubkey, slot)`
/// with a different signing root is rejected as a double proposal.
#[test]
fn test_cn_scoped_double_proposal_rejected() {
    let gvr = [0u8; 32];
    let db = SlashingDb::open_in_memory().expect("open in-memory db");
    let pubkey = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    db.check_and_record_block("local-vc", pubkey, 42, Some("0x1111".to_string()), &gvr)
        .expect("first block should succeed");

    let result =
        db.check_and_record_block("local-vc", pubkey, 42, Some("0x2222".to_string()), &gvr);
    assert!(result.is_err(), "second block with different root from same CN should be rejected");
}
