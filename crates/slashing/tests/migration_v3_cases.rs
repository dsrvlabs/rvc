//! Migration regression tests: v2 → v3 schema (Issue 2.4).
//!
//! Builds a synthetic v2-schema DB (CN-keyed indices) and inserts rows that cover
//! all five duplicate row-pair cases described in the migration specification:
//!
//! 1. Block: same (pubkey,gvr,slot), differing only `client_cn` → keep one; smallest CN.
//! 2. Block: same (pubkey,gvr,slot), differing `signing_root` → keep MIN(root); marker=1.
//! 3. Attestation: same (pubkey,gvr,target_epoch), differing only `client_cn` → keep one.
//! 4. Attestation: same (pubkey,gvr,target_epoch), differing `source_epoch` → keep MAX(source); marker=1.
//! 5. Attestation: same (pubkey,gvr,target_epoch), differing `signing_root` → keep one; marker=1.
//!
//! Assertions:
//! - Each case resolved per the policy.
//! - New unique indices present; CN-keyed ones gone.
//! - Migration is idempotent (run again → no-op).
//! - Pre-migration-rejected messages still rejected after migration.
//! - Cross-CN double-sign that was silently accepted is now rejected.

use rusqlite::Connection;
use tempfile::tempdir;

use rvc_slashing::{
    AttestationSlashingViolation, BlockSlashingViolation, SlashingDb, SlashingError,
};

/// A realistic BLS pubkey (48 bytes × 2 hex chars + "0x").
const PUBKEY: &str =
    "0xabababababababababababababababababababababababababababababababababababababababababababababababababababab";

/// GVR used in all rows.
const GVR_HEX: &str = "0x0707070707070707070707070707070707070707070707070707070707070707";

// ── DB builder ───────────────────────────────────────────────────────────────

/// Build a v2-schema DB (CN-keyed unique indices) at `path`.
///
/// Inserts rows for all five duplicate-pair test cases.  Each case inserts two rows
/// with the same (pubkey, gvr, slot/target_epoch) but differing in the dimension
/// under test.
fn build_v2_db_with_duplicates(path: &std::path::Path) {
    let conn = Connection::open(path).expect("open");
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
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
         -- v2 CN-keyed indices.
         CREATE UNIQUE INDEX IF NOT EXISTS idx_attestations_cn_pubkey_target
             ON attestations(client_cn, pubkey, target_epoch);
         CREATE UNIQUE INDEX IF NOT EXISTS idx_blocks_cn_pubkey_slot
             ON blocks(client_cn, pubkey, slot);
         INSERT OR REPLACE INTO metadata (key, value) VALUES ('schema_version', '2');
         INSERT OR REPLACE INTO metadata (key, value) VALUES ('genesis_validators_root', '0x0707070707070707070707070707070707070707070707070707070707070707');",
    )
    .expect("create v2 schema");

    // ── Case 1: Blocks same (pubkey, gvr, slot=1000), differing client_cn only.
    // Expected: keep one row, client_cn = lexicographically smaller ('cn-A').
    conn.execute(
        "INSERT INTO blocks (client_cn, pubkey, slot, signing_root, genesis_validators_root)
         VALUES ('cn-B', ?1, 1000, '0xroot_same', ?2)",
        [PUBKEY, GVR_HEX],
    )
    .expect("case1 cn-B block");
    conn.execute(
        "INSERT INTO blocks (client_cn, pubkey, slot, signing_root, genesis_validators_root)
         VALUES ('cn-A', ?1, 1000, '0xroot_same', ?2)",
        [PUBKEY, GVR_HEX],
    )
    .expect("case1 cn-A block");

    // ── Case 2: Blocks same (pubkey, gvr, slot=2000), differing signing_root.
    // Expected: keep row with MIN signing_root ('0xroot_a' < '0xroot_b'); marker=1.
    conn.execute(
        "INSERT INTO blocks (client_cn, pubkey, slot, signing_root, genesis_validators_root)
         VALUES ('cn-A', ?1, 2000, '0xroot_b', ?2)",
        [PUBKEY, GVR_HEX],
    )
    .expect("case2 root_b block");
    conn.execute(
        "INSERT INTO blocks (client_cn, pubkey, slot, signing_root, genesis_validators_root)
         VALUES ('cn-B', ?1, 2000, '0xroot_a', ?2)",
        [PUBKEY, GVR_HEX],
    )
    .expect("case2 root_a block");

    // ── Case 3: Attestations same (pubkey, gvr, target_epoch=50), differing client_cn only.
    // Expected: keep one row.
    conn.execute(
        "INSERT INTO attestations (client_cn, pubkey, source_epoch, target_epoch, signing_root, genesis_validators_root)
         VALUES ('cn-B', ?1, 40, 50, '0xatt_root_same', ?2)",
        [PUBKEY, GVR_HEX],
    )
    .expect("case3 cn-B att");
    conn.execute(
        "INSERT INTO attestations (client_cn, pubkey, source_epoch, target_epoch, signing_root, genesis_validators_root)
         VALUES ('cn-A', ?1, 40, 50, '0xatt_root_same', ?2)",
        [PUBKEY, GVR_HEX],
    )
    .expect("case3 cn-A att");

    // ── Case 4: Attestations same (pubkey, gvr, target_epoch=60), differing source_epoch.
    // Expected: keep row with LARGER source_epoch (40 > 30); marker=1.
    conn.execute(
        "INSERT INTO attestations (client_cn, pubkey, source_epoch, target_epoch, signing_root, genesis_validators_root)
         VALUES ('cn-A', ?1, 30, 60, '0xatt_root_case4', ?2)",
        [PUBKEY, GVR_HEX],
    )
    .expect("case4 source=30 att");
    conn.execute(
        "INSERT INTO attestations (client_cn, pubkey, source_epoch, target_epoch, signing_root, genesis_validators_root)
         VALUES ('cn-B', ?1, 40, 60, '0xatt_root_case4', ?2)",
        [PUBKEY, GVR_HEX],
    )
    .expect("case4 source=40 att");

    // ── Case 5: Attestations same (pubkey, gvr, target_epoch=70), differing signing_root.
    // Expected: keep one (first by source_epoch DESC then cn ASC); marker=1.
    conn.execute(
        "INSERT INTO attestations (client_cn, pubkey, source_epoch, target_epoch, signing_root, genesis_validators_root)
         VALUES ('cn-A', ?1, 55, 70, '0xatt_root_z', ?2)",
        [PUBKEY, GVR_HEX],
    )
    .expect("case5 root_z att");
    conn.execute(
        "INSERT INTO attestations (client_cn, pubkey, source_epoch, target_epoch, signing_root, genesis_validators_root)
         VALUES ('cn-B', ?1, 55, 70, '0xatt_root_y', ?2)",
        [PUBKEY, GVR_HEX],
    )
    .expect("case5 root_y att");
}

// ── Helper queries ────────────────────────────────────────────────────────────

fn index_exists(conn: &Connection, name: &str) -> bool {
    conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?1",
        [name],
        |row| row.get::<_, i64>(0),
    )
    .unwrap_or(0)
        > 0
}

fn read_schema_version(conn: &Connection) -> Option<i64> {
    conn.query_row("SELECT value FROM metadata WHERE key = 'schema_version'", [], |row| {
        row.get::<_, String>(0)
    })
    .ok()
    .and_then(|v| v.parse().ok())
}

// ── Test 1: all five cases resolved correctly ─────────────────────────────────

#[test]
fn test_v3_migration_resolves_all_five_cases() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("dup_cases.db");

    build_v2_db_with_duplicates(&path);

    // Trigger migration by opening via SlashingDb.
    let db = SlashingDb::open(&path).expect("open must trigger v3 migration");
    drop(db);

    let conn = Connection::open(&path).expect("direct open");

    // Schema version = 3.
    assert_eq!(read_schema_version(&conn), Some(3));

    // ── Case 1: block at slot=1000, same root, differing CN.
    let (cn_1, marker_1, root_1): (String, i64, Option<String>) = conn
        .query_row(
            "SELECT client_cn, slashing_history_marker, signing_root
             FROM blocks WHERE pubkey = ?1 AND slot = 1000",
            [PUBKEY],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("case1 block must exist");

    assert_eq!(cn_1, "cn-A", "case1: keeper client_cn must be lexicographically smaller 'cn-A'");
    assert_eq!(marker_1, 0, "case1: no conflicting root → marker=0");
    assert_eq!(root_1.as_deref(), Some("0xroot_same"));

    let count_1: i64 = conn
        .query_row("SELECT COUNT(*) FROM blocks WHERE pubkey = ?1 AND slot = 1000", [PUBKEY], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(count_1, 1, "case1: exactly one row survives");

    // ── Case 2: block at slot=2000, differing signing_root.
    let (root_2, marker_2): (Option<String>, i64) = conn
        .query_row(
            "SELECT signing_root, slashing_history_marker
             FROM blocks WHERE pubkey = ?1 AND slot = 2000",
            [PUBKEY],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("case2 block must exist");

    assert_eq!(
        root_2.as_deref(),
        Some("0xroot_a"),
        "case2: keeper must have MIN signing_root '0xroot_a'"
    );
    assert_eq!(marker_2, 1, "case2: conflicting root → marker=1");

    let count_2: i64 = conn
        .query_row("SELECT COUNT(*) FROM blocks WHERE pubkey = ?1 AND slot = 2000", [PUBKEY], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(count_2, 1, "case2: exactly one row survives");

    // ── Case 3: attestation at target_epoch=50, same root, differing CN.
    let (att_count_3, att_marker_3): (i64, i64) = conn
        .query_row(
            "SELECT COUNT(*), slashing_history_marker
             FROM attestations WHERE pubkey = ?1 AND target_epoch = 50",
            [PUBKEY],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("case3 att must exist");

    assert_eq!(att_count_3, 1, "case3: exactly one row survives");
    assert_eq!(att_marker_3, 0, "case3: no conflicting source/root → marker=0");

    // ── Case 4: attestation at target_epoch=60, differing source_epoch.
    let (att_source_4, att_marker_4): (i64, i64) = conn
        .query_row(
            "SELECT source_epoch, slashing_history_marker
             FROM attestations WHERE pubkey = ?1 AND target_epoch = 60",
            [PUBKEY],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("case4 att must exist");

    assert_eq!(att_source_4, 40, "case4: keeper must have LARGER source_epoch=40");
    assert_eq!(att_marker_4, 1, "case4: conflicting source_epoch → marker=1");

    let count_4: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM attestations WHERE pubkey = ?1 AND target_epoch = 60",
            [PUBKEY],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count_4, 1, "case4: exactly one row survives");

    // ── Case 5: attestation at target_epoch=70, differing signing_root.
    // Both rows have source_epoch=55; sorted by client_cn ASC → 'cn-A' is keeper.
    // Keeper has root='0xatt_root_z'; cn-B's root='0xatt_root_y' is deleted.
    let (att_root_5, att_cn_5, att_marker_5): (Option<String>, String, i64) = conn
        .query_row(
            "SELECT signing_root, client_cn, slashing_history_marker
             FROM attestations WHERE pubkey = ?1 AND target_epoch = 70",
            [PUBKEY],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("case5 att must exist");

    assert_eq!(
        att_root_5.as_deref(),
        Some("0xatt_root_z"),
        "case5: keeper must have signing_root='0xatt_root_z' (cn-A, first by client_cn ASC)"
    );
    assert_eq!(
        att_cn_5, "cn-A",
        "case5: keeper client_cn must be 'cn-A' (lexicographically smaller)"
    );
    assert_eq!(att_marker_5, 1, "case5: conflicting signing_root → marker=1");

    let count_5: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM attestations WHERE pubkey = ?1 AND target_epoch = 70",
            [PUBKEY],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count_5, 1, "case5: exactly one row survives");
}

// ── Test 2: New indices present; CN-keyed ones gone ───────────────────────────

#[test]
fn test_v3_migration_index_names() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("index_check.db");
    build_v2_db_with_duplicates(&path);

    let _db = SlashingDb::open(&path).expect("open");
    drop(_db);

    let conn = Connection::open(&path).expect("direct open");

    // New pubkey-scoped indices must exist.
    assert!(
        index_exists(&conn, "idx_attestations_pubkey_gvr_target"),
        "pubkey-scoped attestation index must exist"
    );
    assert!(
        index_exists(&conn, "idx_blocks_pubkey_gvr_slot"),
        "pubkey-scoped block index must exist"
    );

    // Old CN-keyed indices must be gone.
    assert!(
        !index_exists(&conn, "idx_attestations_cn_pubkey_target"),
        "CN-keyed attestation index must be dropped"
    );
    assert!(
        !index_exists(&conn, "idx_blocks_cn_pubkey_slot"),
        "CN-keyed block index must be dropped"
    );
}

// ── Test 3: Idempotency ───────────────────────────────────────────────────────

#[test]
fn test_v3_migration_is_idempotent() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("idempotent.db");
    build_v2_db_with_duplicates(&path);

    // First open: runs migration.
    let db1 = SlashingDb::open(&path).expect("first open");
    drop(db1);

    // Capture row counts after first migration.
    let (att_count, blk_count): (i64, i64) = {
        let c = Connection::open(&path).unwrap();
        let a: i64 = c.query_row("SELECT COUNT(*) FROM attestations", [], |r| r.get(0)).unwrap();
        let b: i64 = c.query_row("SELECT COUNT(*) FROM blocks", [], |r| r.get(0)).unwrap();
        (a, b)
    };

    // Second open: must be a no-op.
    let db2 = SlashingDb::open(&path).expect("second open");
    drop(db2);

    let (att_count2, blk_count2): (i64, i64) = {
        let c = Connection::open(&path).unwrap();
        let a: i64 = c.query_row("SELECT COUNT(*) FROM attestations", [], |r| r.get(0)).unwrap();
        let b: i64 = c.query_row("SELECT COUNT(*) FROM blocks", [], |r| r.get(0)).unwrap();
        (a, b)
    };

    assert_eq!(att_count2, att_count, "idempotent: attestation count unchanged");
    assert_eq!(blk_count2, blk_count, "idempotent: block count unchanged");

    let version: Option<i64> = {
        let c = Connection::open(&path).unwrap();
        read_schema_version(&c)
    };
    assert_eq!(version, Some(3), "idempotent: schema_version stays 3");
}

// ── Test 4: Migration invariant — pre-migration rejections still work ─────────

#[test]
fn test_v3_migration_invariant_rejections_preserved() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("invariant.db");
    build_v2_db_with_duplicates(&path);

    let db = SlashingDb::open(&path).expect("open after migration");

    let gvr: [u8; 32] = [7u8; 32];

    // A same-slot double-block with a different root must still be rejected.
    let err = db
        .stage_block(PUBKEY, 1000, Some("0xnew_root_different".into()), &gvr)
        .expect_err("double-block at slot=1000 must be rejected");
    assert!(
        matches!(
            err,
            SlashingError::SlashableBlock(BlockSlashingViolation::DoubleBlockProposal {
                slot: 1000
            })
        ),
        "expected DoubleBlockProposal, got: {err:?}"
    );

    // Cross-CN double-sign at slot=2000 must also be rejected.
    let err2 = db
        .stage_block(PUBKEY, 2000, Some("0xroot_totally_new".into()), &gvr)
        .expect_err("pubkey-scoped double-block at slot=2000 must be rejected");
    assert!(
        matches!(
            err2,
            SlashingError::SlashableBlock(BlockSlashingViolation::DoubleBlockProposal {
                slot: 2000
            })
        ),
        "expected DoubleBlockProposal, got: {err2:?}"
    );

    // A same-target double-vote must be rejected.
    let err3 = db
        .stage_attestation(PUBKEY, 40, 50, Some("0xconflicting_att_root".into()), &gvr)
        .expect_err("double-vote at target_epoch=50 must be rejected");
    assert!(
        matches!(
            err3,
            SlashingError::SlashableAttestation(AttestationSlashingViolation::DoubleVote {
                target_epoch: 50
            })
        ),
        "expected DoubleVote at 50, got: {err3:?}"
    );
}

// ── Test 5: Fails-closed when NULL gvr rows exist but no metadata GVR is pinned ──

/// Verifies that the v3 migration is fail-closed: if a v2 DB contains rows with
/// NULL `genesis_validators_root` but no `genesis_validators_root` is pinned in
/// `metadata`, `SlashingDb::open` must return `Err(MigrationFailed)` and leave
/// the database unchanged at v2 (no partial migration).
///
/// This pins the critical invariant: the migration must not create a non-enforcing
/// `(pubkey, NULL, slot)` unique index where NULLs are treated as distinct.
#[test]
fn test_v3_migration_fails_closed_null_gvr_without_metadata_pin() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("null_gvr_no_pin.db");

    // Build a v2 DB with a NULL-gvr row and NO genesis_validators_root in metadata.
    {
        let conn = Connection::open(&path).expect("open");
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             CREATE TABLE attestations (
                 id INTEGER PRIMARY KEY,
                 client_cn TEXT NOT NULL DEFAULT '__legacy__',
                 pubkey TEXT NOT NULL,
                 source_epoch INTEGER NOT NULL,
                 target_epoch INTEGER NOT NULL,
                 signing_root TEXT,
                 genesis_validators_root TEXT
             );
             CREATE TABLE blocks (
                 id INTEGER PRIMARY KEY,
                 client_cn TEXT NOT NULL DEFAULT '__legacy__',
                 pubkey TEXT NOT NULL,
                 slot INTEGER NOT NULL,
                 signing_root TEXT,
                 genesis_validators_root TEXT
             );
             CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
             CREATE TABLE watermarks (
                 pubkey TEXT NOT NULL,
                 watermark_type TEXT NOT NULL,
                 value INTEGER NOT NULL,
                 UNIQUE(pubkey, watermark_type)
             );
             CREATE UNIQUE INDEX idx_attestations_cn_pubkey_target
                 ON attestations(client_cn, pubkey, target_epoch);
             CREATE UNIQUE INDEX idx_blocks_cn_pubkey_slot
                 ON blocks(client_cn, pubkey, slot);
             INSERT INTO metadata (key, value) VALUES ('schema_version', '2');",
        )
        .expect("create v2 schema");

        // Insert a row with NULL genesis_validators_root (no metadata GVR pinned).
        conn.execute(
            "INSERT INTO blocks (client_cn, pubkey, slot, signing_root, genesis_validators_root)
             VALUES ('local-vc', '0xcccc', 42, '0xroot', NULL)",
            [],
        )
        .expect("insert null-gvr block");
    }

    let original_bytes = std::fs::read(&path).expect("read original");

    // Open via SlashingDb — the v3 migration MUST fail closed.
    let result = SlashingDb::open(&path);
    assert!(result.is_err(), "migration must fail when NULL gvr rows exist without metadata GVR");
    let err = result.err().expect("is_err checked above");
    match err {
        SlashingError::MigrationFailed(ref msg) => {
            assert!(
                msg.contains("NULL genesis_validators_root")
                    || msg.contains("genesis_validators_root"),
                "error message must mention gvr issue: {msg}"
            );
        }
        other => panic!("expected MigrationFailed, got: {other:?}"),
    }

    // DB must be unchanged — schema still v2.
    let after_bytes = std::fs::read(&path).expect("read after failed migration");
    assert_eq!(
        original_bytes.len(),
        after_bytes.len(),
        "DB file size must not change after failed migration"
    );
    {
        let conn = Connection::open(&path).expect("direct open");
        let version: Option<i64> = conn
            .query_row("SELECT value FROM metadata WHERE key = 'schema_version'", [], |r| {
                r.get::<_, String>(0)
            })
            .ok()
            .and_then(|v| v.parse().ok());
        assert_eq!(version, Some(2), "schema_version must still be 2 after failed migration");
    }
}

// ── Test 6: Cross-CN double-sign now rejected (was silently accepted in v2) ───
// (was Test 5 before the fails-closed test was added above)

#[test]
fn test_v3_migration_cross_cn_double_sign_now_rejected() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("cross_cn.db");

    // Build a fresh v3 DB.
    let db = SlashingDb::open(&path).expect("open v3 db");
    let gvr: [u8; 32] = [7u8; 32];

    // First call commits slot 9000.
    db.stage_block(PUBKEY, 9000, Some("0xroot_cn_a".into()), &gvr)
        .expect("first stage")
        .commit()
        .expect("first commit");

    // Second call — same slot, different root — must be rejected (pubkey-scoped).
    let result = db.stage_block(PUBKEY, 9000, Some("0xroot_cn_b".into()), &gvr);
    assert!(
        matches!(
            result,
            Err(SlashingError::SlashableBlock(BlockSlashingViolation::DoubleBlockProposal {
                slot: 9000
            }))
        ),
        "pubkey-scoped double-sign must be rejected: {result:?}"
    );
}
