//! Regression tests for M-6: per-row genesis_validators_root re-check (ISSUE-3.5).
//!
//! Acceptance criteria:
//! - All four entry points run a SELECT against `metadata.genesis_validators_root` and compare
//!   with the supplied `gvr` argument.
//! - On mismatch: `Err(SlashingError::GenesisRootMismatch { expected, got })`.
//! - On match: the row INSERT writes the per-row `genesis_validators_root` column.
//! - Legacy rows with NULL `genesis_validators_root` do not break violation checks.

use rusqlite::Connection;
use tempfile::tempdir;

use rvc_slashing::{SlashingDb, SlashingError};

const CN: &str = "local-vc";
const PUBKEY: &str = "0xabababababababababababababababababababababababababababababababababababababababababababababababababababab";

// R1: first chain root (pinned in metadata).
const R1: &[u8; 32] = &[0x01u8; 32];
// R2: different chain root (simulates a chain swap).
const R2: &[u8; 32] = &[0x02u8; 32];

/// Helper: open a **file-based** DB at the given path with GVR pinned in metadata.
///
/// File-based DBs allow opening a second `rusqlite::Connection` to inspect row
/// data without going through the public API.
fn open_file_db_with_pinned_gvr(path: &std::path::Path, gvr: &[u8; 32]) -> SlashingDb {
    let db = SlashingDb::open(path).expect("SlashingDb::open");
    let hex = format!("0x{}", hex::encode(gvr));
    db.set_genesis_validators_root(&hex).expect("set_genesis_validators_root");
    db
}

/// Helper: open an **in-memory** DB with GVR pinned in metadata.
fn open_memory_db_with_pinned_gvr(gvr: &[u8; 32]) -> SlashingDb {
    let db = SlashingDb::open_in_memory().expect("open_in_memory");
    let hex = format!("0x{}", hex::encode(gvr));
    db.set_genesis_validators_root(&hex).expect("set_genesis_validators_root");
    db
}

// ── check_and_record_block ────────────────────────────────────────────────────

/// Calling `check_and_record_block` with a gvr that does NOT match the pinned
/// metadata value must return `GenesisRootMismatch`.
#[test]
fn test_check_and_record_block_chain_swap_rejected() {
    let db = open_memory_db_with_pinned_gvr(R1);

    let err = db
        .check_and_record_block(CN, PUBKEY, 100, Some("0xroot".into()), R2)
        .expect_err("chain swap must be rejected");

    match err {
        SlashingError::GenesisRootMismatch { expected, got } => {
            assert_eq!(expected, *R1, "expected pinned gvr R1");
            assert_eq!(got, *R2, "got the swapped gvr R2");
        }
        other => panic!("expected GenesisRootMismatch, got: {other:?}"),
    }
}

/// `check_and_record_block` with gvr matching the pinned value must succeed and
/// write `genesis_validators_root` into the per-row column.
#[test]
fn test_check_and_record_block_matching_gvr_succeeds_and_writes_row_column() {
    let dir = tempdir().expect("tempdir");
    let db_path = dir.path().join("slashing.db");
    let db = open_file_db_with_pinned_gvr(&db_path, R1);

    db.check_and_record_block(CN, PUBKEY, 200, Some("0xroot_ok".into()), R1)
        .expect("matching gvr must succeed");
    drop(db);

    // Open a fresh connection to inspect the per-row column.
    let conn = Connection::open(&db_path).expect("open for inspection");
    let row_gvr: Option<String> = conn
        .query_row(
            "SELECT genesis_validators_root FROM blocks WHERE pubkey = ?1 AND slot = 200",
            [PUBKEY],
            |row| row.get(0),
        )
        .expect("block row must exist");

    let expected_hex = format!("0x{}", hex::encode(R1));
    assert_eq!(row_gvr.as_deref(), Some(expected_hex.as_str()), "per-row gvr must be written");
}

// ── check_and_record_attestation ─────────────────────────────────────────────

/// Calling `check_and_record_attestation` with a mismatched gvr must return
/// `GenesisRootMismatch`.
#[test]
fn test_check_and_record_attestation_chain_swap_rejected() {
    let db = open_memory_db_with_pinned_gvr(R1);

    let err = db
        .check_and_record_attestation(CN, PUBKEY, 1, 2, Some("0xatt_root".into()), R2)
        .expect_err("chain swap must be rejected");

    match err {
        SlashingError::GenesisRootMismatch { expected, got } => {
            assert_eq!(expected, *R1);
            assert_eq!(got, *R2);
        }
        other => panic!("expected GenesisRootMismatch, got: {other:?}"),
    }
}

/// `check_and_record_attestation` with matching gvr must succeed and write the
/// per-row column.
#[test]
fn test_check_and_record_attestation_matching_gvr_succeeds_and_writes_row_column() {
    let dir = tempdir().expect("tempdir");
    let db_path = dir.path().join("slashing.db");
    let db = open_file_db_with_pinned_gvr(&db_path, R1);

    db.check_and_record_attestation(CN, PUBKEY, 3, 5, Some("0xatt_ok".into()), R1)
        .expect("matching gvr must succeed");
    drop(db);

    let conn = Connection::open(&db_path).expect("open for inspection");
    let row_gvr: Option<String> = conn
        .query_row(
            "SELECT genesis_validators_root FROM attestations WHERE pubkey = ?1 AND target_epoch = 5",
            [PUBKEY],
            |row| row.get(0),
        )
        .expect("attestation row must exist");

    let expected_hex = format!("0x{}", hex::encode(R1));
    assert_eq!(row_gvr.as_deref(), Some(expected_hex.as_str()));
}

// ── stage_block ───────────────────────────────────────────────────────────────

/// `stage_block` with a mismatched gvr must return `GenesisRootMismatch` immediately.
#[test]
fn test_stage_block_chain_swap_rejected() {
    let db = open_memory_db_with_pinned_gvr(R1);

    let err = db
        .stage_block(CN, PUBKEY, 300, Some("0xstage_root".into()), R2)
        .expect_err("chain swap must be rejected at stage time");

    match err {
        SlashingError::GenesisRootMismatch { expected, got } => {
            assert_eq!(expected, *R1);
            assert_eq!(got, *R2);
        }
        other => panic!("expected GenesisRootMismatch, got: {other:?}"),
    }
}

/// `stage_block` with matching gvr must succeed; `commit()` must write the
/// per-row `genesis_validators_root` column.
#[test]
fn test_stage_block_matching_gvr_succeeds_and_writes_row_column() {
    let dir = tempdir().expect("tempdir");
    let db_path = dir.path().join("slashing.db");
    let db = open_file_db_with_pinned_gvr(&db_path, R1);

    db.stage_block(CN, PUBKEY, 400, Some("0xstage_ok".into()), R1)
        .expect("stage must succeed")
        .commit()
        .expect("commit must succeed");
    drop(db);

    let conn = Connection::open(&db_path).expect("open for inspection");
    let row_gvr: Option<String> = conn
        .query_row(
            "SELECT genesis_validators_root FROM blocks WHERE pubkey = ?1 AND slot = 400",
            [PUBKEY],
            |row| row.get(0),
        )
        .expect("block row must exist");

    let expected_hex = format!("0x{}", hex::encode(R1));
    assert_eq!(row_gvr.as_deref(), Some(expected_hex.as_str()));
}

// ── stage_attestation ─────────────────────────────────────────────────────────

/// `stage_attestation` with a mismatched gvr must return `GenesisRootMismatch`.
#[test]
fn test_stage_attestation_chain_swap_rejected() {
    let db = open_memory_db_with_pinned_gvr(R1);

    let err = db
        .stage_attestation(CN, PUBKEY, 10, 15, Some("0xatt_stage".into()), R2)
        .expect_err("chain swap must be rejected at stage time");

    match err {
        SlashingError::GenesisRootMismatch { expected, got } => {
            assert_eq!(expected, *R1);
            assert_eq!(got, *R2);
        }
        other => panic!("expected GenesisRootMismatch, got: {other:?}"),
    }
}

/// `stage_attestation` with matching gvr must succeed; `commit()` must write the
/// per-row column.
#[test]
fn test_stage_attestation_matching_gvr_succeeds_and_writes_row_column() {
    let dir = tempdir().expect("tempdir");
    let db_path = dir.path().join("slashing.db");
    let db = open_file_db_with_pinned_gvr(&db_path, R1);

    db.stage_attestation(CN, PUBKEY, 20, 25, Some("0xatt_ok".into()), R1)
        .expect("stage must succeed")
        .commit()
        .expect("commit must succeed");
    drop(db);

    let conn = Connection::open(&db_path).expect("open for inspection");
    let row_gvr: Option<String> = conn
        .query_row(
            "SELECT genesis_validators_root FROM attestations WHERE pubkey = ?1 AND target_epoch = 25",
            [PUBKEY],
            |row| row.get(0),
        )
        .expect("attestation row must exist");

    let expected_hex = format!("0x{}", hex::encode(R1));
    assert_eq!(row_gvr.as_deref(), Some(expected_hex.as_str()));
}

// ── Legacy rows (NULL per-row gvr) do not break violation checks ──────────────

/// A pre-migration row that has NULL `genesis_validators_root` must not interfere
/// with slashing violation checks (double-vote detection still works).
///
/// Strategy: build a file-based DB and insert a legacy-style row (NULL gvr column)
/// via a direct `rusqlite::Connection`, then open it via `SlashingDb` with a
/// pinned GVR and verify that double-vote detection still fires.
#[test]
fn test_legacy_row_no_per_row_gvr_does_not_break_violation_checks() {
    let dir = tempdir().expect("tempdir");
    let db_path = dir.path().join("slashing.db");

    // Step 1: Create the v2 schema and insert a legacy row (NULL gvr) via raw SQL.
    {
        let conn = Connection::open(&db_path).expect("open for legacy insert");
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
             CREATE UNIQUE INDEX IF NOT EXISTS idx_attestations_cn_pubkey_target
                 ON attestations(client_cn, pubkey, target_epoch);
             CREATE UNIQUE INDEX IF NOT EXISTS idx_blocks_cn_pubkey_slot
                 ON blocks(client_cn, pubkey, slot);
             INSERT OR REPLACE INTO metadata (key, value) VALUES ('schema_version', '2');",
        )
        .expect("create v2 schema");

        // Insert a row with NULL genesis_validators_root (legacy-style).
        conn.execute(
            "INSERT INTO attestations (client_cn, pubkey, source_epoch, target_epoch, signing_root, genesis_validators_root)
             VALUES ('local-vc', ?1, 1, 5, '0xlegacy_root', NULL)",
            [PUBKEY],
        )
        .expect("insert legacy row");
    }

    // Step 2: Open via SlashingDb and pin GVR R1 in metadata.
    let db = SlashingDb::open(&db_path).expect("SlashingDb::open");
    let hex = format!("0x{}", hex::encode(R1));
    db.set_genesis_validators_root(&hex).expect("set gvr");

    // Step 3: A double-vote attempt (same target_epoch=5, different signing_root) must
    // still be caught by the violation check even though the existing row has NULL gvr.
    let err = db
        .check_and_record_attestation(CN, PUBKEY, 2, 5, Some("0xdifferent_root".into()), R1)
        .expect_err("double-vote must be rejected");

    assert!(
        matches!(err, SlashingError::SlashableAttestation(_)),
        "expected SlashableAttestation, got: {err:?}"
    );
}

// ── No pinned GVR → check is skipped (backward compat) ───────────────────────

/// When no `genesis_validators_root` is set in metadata, the GVR check must
/// be skipped (backward-compatible behavior for DBs that pre-date ISSUE-3.5).
#[test]
fn test_no_pinned_gvr_check_is_skipped() {
    let db = SlashingDb::open_in_memory().expect("open");

    // Even with an arbitrary gvr, the call must succeed (no pinned value to compare).
    db.check_and_record_block(CN, PUBKEY, 1, Some("0xroot".into()), R2)
        .expect("no pinned gvr → check is skipped → must succeed");
}

// ── GVR cache: second call does not re-read from DB ──────────────────────────

/// After the first call populates the cache, subsequent mismatch calls must also
/// return `GenesisRootMismatch` (cache works correctly for repeated checks).
#[test]
fn test_gvr_cache_populated_after_first_check() {
    let db = open_memory_db_with_pinned_gvr(R1);

    // First call: populates cache from DB, passes (matching gvr).
    db.check_and_record_block(CN, PUBKEY, 500, Some("0xfirst".into()), R1)
        .expect("first call must succeed");

    // Second call: cache is already populated; mismatch must still be caught.
    let err = db
        .check_and_record_block(CN, PUBKEY, 501, Some("0xsecond".into()), R2)
        .expect_err("cached mismatch must be rejected");

    assert!(
        matches!(err, SlashingError::GenesisRootMismatch { .. }),
        "expected GenesisRootMismatch, got: {err:?}"
    );
}

// ── GVR cache: absence is NOT cached (review fix MF-1) ─────────────────────

/// Critical regression: if a signing call observes "no pinned gvr" before
/// `set_genesis_validators_root` is called, the cache must NOT permanently
/// disable the chain-swap check. Subsequent calls after pinning must enforce it.
#[test]
fn test_gvr_cache_none_not_poisoned_after_set() {
    let db = SlashingDb::open_in_memory().expect("open");

    // First call: no pinned GVR → check is skipped (returns Ok).
    db.check_and_record_block(CN, PUBKEY, 100, Some("0xfirst".into()), R1)
        .expect("no pinned gvr: skipped → must succeed");

    // Now pin GVR R1.
    db.set_genesis_validators_root(&format!("0x{}", hex::encode(R1))).expect("set should succeed");

    // Next call with a DIFFERENT gvr must now be rejected — the cache must
    // have re-read from DB rather than use the stale "no pinned gvr → skip".
    let err = db
        .check_and_record_block(CN, PUBKEY, 101, Some("0xsecond".into()), R2)
        .expect_err("after pinning, mismatch must be rejected");
    assert!(
        matches!(err, SlashingError::GenesisRootMismatch { .. }),
        "expected GenesisRootMismatch after pinning, got: {err:?}"
    );

    // Same call with the matching gvr must succeed (and the cache is now sealed).
    db.check_and_record_block(CN, PUBKEY, 102, Some("0xthird".into()), R1)
        .expect("matching gvr after pinning must succeed");
}
