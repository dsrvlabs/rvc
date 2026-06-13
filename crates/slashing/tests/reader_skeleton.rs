//! Integration tests for the `SlashingDbReader` read-only seam (Issue 1.4).
//!
//! Proves that:
//! - `SlashingDb` implements `SlashingDbReader`.
//! - `last_signed_attestation` returns the max target epoch for a known pubkey under the pinned GVR.
//! - Returns `None` for an unknown pubkey.
//! - Returns `None` when queried with a GVR that differs from the one pinned in the DB.
//! - Returns `Some(max)` when NO GVR is pinned (backward-compat: fail-open on unpinned DB).
//! - The trait is object-safe (cast to `&dyn SlashingDbReader` works).

use rvc_slashing::{SlashingDb, SlashingDbReader};

const CN: &str = "local-vc";
const PUBKEY: &str =
    "0xaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd";
const GVR: &[u8; 32] = &[7u8; 32];
const OTHER_GVR: &[u8; 32] = &[8u8; 32];

fn open_db_with_gvr() -> SlashingDb {
    let db = SlashingDb::open_in_memory().expect("open_in_memory");
    let hex = format!("0x{}", hex::encode(GVR));
    db.set_genesis_validators_root(&hex).expect("set_genesis_validators_root");
    db
}

/// Stage + commit one attestation; assert the reader returns that target epoch.
#[test]
fn test_last_signed_attestation_returns_max_target_epoch() {
    let db = open_db_with_gvr();

    db.stage_attestation(CN, PUBKEY, 4, 5, Some("0xdeadbeef".to_string()), GVR)
        .expect("stage")
        .commit()
        .expect("commit");

    let reader: &dyn SlashingDbReader = &db;
    let result = reader.last_signed_attestation(PUBKEY, GVR);
    assert_eq!(result, Some(5), "expected target epoch 5");
}

/// Stage two attestations for the same pubkey; reader must return the higher target.
#[test]
fn test_last_signed_attestation_returns_highest_of_multiple() {
    let db = open_db_with_gvr();

    db.stage_attestation(CN, PUBKEY, 4, 5, None, GVR).expect("stage 1").commit().expect("commit 1");
    db.stage_attestation(CN, PUBKEY, 5, 10, None, GVR)
        .expect("stage 2")
        .commit()
        .expect("commit 2");

    let reader: &dyn SlashingDbReader = &db;
    assert_eq!(reader.last_signed_attestation(PUBKEY, GVR), Some(10));
}

/// A pubkey with no records must produce `None`.
#[test]
fn test_last_signed_attestation_unknown_pubkey_returns_none() {
    let db = open_db_with_gvr();

    let reader: &dyn SlashingDbReader = &db;
    assert_eq!(reader.last_signed_attestation("0xunknown0000", GVR), None);
}

/// Querying with a GVR different from the one pinned in the DB must return `None`.
#[test]
fn test_last_signed_attestation_wrong_gvr_returns_none() {
    let db = open_db_with_gvr();

    db.stage_attestation(CN, PUBKEY, 4, 5, None, GVR).expect("stage").commit().expect("commit");

    let reader: &dyn SlashingDbReader = &db;
    assert_eq!(
        reader.last_signed_attestation(PUBKEY, OTHER_GVR),
        None,
        "different GVR must yield None even when records exist"
    );
}

/// When the DB has NO pinned GVR (fresh DB, no `set_genesis_validators_root` call),
/// `last_signed_attestation` must still return `Some(max_target_epoch)`.
///
/// This pins the documented backward-compat behaviour: an unpinned DB is fail-open
/// so that validators migrating from legacy setups (no GVR in metadata) are not
/// incorrectly treated as having no history.
#[test]
fn test_last_signed_attestation_no_pinned_gvr_returns_some() {
    // Open without pinning any GVR.
    let db = SlashingDb::open_in_memory().expect("open_in_memory");

    db.stage_attestation(CN, PUBKEY, 4, 5, None, GVR).expect("stage").commit().expect("commit");

    let reader: &dyn SlashingDbReader = &db;
    assert_eq!(
        reader.last_signed_attestation(PUBKEY, GVR),
        Some(5),
        "unpinned DB must return Some — fail-open backward-compat"
    );
}
