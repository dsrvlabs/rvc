//! Sync committee helpers shared by the orchestrator's production path.
//!
//! The former message/contribution lifecycle twin (and its signer/beacon traits)
//! was deleted (RF2-01 / B1). Production path:
//! `crates/rvc/src/orchestrator/sync_committee.rs` (`SyncCommitteeService`).
//! This crate retains only the aggregator check, its constants, and `SyncServiceError`.

mod error;

use sha2::{Digest, Sha256};

pub use error::SyncServiceError;

/// Total validators in a sync committee (Altair+).
pub const SYNC_COMMITTEE_SIZE: u64 = 512;

/// Number of subnets the sync committee is split across.
pub const SYNC_COMMITTEE_SUBNET_COUNT: u64 = 4;

/// Target number of aggregators per sync subcommittee.
pub const TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE: u64 = 16;

/// Returns `true` when `selection_proof` selects the validator as a sync
/// committee aggregator (`sha256(proof)[0..8] as u64 % modulo == 0`).
pub fn is_sync_committee_aggregator(selection_proof: &[u8]) -> bool {
    let modulo = (SYNC_COMMITTEE_SIZE
        / SYNC_COMMITTEE_SUBNET_COUNT
        / TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE)
        .max(1);

    let hash = Sha256::digest(selection_proof);
    let value = u64::from_le_bytes(hash[0..8].try_into().expect("sha256 output is 32 bytes"));
    value % modulo == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Find a selection proof that passes the aggregator check.
    fn find_aggregator_proof() -> Vec<u8> {
        let modulo = (SYNC_COMMITTEE_SIZE
            / SYNC_COMMITTEE_SUBNET_COUNT
            / TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE)
            .max(1);
        for i in 0u64.. {
            let proof = i.to_le_bytes().to_vec();
            let hash = Sha256::digest(&proof);
            let value = u64::from_le_bytes(hash[0..8].try_into().unwrap());
            if value % modulo == 0 {
                return proof;
            }
        }
        unreachable!()
    }

    /// Find a selection proof that does NOT pass the aggregator check.
    fn find_non_aggregator_proof() -> Vec<u8> {
        let modulo = (SYNC_COMMITTEE_SIZE
            / SYNC_COMMITTEE_SUBNET_COUNT
            / TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE)
            .max(1);
        for i in 0u64.. {
            let proof = i.to_le_bytes().to_vec();
            let hash = Sha256::digest(&proof);
            let value = u64::from_le_bytes(hash[0..8].try_into().unwrap());
            if value % modulo != 0 {
                return proof;
            }
        }
        unreachable!()
    }

    // --- is_sync_committee_aggregator tests ---

    #[test]
    fn test_is_sync_committee_aggregator_with_known_aggregator() {
        let proof = find_aggregator_proof();
        assert!(is_sync_committee_aggregator(&proof));
    }

    #[test]
    fn test_is_sync_committee_aggregator_with_known_non_aggregator() {
        let proof = find_non_aggregator_proof();
        assert!(!is_sync_committee_aggregator(&proof));
    }

    #[test]
    fn test_is_sync_committee_aggregator_modulo_correctness() {
        let modulo = SYNC_COMMITTEE_SIZE
            / SYNC_COMMITTEE_SUBNET_COUNT
            / TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE;
        // 512 / 4 / 16 = 8
        assert_eq!(modulo, 8);
    }

    #[test]
    fn test_is_sync_committee_aggregator_empty_proof() {
        // Empty proof should still produce a deterministic result
        let result = is_sync_committee_aggregator(&[]);
        // SHA256 of empty input is known: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        // First 8 bytes as LE u64: 0xc8f4fb9a14_1cfc98 => check modulo 8
        let hash = Sha256::digest([]);
        let value = u64::from_le_bytes(hash[0..8].try_into().unwrap());
        assert_eq!(result, value % 8 == 0);
    }
}
