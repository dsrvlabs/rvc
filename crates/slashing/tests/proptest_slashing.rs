//! Property-based tests for slashing protection invariants.
//!
//! Uses proptest to verify that the slashing DB enforces EIP-3076
//! constraints under random input sequences.

use proptest::prelude::*;
use rvc_slashing::SlashingDb;

/// Configuration for proptest: 256 cases per property for CI friendliness.
const PROPTEST_CASES: u32 = 256;

fn config() -> ProptestConfig {
    ProptestConfig { cases: PROPTEST_CASES, ..ProptestConfig::default() }
}

fn hex_root(n: u8) -> String {
    format!("0x{}", hex::encode([n; 32]))
}

fn pubkey(n: u8) -> String {
    format!("0x{}", hex::encode([n; 48]))
}

// =========================================================================
// Property 1: No double proposals
// Same (validator, slot) with different signing roots → exactly one success
// =========================================================================

proptest! {
    #![proptest_config(config())]

    #[test]
    fn proptest_no_double_proposals(
        slot in 0u64..100_000,
        root_a_byte in 1u8..255,
        root_b_byte in 1u8..255,
    ) {
        let db = SlashingDb::open_in_memory().unwrap();
        let pk = pubkey(1);
        let root_a = Some(hex_root(root_a_byte));
        let root_b = Some(hex_root(root_b_byte));

        if root_a == root_b {
            // Same signing root — both should succeed (idempotent re-signing)
            prop_assert!(db.check_and_record_block(&pk, slot, root_a.clone()).is_ok());
            prop_assert!(db.check_and_record_block(&pk, slot, root_b).is_ok());
        } else {
            // Different signing roots — exactly one should succeed
            let r1 = db.check_and_record_block(&pk, slot, root_a);
            let r2 = db.check_and_record_block(&pk, slot, root_b);
            prop_assert!(r1.is_ok());
            prop_assert!(r2.is_err());
        }
    }
}

// =========================================================================
// Property 2: No double votes
// Same (validator, target_epoch) with different signing roots → exactly one success
// =========================================================================

proptest! {
    #![proptest_config(config())]

    #[test]
    fn proptest_no_double_votes(
        source_a in 0u64..50_000,
        source_b in 0u64..50_000,
        target in 1u64..100_000,
        root_a_byte in 1u8..255,
        root_b_byte in 1u8..255,
    ) {
        let db = SlashingDb::open_in_memory().unwrap();
        let pk = pubkey(1);
        let root_a = Some(hex_root(root_a_byte));
        let root_b = Some(hex_root(root_b_byte));

        // First attestation should always succeed
        let r1 = db.check_and_record_attestation(&pk, source_a, target, root_a.clone());
        prop_assert!(r1.is_ok());

        if root_a == root_b {
            // Same signing root — idempotent, should succeed
            let r2 = db.check_and_record_attestation(&pk, source_b, target, root_b);
            prop_assert!(r2.is_ok());
        } else {
            // Different signing roots — must be rejected (double vote)
            let r2 = db.check_and_record_attestation(&pk, source_b, target, root_b);
            prop_assert!(r2.is_err());
        }
    }
}

// =========================================================================
// Property 3: No surround votes
// Accepted attestations never form surround pairs
// =========================================================================

proptest! {
    #![proptest_config(config())]

    #[test]
    fn proptest_no_surround_votes(
        attestations in prop::collection::vec(
            (0u64..1000, 1u64..1000),
            1..20
        ),
    ) {
        let db = SlashingDb::open_in_memory().unwrap();
        let pk = pubkey(1);

        // Track successfully recorded attestations
        let mut accepted: Vec<(u64, u64)> = Vec::new();

        for (source, target_offset) in &attestations {
            let target = source + target_offset; // Ensure target > source
            let root = Some(hex_root((target % 255) as u8 + 1));

            if db.check_and_record_attestation(&pk, *source, target, root).is_ok() {
                accepted.push((*source, target));
            }
        }

        // Verify no surround pairs exist among accepted attestations
        for i in 0..accepted.len() {
            for j in 0..accepted.len() {
                if i == j {
                    continue;
                }
                let (s_i, t_i) = accepted[i];
                let (s_j, t_j) = accepted[j];
                // i surrounds j: s_i < s_j AND t_i > t_j
                prop_assert!(
                    !(s_i < s_j && t_i > t_j),
                    "surround detected: ({}, {}) surrounds ({}, {})",
                    s_i, t_i, s_j, t_j,
                );
            }
        }
    }
}

// =========================================================================
// Property 4: Monotonicity
// After operations, min slot/epoch watermarks never decrease
// =========================================================================

proptest! {
    #![proptest_config(config())]

    #[test]
    fn proptest_block_slot_monotonicity(
        slots in prop::collection::vec(0u64..100_000, 1..30),
    ) {
        let db = SlashingDb::open_in_memory().unwrap();
        let pk = pubkey(1);

        let mut max_slot: Option<u64> = None;

        for (i, &slot) in slots.iter().enumerate() {
            let root = Some(hex_root(i as u8 + 1));
            let _ = db.check_and_record_block(&pk, slot, root);

            let current_max = db.last_signed_block_slot(&pk).unwrap();
            if let Some(prev) = max_slot {
                // Max slot must never decrease
                prop_assert!(
                    current_max.unwrap_or(0) >= prev,
                    "block slot watermark decreased: {} -> {:?}",
                    prev, current_max,
                );
            }
            if let Some(cm) = current_max {
                max_slot = Some(cm);
            }
        }
    }

    #[test]
    fn proptest_attestation_epoch_monotonicity(
        attestations in prop::collection::vec(
            (0u64..1000, 1u64..1000),
            1..30
        ),
    ) {
        let db = SlashingDb::open_in_memory().unwrap();
        let pk = pubkey(1);

        let mut max_target: Option<u64> = None;

        for (i, (source, target_offset)) in attestations.iter().enumerate() {
            let target = source + target_offset;
            let root = Some(hex_root(i as u8 + 1));
            let _ = db.check_and_record_attestation(&pk, *source, target, root);

            let current_max = db.last_signed_attestation_epoch(&pk).unwrap();
            if let Some(prev) = max_target {
                // Max target epoch must never decrease
                prop_assert!(
                    current_max.unwrap_or(0) >= prev,
                    "attestation epoch watermark decreased: {} -> {:?}",
                    prev, current_max,
                );
            }
            if let Some(cm) = current_max {
                max_target = Some(cm);
            }
        }
    }
}

// =========================================================================
// Property 5: Independence
// Validator A's operations never affect validator B's outcomes
// =========================================================================

proptest! {
    #![proptest_config(config())]

    #[test]
    fn proptest_validator_independence_blocks(
        slot in 0u64..100_000,
        root_byte in 1u8..255,
    ) {
        let db = SlashingDb::open_in_memory().unwrap();
        let pk_a = pubkey(1);
        let pk_b = pubkey(2);
        let root = Some(hex_root(root_byte));

        // Validator A records a block
        db.check_and_record_block(&pk_a, slot, root.clone()).unwrap();

        // Validator B should still be able to propose at the same slot
        let result = db.check_and_record_block(&pk_b, slot, root);
        prop_assert!(result.is_ok(), "validator B blocked by validator A's block at slot {}", slot);
    }

    #[test]
    fn proptest_validator_independence_attestations(
        source in 0u64..50_000,
        target in 50_001u64..100_000,
        root_byte in 1u8..255,
    ) {
        let db = SlashingDb::open_in_memory().unwrap();
        let pk_a = pubkey(1);
        let pk_b = pubkey(2);
        let root = Some(hex_root(root_byte));

        // Validator A records an attestation
        db.check_and_record_attestation(&pk_a, source, target, root.clone()).unwrap();

        // Validator B should still be able to attest with the same epochs
        let result = db.check_and_record_attestation(&pk_b, source, target, root);
        prop_assert!(
            result.is_ok(),
            "validator B blocked by validator A's attestation ({}, {})",
            source, target,
        );
    }
}

// =========================================================================
// Property 6: Re-signing safety
// Same message (same signing root) always succeeds
// =========================================================================

proptest! {
    #![proptest_config(config())]

    #[test]
    fn proptest_resign_block_always_succeeds(
        slot in 0u64..100_000,
        root_byte in 1u8..255,
        repeat_count in 2u8..10,
    ) {
        let db = SlashingDb::open_in_memory().unwrap();
        let pk = pubkey(1);
        let root = Some(hex_root(root_byte));

        for _ in 0..repeat_count {
            let result = db.check_and_record_block(&pk, slot, root.clone());
            prop_assert!(result.is_ok(), "re-signing block at slot {} with same root failed", slot);
        }

        // Should still only have one record
        let blocks = db.get_blocks(&pk).unwrap();
        prop_assert_eq!(blocks.len(), 1);
    }

    #[test]
    fn proptest_resign_attestation_always_succeeds(
        source in 0u64..50_000,
        target in 50_001u64..100_000,
        root_byte in 1u8..255,
        repeat_count in 2u8..10,
    ) {
        let db = SlashingDb::open_in_memory().unwrap();
        let pk = pubkey(1);
        let root = Some(hex_root(root_byte));

        for _ in 0..repeat_count {
            let result = db.check_and_record_attestation(&pk, source, target, root.clone());
            prop_assert!(
                result.is_ok(),
                "re-signing attestation ({}, {}) with same root failed",
                source, target,
            );
        }

        // Should still only have one record
        let attestations = db.get_attestations(&pk).unwrap();
        prop_assert_eq!(attestations.len(), 1);
    }
}
