use sha2::{Digest, Sha256};

use super::bls::{SecretKey, Signature};
use super::signing::{compute_domain, compute_signing_root};
use eth_types::{
    AggregateAndProof, ElectraAggregateAndProof, ForkName, ForkSchedule, Root, Slot,
    DOMAIN_AGGREGATE_AND_PROOF, DOMAIN_SELECTION_PROOF, SLOTS_PER_EPOCH,
    TARGET_AGGREGATORS_PER_COMMITTEE,
};

#[tracing::instrument(
    name = "rvc.crypto.sign_selection_proof",
    level = "debug",
    skip_all,
    fields(rvc.signing_type = "selection_proof"),
)]
/// Signs a slot with DOMAIN_SELECTION_PROOF to produce a selection proof
/// for attestation aggregation.
pub fn sign_selection_proof(
    slot: Slot,
    secret_key: &SecretKey,
    fork_schedule: &ForkSchedule,
    genesis_validators_root: Root,
) -> Signature {
    let epoch = slot / SLOTS_PER_EPOCH;
    let fork_name = ForkName::from_epoch(epoch, fork_schedule);
    let fork_version = fork_name.fork_version(fork_schedule);
    let domain = compute_domain(DOMAIN_SELECTION_PROOF, fork_version, genesis_validators_root);
    let signing_root = compute_signing_root(&slot, domain);
    secret_key.sign(&signing_root)
}

#[tracing::instrument(
    name = "rvc.crypto.sign_aggregate_and_proof",
    level = "debug",
    skip_all,
    fields(rvc.signing_type = "aggregate_and_proof"),
)]
/// Signs an AggregateAndProof with DOMAIN_AGGREGATE_AND_PROOF.
pub fn sign_aggregate_and_proof(
    aggregate_and_proof: &AggregateAndProof,
    secret_key: &SecretKey,
    fork_schedule: &ForkSchedule,
    genesis_validators_root: Root,
) -> Signature {
    let epoch = aggregate_and_proof.aggregate.data.slot / SLOTS_PER_EPOCH;
    let fork_name = ForkName::from_epoch(epoch, fork_schedule);
    let fork_version = fork_name.fork_version(fork_schedule);
    let domain = compute_domain(DOMAIN_AGGREGATE_AND_PROOF, fork_version, genesis_validators_root);
    let signing_root = compute_signing_root(aggregate_and_proof, domain);
    secret_key.sign(&signing_root)
}

#[tracing::instrument(
    name = "rvc.crypto.sign_electra_aggregate_and_proof",
    level = "debug",
    skip_all,
    fields(rvc.signing_type = "electra_aggregate_and_proof"),
)]
/// Signs an ElectraAggregateAndProof with DOMAIN_AGGREGATE_AND_PROOF.
pub fn sign_electra_aggregate_and_proof(
    aggregate_and_proof: &ElectraAggregateAndProof,
    secret_key: &SecretKey,
    fork_schedule: &ForkSchedule,
    genesis_validators_root: Root,
) -> Signature {
    let epoch = aggregate_and_proof.aggregate.data.slot / SLOTS_PER_EPOCH;
    let fork_name = ForkName::from_epoch(epoch, fork_schedule);
    let fork_version = fork_name.fork_version(fork_schedule);
    let domain = compute_domain(DOMAIN_AGGREGATE_AND_PROOF, fork_version, genesis_validators_root);
    let signing_root = compute_signing_root(aggregate_and_proof, domain);
    secret_key.sign(&signing_root)
}

/// Determines whether a validator is an aggregator for a given committee.
///
/// Per the Ethereum consensus spec:
/// ```text
/// modulo = max(1, len(committee) // TARGET_AGGREGATORS_PER_COMMITTEE)
/// return bytes_to_uint64(hash(slot_signature)[0:8]) % modulo == 0
/// ```
pub fn is_aggregator(committee_length: u64, selection_proof: &[u8]) -> bool {
    let modulo = (committee_length / TARGET_AGGREGATORS_PER_COMMITTEE).max(1);
    let hash = Sha256::digest(selection_proof);
    let value = u64::from_le_bytes(hash[..8].try_into().expect("hash is at least 8 bytes"));
    value % modulo == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::compute_domain;
    use eth_types::{AttestationData, Checkpoint, ElectraAggregateAndProof, ElectraAttestation};

    fn test_fork_schedule() -> ForkSchedule {
        ForkSchedule {
            genesis_fork_version: [0, 0, 0, 0],
            altair_fork_epoch: 74240,
            altair_fork_version: [1, 0, 0, 0],
            bellatrix_fork_epoch: 144896,
            bellatrix_fork_version: [2, 0, 0, 0],
            capella_fork_epoch: 194048,
            capella_fork_version: [3, 0, 0, 0],
            deneb_fork_epoch: 269568,
            deneb_fork_version: [4, 0, 0, 0],
            electra_fork_epoch: 364544,
            electra_fork_version: [5, 0, 0, 0],
            fulu_fork_epoch: u64::MAX,
            fulu_fork_version: [6, 0, 0, 0],
        }
    }

    fn test_genesis_validators_root() -> Root {
        [0xaa; 32]
    }

    fn sample_aggregate_and_proof(slot: Slot) -> AggregateAndProof {
        AggregateAndProof {
            aggregator_index: 42,
            aggregate: eth_types::Attestation {
                aggregation_bits: vec![0xff; 4],
                data: AttestationData {
                    slot,
                    index: 1,
                    beacon_block_root: [1u8; 32],
                    // Source is a prior justified checkpoint; target is the current epoch
                    source: Checkpoint { epoch: slot / SLOTS_PER_EPOCH - 1, root: [2u8; 32] },
                    target: Checkpoint { epoch: slot / SLOTS_PER_EPOCH, root: [3u8; 32] },
                },
                signature: vec![0xaa; 96],
            },
            selection_proof: vec![0xbb; 96],
        }
    }

    #[test]
    fn test_sign_selection_proof_valid() {
        let secret_key = SecretKey::generate();
        let public_key = secret_key.public_key();
        let slot: Slot = 100;
        let schedule = test_fork_schedule();
        let genesis_root = test_genesis_validators_root();

        let signature = sign_selection_proof(slot, &secret_key, &schedule, genesis_root);

        let epoch = slot / SLOTS_PER_EPOCH;
        let fork_name = ForkName::from_epoch(epoch, &schedule);
        let fork_version = fork_name.fork_version(&schedule);
        let domain = compute_domain(DOMAIN_SELECTION_PROOF, fork_version, genesis_root);
        let signing_root = compute_signing_root(&slot, domain);

        assert!(signature.verify(&public_key, &signing_root).is_ok());
    }

    #[test]
    fn test_sign_selection_proof_different_slots_different_sigs() {
        let secret_key = SecretKey::generate();
        let schedule = test_fork_schedule();
        let genesis_root = test_genesis_validators_root();

        let sig1 = sign_selection_proof(100, &secret_key, &schedule, genesis_root);
        let sig2 = sign_selection_proof(200, &secret_key, &schedule, genesis_root);

        assert_ne!(sig1.to_bytes(), sig2.to_bytes());
    }

    #[test]
    fn test_sign_selection_proof_uses_correct_domain() {
        let secret_key = SecretKey::generate();
        let public_key = secret_key.public_key();
        let slot: Slot = 100;
        let schedule = test_fork_schedule();
        let genesis_root = test_genesis_validators_root();

        let signature = sign_selection_proof(slot, &secret_key, &schedule, genesis_root);

        // Wrong domain should fail verification
        let wrong_domain =
            compute_domain(DOMAIN_AGGREGATE_AND_PROOF, schedule.genesis_fork_version, genesis_root);
        let wrong_signing_root = compute_signing_root(&slot, wrong_domain);
        assert!(signature.verify(&public_key, &wrong_signing_root).is_err());
    }

    #[test]
    fn test_sign_selection_proof_fork_aware() {
        let secret_key = SecretKey::generate();
        let public_key = secret_key.public_key();
        let genesis_root = test_genesis_validators_root();
        let schedule = test_fork_schedule();

        // Altair slot
        let slot_altair: Slot = 74240 * SLOTS_PER_EPOCH;
        let sig_altair = sign_selection_proof(slot_altair, &secret_key, &schedule, genesis_root);

        let domain =
            compute_domain(DOMAIN_SELECTION_PROOF, schedule.altair_fork_version, genesis_root);
        let signing_root = compute_signing_root(&slot_altair, domain);
        assert!(sig_altair.verify(&public_key, &signing_root).is_ok());
    }

    #[test]
    fn test_sign_aggregate_and_proof_valid() {
        let secret_key = SecretKey::generate();
        let public_key = secret_key.public_key();
        let schedule = test_fork_schedule();
        let genesis_root = test_genesis_validators_root();

        let agg_and_proof = sample_aggregate_and_proof(100);

        let signature =
            sign_aggregate_and_proof(&agg_and_proof, &secret_key, &schedule, genesis_root);

        let epoch = agg_and_proof.aggregate.data.slot / SLOTS_PER_EPOCH;
        let fork_name = ForkName::from_epoch(epoch, &schedule);
        let fork_version = fork_name.fork_version(&schedule);
        let domain = compute_domain(DOMAIN_AGGREGATE_AND_PROOF, fork_version, genesis_root);
        let signing_root = compute_signing_root(&agg_and_proof, domain);

        assert!(signature.verify(&public_key, &signing_root).is_ok());
    }

    #[test]
    fn test_sign_aggregate_and_proof_uses_correct_domain() {
        let secret_key = SecretKey::generate();
        let public_key = secret_key.public_key();
        let schedule = test_fork_schedule();
        let genesis_root = test_genesis_validators_root();

        let agg_and_proof = sample_aggregate_and_proof(100);

        let signature =
            sign_aggregate_and_proof(&agg_and_proof, &secret_key, &schedule, genesis_root);

        // Wrong domain should fail
        let wrong_domain =
            compute_domain(DOMAIN_SELECTION_PROOF, schedule.genesis_fork_version, genesis_root);
        let wrong_signing_root = compute_signing_root(&agg_and_proof, wrong_domain);
        assert!(signature.verify(&public_key, &wrong_signing_root).is_err());
    }

    #[test]
    fn test_sign_aggregate_and_proof_different_aggregator_different_sig() {
        let secret_key = SecretKey::generate();
        let schedule = test_fork_schedule();
        let genesis_root = test_genesis_validators_root();

        let agg1 = sample_aggregate_and_proof(100);
        let mut agg2 = sample_aggregate_and_proof(100);
        agg2.aggregator_index = 99;

        let sig1 = sign_aggregate_and_proof(&agg1, &secret_key, &schedule, genesis_root);
        let sig2 = sign_aggregate_and_proof(&agg2, &secret_key, &schedule, genesis_root);

        assert_ne!(sig1.to_bytes(), sig2.to_bytes());
    }

    #[test]
    fn test_is_aggregator_modulo_committee_128() {
        // committee_length=128 → modulo = 128/16 = 8
        use eth_types::TARGET_AGGREGATORS_PER_COMMITTEE;
        let modulo = (128u64 / TARGET_AGGREGATORS_PER_COMMITTEE).max(1);
        assert_eq!(modulo, 8);

        let agg_proof = find_aggregator_proof_for_modulo(modulo);
        assert!(is_aggregator(128, &agg_proof));

        let non_agg_proof = find_non_aggregator_proof_for_modulo(modulo);
        assert!(!is_aggregator(128, &non_agg_proof));
    }

    #[test]
    fn test_is_aggregator_modulo_committee_8() {
        // committee_length=8 → 8/16 = 0 → max(1, 0) = 1
        // All validators are aggregators (modulo 1 always == 0)
        assert!(is_aggregator(8, &[0x00; 96]));
        assert!(is_aggregator(8, &[0xff; 96]));
        assert!(is_aggregator(8, &[0xab; 96]));
    }

    #[test]
    fn test_is_aggregator_modulo_committee_0() {
        // committee_length=0 → 0/16 = 0 → max(1, 0) = 1
        // All validators are aggregators (modulo 1 always == 0)
        assert!(is_aggregator(0, &[0xaa; 96]));
        assert!(is_aggregator(0, &[0xff; 96]));
    }

    #[test]
    fn test_is_aggregator_deterministic() {
        let proof = vec![0xaa; 96];
        let result1 = is_aggregator(128, &proof);
        let result2 = is_aggregator(128, &proof);
        assert_eq!(result1, result2);
    }

    #[test]
    fn test_is_aggregator_different_proofs_may_differ() {
        // committee_length=128 → modulo=8
        let agg_proof = find_aggregator_proof_for_modulo(8);
        let non_agg_proof = find_non_aggregator_proof_for_modulo(8);
        assert_ne!(is_aggregator(128, &agg_proof), is_aggregator(128, &non_agg_proof),);
    }

    #[test]
    fn test_is_aggregator_committee_length_one_always_true() {
        // committee_length=1 → 1/16 = 0 → max(1, 0) = 1 → always aggregator
        assert!(is_aggregator(1, &[0x00; 96]));
        assert!(is_aggregator(1, &[0xff; 96]));
        assert!(is_aggregator(1, &[0xab; 96]));
    }

    #[test]
    fn test_is_aggregator_committee_length_16_modulo_1() {
        // committee_length=16 → 16/16 = 1 → max(1, 1) = 1 → always aggregator
        assert!(is_aggregator(16, &[0x00; 96]));
        assert!(is_aggregator(16, &[0xff; 96]));
    }

    #[test]
    fn test_is_aggregator_large_committee() {
        // committee_length=256 → 256/16 = 16
        use eth_types::TARGET_AGGREGATORS_PER_COMMITTEE;
        let modulo = (256u64 / TARGET_AGGREGATORS_PER_COMMITTEE).max(1);
        assert_eq!(modulo, 16);

        let agg_proof = find_aggregator_proof_for_modulo(modulo);
        assert!(is_aggregator(256, &agg_proof));

        let non_agg_proof = find_non_aggregator_proof_for_modulo(modulo);
        assert!(!is_aggregator(256, &non_agg_proof));
    }

    fn sample_electra_aggregate_and_proof(slot: Slot) -> ElectraAggregateAndProof {
        ElectraAggregateAndProof {
            aggregator_index: 42,
            aggregate: ElectraAttestation {
                aggregation_bits: vec![0xff; 4],
                data: AttestationData {
                    slot,
                    index: 0,
                    beacon_block_root: [1u8; 32],
                    // Source is a prior justified checkpoint; target is the current epoch
                    source: Checkpoint { epoch: slot / SLOTS_PER_EPOCH - 1, root: [2u8; 32] },
                    target: Checkpoint { epoch: slot / SLOTS_PER_EPOCH, root: [3u8; 32] },
                },
                signature: vec![0xaa; 96],
                committee_bits: vec![0x01, 0, 0, 0, 0, 0, 0, 0],
            },
            selection_proof: vec![0xbb; 96],
        }
    }

    #[test]
    fn test_sign_electra_aggregate_and_proof_valid() {
        let secret_key = SecretKey::generate();
        let public_key = secret_key.public_key();
        let schedule = test_fork_schedule();
        let genesis_root = test_genesis_validators_root();

        let slot = schedule.electra_fork_epoch * SLOTS_PER_EPOCH;
        let agg_and_proof = sample_electra_aggregate_and_proof(slot);

        let signature =
            sign_electra_aggregate_and_proof(&agg_and_proof, &secret_key, &schedule, genesis_root);

        let epoch = agg_and_proof.aggregate.data.slot / SLOTS_PER_EPOCH;
        let fork_name = ForkName::from_epoch(epoch, &schedule);
        let fork_version = fork_name.fork_version(&schedule);
        let domain = compute_domain(DOMAIN_AGGREGATE_AND_PROOF, fork_version, genesis_root);
        let signing_root = compute_signing_root(&agg_and_proof, domain);

        assert!(signature.verify(&public_key, &signing_root).is_ok());
    }

    #[test]
    fn test_sign_electra_aggregate_and_proof_different_root_from_pre_electra() {
        let secret_key = SecretKey::generate();
        let schedule = test_fork_schedule();
        let genesis_root = test_genesis_validators_root();

        let slot = schedule.electra_fork_epoch * SLOTS_PER_EPOCH;

        let pre_electra = sample_aggregate_and_proof(slot);
        let electra = sample_electra_aggregate_and_proof(slot);

        let sig_pre = sign_aggregate_and_proof(&pre_electra, &secret_key, &schedule, genesis_root);
        let sig_electra =
            sign_electra_aggregate_and_proof(&electra, &secret_key, &schedule, genesis_root);

        assert_ne!(sig_pre.to_bytes(), sig_electra.to_bytes());
    }

    #[test]
    fn test_sign_electra_aggregate_and_proof_uses_correct_domain() {
        let secret_key = SecretKey::generate();
        let public_key = secret_key.public_key();
        let schedule = test_fork_schedule();
        let genesis_root = test_genesis_validators_root();

        let slot = schedule.electra_fork_epoch * SLOTS_PER_EPOCH;
        let agg_and_proof = sample_electra_aggregate_and_proof(slot);

        let signature =
            sign_electra_aggregate_and_proof(&agg_and_proof, &secret_key, &schedule, genesis_root);

        // Wrong domain should fail
        let wrong_domain =
            compute_domain(DOMAIN_SELECTION_PROOF, schedule.genesis_fork_version, genesis_root);
        let wrong_signing_root = compute_signing_root(&agg_and_proof, wrong_domain);
        assert!(signature.verify(&public_key, &wrong_signing_root).is_err());
    }

    fn find_aggregator_proof_for_modulo(modulo: u64) -> Vec<u8> {
        for i in 0u64.. {
            let proof = i.to_le_bytes().to_vec();
            let hash = Sha256::digest(&proof);
            let value = u64::from_le_bytes(hash[..8].try_into().unwrap());
            if value % modulo == 0 {
                return proof;
            }
        }
        unreachable!()
    }

    fn find_non_aggregator_proof_for_modulo(modulo: u64) -> Vec<u8> {
        for i in 0u64.. {
            let proof = i.to_le_bytes().to_vec();
            let hash = Sha256::digest(&proof);
            let value = u64::from_le_bytes(hash[..8].try_into().unwrap());
            if value % modulo != 0 {
                return proof;
            }
        }
        unreachable!()
    }
}
