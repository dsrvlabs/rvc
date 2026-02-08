use super::bls::{SecretKey, Signature};
use super::signing::{compute_domain, compute_signing_root};
use eth_types::{
    ContributionAndProof, ForkName, ForkSchedule, Root, Slot, SyncAggregatorSelectionData,
    DOMAIN_CONTRIBUTION_AND_PROOF, DOMAIN_SYNC_COMMITTEE, DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF,
    SLOTS_PER_EPOCH,
};

pub fn sign_sync_committee_message(
    beacon_block_root: &Root,
    slot: Slot,
    secret_key: &SecretKey,
    fork_schedule: &ForkSchedule,
    genesis_validators_root: Root,
) -> Signature {
    let epoch = slot / SLOTS_PER_EPOCH;
    let fork_name = ForkName::from_epoch(epoch, fork_schedule);
    let fork_version = fork_name.fork_version(fork_schedule);
    let domain = compute_domain(DOMAIN_SYNC_COMMITTEE, fork_version, genesis_validators_root);
    let signing_root = compute_signing_root(beacon_block_root, domain);
    secret_key.sign(&signing_root)
}

pub fn sign_contribution_and_proof(
    contribution_and_proof: &ContributionAndProof,
    secret_key: &SecretKey,
    fork_schedule: &ForkSchedule,
    genesis_validators_root: Root,
) -> Signature {
    let epoch = contribution_and_proof.contribution.slot / SLOTS_PER_EPOCH;
    let fork_name = ForkName::from_epoch(epoch, fork_schedule);
    let fork_version = fork_name.fork_version(fork_schedule);
    let domain =
        compute_domain(DOMAIN_CONTRIBUTION_AND_PROOF, fork_version, genesis_validators_root);
    let signing_root = compute_signing_root(contribution_and_proof, domain);
    secret_key.sign(&signing_root)
}

pub fn sign_sync_committee_selection_proof(
    slot: Slot,
    subcommittee_index: u64,
    secret_key: &SecretKey,
    fork_schedule: &ForkSchedule,
    genesis_validators_root: Root,
) -> Signature {
    let epoch = slot / SLOTS_PER_EPOCH;
    let fork_name = ForkName::from_epoch(epoch, fork_schedule);
    let fork_version = fork_name.fork_version(fork_schedule);
    let domain = compute_domain(
        DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF,
        fork_version,
        genesis_validators_root,
    );
    let selection_data = SyncAggregatorSelectionData { slot, subcommittee_index };
    let signing_root = compute_signing_root(&selection_data, domain);
    secret_key.sign(&signing_root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use eth_types::{SyncAggregatorSelectionData, SyncCommitteeContribution};

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
        }
    }

    fn test_genesis_validators_root() -> Root {
        [0xaa; 32]
    }

    #[test]
    fn test_sign_sync_committee_message_valid() {
        let secret_key = SecretKey::generate();
        let public_key = secret_key.public_key();
        let beacon_block_root = [0x11; 32];
        let slot: Slot = 100;
        let schedule = test_fork_schedule();
        let genesis_root = test_genesis_validators_root();

        let signature = sign_sync_committee_message(
            &beacon_block_root,
            slot,
            &secret_key,
            &schedule,
            genesis_root,
        );

        let epoch = slot / SLOTS_PER_EPOCH;
        let fork_name = ForkName::from_epoch(epoch, &schedule);
        let fork_version = fork_name.fork_version(&schedule);
        let domain = compute_domain(DOMAIN_SYNC_COMMITTEE, fork_version, genesis_root);
        let signing_root = compute_signing_root(&beacon_block_root, domain);

        assert!(signature.verify(&public_key, &signing_root).is_ok());
    }

    #[test]
    fn test_sign_sync_committee_message_different_roots_different_sigs() {
        let secret_key = SecretKey::generate();
        let schedule = test_fork_schedule();
        let genesis_root = test_genesis_validators_root();
        let slot: Slot = 100;

        let root1 = [0x11; 32];
        let root2 = [0x22; 32];

        let sig1 = sign_sync_committee_message(&root1, slot, &secret_key, &schedule, genesis_root);
        let sig2 = sign_sync_committee_message(&root2, slot, &secret_key, &schedule, genesis_root);

        assert_ne!(sig1.to_bytes(), sig2.to_bytes());
    }

    #[test]
    fn test_sign_sync_committee_message_fork_aware() {
        let secret_key = SecretKey::generate();
        let public_key = secret_key.public_key();
        let beacon_block_root = [0x11; 32];
        let genesis_root = test_genesis_validators_root();

        let schedule = test_fork_schedule();

        // Phase0 slot (epoch 0)
        let slot_phase0: Slot = 0;
        let sig_phase0 = sign_sync_committee_message(
            &beacon_block_root,
            slot_phase0,
            &secret_key,
            &schedule,
            genesis_root,
        );

        // Altair slot (epoch 74240)
        let slot_altair: Slot = 74240 * SLOTS_PER_EPOCH;
        let sig_altair = sign_sync_committee_message(
            &beacon_block_root,
            slot_altair,
            &secret_key,
            &schedule,
            genesis_root,
        );

        assert_ne!(sig_phase0.to_bytes(), sig_altair.to_bytes());

        // Verify altair signature uses altair fork version
        let domain =
            compute_domain(DOMAIN_SYNC_COMMITTEE, schedule.altair_fork_version, genesis_root);
        let signing_root = compute_signing_root(&beacon_block_root, domain);
        assert!(sig_altair.verify(&public_key, &signing_root).is_ok());
    }

    #[test]
    fn test_sign_sync_committee_message_uses_correct_domain() {
        let secret_key = SecretKey::generate();
        let public_key = secret_key.public_key();
        let beacon_block_root = [0x11; 32];
        let slot: Slot = 100;
        let schedule = test_fork_schedule();
        let genesis_root = test_genesis_validators_root();

        let signature = sign_sync_committee_message(
            &beacon_block_root,
            slot,
            &secret_key,
            &schedule,
            genesis_root,
        );

        // Verify it does NOT verify against a wrong domain
        let wrong_domain = compute_domain(
            DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF,
            schedule.genesis_fork_version,
            genesis_root,
        );
        let wrong_signing_root = compute_signing_root(&beacon_block_root, wrong_domain);
        assert!(signature.verify(&public_key, &wrong_signing_root).is_err());
    }

    #[test]
    fn test_sign_contribution_and_proof_valid() {
        let secret_key = SecretKey::generate();
        let public_key = secret_key.public_key();
        let schedule = test_fork_schedule();
        let genesis_root = test_genesis_validators_root();

        let contribution_and_proof = create_test_contribution_and_proof(100);

        let signature = sign_contribution_and_proof(
            &contribution_and_proof,
            &secret_key,
            &schedule,
            genesis_root,
        );

        let epoch = contribution_and_proof.contribution.slot / SLOTS_PER_EPOCH;
        let fork_name = ForkName::from_epoch(epoch, &schedule);
        let fork_version = fork_name.fork_version(&schedule);
        let domain = compute_domain(DOMAIN_CONTRIBUTION_AND_PROOF, fork_version, genesis_root);
        let signing_root = compute_signing_root(&contribution_and_proof, domain);

        assert!(signature.verify(&public_key, &signing_root).is_ok());
    }

    #[test]
    fn test_sign_contribution_and_proof_uses_correct_domain() {
        let secret_key = SecretKey::generate();
        let public_key = secret_key.public_key();
        let schedule = test_fork_schedule();
        let genesis_root = test_genesis_validators_root();

        let contribution_and_proof = create_test_contribution_and_proof(100);

        let signature = sign_contribution_and_proof(
            &contribution_and_proof,
            &secret_key,
            &schedule,
            genesis_root,
        );

        // Verify it does NOT verify against sync committee domain
        let wrong_domain =
            compute_domain(DOMAIN_SYNC_COMMITTEE, schedule.genesis_fork_version, genesis_root);
        let wrong_signing_root = compute_signing_root(&contribution_and_proof, wrong_domain);
        assert!(signature.verify(&public_key, &wrong_signing_root).is_err());
    }

    #[test]
    fn test_sign_sync_committee_selection_proof_valid() {
        let secret_key = SecretKey::generate();
        let public_key = secret_key.public_key();
        let slot: Slot = 100;
        let subcommittee_index: u64 = 2;
        let schedule = test_fork_schedule();
        let genesis_root = test_genesis_validators_root();

        let signature = sign_sync_committee_selection_proof(
            slot,
            subcommittee_index,
            &secret_key,
            &schedule,
            genesis_root,
        );

        let epoch = slot / SLOTS_PER_EPOCH;
        let fork_name = ForkName::from_epoch(epoch, &schedule);
        let fork_version = fork_name.fork_version(&schedule);
        let domain =
            compute_domain(DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF, fork_version, genesis_root);
        let selection_data = SyncAggregatorSelectionData { slot, subcommittee_index };
        let signing_root = compute_signing_root(&selection_data, domain);

        assert!(signature.verify(&public_key, &signing_root).is_ok());
    }

    #[test]
    fn test_sign_sync_committee_selection_proof_different_slots() {
        let secret_key = SecretKey::generate();
        let schedule = test_fork_schedule();
        let genesis_root = test_genesis_validators_root();

        let sig1 =
            sign_sync_committee_selection_proof(100, 0, &secret_key, &schedule, genesis_root);
        let sig2 =
            sign_sync_committee_selection_proof(200, 0, &secret_key, &schedule, genesis_root);

        assert_ne!(sig1.to_bytes(), sig2.to_bytes());
    }

    #[test]
    fn test_sign_sync_committee_selection_proof_fork_aware() {
        let secret_key = SecretKey::generate();
        let public_key = secret_key.public_key();
        let genesis_root = test_genesis_validators_root();
        let schedule = test_fork_schedule();
        let subcommittee_index: u64 = 1;

        // Deneb slot
        let slot_deneb: Slot = 269568 * SLOTS_PER_EPOCH;
        let sig_deneb = sign_sync_committee_selection_proof(
            slot_deneb,
            subcommittee_index,
            &secret_key,
            &schedule,
            genesis_root,
        );

        // Verify it uses deneb fork version
        let domain = compute_domain(
            DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF,
            schedule.deneb_fork_version,
            genesis_root,
        );
        let selection_data = SyncAggregatorSelectionData { slot: slot_deneb, subcommittee_index };
        let signing_root = compute_signing_root(&selection_data, domain);
        assert!(sig_deneb.verify(&public_key, &signing_root).is_ok());

        // Phase0 slot should produce different signature
        let slot_phase0: Slot = 0;
        let sig_phase0 = sign_sync_committee_selection_proof(
            slot_phase0,
            subcommittee_index,
            &secret_key,
            &schedule,
            genesis_root,
        );

        assert_ne!(sig_deneb.to_bytes(), sig_phase0.to_bytes());
    }

    #[test]
    fn test_sign_sync_committee_selection_proof_uses_correct_domain() {
        let secret_key = SecretKey::generate();
        let public_key = secret_key.public_key();
        let slot: Slot = 100;
        let subcommittee_index: u64 = 0;
        let schedule = test_fork_schedule();
        let genesis_root = test_genesis_validators_root();

        let signature = sign_sync_committee_selection_proof(
            slot,
            subcommittee_index,
            &secret_key,
            &schedule,
            genesis_root,
        );

        // Verify it does NOT verify against sync committee domain
        let wrong_domain =
            compute_domain(DOMAIN_SYNC_COMMITTEE, schedule.genesis_fork_version, genesis_root);
        let selection_data = SyncAggregatorSelectionData { slot, subcommittee_index };
        let wrong_signing_root = compute_signing_root(&selection_data, wrong_domain);
        assert!(signature.verify(&public_key, &wrong_signing_root).is_err());
    }

    #[test]
    fn test_selection_proof_binds_to_subcommittee_index() {
        let secret_key = SecretKey::generate();
        let schedule = test_fork_schedule();
        let genesis_root = test_genesis_validators_root();
        let slot: Slot = 100;

        let sig_sub0 =
            sign_sync_committee_selection_proof(slot, 0, &secret_key, &schedule, genesis_root);
        let sig_sub1 =
            sign_sync_committee_selection_proof(slot, 1, &secret_key, &schedule, genesis_root);

        assert_ne!(sig_sub0.to_bytes(), sig_sub1.to_bytes());
    }

    fn create_test_contribution_and_proof(slot: Slot) -> ContributionAndProof {
        ContributionAndProof {
            aggregator_index: 42,
            contribution: SyncCommitteeContribution {
                slot,
                beacon_block_root: [0x11; 32],
                subcommittee_index: 2,
                aggregation_bits: vec![0xff; 16],
                signature: vec![0xbb; 96],
            },
            selection_proof: vec![0xcc; 96],
        }
    }
}
