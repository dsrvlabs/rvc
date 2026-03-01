use tree_hash::TreeHash;

use super::bls::{SecretKey, Signature};
use eth_types::{AttestationData, Domain, DomainType, Fork, ForkData, Root, SigningData};

pub const DOMAIN_BEACON_ATTESTER: DomainType = [0x01, 0x00, 0x00, 0x00];

fn hash_tree_root<T: TreeHash>(object: &T) -> Root {
    object.tree_hash_root().0
}

pub fn compute_fork_data_root(current_version: [u8; 4], genesis_validators_root: Root) -> Root {
    let fork_data = ForkData { current_version, genesis_validators_root };
    hash_tree_root(&fork_data)
}

pub fn compute_domain(
    domain_type: DomainType,
    fork_version: [u8; 4],
    genesis_validators_root: Root,
) -> Domain {
    let fork_data_root = compute_fork_data_root(fork_version, genesis_validators_root);
    let mut domain = [0u8; 32];
    domain[..4].copy_from_slice(&domain_type);
    domain[4..32].copy_from_slice(&fork_data_root[..28]);
    domain
}

pub fn compute_signing_root<T: TreeHash>(ssz_object: &T, domain: Domain) -> Root {
    let object_root = hash_tree_root(ssz_object);
    let signing_data = SigningData { object_root, domain };
    hash_tree_root(&signing_data)
}

pub fn sign_attestation(
    attestation_data: &AttestationData,
    secret_key: &SecretKey,
    fork: &Fork,
    genesis_validators_root: Root,
) -> Signature {
    let fork_version = if attestation_data.target.epoch >= fork.epoch {
        fork.current_version
    } else {
        fork.previous_version
    };

    let domain = compute_domain(DOMAIN_BEACON_ATTESTER, fork_version, genesis_validators_root);

    let signing_root = compute_signing_root(attestation_data, domain);
    secret_key.sign(&signing_root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use eth_types::{Checkpoint, ForkName, ForkSchedule, SLOTS_PER_EPOCH};
    use tree_hash::TreeHash;

    #[test]
    fn test_hash_tree_root_uses_spec_compliant_tree_hash() {
        let fork_data = ForkData {
            current_version: [0x00, 0x00, 0x00, 0x00],
            genesis_validators_root: [0x00; 32],
        };

        let expected = fork_data.tree_hash_root();
        let actual = hash_tree_root(&fork_data);

        assert_eq!(actual, expected.0);
    }

    #[test]
    fn test_checkpoint_tree_hash_root() {
        let checkpoint = Checkpoint { epoch: 100, root: [0xab; 32] };

        let expected = checkpoint.tree_hash_root();
        let actual = hash_tree_root(&checkpoint);

        assert_eq!(actual, expected.0);
    }

    #[test]
    fn test_attestation_data_tree_hash_root() {
        let data = create_test_attestation_data();

        let expected = data.tree_hash_root();
        let actual = hash_tree_root(&data);

        assert_eq!(actual, expected.0);
    }

    #[test]
    fn test_signing_data_tree_hash_root() {
        let signing_data = SigningData { object_root: [0x11; 32], domain: [0x22; 32] };

        let expected = signing_data.tree_hash_root();
        let actual = hash_tree_root(&signing_data);

        assert_eq!(actual, expected.0);
    }

    #[test]
    fn test_domain_beacon_attester_value() {
        assert_eq!(DOMAIN_BEACON_ATTESTER, [0x01, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_compute_fork_data_root_deterministic() {
        let version = [0x00, 0x00, 0x00, 0x01];
        let genesis_root = [0xab; 32];

        let root1 = compute_fork_data_root(version, genesis_root);
        let root2 = compute_fork_data_root(version, genesis_root);

        assert_eq!(root1, root2);
    }

    #[test]
    fn test_compute_fork_data_root_different_inputs_different_outputs() {
        let version1 = [0x00, 0x00, 0x00, 0x01];
        let version2 = [0x00, 0x00, 0x00, 0x02];
        let genesis_root = [0xab; 32];

        let root1 = compute_fork_data_root(version1, genesis_root);
        let root2 = compute_fork_data_root(version2, genesis_root);

        assert_ne!(root1, root2);
    }

    #[test]
    fn test_compute_domain_includes_domain_type() {
        let domain = compute_domain(DOMAIN_BEACON_ATTESTER, [0x00, 0x00, 0x00, 0x01], [0x00; 32]);

        assert_eq!(&domain[..4], &DOMAIN_BEACON_ATTESTER);
    }

    #[test]
    fn test_compute_domain_different_fork_versions() {
        let genesis_root = [0x00; 32];

        let domain1 =
            compute_domain(DOMAIN_BEACON_ATTESTER, [0x00, 0x00, 0x00, 0x01], genesis_root);
        let domain2 =
            compute_domain(DOMAIN_BEACON_ATTESTER, [0x00, 0x00, 0x00, 0x02], genesis_root);

        assert_ne!(domain1, domain2);
        assert_eq!(&domain1[..4], &domain2[..4]);
    }

    #[test]
    fn test_compute_signing_root_deterministic() {
        let data = create_test_attestation_data();
        let domain = [0x01; 32];

        let root1 = compute_signing_root(&data, domain);
        let root2 = compute_signing_root(&data, domain);

        assert_eq!(root1, root2);
    }

    #[test]
    fn test_compute_signing_root_different_domains() {
        let data = create_test_attestation_data();

        let root1 = compute_signing_root(&data, [0x01; 32]);
        let root2 = compute_signing_root(&data, [0x02; 32]);

        assert_ne!(root1, root2);
    }

    #[test]
    fn test_sign_attestation_produces_valid_signature() {
        let secret_key = SecretKey::generate();
        let public_key = secret_key.public_key();
        let attestation_data = create_test_attestation_data();
        let fork = create_test_fork();
        let genesis_root = [0xaa; 32];

        let signature = sign_attestation(&attestation_data, &secret_key, &fork, genesis_root);

        let fork_version = fork.current_version;
        let domain = compute_domain(DOMAIN_BEACON_ATTESTER, fork_version, genesis_root);
        let signing_root = compute_signing_root(&attestation_data, domain);

        assert!(signature.verify(&public_key, &signing_root).is_ok());
    }

    #[test]
    fn test_sign_attestation_uses_previous_version_for_old_epoch() {
        let secret_key = SecretKey::generate();
        let public_key = secret_key.public_key();
        let genesis_root = [0xaa; 32];

        let fork = Fork {
            previous_version: [0x00, 0x00, 0x00, 0x01],
            current_version: [0x00, 0x00, 0x00, 0x02],
            epoch: 100,
        };

        let attestation_data = AttestationData {
            slot: 1000,
            index: 1,
            beacon_block_root: [0x11; 32],
            source: Checkpoint { epoch: 50, root: [0x22; 32] },
            target: Checkpoint { epoch: 51, root: [0x33; 32] },
        };

        let signature = sign_attestation(&attestation_data, &secret_key, &fork, genesis_root);

        let domain = compute_domain(DOMAIN_BEACON_ATTESTER, fork.previous_version, genesis_root);
        let signing_root = compute_signing_root(&attestation_data, domain);

        assert!(signature.verify(&public_key, &signing_root).is_ok());
    }

    #[test]
    fn test_sign_attestation_uses_current_version_for_current_epoch() {
        let secret_key = SecretKey::generate();
        let public_key = secret_key.public_key();
        let genesis_root = [0xaa; 32];

        let fork = Fork {
            previous_version: [0x00, 0x00, 0x00, 0x01],
            current_version: [0x00, 0x00, 0x00, 0x02],
            epoch: 100,
        };

        let attestation_data = AttestationData {
            slot: 5000,
            index: 1,
            beacon_block_root: [0x11; 32],
            source: Checkpoint { epoch: 150, root: [0x22; 32] },
            target: Checkpoint { epoch: 151, root: [0x33; 32] },
        };

        let signature = sign_attestation(&attestation_data, &secret_key, &fork, genesis_root);

        let domain = compute_domain(DOMAIN_BEACON_ATTESTER, fork.current_version, genesis_root);
        let signing_root = compute_signing_root(&attestation_data, domain);

        assert!(signature.verify(&public_key, &signing_root).is_ok());
    }

    #[test]
    fn test_different_attestation_data_produces_different_signatures() {
        let secret_key = SecretKey::generate();
        let fork = create_test_fork();
        let genesis_root = [0xaa; 32];

        let data1 = create_test_attestation_data();
        let mut data2 = create_test_attestation_data();
        data2.slot = 2000;

        let sig1 = sign_attestation(&data1, &secret_key, &fork, genesis_root);
        let sig2 = sign_attestation(&data2, &secret_key, &fork, genesis_root);

        assert_ne!(sig1.to_bytes(), sig2.to_bytes());
    }

    fn create_test_attestation_data() -> AttestationData {
        AttestationData {
            slot: 1000,
            index: 5,
            beacon_block_root: [0x11; 32],
            source: Checkpoint { epoch: 99, root: [0x22; 32] },
            target: Checkpoint { epoch: 100, root: [0x33; 32] },
        }
    }

    fn create_test_fork() -> Fork {
        Fork {
            previous_version: [0x00, 0x00, 0x00, 0x01],
            current_version: [0x00, 0x00, 0x00, 0x02],
            epoch: 50,
        }
    }

    fn create_boundary_test_schedule() -> ForkSchedule {
        ForkSchedule {
            genesis_fork_version: [0x00, 0x00, 0x00, 0x00],
            altair_fork_epoch: 10,
            altair_fork_version: [0x01, 0x00, 0x00, 0x00],
            bellatrix_fork_epoch: 20,
            bellatrix_fork_version: [0x02, 0x00, 0x00, 0x00],
            capella_fork_epoch: 30,
            capella_fork_version: [0x03, 0x00, 0x00, 0x00],
            deneb_fork_epoch: 40,
            deneb_fork_version: [0x04, 0x00, 0x00, 0x00],
            electra_fork_epoch: 50,
            electra_fork_version: [0x05, 0x00, 0x00, 0x00],
        }
    }

    /// Derives a Fork struct from a ForkSchedule for a given epoch,
    /// mirroring the production logic in orchestrator::derive_fork_for_epoch
    /// and signer::ValidatorSigner::sign_attestation.
    fn derive_fork_for_epoch(epoch: u64, schedule: &ForkSchedule) -> Fork {
        let fork_name = ForkName::from_epoch(epoch, schedule);
        let current_version = fork_name.fork_version(schedule);
        let prior_fork_name = if epoch > 0 {
            ForkName::from_epoch(epoch - 1, schedule)
        } else {
            ForkName::from_epoch(0, schedule)
        };
        let previous_version = prior_fork_name.fork_version(schedule);

        Fork {
            previous_version,
            current_version,
            epoch: if current_version != previous_version { epoch } else { 0 },
        }
    }

    // --- Fork boundary signing tests ---

    #[test]
    fn test_sign_attestation_at_electra_boundary_minus_one_uses_deneb_version() {
        let schedule = create_boundary_test_schedule();
        let electra_epoch = schedule.electra_fork_epoch; // 50
        let target_epoch = electra_epoch - 1; // 49 → Deneb era

        let secret_key = SecretKey::generate();
        let public_key = secret_key.public_key();
        let genesis_root = [0xaa; 32];

        let attestation_data = AttestationData {
            slot: target_epoch * SLOTS_PER_EPOCH,
            index: 0,
            beacon_block_root: [0x11; 32],
            source: Checkpoint { epoch: target_epoch - 1, root: [0x22; 32] },
            target: Checkpoint { epoch: target_epoch, root: [0x33; 32] },
        };

        let fork = derive_fork_for_epoch(target_epoch, &schedule);
        let signature = sign_attestation(&attestation_data, &secret_key, &fork, genesis_root);

        let expected_version = schedule.deneb_fork_version;
        let domain = compute_domain(DOMAIN_BEACON_ATTESTER, expected_version, genesis_root);
        let signing_root = compute_signing_root(&attestation_data, domain);

        assert!(
            signature.verify(&public_key, &signing_root).is_ok(),
            "Attestation at electra_fork_epoch - 1 must use Deneb fork version"
        );
    }

    #[test]
    fn test_sign_attestation_at_electra_boundary_uses_electra_version() {
        let schedule = create_boundary_test_schedule();
        let electra_epoch = schedule.electra_fork_epoch; // 50
        let target_epoch = electra_epoch; // 50 → Electra era

        let secret_key = SecretKey::generate();
        let public_key = secret_key.public_key();
        let genesis_root = [0xaa; 32];

        let attestation_data = AttestationData {
            slot: target_epoch * SLOTS_PER_EPOCH,
            index: 0,
            beacon_block_root: [0x11; 32],
            source: Checkpoint { epoch: target_epoch - 1, root: [0x22; 32] },
            target: Checkpoint { epoch: target_epoch, root: [0x33; 32] },
        };

        let fork = derive_fork_for_epoch(target_epoch, &schedule);
        let signature = sign_attestation(&attestation_data, &secret_key, &fork, genesis_root);

        let expected_version = schedule.electra_fork_version;
        let domain = compute_domain(DOMAIN_BEACON_ATTESTER, expected_version, genesis_root);
        let signing_root = compute_signing_root(&attestation_data, domain);

        assert!(
            signature.verify(&public_key, &signing_root).is_ok(),
            "Attestation at electra_fork_epoch must use Electra fork version"
        );
    }

    #[test]
    fn test_sign_attestation_at_electra_boundary_plus_one_uses_electra_version() {
        let schedule = create_boundary_test_schedule();
        let electra_epoch = schedule.electra_fork_epoch; // 50
        let target_epoch = electra_epoch + 1; // 51 → Electra era

        let secret_key = SecretKey::generate();
        let public_key = secret_key.public_key();
        let genesis_root = [0xaa; 32];

        let attestation_data = AttestationData {
            slot: target_epoch * SLOTS_PER_EPOCH,
            index: 0,
            beacon_block_root: [0x11; 32],
            source: Checkpoint { epoch: target_epoch - 1, root: [0x22; 32] },
            target: Checkpoint { epoch: target_epoch, root: [0x33; 32] },
        };

        let fork = derive_fork_for_epoch(target_epoch, &schedule);
        let signature = sign_attestation(&attestation_data, &secret_key, &fork, genesis_root);

        let expected_version = schedule.electra_fork_version;
        let domain = compute_domain(DOMAIN_BEACON_ATTESTER, expected_version, genesis_root);
        let signing_root = compute_signing_root(&attestation_data, domain);

        assert!(
            signature.verify(&public_key, &signing_root).is_ok(),
            "Attestation at electra_fork_epoch + 1 must use Electra fork version"
        );
    }

    mod proptest_fork_boundary {
        use super::*;
        use proptest::prelude::*;

        prop_compose! {
            fn arb_epoch()(epoch in 1u64..200u64) -> u64 {
                epoch
            }
        }

        proptest! {
            #[test]
            fn derive_fork_for_epoch_produces_correct_fork_version(epoch in 1u64..200u64) {
                let schedule = create_boundary_test_schedule();
                let fork = derive_fork_for_epoch(epoch, &schedule);

                // The spec-expected fork version for this epoch
                let expected_fork_name = ForkName::from_epoch(epoch, &schedule);
                let expected_version = expected_fork_name.fork_version(&schedule);

                // sign_attestation selects fork version via: target_epoch >= fork.epoch → current, else previous
                // Verify the derived Fork produces the expected version through that selection
                let selected_version = if epoch >= fork.epoch {
                    fork.current_version
                } else {
                    fork.previous_version
                };

                prop_assert_eq!(
                    selected_version, expected_version,
                    "epoch {}: derive_fork_for_epoch must produce a Fork that selects {:?}, got {:?}",
                    epoch, expected_version, selected_version
                );
            }
        }
    }
}
