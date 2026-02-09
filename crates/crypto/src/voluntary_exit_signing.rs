use super::bls::{SecretKey, Signature};
use super::signing::{compute_domain, compute_signing_root};
use eth_types::{ForkName, ForkSchedule, Root, VoluntaryExit, DOMAIN_VOLUNTARY_EXIT};

/// Signs a voluntary exit with the correct fork-aware domain.
///
/// Per the Ethereum consensus spec, voluntary exits use `DOMAIN_VOLUNTARY_EXIT`
/// and the fork version corresponding to the exit epoch.
pub fn sign_voluntary_exit(
    voluntary_exit: &VoluntaryExit,
    secret_key: &SecretKey,
    fork_schedule: &ForkSchedule,
    genesis_validators_root: Root,
) -> Signature {
    let fork_name = ForkName::from_epoch(voluntary_exit.epoch, fork_schedule);
    let fork_version = fork_name.fork_version(fork_schedule);
    let domain = compute_domain(DOMAIN_VOLUNTARY_EXIT, fork_version, genesis_validators_root);
    let signing_root = compute_signing_root(voluntary_exit, domain);
    secret_key.sign(&signing_root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::compute_domain;

    fn test_fork_schedule() -> ForkSchedule {
        ForkSchedule {
            genesis_fork_version: [0, 0, 0, 0],
            altair_fork_epoch: 10,
            altair_fork_version: [1, 0, 0, 0],
            bellatrix_fork_epoch: 20,
            bellatrix_fork_version: [2, 0, 0, 0],
            capella_fork_epoch: 30,
            capella_fork_version: [3, 0, 0, 0],
            deneb_fork_epoch: 40,
            deneb_fork_version: [4, 0, 0, 0],
            electra_fork_epoch: 50,
            electra_fork_version: [5, 0, 0, 0],
        }
    }

    fn test_genesis_validators_root() -> Root {
        [0xaa; 32]
    }

    #[test]
    fn test_sign_voluntary_exit_valid() {
        let secret_key = SecretKey::generate();
        let public_key = secret_key.public_key();
        let schedule = test_fork_schedule();
        let genesis_root = test_genesis_validators_root();

        let exit = VoluntaryExit { epoch: 5, validator_index: 42 };

        let signature = sign_voluntary_exit(&exit, &secret_key, &schedule, genesis_root);

        let fork_name = ForkName::from_epoch(exit.epoch, &schedule);
        let fork_version = fork_name.fork_version(&schedule);
        let domain = compute_domain(DOMAIN_VOLUNTARY_EXIT, fork_version, genesis_root);
        let signing_root = compute_signing_root(&exit, domain);

        assert!(signature.verify(&public_key, &signing_root).is_ok());
    }

    #[test]
    fn test_sign_voluntary_exit_uses_correct_domain() {
        let secret_key = SecretKey::generate();
        let public_key = secret_key.public_key();
        let schedule = test_fork_schedule();
        let genesis_root = test_genesis_validators_root();

        let exit = VoluntaryExit { epoch: 5, validator_index: 42 };

        let signature = sign_voluntary_exit(&exit, &secret_key, &schedule, genesis_root);

        // Wrong domain should fail verification
        let wrong_domain = compute_domain(
            eth_types::DOMAIN_BEACON_PROPOSER,
            schedule.genesis_fork_version,
            genesis_root,
        );
        let wrong_signing_root = compute_signing_root(&exit, wrong_domain);
        assert!(signature.verify(&public_key, &wrong_signing_root).is_err());
    }

    #[test]
    fn test_sign_voluntary_exit_fork_aware() {
        let secret_key = SecretKey::generate();
        let public_key = secret_key.public_key();
        let schedule = test_fork_schedule();
        let genesis_root = test_genesis_validators_root();

        // Exit at Altair epoch
        let exit = VoluntaryExit { epoch: 15, validator_index: 42 };
        let signature = sign_voluntary_exit(&exit, &secret_key, &schedule, genesis_root);

        let domain =
            compute_domain(DOMAIN_VOLUNTARY_EXIT, schedule.altair_fork_version, genesis_root);
        let signing_root = compute_signing_root(&exit, domain);
        assert!(signature.verify(&public_key, &signing_root).is_ok());

        // Genesis fork version should fail
        let wrong_domain =
            compute_domain(DOMAIN_VOLUNTARY_EXIT, schedule.genesis_fork_version, genesis_root);
        let wrong_signing_root = compute_signing_root(&exit, wrong_domain);
        assert!(signature.verify(&public_key, &wrong_signing_root).is_err());
    }

    #[test]
    fn test_sign_voluntary_exit_different_epochs_different_sigs() {
        let secret_key = SecretKey::generate();
        let schedule = test_fork_schedule();
        let genesis_root = test_genesis_validators_root();

        let exit1 = VoluntaryExit { epoch: 5, validator_index: 42 };
        let exit2 = VoluntaryExit { epoch: 15, validator_index: 42 };

        let sig1 = sign_voluntary_exit(&exit1, &secret_key, &schedule, genesis_root);
        let sig2 = sign_voluntary_exit(&exit2, &secret_key, &schedule, genesis_root);

        assert_ne!(sig1.to_bytes(), sig2.to_bytes());
    }

    #[test]
    fn test_sign_voluntary_exit_different_validators_different_sigs() {
        let secret_key = SecretKey::generate();
        let schedule = test_fork_schedule();
        let genesis_root = test_genesis_validators_root();

        let exit1 = VoluntaryExit { epoch: 5, validator_index: 42 };
        let exit2 = VoluntaryExit { epoch: 5, validator_index: 99 };

        let sig1 = sign_voluntary_exit(&exit1, &secret_key, &schedule, genesis_root);
        let sig2 = sign_voluntary_exit(&exit2, &secret_key, &schedule, genesis_root);

        assert_ne!(sig1.to_bytes(), sig2.to_bytes());
    }

    #[test]
    fn test_sign_voluntary_exit_deterministic() {
        let secret_key = SecretKey::generate();
        let schedule = test_fork_schedule();
        let genesis_root = test_genesis_validators_root();

        let exit = VoluntaryExit { epoch: 5, validator_index: 42 };

        let sig1 = sign_voluntary_exit(&exit, &secret_key, &schedule, genesis_root);
        let sig2 = sign_voluntary_exit(&exit, &secret_key, &schedule, genesis_root);

        assert_eq!(sig1.to_bytes(), sig2.to_bytes());
    }
}
