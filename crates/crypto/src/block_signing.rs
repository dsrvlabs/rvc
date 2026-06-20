use eth_types::{
    Epoch, ForkName, ForkSchedule, Root, DOMAIN_BEACON_PROPOSER, DOMAIN_RANDAO, SLOTS_PER_EPOCH,
};

use crate::bls::{SecretKey, Signature};
use crate::signing::{compute_domain, compute_signing_root};

#[tracing::instrument(
    name = "rvc.crypto.sign_block",
    level = "debug",
    skip_all,
    fields(rvc.signing_type = "block"),
)]
/// Sign a beacon block with the correct fork-aware domain.
///
/// `block_root` must be the `hash_tree_root()` of the `BeaconBlock`.
/// Because `[u8; 32]` tree-hashes as the identity, callers can pass
/// a pre-computed root directly.
pub fn sign_block(
    block_root: &Root,
    slot: u64,
    secret_key: &SecretKey,
    fork_schedule: &ForkSchedule,
    genesis_validators_root: &Root,
) -> Signature {
    let epoch = slot / SLOTS_PER_EPOCH;
    let fork_name = ForkName::from_epoch(epoch, fork_schedule);
    let fork_version = fork_name.fork_version(fork_schedule);

    let domain = compute_domain(DOMAIN_BEACON_PROPOSER, fork_version, *genesis_validators_root);
    let signing_root = compute_signing_root(block_root, domain);
    secret_key.sign(&signing_root)
}

#[tracing::instrument(
    name = "rvc.crypto.sign_randao",
    level = "debug",
    skip_all,
    fields(rvc.signing_type = "randao"),
)]
/// Sign a RANDAO reveal for a given epoch.
pub fn sign_randao_reveal(
    epoch: Epoch,
    secret_key: &SecretKey,
    fork_schedule: &ForkSchedule,
    genesis_validators_root: &Root,
) -> Signature {
    let fork_name = ForkName::from_epoch(epoch, fork_schedule);
    let fork_version = fork_name.fork_version(fork_schedule);

    let domain = compute_domain(DOMAIN_RANDAO, fork_version, *genesis_validators_root);
    let signing_root = compute_signing_root(&epoch, domain);
    secret_key.sign(&signing_root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls::SecretKey;
    use crate::signing::compute_domain;

    fn test_schedule() -> ForkSchedule {
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
            fulu_fork_epoch: 60,
            fulu_fork_version: [6, 0, 0, 0],
        }
    }

    #[test]
    fn test_domain_beacon_proposer_value() {
        assert_eq!(DOMAIN_BEACON_PROPOSER, [0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_domain_randao_value() {
        assert_eq!(DOMAIN_RANDAO, [0x02, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_sign_block_produces_valid_signature() {
        let secret_key = SecretKey::generate();
        let public_key = secret_key.public_key();
        let schedule = test_schedule();
        let genesis_root = [0xaa; 32];
        let block_root = [0x11; 32];
        let slot = 5; // epoch 0, Phase0

        let signature = sign_block(&block_root, slot, &secret_key, &schedule, &genesis_root);

        let fork_version = schedule.genesis_fork_version;
        let domain = compute_domain(DOMAIN_BEACON_PROPOSER, fork_version, genesis_root);
        let signing_root = compute_signing_root(&block_root, domain);
        assert!(signature.verify(&public_key, &signing_root).is_ok());
    }

    #[test]
    fn test_sign_block_different_slots_different_signatures() {
        let secret_key = SecretKey::generate();
        let schedule = test_schedule();
        let genesis_root = [0xaa; 32];
        let block_root = [0x11; 32];

        let sig1 = sign_block(&block_root, 5, &secret_key, &schedule, &genesis_root);
        let sig2 =
            sign_block(&block_root, SLOTS_PER_EPOCH * 15, &secret_key, &schedule, &genesis_root);

        assert_ne!(sig1.to_bytes(), sig2.to_bytes());
    }

    #[test]
    fn test_sign_block_different_roots_different_signatures() {
        let secret_key = SecretKey::generate();
        let schedule = test_schedule();
        let genesis_root = [0xaa; 32];

        let sig1 = sign_block(&[0x11; 32], 5, &secret_key, &schedule, &genesis_root);
        let sig2 = sign_block(&[0x22; 32], 5, &secret_key, &schedule, &genesis_root);

        assert_ne!(sig1.to_bytes(), sig2.to_bytes());
    }

    #[test]
    fn test_sign_block_domain_is_proposer() {
        let secret_key = SecretKey::generate();
        let public_key = secret_key.public_key();
        let schedule = test_schedule();
        let genesis_root = [0xaa; 32];
        let block_root = [0x11; 32];
        let slot = 5;

        let signature = sign_block(&block_root, slot, &secret_key, &schedule, &genesis_root);

        // Verify with DOMAIN_BEACON_PROPOSER succeeds
        let fork_version = schedule.genesis_fork_version;
        let domain = compute_domain(DOMAIN_BEACON_PROPOSER, fork_version, genesis_root);
        let signing_root = compute_signing_root(&block_root, domain);
        assert!(signature.verify(&public_key, &signing_root).is_ok());

        // Verify with wrong domain (RANDAO) fails
        let wrong_domain = compute_domain(DOMAIN_RANDAO, fork_version, genesis_root);
        let wrong_signing_root = compute_signing_root(&block_root, wrong_domain);
        assert!(signature.verify(&public_key, &wrong_signing_root).is_err());
    }

    #[test]
    fn test_sign_block_fork_aware() {
        let secret_key = SecretKey::generate();
        let public_key = secret_key.public_key();
        let schedule = test_schedule();
        let genesis_root = [0xaa; 32];
        let block_root = [0x11; 32];

        // Slot in Altair epoch (epoch 15, slot 480)
        let altair_slot = SLOTS_PER_EPOCH * 15;
        let sig = sign_block(&block_root, altair_slot, &secret_key, &schedule, &genesis_root);

        // Verify with Altair fork version
        let domain =
            compute_domain(DOMAIN_BEACON_PROPOSER, schedule.altair_fork_version, genesis_root);
        let signing_root = compute_signing_root(&block_root, domain);
        assert!(sig.verify(&public_key, &signing_root).is_ok());

        // Verify with Phase0 fork version fails
        let wrong_domain =
            compute_domain(DOMAIN_BEACON_PROPOSER, schedule.genesis_fork_version, genesis_root);
        let wrong_signing_root = compute_signing_root(&block_root, wrong_domain);
        assert!(sig.verify(&public_key, &wrong_signing_root).is_err());
    }

    #[test]
    fn test_sign_block_epoch_boundary() {
        let secret_key = SecretKey::generate();
        let public_key = secret_key.public_key();
        let schedule = test_schedule();
        let genesis_root = [0xaa; 32];
        let block_root = [0x11; 32];

        // Last slot of Phase0 (epoch 9, slot 319)
        let phase0_slot = SLOTS_PER_EPOCH * 10 - 1;
        let sig = sign_block(&block_root, phase0_slot, &secret_key, &schedule, &genesis_root);
        let domain =
            compute_domain(DOMAIN_BEACON_PROPOSER, schedule.genesis_fork_version, genesis_root);
        let signing_root = compute_signing_root(&block_root, domain);
        assert!(sig.verify(&public_key, &signing_root).is_ok());

        // First slot of Altair (epoch 10, slot 320)
        let altair_slot = SLOTS_PER_EPOCH * 10;
        let sig = sign_block(&block_root, altair_slot, &secret_key, &schedule, &genesis_root);
        let domain =
            compute_domain(DOMAIN_BEACON_PROPOSER, schedule.altair_fork_version, genesis_root);
        let signing_root = compute_signing_root(&block_root, domain);
        assert!(sig.verify(&public_key, &signing_root).is_ok());
    }

    #[test]
    fn test_sign_randao_reveal_produces_valid_signature() {
        let secret_key = SecretKey::generate();
        let public_key = secret_key.public_key();
        let schedule = test_schedule();
        let genesis_root = [0xaa; 32];
        let epoch = 5; // Phase0

        let signature = sign_randao_reveal(epoch, &secret_key, &schedule, &genesis_root);

        let fork_version = schedule.genesis_fork_version;
        let domain = compute_domain(DOMAIN_RANDAO, fork_version, genesis_root);
        let signing_root = compute_signing_root(&epoch, domain);
        assert!(signature.verify(&public_key, &signing_root).is_ok());
    }

    #[test]
    fn test_sign_randao_different_epochs_different_signatures() {
        let secret_key = SecretKey::generate();
        let schedule = test_schedule();
        let genesis_root = [0xaa; 32];

        let sig1 = sign_randao_reveal(5, &secret_key, &schedule, &genesis_root);
        let sig2 = sign_randao_reveal(15, &secret_key, &schedule, &genesis_root);

        assert_ne!(sig1.to_bytes(), sig2.to_bytes());
    }

    #[test]
    fn test_sign_randao_reveal_fork_aware() {
        let secret_key = SecretKey::generate();
        let public_key = secret_key.public_key();
        let schedule = test_schedule();
        let genesis_root = [0xaa; 32];

        // Epoch in Deneb range
        let epoch = 45;
        let signature = sign_randao_reveal(epoch, &secret_key, &schedule, &genesis_root);

        // Verify with Deneb fork version
        let domain = compute_domain(DOMAIN_RANDAO, schedule.deneb_fork_version, genesis_root);
        let signing_root = compute_signing_root(&epoch, domain);
        assert!(signature.verify(&public_key, &signing_root).is_ok());

        // Verify with wrong fork version fails
        let wrong_domain =
            compute_domain(DOMAIN_RANDAO, schedule.genesis_fork_version, genesis_root);
        let wrong_signing_root = compute_signing_root(&epoch, wrong_domain);
        assert!(signature.verify(&public_key, &wrong_signing_root).is_err());
    }

    #[test]
    fn test_sign_randao_reveal_domain_is_randao() {
        let secret_key = SecretKey::generate();
        let public_key = secret_key.public_key();
        let schedule = test_schedule();
        let genesis_root = [0xaa; 32];
        let epoch = 5;

        let signature = sign_randao_reveal(epoch, &secret_key, &schedule, &genesis_root);

        // Verify with DOMAIN_RANDAO succeeds
        let fork_version = schedule.genesis_fork_version;
        let domain = compute_domain(DOMAIN_RANDAO, fork_version, genesis_root);
        let signing_root = compute_signing_root(&epoch, domain);
        assert!(signature.verify(&public_key, &signing_root).is_ok());

        // Verify with wrong domain (PROPOSER) fails
        let wrong_domain = compute_domain(DOMAIN_BEACON_PROPOSER, fork_version, genesis_root);
        let wrong_signing_root = compute_signing_root(&epoch, wrong_domain);
        assert!(signature.verify(&public_key, &wrong_signing_root).is_err());
    }

    #[test]
    fn test_compute_domain_beacon_proposer() {
        let genesis_root = [0xaa; 32];
        let fork_version = [0x01, 0x00, 0x00, 0x00];

        let domain = compute_domain(DOMAIN_BEACON_PROPOSER, fork_version, genesis_root);

        // First 4 bytes are the domain type
        assert_eq!(&domain[..4], &DOMAIN_BEACON_PROPOSER);
        // Domain is 32 bytes
        assert_eq!(domain.len(), 32);
    }

    #[test]
    fn test_compute_domain_randao() {
        let genesis_root = [0xaa; 32];
        let fork_version = [0x01, 0x00, 0x00, 0x00];

        let domain = compute_domain(DOMAIN_RANDAO, fork_version, genesis_root);

        assert_eq!(&domain[..4], &DOMAIN_RANDAO);
        assert_eq!(domain.len(), 32);
    }

    #[test]
    fn test_sign_block_slot_zero() {
        let secret_key = SecretKey::generate();
        let public_key = secret_key.public_key();
        let schedule = test_schedule();
        let genesis_root = [0x00; 32];
        let block_root = [0x11; 32];

        let signature = sign_block(&block_root, 0, &secret_key, &schedule, &genesis_root);

        let domain =
            compute_domain(DOMAIN_BEACON_PROPOSER, schedule.genesis_fork_version, genesis_root);
        let signing_root = compute_signing_root(&block_root, domain);
        assert!(signature.verify(&public_key, &signing_root).is_ok());
    }

    #[test]
    fn test_sign_randao_reveal_epoch_zero() {
        let secret_key = SecretKey::generate();
        let public_key = secret_key.public_key();
        let schedule = test_schedule();
        let genesis_root = [0x00; 32];
        let epoch: Epoch = 0;

        let signature = sign_randao_reveal(epoch, &secret_key, &schedule, &genesis_root);

        let domain = compute_domain(DOMAIN_RANDAO, schedule.genesis_fork_version, genesis_root);
        let signing_root = compute_signing_root(&epoch, domain);
        assert!(signature.verify(&public_key, &signing_root).is_ok());
    }

    // KAT (report §5 bullet 4): pin the block signing-root construction against an
    // externally-derived literal instead of a self-referential sign-then-verify (which
    // recomputes the domain on both sides). Rebuilds the root the way `sign_block` does —
    // compute_signing_root(&block_root, compute_domain(DOMAIN_BEACON_PROPOSER, fork_version, gvr)).
    // Asserting on the signing root keeps the KAT deterministic and key-independent.
    // Golden value derived independently with `remerkleable` (SigningData / ForkData
    // containers), NOT recomputed via rvc compute_* alone:
    //   inputs: domain_type = DOMAIN_BEACON_PROPOSER (0x00000000),
    //           fork_version = 0x00000000 (Phase0 slot → genesis_fork_version),
    //           genesis_validators_root = 0xaa…aa, block_root = 0x11…11
    //   domain        = 000000009ef814b42fa0be12d197c44d3e8e03441a4b1118237658368ba13510
    //   signing_root  = 801fbd741752f6a9abaf0fd820f9b31bb78fc4ba269b513a38d6fdf3f79dad8c
    #[test]
    fn test_block_signing_root_known_answer() {
        const EXPECTED: Root = [
            0x80, 0x1f, 0xbd, 0x74, 0x17, 0x52, 0xf6, 0xa9, 0xab, 0xaf, 0x0f, 0xd8, 0x20, 0xf9,
            0xb3, 0x1b, 0xb7, 0x8f, 0xc4, 0xba, 0x26, 0x9b, 0x51, 0x3a, 0x38, 0xd6, 0xfd, 0xf3,
            0xf7, 0x9d, 0xad, 0x8c,
        ];
        let fork_version = [0x00, 0x00, 0x00, 0x00]; // Phase0 slot → genesis_fork_version
        let genesis_validators_root: Root = [0xaa; 32];
        let block_root: Root = [0x11; 32];

        let domain = compute_domain(DOMAIN_BEACON_PROPOSER, fork_version, genesis_validators_root);
        let signing_root = compute_signing_root(&block_root, domain);
        assert_eq!(signing_root, EXPECTED);
    }

    // KAT (report §5 bullet 4): pin the RANDAO signing-root construction against an
    // externally-derived literal. Rebuilds the root the way `sign_randao_reveal` does —
    // compute_signing_root(&epoch, compute_domain(DOMAIN_RANDAO, fork_version, gvr)).
    // The epoch is a u64; its hash_tree_root is the little-endian 8 bytes right-padded to
    // 32. Golden value derived independently with `remerkleable`:
    //   inputs: domain_type = DOMAIN_RANDAO (0x02000000),
    //           fork_version = 0x00000000 (Phase0 epoch → genesis_fork_version),
    //           genesis_validators_root = 0xaa…aa, epoch = 5
    //   domain        = 020000009ef814b42fa0be12d197c44d3e8e03441a4b1118237658368ba13510
    //   signing_root  = 45bb77a0966aa2e901f607e96d76c645b8cba134e685ae262e178e3f76beda4c
    #[test]
    fn test_randao_signing_root_known_answer() {
        const EXPECTED: Root = [
            0x45, 0xbb, 0x77, 0xa0, 0x96, 0x6a, 0xa2, 0xe9, 0x01, 0xf6, 0x07, 0xe9, 0x6d, 0x76,
            0xc6, 0x45, 0xb8, 0xcb, 0xa1, 0x34, 0xe6, 0x85, 0xae, 0x26, 0x2e, 0x17, 0x8e, 0x3f,
            0x76, 0xbe, 0xda, 0x4c,
        ];
        let fork_version = [0x00, 0x00, 0x00, 0x00]; // Phase0 epoch → genesis_fork_version
        let genesis_validators_root: Root = [0xaa; 32];
        let epoch: Epoch = 5;

        let domain = compute_domain(DOMAIN_RANDAO, fork_version, genesis_validators_root);
        let signing_root = compute_signing_root(&epoch, domain);
        assert_eq!(signing_root, EXPECTED);
    }
}
