use super::bls::{SecretKey, Signature};
use super::signing::{compute_domain, compute_signing_root};
use eth_types::{ValidatorRegistrationV1, DOMAIN_APPLICATION_BUILDER};

#[tracing::instrument(
    name = "crypto.sign_builder_registration",
    level = "debug",
    skip_all,
    fields(signing_type = "builder_registration")
)]
pub fn sign_builder_registration(
    registration: &ValidatorRegistrationV1,
    secret_key: &SecretKey,
    fork_version: [u8; 4],
) -> Signature {
    let zeroed_genesis_root = [0u8; 32];
    let domain = compute_domain(DOMAIN_APPLICATION_BUILDER, fork_version, zeroed_genesis_root);
    let signing_root = compute_signing_root(registration, domain);
    secret_key.sign(&signing_root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls::SecretKey;
    use crate::signing::compute_domain;

    fn sample_registration() -> ValidatorRegistrationV1 {
        ValidatorRegistrationV1 {
            fee_recipient: [0xab; 20],
            gas_limit: 30_000_000,
            timestamp: 1_700_000_000,
            pubkey: [0xcd; 48],
        }
    }

    #[test]
    fn test_builder_domain_application_builder_value() {
        assert_eq!(DOMAIN_APPLICATION_BUILDER, [0x00, 0x00, 0x00, 0x01]);
    }

    #[test]
    fn test_sign_builder_registration_produces_valid_signature() {
        let secret_key = SecretKey::generate();
        let public_key = secret_key.public_key();
        let registration = sample_registration();
        let fork_version = [0x01, 0x00, 0x00, 0x00];

        let signature = sign_builder_registration(&registration, &secret_key, fork_version);

        let zeroed_genesis_root = [0u8; 32];
        let domain = compute_domain(DOMAIN_APPLICATION_BUILDER, fork_version, zeroed_genesis_root);
        let signing_root = compute_signing_root(&registration, domain);
        assert!(signature.verify(&public_key, &signing_root).is_ok());
    }

    #[test]
    fn test_sign_builder_registration_uses_zeroed_genesis_root() {
        let secret_key = SecretKey::generate();
        let public_key = secret_key.public_key();
        let registration = sample_registration();
        let fork_version = [0x01, 0x00, 0x00, 0x00];

        let signature = sign_builder_registration(&registration, &secret_key, fork_version);

        // Verify with zeroed genesis root succeeds
        let zeroed_genesis_root = [0u8; 32];
        let domain = compute_domain(DOMAIN_APPLICATION_BUILDER, fork_version, zeroed_genesis_root);
        let signing_root = compute_signing_root(&registration, domain);
        assert!(signature.verify(&public_key, &signing_root).is_ok());

        // Verify with non-zeroed genesis root fails — proves zeroed root is used
        let non_zeroed_genesis_root = [0xaa; 32];
        let wrong_domain =
            compute_domain(DOMAIN_APPLICATION_BUILDER, fork_version, non_zeroed_genesis_root);
        let wrong_signing_root = compute_signing_root(&registration, wrong_domain);
        assert!(signature.verify(&public_key, &wrong_signing_root).is_err());
    }

    #[test]
    fn test_sign_builder_registration_uses_correct_domain() {
        let secret_key = SecretKey::generate();
        let public_key = secret_key.public_key();
        let registration = sample_registration();
        let fork_version = [0x01, 0x00, 0x00, 0x00];

        let signature = sign_builder_registration(&registration, &secret_key, fork_version);

        // Verify with DOMAIN_APPLICATION_BUILDER succeeds
        let zeroed_genesis_root = [0u8; 32];
        let domain = compute_domain(DOMAIN_APPLICATION_BUILDER, fork_version, zeroed_genesis_root);
        let signing_root = compute_signing_root(&registration, domain);
        assert!(signature.verify(&public_key, &signing_root).is_ok());

        // Verify with wrong domain (BEACON_PROPOSER) fails
        let wrong_domain =
            compute_domain(eth_types::DOMAIN_BEACON_PROPOSER, fork_version, zeroed_genesis_root);
        let wrong_signing_root = compute_signing_root(&registration, wrong_domain);
        assert!(signature.verify(&public_key, &wrong_signing_root).is_err());
    }

    #[test]
    fn test_sign_builder_registration_deterministic() {
        let secret_key = SecretKey::generate();
        let registration = sample_registration();
        let fork_version = [0x01, 0x00, 0x00, 0x00];

        let sig1 = sign_builder_registration(&registration, &secret_key, fork_version);
        let sig2 = sign_builder_registration(&registration, &secret_key, fork_version);

        assert_eq!(sig1.to_bytes(), sig2.to_bytes());
    }

    #[test]
    fn test_sign_builder_registration_different_registrations_different_signatures() {
        let secret_key = SecretKey::generate();
        let fork_version = [0x01, 0x00, 0x00, 0x00];

        let reg1 = sample_registration();
        let mut reg2 = sample_registration();
        reg2.gas_limit = 999;

        let sig1 = sign_builder_registration(&reg1, &secret_key, fork_version);
        let sig2 = sign_builder_registration(&reg2, &secret_key, fork_version);

        assert_ne!(sig1.to_bytes(), sig2.to_bytes());
    }

    #[test]
    fn test_sign_builder_registration_different_fork_versions_different_signatures() {
        let secret_key = SecretKey::generate();
        let registration = sample_registration();

        let sig1 = sign_builder_registration(&registration, &secret_key, [0x01, 0x00, 0x00, 0x00]);
        let sig2 = sign_builder_registration(&registration, &secret_key, [0x02, 0x00, 0x00, 0x00]);

        assert_ne!(sig1.to_bytes(), sig2.to_bytes());
    }
}
