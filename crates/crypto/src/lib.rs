//! BLS key operations, EIP-2335 keystore decryption, key management, and Ethereum signing utilities.

mod aggregation_signing;
mod block_signing;
mod bls;
mod decryption_tracker;
mod error;
mod key_manager;
mod keystore;
mod signing;
mod sync_signing;

pub use aggregation_signing::{is_aggregator, sign_aggregate_and_proof, sign_selection_proof};
pub use block_signing::{sign_block, sign_randao_reveal};
pub use bls::{
    PublicKey, SecretKey, Signature, PUBLIC_KEY_BYTES_LEN, SECRET_KEY_BYTES_LEN,
    SIGNATURE_BYTES_LEN,
};
pub use decryption_tracker::DecryptionAttemptTracker;
pub use error::{BlsError, KeyManagerError, KeystoreError};
pub use eth_types::{DOMAIN_BEACON_PROPOSER, DOMAIN_RANDAO};
pub use key_manager::KeyManager;
pub use keystore::{KdfParams, Keystore, Pbkdf2Params, ScryptParams};
pub use signing::{
    compute_domain, compute_fork_data_root, compute_signing_root, sign_attestation,
    DOMAIN_BEACON_ATTESTER,
};
pub use sync_signing::{
    sign_contribution_and_proof, sign_sync_committee_message, sign_sync_committee_selection_proof,
};
