//! BLS key operations, EIP-2335 keystore decryption, key management, and Ethereum signing utilities.

mod aggregation_signing;
mod bls;
mod composite_signer;
pub mod eip2333;
mod error;
pub mod hex;
pub mod insecure;
mod key_manager;
mod keystore;
pub mod logging;
pub mod mnemonic;
pub mod pubkey;
mod remote_signer;
mod signer_trait;
mod signing;
pub mod typed_signer;
mod voluntary_exit_signing;

pub use aggregation_signing::is_aggregator;
pub use bls::{
    PublicKey, SecretKey, Signature, PUBLIC_KEY_BYTES_LEN, SECRET_KEY_BYTES_LEN,
    SIGNATURE_BYTES_LEN,
};
pub use composite_signer::CompositeSigner;
pub use error::{BlsError, KeyManagerError, KeystoreError};
pub use eth_types::{DOMAIN_BEACON_ATTESTER, DOMAIN_BEACON_PROPOSER, DOMAIN_RANDAO};
pub use hex::{strip_prefix_strict, HexError};
pub use insecure::{InsecureGate, InsecureGateError, InsecureMode};
pub use key_manager::{KeyManager, WILDCARD_KEY};
pub use keystore::{EncryptionKdf, KdfParams, Keystore, Pbkdf2Params, ScryptParams};
pub use pubkey::CanonicalPubkey;
pub use remote_signer::{
    build_aggregate_and_proof_request, build_aggregation_slot_request, build_attestation_request,
    build_blinded_block_v2_request, build_block_v2_request, build_contribution_and_proof_request,
    build_randao_reveal_request, build_sync_committee_message_request,
    build_sync_selection_proof_request, build_validator_registration_request,
    build_voluntary_exit_request, check_remote_signer_url, AggregationSlotPayload,
    BeaconBlockEnvelope, RandaoRevealPayload, RemoteSigner, RemoteSignerConfig,
    SyncSelectionPayload, Web3SignerPayload, Web3SignerSignRequest, WireForkInfo,
    REMOTE_SIGNER_INSECURE_ENV_VAR,
};
pub use signer_trait::{LocalSigner, Signer, SigningError};
pub use signing::{compute_domain, compute_fork_data_root, compute_signing_root};
pub use typed_signer::{capella_capped_fork_version, SignContext, TypedSigner};
pub use voluntary_exit_signing::sign_voluntary_exit;
