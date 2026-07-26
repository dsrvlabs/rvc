//! BLS key operations, EIP-2335 keystore decryption, key management, and Ethereum signing utilities.
//!
//! # Signer hierarchy
//!
//! Signing types stack from raw BLS backends up to the safe-signing gates in the
//! `rvc-signer` library crate. Read bottom-up:
//!
//! | Layer | Type | Crate | Role |
//! |-------|------|-------|------|
//! | 1. Raw backend | [`Signer`] | this crate | Sign a 32-byte root with a pubkey. Implemented by [`LocalSigner`], [`RemoteSigner`], and [`CompositeSigner`]. |
//! | 2. Typed backend | [`TypedSigner`] | this crate | One method per consensus duty; computes the signing root then signs. [`LocalSigner`] implements it; gRPC remotes are typed-only. |
//! | 3. Key router | [`CompositeSigner`] | this crate | Routes each pubkey to local, HTTP remote, gRPC remote, or dynamic local keys. Implements [`Signer`]. |
//! | 4a. VC service | `SignerService` | `rvc-signer` (`crates/signer`) | Validator-client path: enablement + slashing stage/commit + metrics around the composite. |
//! | 4b. Gate | `SigningGate` | `rvc-signer` (`crates/signer`) | Remote-signer / multi-transport path: same defenses via a shared slashable core (`sign_slashable`) plus non-slashable helpers. |
//!
//! Related helpers (not layers): `LocalSigner` (in-process keys), `RemoteSigner`
//! (Web3Signer HTTP), `ValidatorSigner` (async trait over duty-shaped methods on
//! the VC path). Prefer constructing a [`CompositeSigner`] and wrapping it in
//! `SignerService` or `SigningGate` rather than calling backends directly from
//! duty code.
//!
//! ## Package-name collision (`rvc-signer`)
//!
//! Cargo package **`rvc-signer`** is the library at `crates/signer` (Rust crate
//! name `rvc_signer`). Package **`rvc-signer-bin`** at `bin/rvc-signer` builds a
//! **binary** also named `rvc-signer`. Logs and `use rvc_signer::…` refer to the
//! library; the binary is the server process. The rename/split is deferred to
//! Phase 5 **F2** (promote the bin lib to `crates/signer-server`).

#![deny(rustdoc::broken_intra_doc_links)]

mod aggregation_signing;
mod bls;
mod composite_signer;
pub mod eip2333;
mod error;
pub mod insecure;
mod key_manager;
mod keystore;
pub mod mnemonic;
mod remote_signer;
mod signer_trait;
mod signing;
mod signing_root;
pub mod typed_signer;
mod voluntary_exit_signing;

pub use aggregation_signing::is_aggregator;
pub use bls::{
    PublicKey, SecretKey, Signature, PUBLIC_KEY_BYTES_LEN, SECRET_KEY_BYTES_LEN,
    SIGNATURE_BYTES_LEN,
};
pub use composite_signer::CompositeSigner;
pub use error::{BlsError, KeyManagerError, KeystoreError, SigningError};
pub use eth_types::{DOMAIN_BEACON_ATTESTER, DOMAIN_BEACON_PROPOSER, DOMAIN_RANDAO};
pub use insecure::{InsecureGate, InsecureGateError, InsecureMode};
pub use key_manager::{KeyManager, WILDCARD_KEY};
pub use keystore::{EncryptionKdf, KdfParams, Keystore, Pbkdf2Params, ScryptParams};
pub use remote_signer::{
    build_aggregate_and_proof_request, build_aggregation_slot_request, build_attestation_request,
    build_blinded_block_v2_request, build_block_v2_request, build_contribution_and_proof_request,
    build_randao_reveal_request, build_sync_committee_message_request,
    build_sync_selection_proof_request, build_validator_registration_request,
    build_voluntary_exit_request, check_remote_signer_url, sign_request_to_json,
    AggregationSlotPayload, BeaconBlockEnvelope, RandaoRevealPayload, RemoteSigner,
    RemoteSignerConfig, SignRequestJson, SyncSelectionPayload, Web3SignerPayload,
    Web3SignerSignRequest, WireForkInfo, WireForkInfoExt, REMOTE_SIGNER_INSECURE_ENV_VAR,
};
pub use signer_trait::{LocalSigner, Signer};
pub use signing::{compute_domain, compute_fork_data_root, compute_signing_root};
pub use signing_root::{
    capella_capped_fork_version, signing_root_for, signing_root_with_fork_version, DutyRef,
    SigningCtx,
};
pub use typed_signer::{SignContext, TypedSigner};
pub use voluntary_exit_signing::sign_voluntary_exit;
