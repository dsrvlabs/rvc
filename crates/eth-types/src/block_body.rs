//! Typed SSZ `BeaconBlockBody` containers for body-leaf `hash_tree_root` (SEC-6).
//!
//! Production Electra full + blinded bodies and shared sub-containers with
//! `TreeHash` (via `tree_hash_derive`) and SSZ Encode/Decode (via `ssz08` =
//! ethereum_ssz 0.8, matching `ssz_types` trait impls).
//!
//! Wire `Vec<u8>` bodies still live on [`crate::BeaconBlock`]; SEC-6c decodes
//! them via [`BeaconBlockBodyElectra::from_ssz_bytes`] (and the blinded
//! counterpart) inside `try_tree_hash_root` for the body leaf.
//!
//! Design (see `plan/security-2026-07-18/spike-sec6-block-body-htr.md`):
//! hand-typed per-fork containers via `tree_hash_derive` + `ssz_types`
//! (`VariableList` / `FixedVector` / `BitVector`) — not a full consensus-types
//! library. Encode/Decode use ethereum_ssz **0.8** because `ssz_types` 0.10.1
//! implements those traits against 0.8 only (workspace `ssz` remains 0.9).

use ssz08::{Decode, DecodeError, Encode, SszDecoderBuilder, SszEncoder, BYTES_PER_LENGTH_OFFSET};
use ssz_types::{
    typenum::{
        U1, U1048576, U1073741824, U131072, U16, U2, U256, U32, U33, U4096, U512, U64, U8, U8192,
    },
    BitList, BitVector, FixedVector, VariableList,
};
use thiserror::Error;
use tree_hash::{Hash256, PackedEncoding, TreeHash, TreeHashType};
use tree_hash_derive::TreeHash;

// ---------------------------------------------------------------------------
// Mainnet preset bounds (consensus-specs presets/mainnet)
// ---------------------------------------------------------------------------

/// `MAX_PROPOSER_SLASHINGS`
pub type MaxProposerSlashings = U16;
/// `MAX_ATTESTER_SLASHINGS_ELECTRA`
pub type MaxAttesterSlashingsElectra = U1;
/// `MAX_ATTESTATIONS_ELECTRA`
pub type MaxAttestationsElectra = U8;
/// `MAX_DEPOSITS`
pub type MaxDeposits = U16;
/// `MAX_VOLUNTARY_EXITS`
pub type MaxVoluntaryExits = U16;
/// `MAX_BLS_TO_EXECUTION_CHANGES`
pub type MaxBlsToExecutionChanges = U16;
/// `MAX_BLOB_COMMITMENTS_PER_BLOCK`
pub type MaxBlobCommitmentsPerBlock = U4096;
/// `SYNC_COMMITTEE_SIZE`
pub type SyncCommitteeSize = U512;
/// `BYTES_PER_LOGS_BLOOM`
pub type BytesPerLogsBloom = U256;
/// `MAX_EXTRA_DATA_BYTES`
pub type MaxExtraDataBytes = U32;
/// `MAX_BYTES_PER_TRANSACTION`
pub type MaxBytesPerTransaction = U1073741824;
/// `MAX_TRANSACTIONS_PER_PAYLOAD`
pub type MaxTransactionsPerPayload = U1048576;
/// `MAX_WITHDRAWALS_PER_PAYLOAD`
pub type MaxWithdrawalsPerPayload = U16;
/// `MAX_DEPOSIT_REQUESTS_PER_PAYLOAD`
pub type MaxDepositRequestsPerPayload = U8192;
/// `MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD`
pub type MaxWithdrawalRequestsPerPayload = U16;
/// `MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD`
pub type MaxConsolidationRequestsPerPayload = U2;
/// `DEPOSIT_CONTRACT_TREE_DEPTH + 1` (Deposit.proof length)
pub type DepositProofLength = U33;
/// `MAX_VALIDATORS_PER_COMMITTEE * MAX_COMMITTEES_PER_SLOT` (= 131072)
pub type MaxValidatorsPerSlot = U131072;
/// `MAX_COMMITTEES_PER_SLOT`
pub type MaxCommitteesPerSlot = U64;

// ---------------------------------------------------------------------------
// Decode errors (public surface for Vec<u8> → typed body)
// ---------------------------------------------------------------------------

/// Error decoding a typed `BeaconBlockBody` (or sub-container) from SSZ bytes.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BodySszError {
    #[error("invalid SSZ body encoding: {0}")]
    InvalidEncoding(String),
}

impl From<DecodeError> for BodySszError {
    fn from(err: DecodeError) -> Self {
        BodySszError::InvalidEncoding(format!("{err:?}"))
    }
}

// ---------------------------------------------------------------------------
// SSZ container Encode/Decode helper (ethereum_ssz 0.8 trait surface)
// ---------------------------------------------------------------------------

/// Generate `ssz08::{Encode, Decode}` for a named SSZ container in field order.
///
/// Field order is merkleization- and serialization-sensitive — keep in sync
/// with the struct definition and the consensus-specs container.
macro_rules! impl_ssz_container {
    ($ty:ident { $($field:ident : $ftype:ty),* $(,)? }) => {
        impl Encode for $ty {
            fn is_ssz_fixed_len() -> bool {
                $( <$ftype as Encode>::is_ssz_fixed_len() && )* true
            }

            fn ssz_fixed_len() -> usize {
                if <Self as Encode>::is_ssz_fixed_len() {
                    $( <$ftype as Encode>::ssz_fixed_len() + )* 0
                } else {
                    BYTES_PER_LENGTH_OFFSET
                }
            }

            fn ssz_bytes_len(&self) -> usize {
                if <Self as Encode>::is_ssz_fixed_len() {
                    <Self as Encode>::ssz_fixed_len()
                } else {
                    let mut len = 0usize;
                    $(
                        len += if <$ftype as Encode>::is_ssz_fixed_len() {
                            <$ftype as Encode>::ssz_fixed_len()
                        } else {
                            BYTES_PER_LENGTH_OFFSET + self.$field.ssz_bytes_len()
                        };
                    )*
                    len
                }
            }

            fn ssz_append(&self, buf: &mut Vec<u8>) {
                let offset = $( <$ftype as Encode>::ssz_fixed_len() + )* 0;
                let mut encoder = SszEncoder::container(buf, offset);
                $( encoder.append(&self.$field); )*
                encoder.finalize();
            }
        }

        impl Decode for $ty {
            fn is_ssz_fixed_len() -> bool {
                $( <$ftype as Decode>::is_ssz_fixed_len() && )* true
            }

            fn ssz_fixed_len() -> usize {
                if <Self as Decode>::is_ssz_fixed_len() {
                    $( <$ftype as Decode>::ssz_fixed_len() + )* 0
                } else {
                    BYTES_PER_LENGTH_OFFSET
                }
            }

            fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
                let mut builder = SszDecoderBuilder::new(bytes);
                $( builder.register_type::<$ftype>()?; )*
                let mut decoder = builder.build()?;
                Ok(Self {
                    $( $field: decoder.decode_next()?, )*
                })
            }
        }
    };
}

// ---------------------------------------------------------------------------
// Primitive wrappers
// ---------------------------------------------------------------------------

/// SSZ `uint256` (little-endian 32 bytes). Matches `alloy_primitives::U256`
/// `TreeHash` used by `tree_hash` 0.9 without pinning a direct alloy version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Uint256(pub [u8; 32]);

impl Uint256 {
    /// Construct from a `u64` (low limb); used by tests and small fixtures.
    pub fn from_u64(v: u64) -> Self {
        let mut bytes = [0u8; 32];
        bytes[0..8].copy_from_slice(&v.to_le_bytes());
        Self(bytes)
    }
}

impl TreeHash for Uint256 {
    fn tree_hash_type() -> TreeHashType {
        TreeHashType::Basic
    }

    fn tree_hash_packed_encoding(&self) -> PackedEncoding {
        PackedEncoding::from(self.0)
    }

    fn tree_hash_packing_factor() -> usize {
        1
    }

    fn tree_hash_root(&self) -> Hash256 {
        Hash256::from(self.0)
    }
}

impl Encode for Uint256 {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        32
    }

    fn ssz_bytes_len(&self) -> usize {
        32
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.0);
    }
}

impl Decode for Uint256 {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        32
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let arr = <[u8; 32]>::from_ssz_bytes(bytes)?;
        Ok(Self(arr))
    }
}

/// SSZ `Transaction` = `ByteList[MAX_BYTES_PER_TRANSACTION]`.
pub type Transaction = VariableList<u8, MaxBytesPerTransaction>;
/// SSZ `KZGCommitment` = `Bytes48`.
pub type KzgCommitment = [u8; 48];

// ---------------------------------------------------------------------------
// Shared sub-containers
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
pub struct Eth1Data {
    pub deposit_root: [u8; 32],
    pub deposit_count: u64,
    pub block_hash: [u8; 32],
}
impl_ssz_container!(Eth1Data { deposit_root: [u8; 32], deposit_count: u64, block_hash: [u8; 32] });

#[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
pub struct Checkpoint {
    pub epoch: u64,
    pub root: [u8; 32],
}
impl_ssz_container!(Checkpoint { epoch: u64, root: [u8; 32] });

#[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
pub struct AttestationData {
    pub slot: u64,
    pub index: u64,
    pub beacon_block_root: [u8; 32],
    pub source: Checkpoint,
    pub target: Checkpoint,
}
impl_ssz_container!(AttestationData {
    slot: u64,
    index: u64,
    beacon_block_root: [u8; 32],
    source: Checkpoint,
    target: Checkpoint,
});

#[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
pub struct BeaconBlockHeader {
    pub slot: u64,
    pub proposer_index: u64,
    pub parent_root: [u8; 32],
    pub state_root: [u8; 32],
    pub body_root: [u8; 32],
}
impl_ssz_container!(BeaconBlockHeader {
    slot: u64,
    proposer_index: u64,
    parent_root: [u8; 32],
    state_root: [u8; 32],
    body_root: [u8; 32],
});

#[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
pub struct SignedBeaconBlockHeader {
    pub message: BeaconBlockHeader,
    pub signature: [u8; 96],
}
impl_ssz_container!(SignedBeaconBlockHeader { message: BeaconBlockHeader, signature: [u8; 96] });

#[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
pub struct ProposerSlashing {
    pub signed_header_1: SignedBeaconBlockHeader,
    pub signed_header_2: SignedBeaconBlockHeader,
}
impl_ssz_container!(ProposerSlashing {
    signed_header_1: SignedBeaconBlockHeader,
    signed_header_2: SignedBeaconBlockHeader,
});

#[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
pub struct IndexedAttestationElectra {
    pub attesting_indices: VariableList<u64, MaxValidatorsPerSlot>,
    pub data: AttestationData,
    pub signature: [u8; 96],
}
impl_ssz_container!(IndexedAttestationElectra {
    attesting_indices: VariableList<u64, MaxValidatorsPerSlot>,
    data: AttestationData,
    signature: [u8; 96],
});

#[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
pub struct AttesterSlashingElectra {
    pub attestation_1: IndexedAttestationElectra,
    pub attestation_2: IndexedAttestationElectra,
}
impl_ssz_container!(AttesterSlashingElectra {
    attestation_1: IndexedAttestationElectra,
    attestation_2: IndexedAttestationElectra,
});

#[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
pub struct AttestationElectra {
    pub aggregation_bits: BitList<MaxValidatorsPerSlot>,
    pub data: AttestationData,
    pub signature: [u8; 96],
    pub committee_bits: BitVector<MaxCommitteesPerSlot>,
}
impl_ssz_container!(AttestationElectra {
    aggregation_bits: BitList<MaxValidatorsPerSlot>,
    data: AttestationData,
    signature: [u8; 96],
    committee_bits: BitVector<MaxCommitteesPerSlot>,
});

#[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
pub struct DepositData {
    pub pubkey: [u8; 48],
    pub withdrawal_credentials: [u8; 32],
    pub amount: u64,
    pub signature: [u8; 96],
}
impl_ssz_container!(DepositData {
    pubkey: [u8; 48],
    withdrawal_credentials: [u8; 32],
    amount: u64,
    signature: [u8; 96],
});

#[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
pub struct Deposit {
    pub proof: FixedVector<[u8; 32], DepositProofLength>,
    pub data: DepositData,
}
impl_ssz_container!(Deposit {
    proof: FixedVector<[u8; 32], DepositProofLength>,
    data: DepositData,
});

#[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
pub struct VoluntaryExit {
    pub epoch: u64,
    pub validator_index: u64,
}
impl_ssz_container!(VoluntaryExit { epoch: u64, validator_index: u64 });

#[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
pub struct SignedVoluntaryExit {
    pub message: VoluntaryExit,
    pub signature: [u8; 96],
}
impl_ssz_container!(SignedVoluntaryExit { message: VoluntaryExit, signature: [u8; 96] });

#[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
pub struct SyncAggregate {
    pub sync_committee_bits: BitVector<SyncCommitteeSize>,
    pub sync_committee_signature: [u8; 96],
}
impl_ssz_container!(SyncAggregate {
    sync_committee_bits: BitVector<SyncCommitteeSize>,
    sync_committee_signature: [u8; 96],
});

#[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
pub struct Withdrawal {
    pub index: u64,
    pub validator_index: u64,
    pub address: [u8; 20],
    pub amount: u64,
}
impl_ssz_container!(Withdrawal {
    index: u64,
    validator_index: u64,
    address: [u8; 20],
    amount: u64,
});

/// Deneb+ full `ExecutionPayload` (Electra unchanged).
#[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
pub struct ExecutionPayload {
    pub parent_hash: [u8; 32],
    pub fee_recipient: [u8; 20],
    pub state_root: [u8; 32],
    pub receipts_root: [u8; 32],
    pub logs_bloom: FixedVector<u8, BytesPerLogsBloom>,
    pub prev_randao: [u8; 32],
    pub block_number: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    pub extra_data: VariableList<u8, MaxExtraDataBytes>,
    pub base_fee_per_gas: Uint256,
    pub block_hash: [u8; 32],
    pub transactions: VariableList<Transaction, MaxTransactionsPerPayload>,
    pub withdrawals: VariableList<Withdrawal, MaxWithdrawalsPerPayload>,
    pub blob_gas_used: u64,
    pub excess_blob_gas: u64,
}
impl_ssz_container!(ExecutionPayload {
    parent_hash: [u8; 32],
    fee_recipient: [u8; 20],
    state_root: [u8; 32],
    receipts_root: [u8; 32],
    logs_bloom: FixedVector<u8, BytesPerLogsBloom>,
    prev_randao: [u8; 32],
    block_number: u64,
    gas_limit: u64,
    gas_used: u64,
    timestamp: u64,
    extra_data: VariableList<u8, MaxExtraDataBytes>,
    base_fee_per_gas: Uint256,
    block_hash: [u8; 32],
    transactions: VariableList<Transaction, MaxTransactionsPerPayload>,
    withdrawals: VariableList<Withdrawal, MaxWithdrawalsPerPayload>,
    blob_gas_used: u64,
    excess_blob_gas: u64,
});

/// Blinded header form of the execution payload (body field for MEV path).
#[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
pub struct ExecutionPayloadHeader {
    pub parent_hash: [u8; 32],
    pub fee_recipient: [u8; 20],
    pub state_root: [u8; 32],
    pub receipts_root: [u8; 32],
    pub logs_bloom: FixedVector<u8, BytesPerLogsBloom>,
    pub prev_randao: [u8; 32],
    pub block_number: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    pub extra_data: VariableList<u8, MaxExtraDataBytes>,
    pub base_fee_per_gas: Uint256,
    pub block_hash: [u8; 32],
    pub transactions_root: [u8; 32],
    pub withdrawals_root: [u8; 32],
    pub blob_gas_used: u64,
    pub excess_blob_gas: u64,
}
impl_ssz_container!(ExecutionPayloadHeader {
    parent_hash: [u8; 32],
    fee_recipient: [u8; 20],
    state_root: [u8; 32],
    receipts_root: [u8; 32],
    logs_bloom: FixedVector<u8, BytesPerLogsBloom>,
    prev_randao: [u8; 32],
    block_number: u64,
    gas_limit: u64,
    gas_used: u64,
    timestamp: u64,
    extra_data: VariableList<u8, MaxExtraDataBytes>,
    base_fee_per_gas: Uint256,
    block_hash: [u8; 32],
    transactions_root: [u8; 32],
    withdrawals_root: [u8; 32],
    blob_gas_used: u64,
    excess_blob_gas: u64,
});

#[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
pub struct BlsToExecutionChange {
    pub validator_index: u64,
    pub from_bls_pubkey: [u8; 48],
    pub to_execution_address: [u8; 20],
}
impl_ssz_container!(BlsToExecutionChange {
    validator_index: u64,
    from_bls_pubkey: [u8; 48],
    to_execution_address: [u8; 20],
});

#[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
pub struct SignedBlsToExecutionChange {
    pub message: BlsToExecutionChange,
    pub signature: [u8; 96],
}
impl_ssz_container!(SignedBlsToExecutionChange {
    message: BlsToExecutionChange,
    signature: [u8; 96],
});

#[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
pub struct DepositRequest {
    pub pubkey: [u8; 48],
    pub withdrawal_credentials: [u8; 32],
    pub amount: u64,
    pub signature: [u8; 96],
    pub index: u64,
}
impl_ssz_container!(DepositRequest {
    pubkey: [u8; 48],
    withdrawal_credentials: [u8; 32],
    amount: u64,
    signature: [u8; 96],
    index: u64,
});

#[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
pub struct WithdrawalRequest {
    pub source_address: [u8; 20],
    pub validator_pubkey: [u8; 48],
    pub amount: u64,
}
impl_ssz_container!(WithdrawalRequest {
    source_address: [u8; 20],
    validator_pubkey: [u8; 48],
    amount: u64,
});

#[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
pub struct ConsolidationRequest {
    pub source_address: [u8; 20],
    pub source_pubkey: [u8; 48],
    pub target_pubkey: [u8; 48],
}
impl_ssz_container!(ConsolidationRequest {
    source_address: [u8; 20],
    source_pubkey: [u8; 48],
    target_pubkey: [u8; 48],
});

#[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
pub struct ExecutionRequests {
    pub deposits: VariableList<DepositRequest, MaxDepositRequestsPerPayload>,
    pub withdrawals: VariableList<WithdrawalRequest, MaxWithdrawalRequestsPerPayload>,
    pub consolidations: VariableList<ConsolidationRequest, MaxConsolidationRequestsPerPayload>,
}
impl_ssz_container!(ExecutionRequests {
    deposits: VariableList<DepositRequest, MaxDepositRequestsPerPayload>,
    withdrawals: VariableList<WithdrawalRequest, MaxWithdrawalRequestsPerPayload>,
    consolidations: VariableList<ConsolidationRequest, MaxConsolidationRequestsPerPayload>,
});

// ---------------------------------------------------------------------------
// Electra body variants
// ---------------------------------------------------------------------------

/// Electra `BeaconBlockBody` (13 fields; Fulu shares this layout).
///
/// Spec order is merkleization-sensitive — do not reorder.
#[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
pub struct BeaconBlockBodyElectra {
    pub randao_reveal: [u8; 96],
    pub eth1_data: Eth1Data,
    pub graffiti: [u8; 32],
    pub proposer_slashings: VariableList<ProposerSlashing, MaxProposerSlashings>,
    pub attester_slashings: VariableList<AttesterSlashingElectra, MaxAttesterSlashingsElectra>,
    pub attestations: VariableList<AttestationElectra, MaxAttestationsElectra>,
    pub deposits: VariableList<Deposit, MaxDeposits>,
    pub voluntary_exits: VariableList<SignedVoluntaryExit, MaxVoluntaryExits>,
    pub sync_aggregate: SyncAggregate,
    pub execution_payload: ExecutionPayload,
    pub bls_to_execution_changes:
        VariableList<SignedBlsToExecutionChange, MaxBlsToExecutionChanges>,
    pub blob_kzg_commitments: VariableList<KzgCommitment, MaxBlobCommitmentsPerBlock>,
    pub execution_requests: ExecutionRequests,
}
impl_ssz_container!(BeaconBlockBodyElectra {
    randao_reveal: [u8; 96],
    eth1_data: Eth1Data,
    graffiti: [u8; 32],
    proposer_slashings: VariableList<ProposerSlashing, MaxProposerSlashings>,
    attester_slashings: VariableList<AttesterSlashingElectra, MaxAttesterSlashingsElectra>,
    attestations: VariableList<AttestationElectra, MaxAttestationsElectra>,
    deposits: VariableList<Deposit, MaxDeposits>,
    voluntary_exits: VariableList<SignedVoluntaryExit, MaxVoluntaryExits>,
    sync_aggregate: SyncAggregate,
    execution_payload: ExecutionPayload,
    bls_to_execution_changes: VariableList<SignedBlsToExecutionChange, MaxBlsToExecutionChanges>,
    blob_kzg_commitments: VariableList<KzgCommitment, MaxBlobCommitmentsPerBlock>,
    execution_requests: ExecutionRequests,
});

impl BeaconBlockBodyElectra {
    /// Decode SSZ bytes into a typed Electra `BeaconBlockBody`.
    pub fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, BodySszError> {
        <Self as Decode>::from_ssz_bytes(bytes).map_err(Into::into)
    }

    /// Encode this body to canonical SSZ bytes.
    pub fn as_ssz_bytes(&self) -> Vec<u8> {
        Encode::as_ssz_bytes(self)
    }
}

/// Electra blinded body: `execution_payload` → `ExecutionPayloadHeader`.
#[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
pub struct BlindedBeaconBlockBodyElectra {
    pub randao_reveal: [u8; 96],
    pub eth1_data: Eth1Data,
    pub graffiti: [u8; 32],
    pub proposer_slashings: VariableList<ProposerSlashing, MaxProposerSlashings>,
    pub attester_slashings: VariableList<AttesterSlashingElectra, MaxAttesterSlashingsElectra>,
    pub attestations: VariableList<AttestationElectra, MaxAttestationsElectra>,
    pub deposits: VariableList<Deposit, MaxDeposits>,
    pub voluntary_exits: VariableList<SignedVoluntaryExit, MaxVoluntaryExits>,
    pub sync_aggregate: SyncAggregate,
    pub execution_payload_header: ExecutionPayloadHeader,
    pub bls_to_execution_changes:
        VariableList<SignedBlsToExecutionChange, MaxBlsToExecutionChanges>,
    pub blob_kzg_commitments: VariableList<KzgCommitment, MaxBlobCommitmentsPerBlock>,
    pub execution_requests: ExecutionRequests,
}
impl_ssz_container!(BlindedBeaconBlockBodyElectra {
    randao_reveal: [u8; 96],
    eth1_data: Eth1Data,
    graffiti: [u8; 32],
    proposer_slashings: VariableList<ProposerSlashing, MaxProposerSlashings>,
    attester_slashings: VariableList<AttesterSlashingElectra, MaxAttesterSlashingsElectra>,
    attestations: VariableList<AttestationElectra, MaxAttestationsElectra>,
    deposits: VariableList<Deposit, MaxDeposits>,
    voluntary_exits: VariableList<SignedVoluntaryExit, MaxVoluntaryExits>,
    sync_aggregate: SyncAggregate,
    execution_payload_header: ExecutionPayloadHeader,
    bls_to_execution_changes: VariableList<SignedBlsToExecutionChange, MaxBlsToExecutionChanges>,
    blob_kzg_commitments: VariableList<KzgCommitment, MaxBlobCommitmentsPerBlock>,
    execution_requests: ExecutionRequests,
});

impl BlindedBeaconBlockBodyElectra {
    /// Decode SSZ bytes into a typed Electra blinded `BeaconBlockBody`.
    pub fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, BodySszError> {
        <Self as Decode>::from_ssz_bytes(bytes).map_err(Into::into)
    }

    /// Encode this blinded body to canonical SSZ bytes.
    pub fn as_ssz_bytes(&self) -> Vec<u8> {
        Encode::as_ssz_bytes(self)
    }
}

// ---------------------------------------------------------------------------
// Convenience free functions (stable names for SEC-6c wiring)
// ---------------------------------------------------------------------------

/// Decode wire `Vec<u8>` / SSZ body bytes into [`BeaconBlockBodyElectra`].
pub fn decode_beacon_block_body_electra(
    bytes: &[u8],
) -> Result<BeaconBlockBodyElectra, BodySszError> {
    BeaconBlockBodyElectra::from_ssz_bytes(bytes)
}

/// Decode wire SSZ bytes into [`BlindedBeaconBlockBodyElectra`].
pub fn decode_blinded_beacon_block_body_electra(
    bytes: &[u8],
) -> Result<BlindedBeaconBlockBodyElectra, BodySszError> {
    BlindedBeaconBlockBodyElectra::from_ssz_bytes(bytes)
}

// ---------------------------------------------------------------------------
// External-vector fixtures (SEC-6a/b/c KATs; also usable as valid Electra bodies)
// ---------------------------------------------------------------------------

/// External known-good Electra body root from independent `remerkleable` oracle.
///
/// Matches [`external_vector_electra_body`]'s field construction.
pub const EXTERNAL_ELECTRA_BODY_ROOT_HEX: &str =
    "58953d11e9b51a6e95c8c70ca51b7ad6b6e557a91caab298a71688dfab9e4870";

/// External known-good Electra **block** root (`remerkleable` over the full
/// `BeaconBlock` with slot=3_000_000, proposer=42, parent=`0x11…`, state=`0x22…`,
/// body=[`external_vector_electra_body`]).
pub const EXTERNAL_ELECTRA_BLOCK_ROOT_HEX: &str =
    "b3f19bf190b0ab2466738ba06bbaf6e481041ca66db733c549975b27b53c92b9";

/// Deterministic Electra body matching the external `remerkleable` vector:
/// fixed non-zero leaves for signatures / eth1 / payload fields; empty op lists.
pub fn external_vector_electra_body() -> BeaconBlockBodyElectra {
    let mut graffiti = [0u8; 32];
    graffiti[..28].copy_from_slice(b"rvc-sec6a-spike-electra!!!!!");

    BeaconBlockBodyElectra {
        randao_reveal: [0x11; 96],
        eth1_data: Eth1Data { deposit_root: [0x22; 32], deposit_count: 7, block_hash: [0x33; 32] },
        graffiti,
        proposer_slashings: VariableList::from(vec![]),
        attester_slashings: VariableList::from(vec![]),
        attestations: VariableList::from(vec![]),
        deposits: VariableList::from(vec![]),
        voluntary_exits: VariableList::from(vec![]),
        sync_aggregate: SyncAggregate {
            sync_committee_bits: BitVector::new(),
            sync_committee_signature: [0x44; 96],
        },
        execution_payload: ExecutionPayload {
            parent_hash: [0x55; 32],
            fee_recipient: [0x66; 20],
            state_root: [0x77; 32],
            receipts_root: [0x88; 32],
            logs_bloom: FixedVector::from(vec![0u8; 256]),
            prev_randao: [0x99; 32],
            block_number: 12_345,
            gas_limit: 30_000_000,
            gas_used: 1_000_000,
            timestamp: 1_700_000_000,
            extra_data: VariableList::from(vec![]),
            base_fee_per_gas: Uint256::from_u64(7),
            block_hash: [0xaa; 32],
            transactions: VariableList::from(vec![]),
            withdrawals: VariableList::from(vec![]),
            blob_gas_used: 0,
            excess_blob_gas: 0,
        },
        bls_to_execution_changes: VariableList::from(vec![]),
        blob_kzg_commitments: VariableList::from(vec![]),
        execution_requests: ExecutionRequests {
            deposits: VariableList::from(vec![]),
            withdrawals: VariableList::from(vec![]),
            consolidations: VariableList::from(vec![]),
        },
    }
}

/// Execution payload header corresponding to [`external_vector_electra_body`]'s
/// payload (empty txs/withdrawals → their empty-list roots).
pub fn external_vector_execution_payload_header() -> ExecutionPayloadHeader {
    let p = &external_vector_electra_body().execution_payload;
    ExecutionPayloadHeader {
        parent_hash: p.parent_hash,
        fee_recipient: p.fee_recipient,
        state_root: p.state_root,
        receipts_root: p.receipts_root,
        logs_bloom: p.logs_bloom.clone(),
        prev_randao: p.prev_randao,
        block_number: p.block_number,
        gas_limit: p.gas_limit,
        gas_used: p.gas_used,
        timestamp: p.timestamp,
        extra_data: p.extra_data.clone(),
        base_fee_per_gas: p.base_fee_per_gas,
        block_hash: p.block_hash,
        // Empty list roots for transactions / withdrawals (spec empty List roots).
        transactions_root: {
            let root = VariableList::<Transaction, MaxTransactionsPerPayload>::from(vec![])
                .tree_hash_root();
            let mut out = [0u8; 32];
            out.copy_from_slice(root.as_slice());
            out
        },
        withdrawals_root: {
            let root =
                VariableList::<Withdrawal, MaxWithdrawalsPerPayload>::from(vec![]).tree_hash_root();
            let mut out = [0u8; 32];
            out.copy_from_slice(root.as_slice());
            out
        },
        blob_gas_used: p.blob_gas_used,
        excess_blob_gas: p.excess_blob_gas,
    }
}

/// Blinded Electra body matching the external vector (header instead of payload).
///
/// With empty txs/withdrawals the body HTR equals [`EXTERNAL_ELECTRA_BODY_ROOT_HEX`].
pub fn external_vector_blinded_electra_body() -> BlindedBeaconBlockBodyElectra {
    let full = external_vector_electra_body();
    BlindedBeaconBlockBodyElectra {
        randao_reveal: full.randao_reveal,
        eth1_data: full.eth1_data,
        graffiti: full.graffiti,
        proposer_slashings: full.proposer_slashings,
        attester_slashings: full.attester_slashings,
        attestations: full.attestations,
        deposits: full.deposits,
        voluntary_exits: full.voluntary_exits,
        sync_aggregate: full.sync_aggregate,
        execution_payload_header: external_vector_execution_payload_header(),
        bls_to_execution_changes: full.bls_to_execution_changes,
        blob_kzg_commitments: full.blob_kzg_commitments,
        execution_requests: full.execution_requests,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_hash::TreeHash;

    fn hex32(s: &str) -> Hash256 {
        let bytes = hex::decode(s.trim_start_matches("0x")).expect("hex");
        Hash256::from_slice(&bytes)
    }

    #[test]
    fn test_beacon_block_body_electra_htr_matches_external_vector() {
        let body = external_vector_electra_body();
        let root = body.tree_hash_root();
        assert_eq!(
            root,
            hex32(EXTERNAL_ELECTRA_BODY_ROOT_HEX),
            "Electra BeaconBlockBody hash_tree_root must match external remerkleable KAT"
        );
    }

    /// Alias retained for continuity with SEC-6a test name.
    #[test]
    fn test_electra_body_htr_matches_external_vector() {
        let body = external_vector_electra_body();
        assert_eq!(body.tree_hash_root(), hex32(EXTERNAL_ELECTRA_BODY_ROOT_HEX));
    }

    #[test]
    fn test_execution_payload_htr_matches_vector() {
        let body = external_vector_electra_body();
        assert_eq!(
            body.execution_payload.tree_hash_root(),
            hex32("d87a64ee3dee74c2b0f88fdae16256f0b81d5a58e1729f62089406ba46b6074d"),
        );
    }

    #[test]
    fn test_sync_aggregate_htr_matches_vector() {
        let body = external_vector_electra_body();
        assert_eq!(
            body.sync_aggregate.tree_hash_root(),
            hex32("40f2635c94dcb243d972e11a55968c92d8bbc8f9715cc8a4a14b6dd2179044f6"),
        );
    }

    #[test]
    fn test_empty_list_roots_match_spec_limits() {
        // Empty List[Composite, N] roots depend only on N (composite packing_factor=1).
        // remerkleable KATs (same oracle as the body vector):
        assert_eq!(
            VariableList::<ProposerSlashing, MaxProposerSlashings>::from(vec![]).tree_hash_root(),
            hex32("792930bbd5baac43bcc798ee49aa8185ef76bb3b44ba62b91d86ae569e4bb535"),
        );
        assert_eq!(
            VariableList::<AttesterSlashingElectra, MaxAttesterSlashingsElectra>::from(vec![])
                .tree_hash_root(),
            hex32("f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b"),
        );
        assert_eq!(
            VariableList::<AttestationElectra, MaxAttestationsElectra>::from(vec![])
                .tree_hash_root(),
            hex32("e8e527e84f666163a90ef900e013f56b0a4d020148b2224057b719f351b003a6"),
        );
        assert_eq!(
            VariableList::<KzgCommitment, MaxBlobCommitmentsPerBlock>::from(vec![])
                .tree_hash_root(),
            hex32("dba9671bac9513c9482f1416a53aabd2c6ce90d5a5f865ce5a55c775325c9136"),
        );
    }

    #[test]
    fn test_subcontainer_roots_match_external_vector_components() {
        let body = external_vector_electra_body();
        assert_eq!(
            body.eth1_data.tree_hash_root(),
            hex32("80967e80c7b8a102a59fc1827ef03adae06eb892466e61a12c25fdb370fa2ab4"),
        );
        assert_eq!(
            body.sync_aggregate.tree_hash_root(),
            hex32("40f2635c94dcb243d972e11a55968c92d8bbc8f9715cc8a4a14b6dd2179044f6"),
        );
        assert_eq!(
            body.execution_payload.tree_hash_root(),
            hex32("d87a64ee3dee74c2b0f88fdae16256f0b81d5a58e1729f62089406ba46b6074d"),
        );
        assert_eq!(
            body.execution_requests.tree_hash_root(),
            hex32("85e253b40599d0df756be043ea6949e49a07e756deef72b3588a4b05362206b5"),
        );
    }

    #[test]
    fn test_beacon_block_body_electra_decode_roundtrip() {
        let original = external_vector_electra_body();
        let encoded = original.as_ssz_bytes();
        let decoded = BeaconBlockBodyElectra::from_ssz_bytes(&encoded)
            .expect("decode external-vector Electra body");
        assert_eq!(decoded, original);
        // HTR is preserved across the wire encode/decode path.
        assert_eq!(decoded.tree_hash_root(), hex32(EXTERNAL_ELECTRA_BODY_ROOT_HEX));
        // Free-function entry point matches the method.
        let via_fn = decode_beacon_block_body_electra(&encoded).expect("fn decode");
        assert_eq!(via_fn, original);
    }

    #[test]
    fn test_beacon_block_body_electra_decode_rejects_truncated() {
        let encoded = external_vector_electra_body().as_ssz_bytes();
        assert!(encoded.len() > 16);
        let err = BeaconBlockBodyElectra::from_ssz_bytes(&encoded[..16]);
        assert!(err.is_err(), "truncated body must fail decode");
    }

    #[test]
    fn test_blinded_beacon_block_body_electra_decode_roundtrip() {
        let original = external_vector_blinded_electra_body();
        let encoded = original.as_ssz_bytes();
        let decoded = BlindedBeaconBlockBodyElectra::from_ssz_bytes(&encoded)
            .expect("decode blinded Electra body");
        assert_eq!(decoded, original);
        // When transactions/withdrawals are empty and the header stores those empty-list
        // roots, htr(ExecutionPayload) == htr(ExecutionPayloadHeader), so full and
        // blinded body roots coincide. That is correct SSZ — not a type confusion.
        let full = external_vector_electra_body();
        assert_eq!(
            original.execution_payload_header.tree_hash_root(),
            full.execution_payload.tree_hash_root(),
        );
        assert_eq!(decoded.tree_hash_root(), full.tree_hash_root());
        // Wire encodings still differ (payload bytes vs header roots).
        assert_ne!(encoded, full.as_ssz_bytes());
    }

    #[test]
    fn test_electra_body_with_nonempty_ops_roundtrip_and_stable_htr() {
        // Non-empty lists exercise VariableList of composites + FixedVector proof.
        let mut body = external_vector_electra_body();

        let header = BeaconBlockHeader {
            slot: 1,
            proposer_index: 2,
            parent_root: [0xab; 32],
            state_root: [0xcd; 32],
            body_root: [0xef; 32],
        };
        let signed = SignedBeaconBlockHeader { message: header, signature: [0x5a; 96] };
        let slashing = ProposerSlashing {
            signed_header_1: signed.clone(),
            signed_header_2: SignedBeaconBlockHeader {
                message: BeaconBlockHeader {
                    slot: 1,
                    proposer_index: 2,
                    parent_root: [0xab; 32],
                    state_root: [0xcd; 32],
                    body_root: [0x11; 32], // differ body_root so headers are distinct
                },
                signature: [0x5b; 96],
            },
        };
        body.proposer_slashings = VariableList::from(vec![slashing]);

        let proof_leaves: Vec<[u8; 32]> = (0..33).map(|i| [i as u8; 32]).collect();
        let deposit = Deposit {
            proof: FixedVector::from(proof_leaves),
            data: DepositData {
                pubkey: [0xde; 48],
                withdrawal_credentials: [0xad; 32],
                amount: 32_000_000_000,
                signature: [0xbe; 96],
            },
        };
        body.deposits = VariableList::from(vec![deposit]);

        let withdrawal =
            Withdrawal { index: 9, validator_index: 42, address: [0xca; 20], amount: 1_000 };
        body.execution_payload.withdrawals = VariableList::from(vec![withdrawal]);

        let tx: Transaction = VariableList::from(vec![0x02, 0xf8, 0x01]);
        body.execution_payload.transactions = VariableList::from(vec![tx]);

        body.blob_kzg_commitments = VariableList::from(vec![[0xbb; 48], [0xcc; 48]]);

        body.execution_requests.deposits = VariableList::from(vec![DepositRequest {
            pubkey: [0x11; 48],
            withdrawal_credentials: [0x22; 32],
            amount: 1,
            signature: [0x33; 96],
            index: 0,
        }]);

        let encoded = body.as_ssz_bytes();
        let decoded =
            BeaconBlockBodyElectra::from_ssz_bytes(&encoded).expect("non-empty ops body decode");
        assert_eq!(decoded, body);
        // HTR must be stable across encode/decode (not compared to external KAT —
        // field set differs from the empty-ops vector).
        assert_eq!(decoded.tree_hash_root(), body.tree_hash_root());
        assert_ne!(
            body.tree_hash_root(),
            hex32(EXTERNAL_ELECTRA_BODY_ROOT_HEX),
            "non-empty ops must change the body root vs empty-ops external vector"
        );
    }

    #[test]
    fn test_eth1_data_ssz_roundtrip() {
        let eth1 = Eth1Data { deposit_root: [0x22; 32], deposit_count: 7, block_hash: [0x33; 32] };
        let bytes = Encode::as_ssz_bytes(&eth1);
        assert_eq!(bytes.len(), 32 + 8 + 32);
        let back = <Eth1Data as Decode>::from_ssz_bytes(&bytes).unwrap();
        assert_eq!(back, eth1);
        assert_eq!(
            eth1.tree_hash_root(),
            hex32("80967e80c7b8a102a59fc1827ef03adae06eb892466e61a12c25fdb370fa2ab4"),
        );
    }

    #[test]
    fn test_uint256_ssz_roundtrip() {
        let v = Uint256::from_u64(7);
        let bytes = Encode::as_ssz_bytes(&v);
        assert_eq!(bytes.len(), 32);
        assert_eq!(bytes[0], 7);
        let back = <Uint256 as Decode>::from_ssz_bytes(&bytes).unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn test_electra_body_fixed_portion_length() {
        // Electra fixed portion: 396 bytes (Deneb 392 + 4 for execution_requests offset).
        // Verified by encoding an empty-ops body and reading the first variable offset.
        let encoded = external_vector_electra_body().as_ssz_bytes();
        // First variable field is proposer_slashings; its offset equals the fixed portion length.
        // Layout fixed fields before first var offset: randao(96)+eth1(72)+graffiti(32) = 200,
        // then 5 var offsets (20) → 220, then sync_aggregate(160) → 380, then 4 var offsets (16) → 396.
        const ELECTRA_FIXED_LEN: u32 = 396;
        let first_var_offset = u32::from_le_bytes(encoded[200..204].try_into().unwrap());
        assert_eq!(first_var_offset, ELECTRA_FIXED_LEN);
        assert!(encoded.len() >= ELECTRA_FIXED_LEN as usize);
    }
}
