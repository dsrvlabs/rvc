//! Typed SSZ `BeaconBlockBody` containers for body-leaf `hash_tree_root` (SEC-6).
//!
//! SEC-6a prototype seed: Electra full body + shared sub-containers needed to
//! compute a spec-correct body root. Wire `Vec<u8>` bodies still live on
//! [`crate::BeaconBlock`]; SEC-6b/6c will decode into these types and replace
//! the non-spec `vec_u8_tree_hash_root` body leaf.
//!
//! Design (see `plan/security-2026-07-18/spike-sec6-block-body-htr.md`):
//! hand-typed per-fork containers via `tree_hash_derive` + `ssz_types`
//! (`VariableList` / `FixedVector` / `BitVector`) — not a full consensus-types
//! library.

use ssz_types::{
    typenum::{
        U1, U1048576, U1073741824, U131072, U16, U2, U256, U32, U33, U4096, U512, U64, U8, U8192,
    },
    BitList, BitVector, FixedVector, VariableList,
};
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

#[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
pub struct Checkpoint {
    pub epoch: u64,
    pub root: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
pub struct AttestationData {
    pub slot: u64,
    pub index: u64,
    pub beacon_block_root: [u8; 32],
    pub source: Checkpoint,
    pub target: Checkpoint,
}

#[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
pub struct BeaconBlockHeader {
    pub slot: u64,
    pub proposer_index: u64,
    pub parent_root: [u8; 32],
    pub state_root: [u8; 32],
    pub body_root: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
pub struct SignedBeaconBlockHeader {
    pub message: BeaconBlockHeader,
    pub signature: [u8; 96],
}

#[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
pub struct ProposerSlashing {
    pub signed_header_1: SignedBeaconBlockHeader,
    pub signed_header_2: SignedBeaconBlockHeader,
}

#[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
pub struct IndexedAttestationElectra {
    pub attesting_indices: VariableList<u64, MaxValidatorsPerSlot>,
    pub data: AttestationData,
    pub signature: [u8; 96],
}

#[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
pub struct AttesterSlashingElectra {
    pub attestation_1: IndexedAttestationElectra,
    pub attestation_2: IndexedAttestationElectra,
}

#[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
pub struct AttestationElectra {
    pub aggregation_bits: BitList<MaxValidatorsPerSlot>,
    pub data: AttestationData,
    pub signature: [u8; 96],
    pub committee_bits: BitVector<MaxCommitteesPerSlot>,
}

#[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
pub struct DepositData {
    pub pubkey: [u8; 48],
    pub withdrawal_credentials: [u8; 32],
    pub amount: u64,
    pub signature: [u8; 96],
}

#[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
pub struct Deposit {
    pub proof: FixedVector<[u8; 32], DepositProofLength>,
    pub data: DepositData,
}

#[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
pub struct VoluntaryExit {
    pub epoch: u64,
    pub validator_index: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
pub struct SignedVoluntaryExit {
    pub message: VoluntaryExit,
    pub signature: [u8; 96],
}

#[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
pub struct SyncAggregate {
    pub sync_committee_bits: BitVector<SyncCommitteeSize>,
    pub sync_committee_signature: [u8; 96],
}

#[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
pub struct Withdrawal {
    pub index: u64,
    pub validator_index: u64,
    pub address: [u8; 20],
    pub amount: u64,
}

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

#[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
pub struct BLSToExecutionChange {
    pub validator_index: u64,
    pub from_bls_pubkey: [u8; 48],
    pub to_execution_address: [u8; 20],
}

#[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
pub struct SignedBlsToExecutionChange {
    pub message: BLSToExecutionChange,
    pub signature: [u8; 96],
}

#[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
pub struct DepositRequest {
    pub pubkey: [u8; 48],
    pub withdrawal_credentials: [u8; 32],
    pub amount: u64,
    pub signature: [u8; 96],
    pub index: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
pub struct WithdrawalRequest {
    pub source_address: [u8; 20],
    pub validator_pubkey: [u8; 48],
    pub amount: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
pub struct ConsolidationRequest {
    pub source_address: [u8; 20],
    pub source_pubkey: [u8; 48],
    pub target_pubkey: [u8; 48],
}

#[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
pub struct ExecutionRequests {
    pub deposits: VariableList<DepositRequest, MaxDepositRequestsPerPayload>,
    pub withdrawals: VariableList<WithdrawalRequest, MaxWithdrawalRequestsPerPayload>,
    pub consolidations: VariableList<ConsolidationRequest, MaxConsolidationRequestsPerPayload>,
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use tree_hash::TreeHash;

    /// External known-good body root from an independent SSZ oracle (`remerkleable`),
    /// modelling Electra `BeaconBlockBody` with the field values constructed below.
    ///
    /// Generated offline (no network in tests):
    /// ```text
    /// remerkleable Container hash_tree_root over the same field values
    /// ```
    /// Source script: plan note + this test's field construction. Do not recompute
    /// the expected root from rvc helpers — that would defeat the KAT.
    const EXTERNAL_ELECTRA_BODY_ROOT_HEX: &str =
        "58953d11e9b51a6e95c8c70ca51b7ad6b6e557a91caab298a71688dfab9e4870";

    fn hex32(s: &str) -> Hash256 {
        let bytes = hex::decode(s.trim_start_matches("0x")).expect("hex");
        Hash256::from_slice(&bytes)
    }

    /// Deterministic Electra body matching the external `remerkleable` vector:
    /// fixed non-zero leaves for signatures / eth1 / payload header fields;
    /// all operation lists and blob commitments empty.
    fn external_vector_electra_body() -> BeaconBlockBodyElectra {
        let mut graffiti = [0u8; 32];
        graffiti[..28].copy_from_slice(b"rvc-sec6a-spike-electra!!!!!");

        BeaconBlockBodyElectra {
            randao_reveal: [0x11; 96],
            eth1_data: Eth1Data {
                deposit_root: [0x22; 32],
                deposit_count: 7,
                block_hash: [0x33; 32],
            },
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

    #[test]
    fn test_electra_body_htr_matches_external_vector() {
        let body = external_vector_electra_body();
        let root = body.tree_hash_root();
        assert_eq!(
            root,
            hex32(EXTERNAL_ELECTRA_BODY_ROOT_HEX),
            "Electra BeaconBlockBody hash_tree_root must match external remerkleable KAT"
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
}
