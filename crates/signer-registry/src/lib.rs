//! Compile-time registry of every gRPC signing entry point on `rvc-signer`.
//!
//! DEV-ONLY (ADR-010): no production code links this crate. Consumed by the PRD M4
//! enumeration test (Phase 2 Task 2.1) to assert every registered handler is either a
//! non-slashable message type or routes through `SigningGate`. Empty until Phase 2.
#![forbid(unsafe_code)]

/// Class of consensus message a signing method handles.
///
/// One variant per distinct signing domain / SSZ message shape so the Phase 2 M4
/// enumeration test can apply per-domain policy precisely. Splitting domains that share
/// a Rust type but differ in SSZ payload or domain constant (e.g. beacon vs sync-committee
/// selection, base vs Electra aggregate) is deliberate: collapsing them would make a
/// gate-completeness check imprecise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageKind {
    /// `SignBeaconBlock` / `SignBlindedBeaconBlock` — `DOMAIN_BEACON_PROPOSER` (slashable).
    Block,
    /// `SignAttestation` — `DOMAIN_BEACON_ATTESTER` (slashable).
    Attestation,
    /// `AggregateAndProof` (Phase0/Altair) — `DOMAIN_AGGREGATE_AND_PROOF`.
    Aggregate,
    /// `ElectraAggregateAndProof` — `DOMAIN_AGGREGATE_AND_PROOF`, distinct SSZ type.
    ElectraAggregate,
    /// `SyncCommitteeMessage` — `DOMAIN_SYNC_COMMITTEE`.
    SyncMessage,
    /// `ContributionAndProof` — `DOMAIN_CONTRIBUTION_AND_PROOF`.
    SyncContribution,
    /// RANDAO reveal — `DOMAIN_RANDAO`.
    RandaoReveal,
    /// Voluntary exit — `DOMAIN_VOLUNTARY_EXIT`.
    VoluntaryExit,
    /// Validator/builder registration — `DOMAIN_APPLICATION_BUILDER`.
    BuilderRegistration,
    /// Beacon committee aggregator selection — `DOMAIN_SELECTION_PROOF`.
    Selection,
    /// Sync committee aggregator selection — `DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF`.
    SyncSelection,
    /// Legacy v1 raw-root `sign(signing_root, pubkey)` — no typed domain.
    V1RawRoot,
}

/// Whether a signing method routes through the slashing/doppelganger `SigningGate`.
///
/// An enum (rather than a bare `bool`) so a mis-typed registry entry for a slashable
/// message is a visible, reviewable mistake rather than a silent boolean flip.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GateRouting {
    /// Routes through `SigningGate::sign_*` (required for slashable message kinds).
    Gated,
    /// Does not route through the gate (only valid for non-slashable message kinds).
    NonSlashable,
}

/// Compile-time metadata for one gRPC signing method on the live listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SigningMethod {
    pub service: &'static str,
    pub method: &'static str,
    pub message_kind: MessageKind,
    pub gate_routing: GateRouting,
}

/// Every gRPC signing method on the live listener, classified by message kind and gate routing.
///
/// This is the canonical surface enumerated by the PRD M4 gate.  Adding a new signing RPC
/// without a matching entry here (or mis-classifying its `gate_routing`) will be caught by
/// `bin/rvc-signer/tests/signing_path_enumeration.rs`.  Issue 2.13 strengthens the gate to
/// verify each entry actually invokes `SigningGate` at runtime.
///
/// Only live-listener signing methods are listed:
/// - `list_public_keys` and `get_status` are informational, not signing methods.
/// - The v1 raw-root `sign` RPC has been removed from the live listener (SS-1, Issue 2.2).
///
/// Service path is the protobuf fully-qualified service name (`package.ServiceName`).
pub const REGISTERED_METHODS: &[SigningMethod] = &[
    SigningMethod {
        service: "signer.v2.SignerService",
        method: "SignBeaconBlock",
        message_kind: MessageKind::Block,
        gate_routing: GateRouting::Gated,
    },
    SigningMethod {
        service: "signer.v2.SignerService",
        method: "SignBlindedBeaconBlock",
        message_kind: MessageKind::Block,
        gate_routing: GateRouting::Gated,
    },
    SigningMethod {
        service: "signer.v2.SignerService",
        method: "SignAttestationData",
        message_kind: MessageKind::Attestation,
        gate_routing: GateRouting::Gated,
    },
    // TODO(SS-2/SS-3, Phase 4): reclassify aggregate as non-slashable once the
    // SignAggregateAndProof path is fixed to not stage attestation slashing records.
    SigningMethod {
        service: "signer.v2.SignerService",
        method: "SignAggregateAndProof",
        message_kind: MessageKind::Aggregate,
        gate_routing: GateRouting::Gated,
    },
    SigningMethod {
        service: "signer.v2.SignerService",
        method: "SignRandaoReveal",
        message_kind: MessageKind::RandaoReveal,
        gate_routing: GateRouting::NonSlashable,
    },
    SigningMethod {
        service: "signer.v2.SignerService",
        method: "SignSyncCommitteeMessage",
        message_kind: MessageKind::SyncMessage,
        gate_routing: GateRouting::NonSlashable,
    },
    SigningMethod {
        service: "signer.v2.SignerService",
        method: "SignSyncAggregatorSelectionData",
        message_kind: MessageKind::SyncSelection,
        gate_routing: GateRouting::NonSlashable,
    },
    SigningMethod {
        service: "signer.v2.SignerService",
        method: "SignContributionAndProof",
        message_kind: MessageKind::SyncContribution,
        gate_routing: GateRouting::NonSlashable,
    },
    SigningMethod {
        service: "signer.v2.SignerService",
        method: "SignBuilderRegistration",
        message_kind: MessageKind::BuilderRegistration,
        gate_routing: GateRouting::NonSlashable,
    },
    SigningMethod {
        service: "signer.v2.SignerService",
        method: "SignVoluntaryExit",
        message_kind: MessageKind::VoluntaryExit,
        gate_routing: GateRouting::NonSlashable,
    },
];
