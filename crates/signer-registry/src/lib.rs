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

/// Every registered gRPC signing method. EMPTY until Phase 2 Task 2.1 populates it.
pub const REGISTERED_METHODS: &[SigningMethod] = &[];
