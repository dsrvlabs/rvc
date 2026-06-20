//! gRPC signer service implementation.
//!
//! # V1 service (`SignerService` from `signer.proto`)
//! The v1 raw-root `sign(signing_root, pubkey)` RPC is **deprecated** and kept
//! alive until ISSUE-1.8 deletes the v1 client path.  Do not add new features
//! to the v1 handler.
//!
//! # V2 service (`SignerService` from `signer.v2.proto`)
//! All 10 typed RPCs are implemented (ISSUE-1.6a–d) and route through
//! `SigningGate` (Issue 2.10a — D-3).
//!
//! # Gate routing (D-3 wiring, Issue 2.10a)
//!
//! Every typed v2 handler now routes through `SigningGate::sign_*`:
//!
//! - Slashable handlers (`sign_beacon_block`, `sign_blinded_beacon_block`,
//!   `sign_attestation_data`): `gate.sign_block` / `gate.sign_attestation`.
//!   The gate manages: per-pubkey lock → doppelganger check →
//!   stage → sign (timeout) → commit/discard.
//!
//! - Non-slashable handlers: `gate.sign_*` (gate check → sign, NO slashing DB).
//!
//! # AlwaysEnabled enablement
//!
//! The standalone `rvc-signer` is a remote signer.  Doppelganger detection is
//! a VC-side concern (the orchestrator enforces it; wired in 2.10b/main.rs).
//! The bin's gate therefore uses an `AlwaysEnabled` `SigningEnablement` so that
//! the doppelganger check always passes here.  The gate still provides:
//! - Slashing protection (stage → commit/discard with `SlashingDb`)
//! - Per-pubkey serialization locks (`ValidatorLockMap`)
//! - Sign timeout (BUG-003 mitigation)
//!
//! # SS-2/SS-3 fix (aggregate-and-proof, Issue 2.10a)
//!
//! The previous `sign_aggregate_and_proof` handler erroneously called
//! `stage_attestation` on the inner attestation's epochs.  This constituted:
//! - SS-2: double-staging an attestation that the VC already committed via
//!   `sign_attestation`.
//! - SS-3: treating `DOMAIN_AGGREGATE_AND_PROOF` signing roots as attestation
//!   slashing watermarks.
//!
//! Routing through `gate.sign_aggregate_and_proof` removes the attestation
//! staging.  The gate's `sign_aggregate_and_proof` is explicitly non-slashable
//! per the Ethereum consensus spec.

use std::sync::Arc;
use std::time::Duration;

use tonic::{Request, Response, Status};
use tracing::Span;

use crate::audit;
use crate::backend::signer_adapter::SigningBackendAsSigner;
use crate::backend::SigningBackend;
use crate::metrics::SignerMetrics;

// V1 imports (deprecated — kept until ISSUE-1.8)
use crate::proto::signer::signer_service_server::SignerService;
use crate::proto::signer::{
    GetStatusRequest, GetStatusResponse, ListPublicKeysRequest, ListPublicKeysResponse,
    SignRequest, SignResponse,
};

// V2 imports
use crate::proto::signer_v2::signer_service_server::SignerService as SignerServiceV2;
use crate::proto::signer_v2::{
    GetStatusRequest as GetStatusRequestV2, GetStatusResponse as GetStatusResponseV2,
    ListPublicKeysRequest as ListPublicKeysRequestV2,
    ListPublicKeysResponse as ListPublicKeysResponseV2, SignAggregateAndProofRequest,
    SignAttestationDataRequest, SignBeaconBlockRequest, SignBlindedBeaconBlockRequest,
    SignBuilderRegistrationRequest, SignContributionAndProofRequest, SignRandaoRevealRequest,
    SignResponse as SignResponseV2, SignSyncAggregatorSelectionDataRequest,
    SignSyncCommitteeMessageRequest, SignVoluntaryExitRequest,
};

use crypto::{
    compute_domain, compute_signing_root, PublicKey, DOMAIN_BEACON_ATTESTER,
    DOMAIN_BEACON_PROPOSER, DOMAIN_RANDAO,
};
use eth_types::{
    decode_attestation_ssz, decode_beacon_block_ssz, decode_blinded_beacon_block_ssz,
    decode_sync_committee_contribution_ssz, AggregateAndProof, AttestationData, Checkpoint,
    ContributionAndProof, SszDecodeError, SyncAggregatorSelectionData, ValidatorRegistrationV1,
    VoluntaryExit, DOMAIN_AGGREGATE_AND_PROOF, DOMAIN_APPLICATION_BUILDER,
    DOMAIN_CONTRIBUTION_AND_PROOF, DOMAIN_SYNC_COMMITTEE, DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF,
    DOMAIN_VOLUNTARY_EXIT,
};
use signer::{SigningGate, SigningGateError, ValidatorLockMap};
use slashing::SlashingDb; // kept for new_v2 constructor parameter type

/// Default per-sign timeout passed to the gate: 4 seconds.
///
/// Well under a 12-second Ethereum slot.  Bounds the SQLite write-lock hold
/// duration per BUG-003.  The `with_sign_timeout` builder is available but
/// not yet wired to a CLI flag; it exists for future operator configuration.
const DEFAULT_SIGN_TIMEOUT: Duration = Duration::from_secs(4);

// ─────────────────────────────────────────────────────────────────────────────
// AlwaysEnabled — the standalone signer's gate enablement
// ─────────────────────────────────────────────────────────────────────────────

/// A `SigningEnablement` that always allows signing.
///
/// The standalone `rvc-signer` is a REMOTE signer; doppelganger detection is a
/// VC-side concern (the orchestrator wired in 2.10b/main.rs enforces it).
/// The gate here provides slashing-protection + per-pubkey-lock layers only;
/// the doppelganger gate is effectively a no-op.
struct AlwaysEnabled;

impl signer::SigningEnablement for AlwaysEnabled {
    fn is_signing_enabled(&self, _pubkey: &PublicKey) -> bool {
        true
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SignerServiceImpl
// ─────────────────────────────────────────────────────────────────────────────

pub struct SignerServiceImpl {
    backend: Arc<dyn SigningBackend>,
    backend_name: String,
    metrics: Option<Arc<SignerMetrics>>,
    /// Gate — `None` when no slashing DB is configured.
    ///
    /// Slashable sign requests fail-closed with `Status::internal` when the gate
    /// is absent (same `require_db` semantics as before).  The gate internally
    /// holds the `Arc<SlashingDb>` so the DB stays alive for the service lifetime.
    gate: Option<SigningGate>,
}

impl SignerServiceImpl {
    /// Create a v1-only service (no slashing DB, no gate).
    ///
    /// **Deprecated**: new callers should use `new_v2`.
    pub fn new(backend: Arc<dyn SigningBackend>, backend_name: String) -> Self {
        Self { backend, backend_name, metrics: None, gate: None }
    }

    /// Create a v2-capable service with an embedded slashing DB and `SigningGate`.
    ///
    /// The gate is built from:
    /// - `slashing_db`: provides slashing protection for block and attestation paths.
    /// - `SigningBackendAsSigner` adapter: wraps the backend as `Arc<dyn crypto::Signer>`.
    /// - `AlwaysEnabled` enablement: doppelganger detection is the calling VC's
    ///   responsibility; the gate here provides slashing + lock layers only.
    /// - A fresh `ValidatorLockMap`: per-pubkey serialization.
    /// - Default 4-second sign timeout (BUG-003 mitigation).
    pub fn new_v2(
        backend: Arc<dyn SigningBackend>,
        backend_name: String,
        slashing_db: Arc<SlashingDb>,
    ) -> Self {
        let adapted_signer =
            Arc::new(SigningBackendAsSigner(Arc::clone(&backend))) as Arc<dyn crypto::Signer>;
        let gate = SigningGate::new_with_raw_signer(
            Arc::clone(&slashing_db),
            Arc::new(AlwaysEnabled),
            adapted_signer,
            Arc::new(ValidatorLockMap::new()),
            DEFAULT_SIGN_TIMEOUT,
        );
        Self { backend, backend_name, metrics: None, gate: Some(gate) }
    }

    pub fn with_metrics(mut self, metrics: Arc<SignerMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Override the sign timeout on the embedded gate (builder style).
    ///
    /// Available for future CLI-flag wiring; not yet operator-configurable.
    /// Has no effect when no gate is present (i.e. `new()` path).
    pub fn with_sign_timeout(mut self, timeout: Duration) -> Self {
        if let Some(gate) = self.gate.take() {
            self.gate = Some(gate.with_sign_timeout(timeout));
        }
        self
    }

    /// Borrow the gate or return an `internal` status if it's missing.
    ///
    /// Used only by **slashable** handlers (block + attestation), which must fail
    /// closed when no slashing DB is configured.
    #[allow(clippy::result_large_err)]
    fn require_gate(&self) -> Result<&SigningGate, Status> {
        self.gate.as_ref().ok_or_else(|| {
            Status::internal(
                "slashing protection database is not configured; \
                 restart with a valid --data-dir or --disable-slashing-protection + \
                 RVC_ALLOW_INSECURE=true",
            )
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Non-slashable backend fallback (BUG-001 fix, Issue 2.10a review)
// ─────────────────────────────────────────────────────────────────────────────
//
// Pre-2.10a, non-slashable handlers called `backend.sign` directly.  Post-2.10a
// the gate owns signing, but the gate is `None` when `--disable-slashing-protection
// + RVC_ALLOW_INSECURE=true` is set (no DB, SignerServiceImpl::new path).
//
// Slashable handlers (block, attestation) keep `require_gate()` — fail-closed
// without a DB, correct.
//
// Non-slashable handlers must work without a DB.  When no gate is present they
// fall through to the backend directly, preserving pre-2.10a semantics.

/// Sign using the backend, mapping `SigningBackendError` to `tonic::Status`.
///
/// Used as the no-gate fallback for non-slashable handlers on the
/// `--disable-slashing-protection` path.
async fn sign_via_backend(
    backend: &dyn crate::backend::SigningBackend,
    signing_root: &[u8; 32],
    pubkey: &[u8; 48],
) -> Result<Vec<u8>, Status> {
    backend.sign(signing_root, pubkey).await.map(|b| b.to_vec()).map_err(|e| match e {
        crate::backend::SigningBackendError::KeyNotFound(_) => {
            Status::not_found("unknown public key")
        }
        other => {
            tracing::error!(error = %other, "signing backend error");
            Status::internal("internal signing error")
        }
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Validate that `pubkey` is exactly 48 bytes.
#[allow(clippy::result_large_err)]
fn validate_pubkey(pubkey: &[u8]) -> Result<[u8; 48], Status> {
    pubkey.try_into().map_err(|_| {
        Status::invalid_argument(format!("pubkey must be 48 bytes, got {}", pubkey.len()))
    })
}

/// Validate that a byte slice is exactly 4 bytes (fork version).
#[allow(clippy::result_large_err)]
fn validate_fork_version(bytes: &[u8], field_name: &str) -> Result<[u8; 4], Status> {
    bytes.try_into().map_err(|_| {
        Status::invalid_argument(format!("{field_name} must be 4 bytes, got {}", bytes.len()))
    })
}

/// Validate that `gvr` is exactly 32 bytes.
#[allow(clippy::result_large_err)]
fn validate_gvr(gvr: &[u8]) -> Result<[u8; 32], Status> {
    gvr.try_into().map_err(|_| {
        Status::invalid_argument(format!(
            "genesis_validators_root must be 32 bytes, got {}",
            gvr.len()
        ))
    })
}

/// Validate that `selection_proof` is exactly 96 bytes (a BLS signature share).
///
/// The proto schema for `AggregateAndProof` and `ContributionAndProof` documents
/// `selection_proof` as a 96-byte BLS signature. The server does NOT verify the
/// signature itself — that is the client's responsibility — but the length must
/// be enforced because `vec_u8_tree_hash_root` is permissive and would silently
/// produce a wrong signing root for any other length.
#[allow(clippy::result_large_err)]
fn validate_selection_proof(bytes: &[u8]) -> Result<Vec<u8>, Status> {
    if bytes.len() != 96 {
        return Err(Status::invalid_argument(format!(
            "selection_proof must be 96 bytes, got {}",
            bytes.len()
        )));
    }
    Ok(bytes.to_vec())
}

/// Convert a `SszDecodeError` to a gRPC `Status::invalid_argument`.
fn ssz_err(e: SszDecodeError) -> Status {
    Status::invalid_argument(format!("SSZ decode error: {e}"))
}

/// Map a `SigningGateError` to a gRPC `Status`.
///
/// # Error sanitization
///
/// SQLite paths, rusqlite internals, and other low-level DB details MUST NOT
/// be forwarded to gRPC callers.  Only slashing-violation details
/// (`SlashableBlock`/`SlashableAttestation` — which carry epoch/slot numbers
/// safe to surface) are included in the response body.  All other DB errors
/// are logged server-side and a generic message is returned to the caller.
///
/// # Mapping rationale
///
/// - `BlockedByDoppelganger` → `FailedPrecondition`: validator not yet cleared;
///   caller should back off and retry after the monitoring window.
/// - `BlockedBySlashingDb(SlashableBlock|SlashableAttestation)` →
///   `FailedPrecondition` with violation details: slashable conflict detected.
///   Caller MUST NOT retry with a different root for the same slot/epoch.
/// - `BlockedBySlashingDb(other)` → `FailedPrecondition` generic: DB I/O error
///   during staging — detail is logged server-side to avoid leaking rusqlite paths.
/// - `SlashingDbCommitFailed` → `Internal` generic: sign succeeded but DB write
///   failed; same-root retry is safe.  Detail logged server-side.
/// - `KeyNotFound` → `NotFound`: pubkey not loaded in backend.
/// - `SigningFailed` → `Internal`: BLS backend error or sign timeout.  Detail
///   logged server-side.
/// - `UnknownPubkey` → `NotFound`: consistent with `KeyNotFound`.  Currently
///   unreachable (the gate returns `BlockedByDoppelganger` for unknown pubkeys
///   because `is_signing_enabled` returns `false` for them).
fn gate_err_to_status(e: SigningGateError) -> Status {
    use slashing::SlashingError;
    match e {
        SigningGateError::BlockedByDoppelganger => {
            Status::failed_precondition("signing blocked by doppelganger gate")
        }
        SigningGateError::BlockedBySlashingDb(inner) => match &inner {
            // Slashing-violation details (epoch/slot numbers) are safe to surface.
            SlashingError::SlashableBlock(_) | SlashingError::SlashableAttestation(_) => {
                Status::failed_precondition(format!("slashing protection violation: {inner}"))
            }
            // All other DB errors (DatabaseError, MigrationError, etc.) may contain
            // rusqlite internals or file paths — log server-side, return generic.
            other => {
                tracing::error!(error = %other, "slashing DB error during staging");
                Status::failed_precondition("slashing protection error")
            }
        },
        SigningGateError::SlashingDbCommitFailed(inner) => {
            // Commit error: same-root retry is safe.  Log detail, return generic.
            tracing::error!(error = %inner, "slashing DB commit failed after successful sign");
            Status::internal("slashing DB commit failed; same-root retry is safe")
        }
        SigningGateError::KeyNotFound => Status::not_found("unknown public key"),
        SigningGateError::SigningFailed(msg) => {
            tracing::error!(error = %msg, "signing backend error");
            Status::internal("internal signing error")
        }
        // Currently unreachable: unknown pubkeys return BlockedByDoppelganger because
        // AlwaysEnabled returns false for them.  Mapped to NotFound for consistency
        // with KeyNotFound if the gate ever distinguishes the two cases.
        SigningGateError::UnknownPubkey => Status::not_found("unknown public key"),
    }
}

/// Encode a pubkey as `0x<hex>` for use in audit logs.
fn pubkey_hex(pubkey: &[u8; 48]) -> String {
    format!("0x{}", hex::encode(pubkey))
}

/// Convert a `PublicKey` from raw bytes, mapping failure to `Status::invalid_argument`.
#[allow(clippy::result_large_err)]
fn pubkey_from_bytes(bytes: &[u8; 48]) -> Result<PublicKey, Status> {
    PublicKey::from_bytes(bytes)
        .map_err(|_| Status::invalid_argument("pubkey bytes are not a valid BLS public key"))
}

// ─────────────────────────────────────────────────────────────────────────────
// V1 SignerService impl — SS-1 FIX (Issue 2.2)
// ─────────────────────────────────────────────────────────────────────────────
// The v1 raw-root `sign(signing_root, pubkey)` path has been removed from the
// live listener (see `main.rs`).  Per ADR-010, the trait impl is kept compiled
// so the proto types remain usable for a future separately-bound, off-by-default
// insecure listener that would require `eth_types::insecure::InsecureGate::Allow`
// (NOT implemented here).  All methods return `Unimplemented` so any accidental
// call produces a clear diagnostic rather than silent misbehavior.
//
// SS-1: v1 raw-root sign bypass — removed in Issue 2.2.
// ─────────────────────────────────────────────────────────────────────────────

#[tonic::async_trait]
impl SignerService for SignerServiceImpl {
    async fn sign(&self, _request: Request<SignRequest>) -> Result<Response<SignResponse>, Status> {
        Err(Status::unimplemented("v1 raw-root signing has been removed; use the v2 typed RPCs."))
    }

    async fn list_public_keys(
        &self,
        _request: Request<ListPublicKeysRequest>,
    ) -> Result<Response<ListPublicKeysResponse>, Status> {
        Err(Status::unimplemented("v1 list_public_keys has been removed; use the v2 typed RPCs."))
    }

    async fn get_status(
        &self,
        _request: Request<GetStatusRequest>,
    ) -> Result<Response<GetStatusResponse>, Status> {
        Err(Status::unimplemented("v1 get_status has been removed; use the v2 typed RPCs."))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// V2 SignerService impl — all handlers route through SigningGate (D-3, Issue 2.10a)
// ─────────────────────────────────────────────────────────────────────────────

#[tonic::async_trait]
impl SignerServiceV2 for SignerServiceImpl {
    // ── SignBeaconBlock ───────────────────────────────────────────────────────

    #[allow(clippy::result_large_err)]
    #[tracing::instrument(name = "rvc.signer.v2.sign_beacon_block", skip_all, fields(pubkey, slot))]
    async fn sign_beacon_block(
        &self,
        req: Request<SignBeaconBlockRequest>,
    ) -> Result<Response<SignResponseV2>, Status> {
        let client_cn = audit::cn::extract_client_cn(&req);
        let r = req.into_inner();

        let pubkey_bytes = validate_pubkey(&r.pubkey)?;
        let pubkey_hex_str = pubkey_hex(&pubkey_bytes);
        Span::current().record("pubkey", pubkey_hex_str.as_str());

        let fork_info =
            r.fork_info.ok_or_else(|| Status::invalid_argument("fork_info required"))?;
        let current_version = validate_fork_version(&fork_info.current_version, "current_version")?;
        let gvr = validate_gvr(&fork_info.genesis_validators_root)?;

        let block = decode_beacon_block_ssz(&r.block_ssz, r.fork_id).map_err(ssz_err)?;
        let slot = block.slot;
        Span::current().record("slot", slot);

        let domain = compute_domain(DOMAIN_BEACON_PROPOSER, current_version, gvr);
        let signing_root = compute_signing_root(&block, domain);

        let pubkey = pubkey_from_bytes(&pubkey_bytes)?;
        let gate = self.require_gate()?;
        let sig = gate
            .sign_block(&pubkey, slot, signing_root, gvr, &client_cn)
            .await
            .map_err(gate_err_to_status)?;

        tracing::info!(
            pubkey = %pubkey_hex_str,
            slot,
            client_cn = %client_cn,
            "sign_beacon_block: success"
        );
        Ok(Response::new(SignResponseV2 { signature: sig }))
    }

    // ── SignBlindedBeaconBlock ────────────────────────────────────────────────

    #[allow(clippy::result_large_err)]
    #[tracing::instrument(
        name = "rvc.signer.v2.sign_blinded_beacon_block",
        skip_all,
        fields(pubkey, slot)
    )]
    async fn sign_blinded_beacon_block(
        &self,
        req: Request<SignBlindedBeaconBlockRequest>,
    ) -> Result<Response<SignResponseV2>, Status> {
        let client_cn = audit::cn::extract_client_cn(&req);
        let r = req.into_inner();

        let pubkey_bytes = validate_pubkey(&r.pubkey)?;
        let pubkey_hex_str = pubkey_hex(&pubkey_bytes);
        Span::current().record("pubkey", pubkey_hex_str.as_str());

        let fork_info =
            r.fork_info.ok_or_else(|| Status::invalid_argument("fork_info required"))?;
        let current_version = validate_fork_version(&fork_info.current_version, "current_version")?;
        let gvr = validate_gvr(&fork_info.genesis_validators_root)?;

        let block = decode_blinded_beacon_block_ssz(&r.block_ssz, r.fork_id).map_err(ssz_err)?;
        let slot = block.slot;
        Span::current().record("slot", slot);

        let domain = compute_domain(DOMAIN_BEACON_PROPOSER, current_version, gvr);
        let signing_root = compute_signing_root(&block, domain);

        let pubkey = pubkey_from_bytes(&pubkey_bytes)?;
        let gate = self.require_gate()?;
        let sig = gate
            .sign_block(&pubkey, slot, signing_root, gvr, &client_cn)
            .await
            .map_err(gate_err_to_status)?;

        tracing::info!(
            pubkey = %pubkey_hex_str,
            slot,
            client_cn = %client_cn,
            "sign_blinded_beacon_block: success"
        );
        Ok(Response::new(SignResponseV2 { signature: sig }))
    }

    // ── SignRandaoReveal ──────────────────────────────────────────────────────

    #[tracing::instrument(
        name = "rvc.signer.v2.sign_randao_reveal",
        skip_all,
        fields(pubkey, epoch)
    )]
    async fn sign_randao_reveal(
        &self,
        req: Request<SignRandaoRevealRequest>,
    ) -> Result<Response<SignResponseV2>, Status> {
        let _client_cn = audit::cn::extract_client_cn(&req);
        let r = req.into_inner();

        let pubkey_bytes = validate_pubkey(&r.pubkey)?;
        let pubkey_hex_str = pubkey_hex(&pubkey_bytes);
        Span::current().record("pubkey", pubkey_hex_str.as_str());

        let fork_info =
            r.fork_info.ok_or_else(|| Status::invalid_argument("fork_info required"))?;
        let current_version = validate_fork_version(&fork_info.current_version, "current_version")?;
        let gvr = validate_gvr(&fork_info.genesis_validators_root)?;

        let epoch = r.epoch;
        Span::current().record("epoch", epoch);

        // Per FR-P0-3: RANDAO is not slashable.
        let domain = compute_domain(DOMAIN_RANDAO, current_version, gvr);
        let signing_root = compute_signing_root(&epoch, domain);

        let sig = if let Some(gate) = &self.gate {
            let pubkey = pubkey_from_bytes(&pubkey_bytes)?;
            gate.sign_randao_reveal(&pubkey, signing_root).await.map_err(gate_err_to_status)?
        } else {
            sign_via_backend(self.backend.as_ref(), &signing_root, &pubkey_bytes).await?
        };

        tracing::info!(
            pubkey = %pubkey_hex_str,
            epoch,
            "sign_randao_reveal: success"
        );
        Ok(Response::new(SignResponseV2 { signature: sig }))
    }

    // ── SignAttestationData ───────────────────────────────────────────────────

    #[allow(clippy::result_large_err)]
    #[tracing::instrument(
        name = "rvc.signer.v2.sign_attestation_data",
        skip_all,
        fields(pubkey, source_epoch, target_epoch)
    )]
    async fn sign_attestation_data(
        &self,
        req: Request<SignAttestationDataRequest>,
    ) -> Result<Response<SignResponseV2>, Status> {
        let client_cn = audit::cn::extract_client_cn(&req);
        let r = req.into_inner();

        let pubkey_bytes = validate_pubkey(&r.pubkey)?;
        let pubkey_hex_str = pubkey_hex(&pubkey_bytes);
        Span::current().record("pubkey", pubkey_hex_str.as_str());

        let fork_info =
            r.fork_info.ok_or_else(|| Status::invalid_argument("fork_info required"))?;
        let current_version = validate_fork_version(&fork_info.current_version, "current_version")?;
        let gvr = validate_gvr(&fork_info.genesis_validators_root)?;

        // Decode AttestationData from proto message fields.
        // Per ISSUE-1.6b spec: the proto carries AttestationData as explicit fields.
        // EIP-7549 index-zeroing is the client's responsibility (H-2 / Phase 2).
        let proto_data =
            r.data.ok_or_else(|| Status::invalid_argument("attestation data required"))?;
        let proto_source = proto_data
            .source
            .ok_or_else(|| Status::invalid_argument("source checkpoint required"))?;
        let proto_target = proto_data
            .target
            .ok_or_else(|| Status::invalid_argument("target checkpoint required"))?;

        let source_root: [u8; 32] = proto_source.root.as_slice().try_into().map_err(|_| {
            Status::invalid_argument(format!(
                "source.root must be 32 bytes, got {}",
                proto_source.root.len()
            ))
        })?;
        let target_root: [u8; 32] = proto_target.root.as_slice().try_into().map_err(|_| {
            Status::invalid_argument(format!(
                "target.root must be 32 bytes, got {}",
                proto_target.root.len()
            ))
        })?;
        let beacon_block_root: [u8; 32] =
            proto_data.beacon_block_root.as_slice().try_into().map_err(|_| {
                Status::invalid_argument(format!(
                    "beacon_block_root must be 32 bytes, got {}",
                    proto_data.beacon_block_root.len()
                ))
            })?;

        let source_epoch = proto_source.epoch;
        let target_epoch = proto_target.epoch;
        Span::current().record("source_epoch", source_epoch);
        Span::current().record("target_epoch", target_epoch);

        let att_data = AttestationData {
            slot: proto_data.slot,
            index: proto_data.index,
            beacon_block_root,
            source: Checkpoint { epoch: source_epoch, root: source_root },
            target: Checkpoint { epoch: target_epoch, root: target_root },
        };

        let domain = compute_domain(DOMAIN_BEACON_ATTESTER, current_version, gvr);
        let signing_root = compute_signing_root(&att_data, domain);

        let pubkey = pubkey_from_bytes(&pubkey_bytes)?;
        let gate = self.require_gate()?;
        let sig = gate
            .sign_attestation(&pubkey, source_epoch, target_epoch, signing_root, gvr, &client_cn)
            .await
            .map_err(gate_err_to_status)?;

        tracing::info!(
            pubkey = %pubkey_hex_str,
            source_epoch,
            target_epoch,
            client_cn = %client_cn,
            "sign_attestation_data: success"
        );
        Ok(Response::new(SignResponseV2 { signature: sig }))
    }

    // ── SignAggregateAndProof ─────────────────────────────────────────────────
    //
    // SS-2/SS-3 FIX (Issue 2.10a): the previous handler erroneously called
    // `stage_attestation` for the aggregate path.  Routing through
    // `gate.sign_aggregate_and_proof` removes that staging because aggregate
    // signing is NOT slashable by the Ethereum consensus spec.  The inner
    // attestation's slashing watermark was already committed by `sign_attestation`.

    #[allow(clippy::result_large_err)]
    #[tracing::instrument(
        name = "rvc.signer.v2.sign_aggregate_and_proof",
        skip_all,
        fields(pubkey, source_epoch, target_epoch)
    )]
    async fn sign_aggregate_and_proof(
        &self,
        req: Request<SignAggregateAndProofRequest>,
    ) -> Result<Response<SignResponseV2>, Status> {
        let client_cn = audit::cn::extract_client_cn(&req);
        let r = req.into_inner();

        let pubkey_bytes = validate_pubkey(&r.pubkey)?;
        let pubkey_hex_str = pubkey_hex(&pubkey_bytes);
        Span::current().record("pubkey", pubkey_hex_str.as_str());

        let fork_info =
            r.fork_info.ok_or_else(|| Status::invalid_argument("fork_info required"))?;
        let current_version = validate_fork_version(&fork_info.current_version, "current_version")?;
        let gvr = validate_gvr(&fork_info.genesis_validators_root)?;

        // Decode the inner Attestation from aggregate_ssz.
        let attestation = decode_attestation_ssz(&r.aggregate_ssz, r.fork_id).map_err(ssz_err)?;

        let source_epoch = attestation.data.source.epoch;
        let target_epoch = attestation.data.target.epoch;
        Span::current().record("source_epoch", source_epoch);
        Span::current().record("target_epoch", target_epoch);

        let selection_proof = validate_selection_proof(&r.selection_proof)?;
        let agg_and_proof = AggregateAndProof {
            aggregator_index: r.aggregator_index,
            aggregate: attestation,
            selection_proof,
        };

        let domain = compute_domain(DOMAIN_AGGREGATE_AND_PROOF, current_version, gvr);
        let signing_root = compute_signing_root(&agg_and_proof, domain);

        // SS-2/SS-3: route through gate.sign_aggregate_and_proof which is non-slashable.
        // No attestation staging occurs here.  Also works without a slashing DB
        // (--disable-slashing-protection) since aggregates are non-slashable.
        let sig = if let Some(gate) = &self.gate {
            let pubkey = pubkey_from_bytes(&pubkey_bytes)?;
            gate.sign_aggregate_and_proof(&pubkey, signing_root)
                .await
                .map_err(gate_err_to_status)?
        } else {
            sign_via_backend(self.backend.as_ref(), &signing_root, &pubkey_bytes).await?
        };

        tracing::info!(
            pubkey = %pubkey_hex_str,
            source_epoch,
            target_epoch,
            client_cn = %client_cn,
            "sign_aggregate_and_proof: success"
        );
        Ok(Response::new(SignResponseV2 { signature: sig }))
    }

    // ── SignSyncCommitteeMessage ──────────────────────────────────────────────

    /// Sign a sync committee message over `beacon_block_root`.
    ///
    /// Per FR-P0-3 / NFR-1: sync messages are **not slashable** — no staging.
    #[tracing::instrument(
        name = "rvc.signer.v2.sign_sync_committee_message",
        skip_all,
        fields(pubkey, slot)
    )]
    async fn sign_sync_committee_message(
        &self,
        req: Request<SignSyncCommitteeMessageRequest>,
    ) -> Result<Response<SignResponseV2>, Status> {
        let client_cn = audit::cn::extract_client_cn(&req);
        let r = req.into_inner();

        let pubkey_bytes = validate_pubkey(&r.pubkey)?;
        let pubkey_hex_str = pubkey_hex(&pubkey_bytes);
        Span::current().record("pubkey", pubkey_hex_str.as_str());

        let fork_info =
            r.fork_info.ok_or_else(|| Status::invalid_argument("fork_info required"))?;
        let current_version = validate_fork_version(&fork_info.current_version, "current_version")?;
        let gvr = validate_gvr(&fork_info.genesis_validators_root)?;

        let slot = r.slot;
        Span::current().record("slot", slot);

        let beacon_block_root: [u8; 32] =
            r.beacon_block_root.as_slice().try_into().map_err(|_| {
                Status::invalid_argument(format!(
                    "beacon_block_root must be 32 bytes, got {}",
                    r.beacon_block_root.len()
                ))
            })?;

        // Sync committee messages sign over beacon_block_root directly.
        // Domain: DOMAIN_SYNC_COMMITTEE (0x07000000).
        let domain = compute_domain(DOMAIN_SYNC_COMMITTEE, current_version, gvr);
        let signing_root = compute_signing_root(&beacon_block_root, domain);

        let sig = if let Some(gate) = &self.gate {
            let pubkey = pubkey_from_bytes(&pubkey_bytes)?;
            gate.sign_sync_committee_message(&pubkey, signing_root)
                .await
                .map_err(gate_err_to_status)?
        } else {
            sign_via_backend(self.backend.as_ref(), &signing_root, &pubkey_bytes).await?
        };

        tracing::info!(
            pubkey = %pubkey_hex_str,
            slot,
            client_cn = %client_cn,
            "sign_sync_committee_message: success"
        );
        Ok(Response::new(SignResponseV2 { signature: sig }))
    }

    // ── SignSyncAggregatorSelectionData ───────────────────────────────────────

    /// Sign a sync aggregator selection proof over `(slot, subcommittee_index)`.
    ///
    /// Per FR-P0-3 / NFR-1: not slashable — no staging.
    #[tracing::instrument(
        name = "rvc.signer.v2.sign_sync_aggregator_selection_data",
        skip_all,
        fields(pubkey, slot)
    )]
    async fn sign_sync_aggregator_selection_data(
        &self,
        req: Request<SignSyncAggregatorSelectionDataRequest>,
    ) -> Result<Response<SignResponseV2>, Status> {
        let client_cn = audit::cn::extract_client_cn(&req);
        let r = req.into_inner();

        let pubkey_bytes = validate_pubkey(&r.pubkey)?;
        let pubkey_hex_str = pubkey_hex(&pubkey_bytes);
        Span::current().record("pubkey", pubkey_hex_str.as_str());

        let fork_info =
            r.fork_info.ok_or_else(|| Status::invalid_argument("fork_info required"))?;
        let current_version = validate_fork_version(&fork_info.current_version, "current_version")?;
        let gvr = validate_gvr(&fork_info.genesis_validators_root)?;

        let slot = r.slot;
        Span::current().record("slot", slot);

        // Domain: DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF (0x08000000).
        // Message: SyncAggregatorSelectionData { slot, subcommittee_index }.
        let domain = compute_domain(DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF, current_version, gvr);
        let selection_data =
            SyncAggregatorSelectionData { slot, subcommittee_index: r.subcommittee_index };
        let signing_root = compute_signing_root(&selection_data, domain);

        let sig = if let Some(gate) = &self.gate {
            let pubkey = pubkey_from_bytes(&pubkey_bytes)?;
            gate.sign_selection_proof(&pubkey, signing_root).await.map_err(gate_err_to_status)?
        } else {
            sign_via_backend(self.backend.as_ref(), &signing_root, &pubkey_bytes).await?
        };

        tracing::info!(
            pubkey = %pubkey_hex_str,
            slot,
            subcommittee_index = r.subcommittee_index,
            client_cn = %client_cn,
            "sign_sync_aggregator_selection_data: success"
        );
        Ok(Response::new(SignResponseV2 { signature: sig }))
    }

    // ── SignContributionAndProof ───────────────────────────────────────────────

    /// Sign a `ContributionAndProof`.
    ///
    /// `contribution_ssz` is SSZ-encoded `SyncCommitteeContribution`; the server
    /// decodes it and wraps it in `ContributionAndProof { aggregator_index,
    /// contribution, selection_proof }` before signing.
    ///
    /// Per FR-P0-3 / NFR-1: not slashable — no staging.
    #[tracing::instrument(
        name = "rvc.signer.v2.sign_contribution_and_proof",
        skip_all,
        fields(pubkey, slot)
    )]
    async fn sign_contribution_and_proof(
        &self,
        req: Request<SignContributionAndProofRequest>,
    ) -> Result<Response<SignResponseV2>, Status> {
        let client_cn = audit::cn::extract_client_cn(&req);
        let r = req.into_inner();

        let pubkey_bytes = validate_pubkey(&r.pubkey)?;
        let pubkey_hex_str = pubkey_hex(&pubkey_bytes);
        Span::current().record("pubkey", pubkey_hex_str.as_str());

        let fork_info =
            r.fork_info.ok_or_else(|| Status::invalid_argument("fork_info required"))?;
        let current_version = validate_fork_version(&fork_info.current_version, "current_version")?;
        let gvr = validate_gvr(&fork_info.genesis_validators_root)?;

        let contribution = decode_sync_committee_contribution_ssz(&r.contribution_ssz, r.fork_id)
            .map_err(ssz_err)?;

        let slot = contribution.slot;
        Span::current().record("slot", slot);

        // The server does NOT verify the selection_proof BLS signature — it is
        // the client's responsibility — but its length is enforced (96 bytes).
        let selection_proof = validate_selection_proof(&r.selection_proof)?;
        let cap = ContributionAndProof {
            aggregator_index: r.aggregator_index,
            contribution,
            selection_proof,
        };

        // Domain: DOMAIN_CONTRIBUTION_AND_PROOF (0x09000000).
        let domain = compute_domain(DOMAIN_CONTRIBUTION_AND_PROOF, current_version, gvr);
        let signing_root = compute_signing_root(&cap, domain);

        let sig = if let Some(gate) = &self.gate {
            let pubkey = pubkey_from_bytes(&pubkey_bytes)?;
            gate.sign_contribution_and_proof(&pubkey, signing_root)
                .await
                .map_err(gate_err_to_status)?
        } else {
            sign_via_backend(self.backend.as_ref(), &signing_root, &pubkey_bytes).await?
        };

        tracing::info!(
            pubkey = %pubkey_hex_str,
            slot,
            aggregator_index = r.aggregator_index,
            client_cn = %client_cn,
            "sign_contribution_and_proof: success"
        );
        Ok(Response::new(SignResponseV2 { signature: sig }))
    }

    // ── SignBuilderRegistration ────────────────────────────────────────────────
    //
    // Per MEV-Boost spec (confirmed as correct by audit "False positive" note):
    // domain = DOMAIN_APPLICATION_BUILDER + GENESIS_FORK_VERSION + ZERO_HASH
    // These are **fixed** constants — NOT from ForkInfo.
    //
    // Not slashable — no stage/commit calls.
    #[tracing::instrument(
        name = "rvc.signer.v2.sign_builder_registration",
        skip_all,
        fields(pubkey)
    )]
    async fn sign_builder_registration(
        &self,
        req: Request<SignBuilderRegistrationRequest>,
    ) -> Result<Response<SignResponseV2>, Status> {
        let _client_cn = audit::cn::extract_client_cn(&req);
        let r = req.into_inner();

        let pubkey_bytes = validate_pubkey(&r.pubkey)?;
        let pubkey_hex_str = pubkey_hex(&pubkey_bytes);
        Span::current().record("pubkey", pubkey_hex_str.as_str());

        let fee_recipient: [u8; 20] = r.fee_recipient.as_slice().try_into().map_err(|_| {
            Status::invalid_argument(format!(
                "fee_recipient must be 20 bytes, got {}",
                r.fee_recipient.len()
            ))
        })?;

        let registration = ValidatorRegistrationV1 {
            fee_recipient,
            gas_limit: r.gas_limit,
            timestamp: r.timestamp,
            pubkey: pubkey_bytes,
        };

        // Per-network GENESIS_FORK_VERSION from the request; empty ⇒ mainnet
        // 0x00000000 (back-compat). ZERO_HASH=[0u8;32] for the genesis gvr.
        let genesis_fork_version: [u8; 4] = if r.genesis_fork_version.is_empty() {
            [0u8; 4]
        } else {
            r.genesis_fork_version.as_slice().try_into().map_err(|_| {
                Status::invalid_argument(format!(
                    "genesis_fork_version must be 4 bytes, got {}",
                    r.genesis_fork_version.len()
                ))
            })?
        };
        let zero_hash = [0u8; 32];
        let domain = compute_domain(DOMAIN_APPLICATION_BUILDER, genesis_fork_version, zero_hash);
        let signing_root = compute_signing_root(&registration, domain);

        let sig = if let Some(gate) = &self.gate {
            let pubkey = pubkey_from_bytes(&pubkey_bytes)?;
            gate.sign_builder_registration(&pubkey, signing_root)
                .await
                .map_err(gate_err_to_status)?
        } else {
            sign_via_backend(self.backend.as_ref(), &signing_root, &pubkey_bytes).await?
        };

        tracing::info!(
            pubkey = %pubkey_hex_str,
            "sign_builder_registration: success"
        );
        Ok(Response::new(SignResponseV2 { signature: sig }))
    }

    // ── SignVoluntaryExit ──────────────────────────────────────────────────────
    //
    // Domain: DOMAIN_VOLUNTARY_EXIT + fork_info.current_version + gvr.
    //
    // EIP-7044 caller responsibility: the caller MUST pass a `current_version`
    // that is already Capella-capped for any post-Capella exit.
    //
    // Not slashable — no stage/commit calls.
    #[tracing::instrument(
        name = "rvc.signer.v2.sign_voluntary_exit",
        skip_all,
        fields(pubkey, epoch, validator_index)
    )]
    async fn sign_voluntary_exit(
        &self,
        req: Request<SignVoluntaryExitRequest>,
    ) -> Result<Response<SignResponseV2>, Status> {
        let _client_cn = audit::cn::extract_client_cn(&req);
        let r = req.into_inner();

        let pubkey_bytes = validate_pubkey(&r.pubkey)?;
        let pubkey_hex_str = pubkey_hex(&pubkey_bytes);
        Span::current().record("pubkey", pubkey_hex_str.as_str());

        let fork_info =
            r.fork_info.ok_or_else(|| Status::invalid_argument("fork_info required"))?;
        let current_version = validate_fork_version(&fork_info.current_version, "current_version")?;
        let gvr = validate_gvr(&fork_info.genesis_validators_root)?;

        let epoch = r.epoch;
        let validator_index = r.validator_index;
        Span::current().record("epoch", epoch);
        Span::current().record("validator_index", validator_index);

        let exit = VoluntaryExit { epoch, validator_index };

        // Domain: DOMAIN_VOLUNTARY_EXIT + current_version (caller-capped per EIP-7044).
        let domain = compute_domain(DOMAIN_VOLUNTARY_EXIT, current_version, gvr);
        let signing_root = compute_signing_root(&exit, domain);

        let sig = if let Some(gate) = &self.gate {
            let pubkey = pubkey_from_bytes(&pubkey_bytes)?;
            gate.sign_voluntary_exit(&pubkey, signing_root).await.map_err(gate_err_to_status)?
        } else {
            sign_via_backend(self.backend.as_ref(), &signing_root, &pubkey_bytes).await?
        };

        tracing::info!(
            pubkey = %pubkey_hex_str,
            epoch,
            validator_index,
            "sign_voluntary_exit: success"
        );
        Ok(Response::new(SignResponseV2 { signature: sig }))
    }

    async fn list_public_keys(
        &self,
        _request: Request<ListPublicKeysRequestV2>,
    ) -> Result<Response<ListPublicKeysResponseV2>, Status> {
        let pubkeys = self.backend.public_keys().into_iter().map(|pk| pk.to_vec()).collect();
        Ok(Response::new(ListPublicKeysResponseV2 { pubkeys }))
    }

    async fn get_status(
        &self,
        _request: Request<GetStatusRequestV2>,
    ) -> Result<Response<GetStatusResponseV2>, Status> {
        let key_count = self.backend.public_keys().len() as u32;
        Ok(Response::new(GetStatusResponseV2 {
            ready: true,
            backend: self.backend_name.clone(),
            key_count,
        }))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::SigningBackendError;
    use async_trait::async_trait;
    use std::sync::Arc;

    #[test]
    fn test_validate_selection_proof_accepts_96_bytes() {
        let buf = [0u8; 96];
        let result = validate_selection_proof(&buf).expect("96 bytes should pass");
        assert_eq!(result.len(), 96);
    }

    #[test]
    fn test_validate_selection_proof_rejects_short() {
        let err = validate_selection_proof(&[0u8; 95]).expect_err("95 bytes must fail");
        assert!(err.message().contains("96 bytes"), "msg: {}", err.message());
        assert!(err.message().contains("95"));
    }

    #[test]
    fn test_validate_selection_proof_rejects_long() {
        let err = validate_selection_proof(&[0u8; 97]).expect_err("97 bytes must fail");
        assert!(err.message().contains("96 bytes"), "msg: {}", err.message());
    }

    #[test]
    fn test_validate_selection_proof_rejects_empty() {
        let err = validate_selection_proof(&[]).expect_err("empty must fail");
        assert!(err.message().contains("96 bytes"));
    }

    // ── Test backend — real BLS signing ──────────────────────────────────────
    //
    // The gate validates pubkeys as BLS points and reconstructs `Signature` from
    // the backend's raw [u8; 96] output.  `MockBackend` must therefore:
    // (a) store real `SecretKey` instances, not arbitrary [u8; 48] values; and
    // (b) produce valid BLS signatures so that `Signature::from_bytes` succeeds.
    //
    // `test_pubkey()` generates a deterministic BLS keypair for unit tests.

    use crypto::{KeyManager, SecretKey};

    /// Generate a deterministic BLS `SecretKey` / pubkey pair for unit tests.
    fn test_secret_key() -> SecretKey {
        use crypto::eip2333::derive_master_sk;
        let seed = [0x11u8; 32];
        derive_master_sk(&seed).expect("derive master sk")
    }

    /// Return the raw 48-byte pubkey for `test_secret_key()`.
    fn test_pubkey_bytes() -> [u8; 48] {
        test_secret_key().public_key().to_bytes()
    }

    struct MockBackend {
        km: Arc<KeyManager>,
    }

    impl MockBackend {
        /// Create a backend pre-loaded with `test_secret_key()`.
        fn with_test_key() -> Self {
            let sk = test_secret_key();
            let mut km = KeyManager::new();
            km.insert(sk);
            Self { km: Arc::new(km) }
        }

        /// Create a backend with no keys.
        fn empty() -> Self {
            Self { km: Arc::new(KeyManager::new()) }
        }
    }

    #[async_trait]
    impl SigningBackend for MockBackend {
        async fn sign(
            &self,
            signing_root: &[u8; 32],
            pubkey: &[u8; 48],
        ) -> Result<[u8; 96], SigningBackendError> {
            let pk = crypto::PublicKey::from_bytes(pubkey)
                .map_err(|_| SigningBackendError::KeyNotFound(*pubkey))?;
            let sk =
                self.km.get_secret_key(&pk).ok_or(SigningBackendError::KeyNotFound(*pubkey))?;
            Ok(sk.sign(signing_root).to_bytes())
        }

        fn public_keys(&self) -> Vec<[u8; 48]> {
            self.km.list_public_keys().iter().map(|pk| pk.to_bytes()).collect()
        }
    }

    fn make_service(backend: MockBackend) -> SignerServiceImpl {
        SignerServiceImpl::new(Arc::new(backend), "basic".to_string())
    }

    fn make_service_v2(backend: MockBackend) -> SignerServiceImpl {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let db = Arc::new(slashing::SlashingDb::open(tmp.path()).unwrap());
        // Keep temp file alive by leaking it
        std::mem::forget(tmp);
        SignerServiceImpl::new_v2(Arc::new(backend), "basic".to_string(), db)
    }

    fn sample_block_ssz(slot: u64) -> Vec<u8> {
        use eth_types::{encode_beacon_block_ssz, BeaconBlock};
        let block = BeaconBlock {
            slot,
            proposer_index: 1,
            parent_root: [0x11; 32],
            state_root: [0x22; 32],
            body: vec![0xde, 0xad],
        };
        encode_beacon_block_ssz(&block, 4)
    }

    fn sample_fork_info() -> crate::proto::signer_v2::ForkInfo {
        crate::proto::signer_v2::ForkInfo {
            previous_version: vec![0x04, 0x00, 0x00, 0x00],
            current_version: vec![0x04, 0x00, 0x00, 0x00],
            epoch: 0,
            genesis_validators_root: vec![0x00; 32],
        }
    }

    // --- V1 tests — updated for SS-1 fix (Issue 2.2) ---
    // All v1 methods return Unimplemented immediately; they never reach the gate.
    // These tests use arbitrary byte arrays as "pubkeys" — v1 returns before any
    // BLS validation so any 48-byte value is fine.

    #[tokio::test]
    async fn test_sign_returns_unimplemented() {
        // V1 sign method returns Unimplemented before any pubkey validation.
        let pubkey_bytes = test_pubkey_bytes();
        let svc = make_service(MockBackend::with_test_key());

        let req = Request::new(SignRequest {
            signing_root: vec![0u8; 32],
            pubkey: pubkey_bytes.to_vec(),
        });
        let err = svc.sign(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unimplemented);
    }

    #[tokio::test]
    async fn test_sign_unknown_key_returns_unimplemented() {
        let svc = make_service(MockBackend::with_test_key());
        // V1 sign returns Unimplemented even for unknown keys.
        let req = Request::new(SignRequest { signing_root: vec![0u8; 32], pubkey: vec![2u8; 48] });
        let err = svc.sign(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unimplemented);
    }

    #[tokio::test]
    async fn test_sign_invalid_signing_root_returns_unimplemented() {
        let svc = make_service(MockBackend::empty());
        let req = Request::new(SignRequest { signing_root: vec![0u8; 16], pubkey: vec![1u8; 48] });
        let err = svc.sign(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unimplemented);
    }

    #[tokio::test]
    async fn test_sign_invalid_pubkey_returns_unimplemented() {
        let svc = make_service(MockBackend::empty());
        let req = Request::new(SignRequest { signing_root: vec![0u8; 32], pubkey: vec![1u8; 32] });
        let err = svc.sign(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unimplemented);
    }

    // --- V2 tests ---
    // These tests use `test_pubkey_bytes()` / `MockBackend::with_test_key()` so
    // the gate's BLS pubkey validation and `Signature::from_bytes` succeed.

    #[tokio::test]
    async fn test_v2_sign_beacon_block_happy_path() {
        let pubkey = test_pubkey_bytes();
        let svc = make_service_v2(MockBackend::with_test_key());

        let req = Request::new(SignBeaconBlockRequest {
            pubkey: pubkey.to_vec(),
            fork_info: Some(sample_fork_info()),
            block_ssz: sample_block_ssz(42),
            fork_id: 4,
        });
        let resp = svc.sign_beacon_block(req).await.unwrap();
        assert_eq!(resp.into_inner().signature.len(), 96);
    }

    #[tokio::test]
    async fn test_v2_sign_beacon_block_missing_fork_info() {
        let pubkey = test_pubkey_bytes();
        let svc = make_service_v2(MockBackend::with_test_key());

        let req = Request::new(SignBeaconBlockRequest {
            pubkey: pubkey.to_vec(),
            fork_info: None,
            block_ssz: sample_block_ssz(42),
            fork_id: 4,
        });
        let err = svc.sign_beacon_block(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn test_v2_sign_beacon_block_bad_pubkey_length() {
        let svc = make_service_v2(MockBackend::empty());

        let req = Request::new(SignBeaconBlockRequest {
            pubkey: vec![1u8; 32], // wrong length — caught before BLS validation
            fork_info: Some(sample_fork_info()),
            block_ssz: sample_block_ssz(42),
            fork_id: 4,
        });
        let err = svc.sign_beacon_block(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn test_v2_sign_beacon_block_unknown_key_returns_not_found() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let db_path = tmp.path().to_path_buf();
        let db = Arc::new(slashing::SlashingDb::open(&db_path).unwrap());
        std::mem::forget(tmp);
        // Empty backend: sign will fail with KeyNotFound.
        let svc = SignerServiceImpl::new_v2(
            Arc::new(MockBackend::empty()),
            "basic".to_string(),
            Arc::clone(&db),
        );

        // Use a valid BLS pubkey so it passes gate validation.
        let pubkey = test_pubkey_bytes();
        let req = Request::new(SignBeaconBlockRequest {
            pubkey: pubkey.to_vec(),
            fork_info: Some(sample_fork_info()),
            block_ssz: sample_block_ssz(42),
            fork_id: 4,
        });
        let err = svc.sign_beacon_block(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);

        // Critical: signer failure must NOT leave a phantom row (M-1 fix, A15).
        let pubkey_hex = format!("0x{}", hex::encode(pubkey));
        let blocks = db.get_blocks(&pubkey_hex).expect("get_blocks");
        assert!(
            blocks.is_empty(),
            "signer failure must not commit a slashing row (stage→sign→commit A15)"
        );
    }

    #[tokio::test]
    async fn test_v2_sign_beacon_block_double_proposal_rejected() {
        let pubkey = test_pubkey_bytes();
        let svc = make_service_v2(MockBackend::with_test_key());

        // First sign
        let req1 = Request::new(SignBeaconBlockRequest {
            pubkey: pubkey.to_vec(),
            fork_info: Some(sample_fork_info()),
            block_ssz: sample_block_ssz(100),
            fork_id: 4,
        });
        svc.sign_beacon_block(req1).await.unwrap();

        // Second sign — different block body → different signing root
        let mut different_ssz = sample_block_ssz(100);
        for b in &mut different_ssz[16..48] {
            *b ^= 0xFF;
        }
        let req2 = Request::new(SignBeaconBlockRequest {
            pubkey: pubkey.to_vec(),
            fork_info: Some(sample_fork_info()),
            block_ssz: different_ssz,
            fork_id: 4,
        });
        let err = svc.sign_beacon_block(req2).await.unwrap_err();
        assert!(
            err.code() == tonic::Code::FailedPrecondition || err.code() == tonic::Code::Aborted,
            "expected slashing rejection, got {:?}",
            err.code()
        );
    }

    #[tokio::test]
    async fn test_v2_sign_randao_reveal_happy_path() {
        let pubkey = test_pubkey_bytes();
        let svc = make_service_v2(MockBackend::with_test_key());

        let req = Request::new(SignRandaoRevealRequest {
            pubkey: pubkey.to_vec(),
            fork_info: Some(sample_fork_info()),
            epoch: 10,
            fork_id: 4,
        });
        let resp = svc.sign_randao_reveal(req).await.unwrap();
        assert_eq!(resp.into_inner().signature.len(), 96);
    }

    #[tokio::test]
    async fn test_v2_sign_randao_same_epoch_twice_both_succeed() {
        let pubkey = test_pubkey_bytes();
        let svc = make_service_v2(MockBackend::with_test_key());

        for _ in 0..2 {
            let req = Request::new(SignRandaoRevealRequest {
                pubkey: pubkey.to_vec(),
                fork_info: Some(sample_fork_info()),
                epoch: 50,
                fork_id: 4,
            });
            svc.sign_randao_reveal(req).await.unwrap();
        }
    }

    #[tokio::test]
    async fn test_v2_sign_blinded_beacon_block_happy_path() {
        use eth_types::{encode_blinded_beacon_block_ssz, BlindedBeaconBlock};
        let pubkey = test_pubkey_bytes();
        let svc = make_service_v2(MockBackend::with_test_key());

        let blinded = BlindedBeaconBlock {
            slot: 200,
            proposer_index: 1,
            parent_root: [0x33; 32],
            state_root: [0x44; 32],
            body: vec![0xca, 0xfe],
        };
        let ssz = encode_blinded_beacon_block_ssz(&blinded, 4);

        let req = Request::new(SignBlindedBeaconBlockRequest {
            pubkey: pubkey.to_vec(),
            fork_info: Some(sample_fork_info()),
            block_ssz: ssz,
            fork_id: 4,
        });
        let resp = svc.sign_blinded_beacon_block(req).await.unwrap();
        assert_eq!(resp.into_inner().signature.len(), 96);
    }

    #[tokio::test]
    async fn test_v2_sign_beacon_block_no_db_returns_internal() {
        // No gate (no DB): gate validation returns Internal before BLS validation.
        let pubkey = test_pubkey_bytes();
        let svc = make_service(MockBackend::with_test_key()); // no DB, no gate

        let req = Request::new(SignBeaconBlockRequest {
            pubkey: pubkey.to_vec(),
            fork_info: Some(sample_fork_info()),
            block_ssz: sample_block_ssz(42),
            fork_id: 4,
        });
        let err = svc.sign_beacon_block(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::Internal);
    }

    // --- BUG-001 regression: non-slashable ops work without a slashing DB ---

    /// BUG-001 regression: `sign_randao_reveal` (a non-slashable operation) on a
    /// service with no slashing DB (`SignerServiceImpl::new`, i.e.
    /// `--disable-slashing-protection` mode) must return a 96-byte signature, NOT
    /// `Internal`.  Pre-fix, every non-slashable handler called `require_gate()?`
    /// which returned `Internal` when `gate.is_none()`.
    #[tokio::test]
    async fn test_v2_sign_randao_no_db_returns_signature() {
        let pubkey = test_pubkey_bytes();
        // `make_service` uses `SignerServiceImpl::new` — no DB, no gate.
        let svc = make_service(MockBackend::with_test_key());

        let req = Request::new(SignRandaoRevealRequest {
            pubkey: pubkey.to_vec(),
            fork_info: Some(sample_fork_info()),
            epoch: 5,
            fork_id: 4,
        });
        // Must succeed: RANDAO is non-slashable and must not require the DB.
        let resp = svc
            .sign_randao_reveal(req)
            .await
            .expect("sign_randao_reveal without a slashing DB must succeed (BUG-001 regression)");
        assert_eq!(
            resp.into_inner().signature.len(),
            96,
            "expected 96-byte BLS signature, got wrong length"
        );
    }

    /// Companion to BUG-001: slashable ops (sign_beacon_block) still fail closed
    /// without a DB — the fail-closed invariant must not be disturbed.
    #[tokio::test]
    async fn test_v2_sign_beacon_block_still_fails_closed_without_db() {
        let pubkey = test_pubkey_bytes();
        let svc = make_service(MockBackend::with_test_key()); // no DB

        let req = Request::new(SignBeaconBlockRequest {
            pubkey: pubkey.to_vec(),
            fork_info: Some(sample_fork_info()),
            block_ssz: sample_block_ssz(42),
            fork_id: 4,
        });
        let err = svc.sign_beacon_block(req).await.unwrap_err();
        assert_eq!(
            err.code(),
            tonic::Code::Internal,
            "slashable op without DB must return Internal (fail-closed)"
        );
    }

    // --- ListPublicKeys / GetStatus v2 ---

    #[tokio::test]
    async fn test_v2_list_public_keys() {
        // Use one real key for the backend (list_public_keys doesn't require valid BLS).
        let svc = make_service_v2(MockBackend::with_test_key());

        let resp =
            SignerServiceV2::list_public_keys(&svc, Request::new(ListPublicKeysRequestV2 {}))
                .await
                .unwrap();
        let pubkeys = resp.into_inner().pubkeys;
        assert_eq!(pubkeys.len(), 1);
    }

    #[tokio::test]
    async fn test_v2_get_status() {
        let svc = make_service_v2(MockBackend::with_test_key());

        let resp =
            SignerServiceV2::get_status(&svc, Request::new(GetStatusRequestV2 {})).await.unwrap();
        let status = resp.into_inner();
        assert!(status.ready);
        assert_eq!(status.key_count, 1);
    }

    // --- Metrics (v1) — updated for SS-1 fix (Issue 2.2) ---

    fn make_service_with_metrics(backend: MockBackend) -> (SignerServiceImpl, Arc<SignerMetrics>) {
        let metrics = Arc::new(SignerMetrics::new());
        let svc = SignerServiceImpl::new(Arc::new(backend), "basic".to_string())
            .with_metrics(Arc::clone(&metrics));
        (svc, metrics)
    }

    #[tokio::test]
    async fn test_v1_sign_returns_unimplemented_no_counter_increment() {
        let pubkey = test_pubkey_bytes();
        let (svc, metrics) = make_service_with_metrics(MockBackend::with_test_key());

        let req =
            Request::new(SignRequest { signing_root: vec![0u8; 32], pubkey: pubkey.to_vec() });
        let err = svc.sign(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unimplemented);
        assert_eq!(metrics.sign_total.with_label_values(&["basic", "success"]).get(), 0);
    }

    #[tokio::test]
    async fn test_v1_sign_error_returns_unimplemented_no_error_counter() {
        let (svc, metrics) = make_service_with_metrics(MockBackend::with_test_key());

        let req = Request::new(SignRequest { signing_root: vec![0u8; 32], pubkey: vec![2u8; 48] });
        let err = svc.sign(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unimplemented);
        assert_eq!(metrics.sign_total.with_label_values(&["basic", "error"]).get(), 0);
        assert_eq!(
            metrics.sign_errors_total.with_label_values(&["basic", "key_not_found"]).get(),
            0
        );
    }
}
