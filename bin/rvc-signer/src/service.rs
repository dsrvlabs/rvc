//! gRPC signer service implementation.
//!
//! # V1 service (`SignerService` from `signer.proto`)
//! The v1 raw-root `sign(signing_root, pubkey)` RPC is **deprecated** and kept
//! alive until ISSUE-1.8 deletes the v1 client path.  Do not add new features
//! to the v1 handler.
//!
//! # V2 service (`SignerService` from `signer.v2.proto`)
//! Typed RPCs for `SignBeaconBlock`, `SignBlindedBeaconBlock`, and
//! `SignRandaoReveal` are implemented here (ISSUE-1.6a).  The remaining 7
//! typed RPCs land in ISSUE-1.6b–d.
//!
//! # Lock-vs-await strategy
//!
//! `StagedBlock<'_>` / `StagedAttestation<'_>` hold a `parking_lot::MutexGuard`
//! (`!Send`) over the SQLite connection.  They **cannot** be held across an
//! `.await` boundary in a multi-threaded tokio runtime.
//!
//! Resolution chosen: **split the locking window** — the slashing check and
//! commit are done in two *separate* synchronous sections, with the async
//! backend sign call in between.  Concretely:
//!
//! 1. Validate + compute signing root (synchronous, no lock needed).
//! 2. `stage_block(...)` — acquires the DB mutex, runs the EIP-3076 check,
//!    leaves the transaction open.  We immediately call `commit()` in the same
//!    synchronous section and pass the pre-computed signing root as proof.
//!    Wait — that loses the "commit only on signer success" guarantee.
//!
//! Actually: we restructure around the fact that `parking_lot::MutexGuard`
//! is `!Send` but the guard can be held for the *entire* sync sub-task.  We use
//! `tokio::task::spawn_blocking` to run stage+sign+commit on a dedicated blocking
//! thread where `.await` is not needed.  The backend `sign` call on `BasicSigner`
//! is already synchronous under the hood (`BLS::sign` is CPU-bound, sub-ms),
//! so wrapping it in `spawn_blocking` is sound.
//!
//! Strategy: `spawn_blocking(|| { stage → sign_sync → commit })`.
//! `BasicSigner` exposes a sync `sign_sync` path; for the async `SigningBackend`
//! trait we instead pass the pre-computed signing root and pubkey into
//! `spawn_blocking`, acquire the DB lock, run the violation check, call
//! `backend.sign_sync()` if available, otherwise use a channel to hand the
//! result back out.
//!
//! **Simpler alternative chosen**: We break the atomic "stage → sign → commit"
//! into a "check + reserve" step followed by a sign then a "finalize" step:
//!
//! 1. `stage_block(slot, root)` — acquire lock, check violations, **commit** the
//!    row immediately (conservative: behaves like the old `check_and_record`).
//! 2. `backend.sign(root, pubkey).await`.
//! 3. On sign success → return sig.  On sign failure → **delete the row** that
//!    was just committed (compensating action).
//!
//! This preserves the safety invariant (only signed roots survive in DB) while
//! keeping the async sign call outside the mutex window.  The trade-off vs the
//! RAII guard design: there is a tiny window between commit and the compensating
//! delete where a signer crash would leave a phantom row.  This is equivalent to
//! the pre-A15 behavior and is acceptable for ISSUE-1.6a; the pure RAII approach
//! (spawn_blocking with sync sign) can replace it in a future ISSUE when
//! `BasicSigner` gains a sync trait.
//!
//! **Update — actual implementation**: after reading `stage.rs` more carefully,
//! `StagedBlock` holds a `MutexGuard` but does NOT implement `Send`.  However,
//! `spawn_blocking` requires `Send`.  So the split approach above is used:
//! the stage guard is acquired and committed/discarded before the `.await` on
//! sign.
//!
//! FINAL strategy:
//! - `stage_block` → if OK, immediately consume the guard via `commit()` (row
//!   committed) before the `.await`.
//! - `backend.sign(...).await`.
//! - If sign fails → we cannot un-commit, BUT we can log a warning.  The row is
//!   still safe (it records the intent to sign slot N; re-signing slot N with the
//!   same root is idempotent; re-signing with a different root is caught by the
//!   double-proposal check which is correct behavior).
//!
//! This is the **safe conservative** approach: over-protective (phantom rows on
//! signer failure) rather than under-protective (unsigned rows in DB).  The
//! pure RAII approach that avoids phantom rows entirely requires a sync sign path
//! and is deferred to a follow-up issue.

use std::sync::Arc;
use std::time::Instant;

use tonic::{Request, Response, Status};
use tracing::Span;

use crate::audit;
use crate::backend::SigningBackend;
use crate::metrics::SignerMetrics;
use crate::slashing::ScopedSlashingDb;

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

use crypto::{compute_domain, compute_signing_root, DOMAIN_BEACON_PROPOSER, DOMAIN_RANDAO};
use eth_types::{decode_beacon_block_ssz, decode_blinded_beacon_block_ssz, SszDecodeError};
use slashing::SlashingDb;

// ─────────���───────────────────────────────────────────────────────────────────
// SignerServiceImpl
// ─────────────────────────────────────────────────────────────────────────────

pub struct SignerServiceImpl {
    backend: Arc<dyn SigningBackend>,
    backend_name: String,
    metrics: Option<Arc<SignerMetrics>>,
    /// Slashing DB — `None` when `--disable-slashing-protection` is active.
    slashing_db: Option<Arc<SlashingDb>>,
}

impl SignerServiceImpl {
    /// Create a v1-only service (no slashing DB).
    ///
    /// **Deprecated**: new callers should use `new_v2`.
    pub fn new(backend: Arc<dyn SigningBackend>, backend_name: String) -> Self {
        Self { backend, backend_name, metrics: None, slashing_db: None }
    }

    /// Create a v2-capable service with an embedded slashing DB.
    pub fn new_v2(
        backend: Arc<dyn SigningBackend>,
        backend_name: String,
        slashing_db: Arc<SlashingDb>,
    ) -> Self {
        Self { backend, backend_name, metrics: None, slashing_db: Some(slashing_db) }
    }

    pub fn with_metrics(mut self, metrics: Arc<SignerMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Borrow the slashing DB or return an `internal` status if it's missing.
    #[allow(clippy::result_large_err)]
    fn require_db(&self) -> Result<&Arc<SlashingDb>, Status> {
        self.slashing_db.as_ref().ok_or_else(|| {
            Status::internal(
                "slashing protection database is not configured; \
                 restart with a valid --data-dir or --disable-slashing-protection + \
                 RVC_ALLOW_INSECURE=true",
            )
        })
    }
}

// ──────────���──────────────────────────────────────────────────────────────���───
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

/// Convert a `SszDecodeError` to a gRPC `Status::invalid_argument`.
fn ssz_err(e: SszDecodeError) -> Status {
    Status::invalid_argument(format!("SSZ decode error: {e}"))
}

/// Convert a slashing error to a gRPC status.
fn slashing_err(e: slashing::SlashingError) -> Status {
    use slashing::SlashingError;
    match e {
        SlashingError::SlashableBlock(_) | SlashingError::SlashableAttestation(_) => {
            Status::failed_precondition(format!("slashing protection violation: {e}"))
        }
        _ => Status::failed_precondition(format!("slashing check failed: {e}")),
    }
}

/// Encode a pubkey as `0x<hex>` for use in audit logs and DB lookups.
fn pubkey_hex(pubkey: &[u8; 48]) -> String {
    format!("0x{}", hex::encode(pubkey))
}

/// Encode a 32-byte root as `0x<hex>`.
fn root_hex(root: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(root))
}

// ────────────���────────────────────────���───────────────────────────────────────
// V1 SignerService impl (DEPRECATED — kept until ISSUE-1.8)
// ────────────────────────────────────────────���────────────────────────────────

#[tonic::async_trait]
impl SignerService for SignerServiceImpl {
    #[tracing::instrument(name = "rvc.signer.sign", skip_all, fields(pubkey))]
    async fn sign(&self, request: Request<SignRequest>) -> Result<Response<SignResponse>, Status> {
        let client_cn = audit::extract_client_cn(&request);
        let req = request.into_inner();

        if req.signing_root.len() != 32 {
            return Err(Status::invalid_argument(format!(
                "signing_root must be 32 bytes, got {}",
                req.signing_root.len()
            )));
        }

        if req.pubkey.len() != 48 {
            return Err(Status::invalid_argument(format!(
                "pubkey must be 48 bytes, got {}",
                req.pubkey.len()
            )));
        }

        let pubkey_hex_str = format!("0x{}", hex::encode(&req.pubkey));
        Span::current().record("pubkey", pubkey_hex_str.as_str());

        let signing_root: [u8; 32] = req.signing_root.try_into().expect("length already validated");
        let pubkey: [u8; 48] = req.pubkey.try_into().expect("length already validated");

        let start = Instant::now();
        let result = self.backend.sign(&signing_root, &pubkey).await;
        let elapsed = start.elapsed();

        if let Some(ref m) = self.metrics {
            m.sign_duration_seconds
                .with_label_values(&[&self.backend_name])
                .observe(elapsed.as_secs_f64());
        }

        let (grpc_result, audit_result) = match result {
            Ok(signature) => {
                if let Some(ref m) = self.metrics {
                    m.sign_total.with_label_values(&[self.backend_name.as_str(), "success"]).inc();
                }
                (
                    Ok(Response::new(SignResponse { signature: signature.to_vec() })),
                    "success".to_string(),
                )
            }
            Err(ref e) => {
                if let Some(ref m) = self.metrics {
                    m.sign_total.with_label_values(&[self.backend_name.as_str(), "error"]).inc();
                    let error_type = crate::metrics::classify_error(e);
                    m.sign_errors_total
                        .with_label_values(&[self.backend_name.as_str(), error_type])
                        .inc();
                }
                let (status, audit_result) = match e {
                    crate::backend::SigningBackendError::KeyNotFound(_) => {
                        (Status::not_found("unknown public key"), "key_not_found".to_string())
                    }
                    _ => {
                        tracing::error!(error = %e, "signing backend error");
                        (Status::internal("internal signing error"), "error".to_string())
                    }
                };
                (Err(status), audit_result)
            }
        };

        audit::log_audit(&audit::AuditEntry {
            timestamp: audit::now_rfc3339(),
            pubkey_hex: pubkey_hex_str,
            client_cn,
            backend: self.backend_name.clone(),
            result: audit_result,
            duration_ms: elapsed.as_millis() as u64,
            rpc: Some("sign".to_string()),
        });

        grpc_result
    }

    async fn list_public_keys(
        &self,
        _request: Request<ListPublicKeysRequest>,
    ) -> Result<Response<ListPublicKeysResponse>, Status> {
        let pubkeys = self.backend.public_keys().into_iter().map(|pk| pk.to_vec()).collect();
        Ok(Response::new(ListPublicKeysResponse { pubkeys }))
    }

    async fn get_status(
        &self,
        _request: Request<GetStatusRequest>,
    ) -> Result<Response<GetStatusResponse>, Status> {
        let key_count = self.backend.public_keys().len() as u32;
        Ok(Response::new(GetStatusResponse {
            ready: true,
            backend: self.backend_name.clone(),
            key_count,
        }))
    }
}

// ───────────────────────────────────────���─────────────────────────────��───────
// V2 SignerService impl
// ────────────────────────────────────────────────────��────────────────────────

#[tonic::async_trait]
impl SignerServiceV2 for SignerServiceImpl {
    // ── SignBeaconBlock ───────────────���───────────────────────────────────────

    #[tracing::instrument(name = "rvc.signer.v2.sign_beacon_block", skip_all, fields(pubkey, slot))]
    async fn sign_beacon_block(
        &self,
        req: Request<SignBeaconBlockRequest>,
    ) -> Result<Response<SignResponseV2>, Status> {
        let client_cn = audit::cn::extract_client_cn(&req);
        let r = req.into_inner();

        let pubkey = validate_pubkey(&r.pubkey)?;
        let pubkey_hex_str = pubkey_hex(&pubkey);
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
        let signing_root_hex = Some(root_hex(&signing_root));

        let db = self.require_db()?;
        let scoped = ScopedSlashingDb::new(Arc::clone(db), client_cn.clone(), gvr);

        // Stage the block — acquires the DB mutex, runs EIP-3076 check.
        // IMPORTANT: commit() is called immediately here (before the .await below)
        // because StagedBlock holds a parking_lot::MutexGuard which is !Send and
        // cannot be held across an .await in a multi-threaded tokio runtime.
        //
        // Trade-off: this is the "safe conservative" approach — the row is committed
        // before the sign, so a signer failure leaves a committed row (same behavior
        // as the pre-A15 check_and_record flow). The row is still safe: re-signing
        // the same (pubkey, slot, signing_root) is idempotent; re-signing with a
        // different root for the same slot is caught by the double-proposal check.
        // The pure RAII approach (stage → sign_sync → commit) requires a sync sign
        // path and is deferred to a future issue.
        {
            let staged = scoped
                .stage_block(&pubkey_hex_str, slot, signing_root_hex)
                .map_err(slashing_err)?;
            staged
                .commit()
                .map_err(|e| Status::internal(format!("slashing DB commit failed: {e}")))?;
        } // MutexGuard released here before .await

        // Sign the block (async, after releasing the DB mutex).
        let sign_result = self.backend.sign(&signing_root, &pubkey).await;

        match sign_result {
            Ok(sig) => {
                tracing::info!(
                    pubkey = %pubkey_hex_str,
                    slot,
                    client_cn = %client_cn,
                    "sign_beacon_block: success"
                );
                Ok(Response::new(SignResponseV2 { signature: sig.to_vec() }))
            }
            Err(e) => {
                tracing::warn!(
                    pubkey = %pubkey_hex_str,
                    slot,
                    client_cn = %client_cn,
                    error = %e,
                    "sign_beacon_block: backend error (slashing row already committed)"
                );
                Err(backend_err_to_status(e))
            }
        }
    }

    // ── SignBlindedBeaconBlock ───────────────────────────────��────────────────

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

        let pubkey = validate_pubkey(&r.pubkey)?;
        let pubkey_hex_str = pubkey_hex(&pubkey);
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
        let signing_root_hex = Some(root_hex(&signing_root));

        let db = self.require_db()?;
        let scoped = ScopedSlashingDb::new(Arc::clone(db), client_cn.clone(), gvr);

        // Same conservative commit-before-sign pattern as sign_beacon_block.
        // See the design note there for the rationale.
        {
            let staged = scoped
                .stage_block(&pubkey_hex_str, slot, signing_root_hex)
                .map_err(slashing_err)?;
            staged
                .commit()
                .map_err(|e| Status::internal(format!("slashing DB commit failed: {e}")))?;
        }

        let sign_result = self.backend.sign(&signing_root, &pubkey).await;

        match sign_result {
            Ok(sig) => {
                tracing::info!(
                    pubkey = %pubkey_hex_str,
                    slot,
                    client_cn = %client_cn,
                    "sign_blinded_beacon_block: success"
                );
                Ok(Response::new(SignResponseV2 { signature: sig.to_vec() }))
            }
            Err(e) => {
                tracing::warn!(
                    pubkey = %pubkey_hex_str,
                    slot,
                    client_cn = %client_cn,
                    error = %e,
                    "sign_blinded_beacon_block: backend error (slashing row already committed)"
                );
                Err(backend_err_to_status(e))
            }
        }
    }

    // ── SignRandaoReveal ──────────────────────���───────────────────────────────

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

        let pubkey = validate_pubkey(&r.pubkey)?;
        let pubkey_hex_str = pubkey_hex(&pubkey);
        Span::current().record("pubkey", pubkey_hex_str.as_str());

        let fork_info =
            r.fork_info.ok_or_else(|| Status::invalid_argument("fork_info required"))?;
        let current_version = validate_fork_version(&fork_info.current_version, "current_version")?;
        let gvr = validate_gvr(&fork_info.genesis_validators_root)?;

        let epoch = r.epoch;
        Span::current().record("epoch", epoch);

        // Per FR-P0-3: RANDAO is not slashable — no stage_block call.
        let domain = compute_domain(DOMAIN_RANDAO, current_version, gvr);
        let signing_root = compute_signing_root(&epoch, domain);

        let sign_result = self.backend.sign(&signing_root, &pubkey).await;

        match sign_result {
            Ok(sig) => {
                tracing::info!(
                    pubkey = %pubkey_hex_str,
                    epoch,
                    "sign_randao_reveal: success"
                );
                Ok(Response::new(SignResponseV2 { signature: sig.to_vec() }))
            }
            Err(e) => {
                tracing::warn!(
                    pubkey = %pubkey_hex_str,
                    epoch,
                    error = %e,
                    "sign_randao_reveal: backend error"
                );
                Err(backend_err_to_status(e))
            }
        }
    }

    // ── Remaining typed RPCs (1.6b / 1.6c / 1.6d) — placeholder stubs ────────
    //
    // These return `Status::unimplemented` until the corresponding issues land.
    // They MUST be present to satisfy the generated trait.

    async fn sign_attestation_data(
        &self,
        _req: Request<SignAttestationDataRequest>,
    ) -> Result<Response<SignResponseV2>, Status> {
        Err(Status::unimplemented("sign_attestation_data: not yet implemented (ISSUE-1.6b)"))
    }

    async fn sign_aggregate_and_proof(
        &self,
        _req: Request<SignAggregateAndProofRequest>,
    ) -> Result<Response<SignResponseV2>, Status> {
        Err(Status::unimplemented("sign_aggregate_and_proof: not yet implemented (ISSUE-1.6b)"))
    }

    async fn sign_sync_committee_message(
        &self,
        _req: Request<SignSyncCommitteeMessageRequest>,
    ) -> Result<Response<SignResponseV2>, Status> {
        Err(Status::unimplemented("sign_sync_committee_message: not yet implemented (ISSUE-1.6c)"))
    }

    async fn sign_sync_aggregator_selection_data(
        &self,
        _req: Request<SignSyncAggregatorSelectionDataRequest>,
    ) -> Result<Response<SignResponseV2>, Status> {
        Err(Status::unimplemented(
            "sign_sync_aggregator_selection_data: not yet implemented (ISSUE-1.6c)",
        ))
    }

    async fn sign_contribution_and_proof(
        &self,
        _req: Request<SignContributionAndProofRequest>,
    ) -> Result<Response<SignResponseV2>, Status> {
        Err(Status::unimplemented("sign_contribution_and_proof: not yet implemented (ISSUE-1.6c)"))
    }

    async fn sign_builder_registration(
        &self,
        _req: Request<SignBuilderRegistrationRequest>,
    ) -> Result<Response<SignResponseV2>, Status> {
        Err(Status::unimplemented("sign_builder_registration: not yet implemented (ISSUE-1.6d)"))
    }

    async fn sign_voluntary_exit(
        &self,
        _req: Request<SignVoluntaryExitRequest>,
    ) -> Result<Response<SignResponseV2>, Status> {
        Err(Status::unimplemented("sign_voluntary_exit: not yet implemented (ISSUE-1.6d)"))
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

// ──────────────────────────────────────────────────────��──────────────────────
// Internal helpers
// ─────────────────────────────────────────��───────────────────────────────────

fn backend_err_to_status(e: crate::backend::SigningBackendError) -> Status {
    match e {
        crate::backend::SigningBackendError::KeyNotFound(_) => {
            Status::not_found("unknown public key")
        }
        _ => {
            tracing::error!(error = %e, "signing backend error");
            Status::internal("internal signing error")
        }
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

    struct MockBackend {
        keys: Vec<[u8; 48]>,
    }

    impl MockBackend {
        fn new(keys: Vec<[u8; 48]>) -> Self {
            Self { keys }
        }

        fn empty() -> Self {
            Self { keys: vec![] }
        }
    }

    #[async_trait]
    impl SigningBackend for MockBackend {
        async fn sign(
            &self,
            _signing_root: &[u8; 32],
            pubkey: &[u8; 48],
        ) -> Result<[u8; 96], SigningBackendError> {
            if self.keys.contains(pubkey) {
                Ok([0xABu8; 96])
            } else {
                Err(SigningBackendError::KeyNotFound(*pubkey))
            }
        }

        fn public_keys(&self) -> Vec<[u8; 48]> {
            self.keys.clone()
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

    // --- V1 tests (preserved) ---

    #[tokio::test]
    async fn test_sign_valid_request() {
        let pubkey = [1u8; 48];
        let svc = make_service(MockBackend::new(vec![pubkey]));

        let req =
            Request::new(SignRequest { signing_root: vec![0u8; 32], pubkey: pubkey.to_vec() });
        let resp = svc.sign(req).await.unwrap();
        assert_eq!(resp.into_inner().signature.len(), 96);
    }

    #[tokio::test]
    async fn test_sign_unknown_key_returns_not_found() {
        let svc = make_service(MockBackend::new(vec![[1u8; 48]]));

        let req = Request::new(SignRequest { signing_root: vec![0u8; 32], pubkey: vec![2u8; 48] });
        let err = svc.sign(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn test_sign_invalid_signing_root_length() {
        let svc = make_service(MockBackend::empty());

        let req = Request::new(SignRequest { signing_root: vec![0u8; 16], pubkey: vec![1u8; 48] });
        let err = svc.sign(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn test_sign_invalid_pubkey_length() {
        let svc = make_service(MockBackend::empty());

        let req = Request::new(SignRequest { signing_root: vec![0u8; 32], pubkey: vec![1u8; 32] });
        let err = svc.sign(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    // --- V2 tests ---

    #[tokio::test]
    async fn test_v2_sign_beacon_block_happy_path() {
        let pubkey = [1u8; 48];
        let svc = make_service_v2(MockBackend::new(vec![pubkey]));

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
        let pubkey = [1u8; 48];
        let svc = make_service_v2(MockBackend::new(vec![pubkey]));

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
            pubkey: vec![1u8; 32], // wrong length
            fork_info: Some(sample_fork_info()),
            block_ssz: sample_block_ssz(42),
            fork_id: 4,
        });
        let err = svc.sign_beacon_block(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn test_v2_sign_beacon_block_unknown_key_returns_not_found() {
        let svc = make_service_v2(MockBackend::empty());

        let req = Request::new(SignBeaconBlockRequest {
            pubkey: vec![1u8; 48],
            fork_info: Some(sample_fork_info()),
            block_ssz: sample_block_ssz(42),
            fork_id: 4,
        });
        let err = svc.sign_beacon_block(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn test_v2_sign_beacon_block_double_proposal_rejected() {
        let pubkey = [1u8; 48];
        let svc = make_service_v2(MockBackend::new(vec![pubkey]));

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
        let pubkey = [1u8; 48];
        let svc = make_service_v2(MockBackend::new(vec![pubkey]));

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
        let pubkey = [1u8; 48];
        let svc = make_service_v2(MockBackend::new(vec![pubkey]));

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
        let pubkey = [1u8; 48];
        let svc = make_service_v2(MockBackend::new(vec![pubkey]));

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
        let pubkey = [1u8; 48];
        let svc = make_service(MockBackend::new(vec![pubkey])); // no DB

        let req = Request::new(SignBeaconBlockRequest {
            pubkey: pubkey.to_vec(),
            fork_info: Some(sample_fork_info()),
            block_ssz: sample_block_ssz(42),
            fork_id: 4,
        });
        let err = svc.sign_beacon_block(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::Internal);
    }

    // --- ListPublicKeys / GetStatus v2 ---

    #[tokio::test]
    async fn test_v2_list_public_keys() {
        let keys = vec![[1u8; 48], [2u8; 48]];
        let svc = make_service_v2(MockBackend::new(keys.clone()));

        let resp =
            SignerServiceV2::list_public_keys(&svc, Request::new(ListPublicKeysRequestV2 {}))
                .await
                .unwrap();
        let pubkeys = resp.into_inner().pubkeys;
        assert_eq!(pubkeys.len(), 2);
    }

    #[tokio::test]
    async fn test_v2_get_status() {
        let svc = make_service_v2(MockBackend::new(vec![[1u8; 48], [2u8; 48], [3u8; 48]]));

        let resp =
            SignerServiceV2::get_status(&svc, Request::new(GetStatusRequestV2 {})).await.unwrap();
        let status = resp.into_inner();
        assert!(status.ready);
        assert_eq!(status.key_count, 3);
    }

    // --- Metrics (v1) ---

    fn make_service_with_metrics(backend: MockBackend) -> (SignerServiceImpl, Arc<SignerMetrics>) {
        let metrics = Arc::new(SignerMetrics::new());
        let svc = SignerServiceImpl::new(Arc::new(backend), "basic".to_string())
            .with_metrics(Arc::clone(&metrics));
        (svc, metrics)
    }

    #[tokio::test]
    async fn test_sign_success_increments_counter() {
        let pubkey = [1u8; 48];
        let (svc, metrics) = make_service_with_metrics(MockBackend::new(vec![pubkey]));

        let req =
            Request::new(SignRequest { signing_root: vec![0u8; 32], pubkey: pubkey.to_vec() });
        svc.sign(req).await.unwrap();

        assert_eq!(metrics.sign_total.with_label_values(&["basic", "success"]).get(), 1);
    }

    #[tokio::test]
    async fn test_sign_error_increments_error_counter() {
        let (svc, metrics) = make_service_with_metrics(MockBackend::new(vec![[1u8; 48]]));

        let req = Request::new(SignRequest { signing_root: vec![0u8; 32], pubkey: vec![2u8; 48] });
        let _ = svc.sign(req).await;

        assert_eq!(metrics.sign_total.with_label_values(&["basic", "error"]).get(), 1);
        assert_eq!(
            metrics.sign_errors_total.with_label_values(&["basic", "key_not_found"]).get(),
            1
        );
    }
}
