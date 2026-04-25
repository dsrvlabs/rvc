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
//! # Lock-vs-await strategy for slashable block RPCs
//!
//! `StagedBlock<'_>` holds a `parking_lot::MutexGuard` (`!Send`).  Holding it
//! across an `.await` boundary is a compile error in a multi-threaded tokio
//! runtime.  The correct solution — and the only one that preserves the
//! stage → sign → commit semantic required by ISSUE-1.4 / architecture A15 —
//! is to run the entire triple on a single OS thread via
//! `tokio::task::spawn_blocking`.
//!
//! ## Why `spawn_blocking` + `Handle::block_on` is the right fit
//!
//! `tokio::task::spawn_blocking` runs a closure on a dedicated thread-pool
//! thread that is allowed to block.  `tokio::runtime::Handle::current()` returns
//! a handle to the current runtime, and `handle.block_on(future)` drives a
//! future to completion on that same thread — this is the documented way to call
//! async code from a blocking context (e.g. from within `spawn_blocking`).
//!
//! ```text
//! spawn_blocking(move || {
//!     let staged = scoped.stage_block(...)?;   // acquires MutexGuard
//!     let sig = Handle::current()
//!         .block_on(backend.sign(...));        // async sign, no .await on calling task
//!     match sig {
//!         Ok(sig) => { staged.commit()?; Ok(sig) }
//!         Err(e)  => { staged.discard();    Err(e) }
//!     }
//! }).await
//! ```
//!
//! The `StagedBlock` guard — and the `MutexGuard` it contains — never crosses
//! an OS-thread boundary: everything runs on the same `spawn_blocking` thread.
//! The async `backend.sign` future is resolved via `block_on`, which drives the
//! future to completion without suspending the closure.
//!
//! ## Consequence
//!
//! - Signer failure → `staged.discard()` → DB transaction rolled back → no
//!   phantom row (M-1 fix, per architecture A15).
//! - Signer success → `staged.commit()` → row persisted atomically.
//! - `sign_randao_reveal` has no slashing check and does not use staging; it
//!   calls `backend.sign` directly via `.await` in the async handler.
//!
//! ## `SigningBackend` is `Send + Sync`
//!
//! Because `SigningBackend` is `Send + Sync`, the `Arc<dyn SigningBackend>` can
//! be moved into the `spawn_blocking` closure and the inner async future it
//! spawns is also `Send`, which is what `Handle::block_on` requires.

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

    #[allow(clippy::result_large_err)]
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

        // Stage → sign → commit, all on one OS thread via spawn_blocking.
        //
        // `StagedBlock<'_>` holds a `parking_lot::MutexGuard` (`!Send`) and
        // therefore cannot be held across an `.await`.  We run the entire
        // stage+sign+commit triple inside `spawn_blocking`; the async
        // `backend.sign` call is resolved via `Handle::current().block_on()`
        // which drives the future to completion on the same blocking thread.
        //
        // On signer error the staged guard is discarded (transaction rolled
        // back), so no phantom row is committed — this is the A15 guarantee.
        let backend = Arc::clone(&self.backend);
        let handle = tokio::runtime::Handle::current();

        let sig = tokio::task::spawn_blocking(move || -> Result<[u8; 96], Status> {
            let staged = scoped
                .stage_block(&pubkey_hex_str, slot, signing_root_hex)
                .map_err(slashing_err)?;

            let sign_result = handle.block_on(backend.sign(&signing_root, &pubkey));

            match sign_result {
                Ok(sig) => {
                    staged
                        .commit()
                        .map_err(|e| Status::internal(format!("slashing DB commit failed: {e}")))?;
                    Ok(sig)
                }
                Err(e) => {
                    staged.discard();
                    Err(backend_err_to_status(e))
                }
            }
        })
        .await
        .map_err(|join_err| {
            Status::internal(format!("sign_beacon_block blocking task panicked: {join_err}"))
        })??;

        tracing::info!(
            pubkey = %pubkey_hex(&pubkey),
            slot,
            client_cn = %client_cn,
            "sign_beacon_block: success"
        );
        Ok(Response::new(SignResponseV2 { signature: sig.to_vec() }))
    }

    // ── SignBlindedBeaconBlock ───────────────────────────────��────────────────

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

        // Same stage → sign → commit pattern as sign_beacon_block.
        // See the module-level docstring for the spawn_blocking + block_on rationale.
        let backend = Arc::clone(&self.backend);
        let handle = tokio::runtime::Handle::current();

        let sig = tokio::task::spawn_blocking(move || -> Result<[u8; 96], Status> {
            let staged = scoped
                .stage_block(&pubkey_hex_str, slot, signing_root_hex)
                .map_err(slashing_err)?;

            let sign_result = handle.block_on(backend.sign(&signing_root, &pubkey));

            match sign_result {
                Ok(sig) => {
                    staged
                        .commit()
                        .map_err(|e| Status::internal(format!("slashing DB commit failed: {e}")))?;
                    Ok(sig)
                }
                Err(e) => {
                    staged.discard();
                    Err(backend_err_to_status(e))
                }
            }
        })
        .await
        .map_err(|join_err| {
            Status::internal(format!(
                "sign_blinded_beacon_block blocking task panicked: {join_err}"
            ))
        })??;

        tracing::info!(
            pubkey = %pubkey_hex(&pubkey),
            slot,
            client_cn = %client_cn,
            "sign_blinded_beacon_block: success"
        );
        Ok(Response::new(SignResponseV2 { signature: sig.to_vec() }))
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
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let db_path = tmp.path().to_path_buf();
        let db = Arc::new(slashing::SlashingDb::open(&db_path).unwrap());
        std::mem::forget(tmp);
        let pubkey = [1u8; 48];
        let svc = SignerServiceImpl::new_v2(
            Arc::new(MockBackend::empty()),
            "basic".to_string(),
            Arc::clone(&db),
        );

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
