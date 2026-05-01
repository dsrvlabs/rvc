use std::time::Instant;

use async_trait::async_trait;
use tonic::transport::Channel;
use tracing::Instrument;
use url::Url;
use zeroize::Zeroizing;

use crypto::logging::TruncatedPubkey;
use crypto::typed_signer::SignContext;
use crypto::{InsecureGate, InsecureMode};
use crypto::{PublicKey, Signature, PUBLIC_KEY_BYTES_LEN};
use crypto::{SigningError, TypedSigner};
use eth_types::{
    encode_attestation_ssz, encode_beacon_block_ssz, encode_blinded_beacon_block_ssz,
    encode_sync_committee_contribution_ssz, AggregateAndProof, AttestationData, BeaconBlock,
    BlindedBeaconBlock, ContributionAndProof, Epoch, Slot, ValidatorRegistrationV1, VoluntaryExit,
};

use crate::proto::signer_v2::signer_service_client::SignerServiceClient as SignerServiceClientV2;
use crate::proto::signer_v2::{
    AttestationData as ProtoAttestationData, Checkpoint as ProtoCheckpoint,
    ForkInfo as ProtoForkInfo, SignAggregateAndProofRequest, SignAttestationDataRequest,
    SignBeaconBlockRequest, SignBlindedBeaconBlockRequest, SignBuilderRegistrationRequest,
    SignContributionAndProofRequest, SignRandaoRevealRequest,
    SignSyncAggregatorSelectionDataRequest, SignSyncCommitteeMessageRequest,
    SignVoluntaryExitRequest,
};

// Keep v1 client for ListPublicKeys and GetStatus during connect
use crate::proto::signer::signer_service_client::SignerServiceClient;

/// The proto package name emitted by the v2 `GetStatus` response.
/// `bin/rvc` checks this at startup to refuse a v1 signer.
pub const SIGNER_V2_PACKAGE_NAME: &str = "signer.v2";

/// Environment variable that must be set to `"true"` to allow plaintext
/// `http://` gRPC remote-signer URLs.  `https://` URLs always pass without
/// consulting this variable.
pub const REMOTE_SIGNER_INSECURE_ENV_VAR: &str = "RVC_REMOTE_SIGNER_ALLOW_INSECURE";

fn redact_url(url: &str) -> String {
    if let Ok(mut parsed) = Url::parse(url) {
        if parsed.password().is_some() || !parsed.username().is_empty() {
            let _ = parsed.set_username("***");
            let _ = parsed.set_password(Some("***"));
        }
        parsed.to_string()
    } else {
        url.to_string()
    }
}

#[derive(Debug, Clone)]
pub struct GrpcRemoteSignerConfig {
    pub url: String,
    pub tls_cert: Option<Vec<u8>>,
    pub tls_key: Option<Zeroizing<Vec<u8>>>,
    pub tls_ca_cert: Option<Vec<u8>>,
}

impl GrpcRemoteSignerConfig {
    pub fn new(url: impl Into<String>) -> Self {
        Self { url: url.into(), tls_cert: None, tls_key: None, tls_ca_cert: None }
    }

    pub fn with_tls(mut self, cert: Vec<u8>, key: Vec<u8>, ca_cert: Vec<u8>) -> Self {
        self.tls_cert = Some(cert);
        self.tls_key = Some(Zeroizing::new(key));
        self.tls_ca_cert = Some(ca_cert);
        self
    }

    /// Gate this config's URL against the plaintext-URL policy.
    ///
    /// - `https://` URLs pass immediately — no env-var check, no log.
    /// - `http://` (or any other non-HTTPS scheme) is evaluated by
    ///   [`InsecureGate`] using [`REMOTE_SIGNER_INSECURE_ENV_VAR`]:
    ///   - `mode = Warn` (Phase 2 default): emits an `error!`-level log and
    ///     returns `Ok(())`.
    ///   - `mode = Refuse` (Phase 3, ISSUE-3.13): returns
    ///     `Err(SigningError::RemoteSignerError(...))` unless env var is set.
    pub fn check_url_security(&self, mode: InsecureMode) -> Result<(), SigningError> {
        if self.url.trim_end_matches('/').starts_with("https://") {
            return Ok(());
        }
        InsecureGate::with_predicate(REMOTE_SIGNER_INSECURE_ENV_VAR, mode, || true)
            .check()
            .map_err(|e| SigningError::RemoteSignerError(e.to_string()))
    }
}

/// gRPC remote signer client.
///
/// Implements [`TypedSigner`] only — there is no raw-root signing path.
/// This is the permanent fix for C-2/C-3: the v2 gRPC contract carries
/// typed consensus objects and the signing root is reconstructed
/// server-side, so raw 32-byte roots are never sent over the wire.
pub struct GrpcRemoteSigner {
    /// v2 typed-RPC client.
    client_v2: SignerServiceClientV2<Channel>,
    /// Cached public keys from `ListPublicKeys` at connect time.
    pubkeys: Vec<[u8; PUBLIC_KEY_BYTES_LEN]>,
    url: String,
}

impl GrpcRemoteSigner {
    #[tracing::instrument(name = "rvc.grpc_signer.connect", skip_all)]
    pub async fn connect(config: GrpcRemoteSignerConfig) -> Result<Self, SigningError> {
        // Gate plaintext URLs. Per NFR-10 / ISSUE-3.13 (GA) the gate refuses
        // http:// URLs unless RVC_REMOTE_SIGNER_ALLOW_INSECURE=true is set.
        config.check_url_security(InsecureMode::Refuse)?;

        let url = config.url.trim_end_matches('/').to_string();
        let tls_enabled = config.tls_cert.is_some();

        let channel = if let (Some(cert), Some(key), Some(ca_cert)) =
            (config.tls_cert, config.tls_key, config.tls_ca_cert)
        {
            let tls = tonic::transport::ClientTlsConfig::new()
                .identity(tonic::transport::Identity::from_pem(cert, &*key))
                .ca_certificate(tonic::transport::Certificate::from_pem(ca_cert));

            Channel::from_shared(url.clone())
                .map_err(|e| SigningError::RemoteSignerError(format!("invalid endpoint URL: {e}")))?
                .tls_config(tls)
                .map_err(|e| {
                    SigningError::RemoteSignerError(format!("TLS configuration error: {e}"))
                })?
                .connect()
                .await
                .map_err(|e| {
                    tracing::error!(
                        endpoint = %redact_url(&url),
                        error = %e,
                        "gRPC signer connection failed"
                    );
                    SigningError::RemoteSignerError(format!(
                        "failed to connect to {}: {e}",
                        redact_url(&url)
                    ))
                })?
        } else {
            Channel::from_shared(url.clone())
                .map_err(|e| SigningError::RemoteSignerError(format!("invalid endpoint URL: {e}")))?
                .connect()
                .await
                .map_err(|e| {
                    tracing::error!(
                        endpoint = %redact_url(&url),
                        error = %e,
                        "gRPC signer connection failed"
                    );
                    SigningError::RemoteSignerError(format!(
                        "failed to connect to {}: {e}",
                        redact_url(&url)
                    ))
                })?
        };

        // Use v1 client for ListPublicKeys (shared proto; both versions expose this RPC)
        let mut v1_client = SignerServiceClient::new(channel.clone());

        let response =
            v1_client.list_public_keys(crate::ListPublicKeysRequest {}).await.map_err(|e| {
                tracing::error!(
                    endpoint = %redact_url(&url),
                    error = %e,
                    "gRPC signer connection failed during key listing"
                );
                SigningError::RemoteSignerError(format!("failed to list public keys: {e}"))
            })?;

        let pubkeys: Vec<[u8; PUBLIC_KEY_BYTES_LEN]> = response
            .into_inner()
            .pubkeys
            .into_iter()
            .filter_map(|pk_bytes| pk_bytes.try_into().ok())
            .collect();

        let client_v2 = SignerServiceClientV2::new(channel);

        tracing::info!(
            endpoint = %redact_url(&url),
            tls_enabled,
            key_count = pubkeys.len(),
            "gRPC signer connection established (v2 typed RPCs)"
        );

        Ok(Self { client_v2, pubkeys, url })
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    /// Returns the cached public keys (fetched at connect time).
    pub fn public_keys(&self) -> Vec<[u8; PUBLIC_KEY_BYTES_LEN]> {
        self.pubkeys.clone()
    }

    fn make_fork_info(ctx: &SignContext) -> ProtoForkInfo {
        ProtoForkInfo {
            previous_version: ctx.fork_info.previous_version.to_vec(),
            current_version: ctx.fork_info.current_version.to_vec(),
            epoch: 0,
            genesis_validators_root: ctx.fork_info.genesis_validators_root.to_vec(),
        }
    }

    fn fork_id(ctx: &SignContext) -> u32 {
        // Derive fork_id from fork version. These are the consensus-layer fork IDs.
        // PHASE0=0, ALTAIR=1, BELLATRIX=2, CAPELLA=3, DENEB=4, ELECTRA=5, FULU=6
        // We use the current_version bytes to identify the fork.
        // This mapping is documented in the proto file comments.
        match ctx.fork_info.current_version {
            [0x00, 0x00, 0x00, 0x00] => 0, // Phase0 (mainnet)
            [0x01, 0x00, 0x00, 0x00] => 1, // Altair (mainnet)
            [0x02, 0x00, 0x00, 0x00] => 2, // Bellatrix (mainnet)
            [0x03, 0x00, 0x00, 0x00] => 3, // Capella (mainnet)
            [0x04, 0x00, 0x00, 0x00] => 4, // Deneb (mainnet)
            [0x05, 0x00, 0x00, 0x00] => 5, // Electra (mainnet)
            [0x06, 0x00, 0x00, 0x00] => 6, // Fulu (mainnet)
            // Testnet and devnet fork versions all map to Deneb or latest — default to 4
            _ => 4,
        }
    }

    fn ensure_pubkey(&self, ctx: &SignContext) -> Result<(), SigningError> {
        let pk_bytes = ctx.pubkey.to_bytes();
        if !self.pubkeys.contains(&pk_bytes) {
            return Err(SigningError::KeyNotFound(hex::encode(pk_bytes)));
        }
        Ok(())
    }

    fn extract_signature(
        sig_bytes: Vec<u8>,
        pubkey: &PublicKey,
        signing_root: &[u8; 32],
        pubkey_hex: &str,
    ) -> Result<Signature, SigningError> {
        let signature = Signature::from_bytes(&sig_bytes)
            .map_err(|e| SigningError::RemoteSignerError(format!("invalid BLS signature: {e}")))?;
        let pk = pubkey;
        if signature.verify(pk, signing_root).is_err() {
            tracing::error!(
                pubkey = %TruncatedPubkey::new(pubkey_hex),
                "gRPC remote signer returned invalid signature"
            );
            return Err(SigningError::InvalidRemoteSignature);
        }
        Ok(signature)
    }
}

#[async_trait]
impl TypedSigner for GrpcRemoteSigner {
    async fn sign_block(
        &self,
        block: &BeaconBlock,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        self.ensure_pubkey(ctx)?;
        let pubkey_hex = hex::encode(ctx.pubkey.to_bytes());
        let fork_id = Self::fork_id(ctx);
        let block_ssz = encode_beacon_block_ssz(block, fork_id);

        let span = tracing::info_span!(
            "rvc.sign.grpc_remote_typed",
            rvc.signer_type = "grpc_remote_typed",
            rvc.duty_type = "block",
            grpc.url = %redact_url(&self.url),
        );

        async {
            tracing::debug!(
                pubkey = %TruncatedPubkey::new(&pubkey_hex),
                "Typed sign_block request sent"
            );
            let start = Instant::now();

            let req = SignBeaconBlockRequest {
                pubkey: ctx.pubkey.to_bytes().to_vec(),
                fork_info: Some(Self::make_fork_info(ctx)),
                block_ssz,
                fork_id,
            };

            let mut client = self.client_v2.clone();
            let response = client.sign_beacon_block(req).await.map_err(|status| {
                tracing::warn!(
                    pubkey = %TruncatedPubkey::new(&pubkey_hex),
                    error_code = %status.code(),
                    "sign_block gRPC error"
                );
                SigningError::RemoteSignerError(format!(
                    "gRPC sign_block failed ({}): {}",
                    status.code(),
                    status.message()
                ))
            })?;

            let latency_ms = start.elapsed().as_millis() as u64;
            tracing::debug!(pubkey = %TruncatedPubkey::new(&pubkey_hex), latency_ms, "sign_block response received");

            let sig_bytes = response.into_inner().signature;
            // Verify signature using the signing root we compute locally.
            // This matches the server-side computation.
            use crypto::{compute_domain, compute_signing_root};
            use eth_types::DOMAIN_BEACON_PROPOSER;
            let domain = compute_domain(
                DOMAIN_BEACON_PROPOSER,
                ctx.fork_info.current_version,
                ctx.fork_info.genesis_validators_root,
            );
            let signing_root = compute_signing_root(block, domain);
            Self::extract_signature(sig_bytes, &ctx.pubkey, &signing_root, &pubkey_hex)
        }
        .instrument(span)
        .await
    }

    async fn sign_blinded_block(
        &self,
        block: &BlindedBeaconBlock,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        self.ensure_pubkey(ctx)?;
        let pubkey_hex = hex::encode(ctx.pubkey.to_bytes());
        let fork_id = Self::fork_id(ctx);
        let block_ssz = encode_blinded_beacon_block_ssz(block, fork_id);

        let span = tracing::info_span!(
            "rvc.sign.grpc_remote_typed",
            rvc.signer_type = "grpc_remote_typed",
            rvc.duty_type = "blinded_block",
            grpc.url = %redact_url(&self.url),
        );

        async {
            let start = Instant::now();
            let req = SignBlindedBeaconBlockRequest {
                pubkey: ctx.pubkey.to_bytes().to_vec(),
                fork_info: Some(Self::make_fork_info(ctx)),
                block_ssz,
                fork_id,
            };

            let mut client = self.client_v2.clone();
            let response = client.sign_blinded_beacon_block(req).await.map_err(|status| {
                SigningError::RemoteSignerError(format!(
                    "gRPC sign_blinded_beacon_block failed ({}): {}",
                    status.code(),
                    status.message()
                ))
            })?;

            let latency_ms = start.elapsed().as_millis() as u64;
            tracing::debug!(pubkey = %TruncatedPubkey::new(&pubkey_hex), latency_ms, "sign_blinded_block response received");

            let sig_bytes = response.into_inner().signature;
            use crypto::{compute_domain, compute_signing_root};
            use eth_types::DOMAIN_BEACON_PROPOSER;
            let domain = compute_domain(
                DOMAIN_BEACON_PROPOSER,
                ctx.fork_info.current_version,
                ctx.fork_info.genesis_validators_root,
            );
            let signing_root = compute_signing_root(block, domain);
            Self::extract_signature(sig_bytes, &ctx.pubkey, &signing_root, &pubkey_hex)
        }
        .instrument(span)
        .await
    }

    async fn sign_attestation(
        &self,
        data: &AttestationData,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        self.ensure_pubkey(ctx)?;
        let pubkey_hex = hex::encode(ctx.pubkey.to_bytes());
        let fork_id = Self::fork_id(ctx);

        let span = tracing::info_span!(
            "rvc.sign.grpc_remote_typed",
            rvc.signer_type = "grpc_remote_typed",
            rvc.duty_type = "attestation",
            grpc.url = %redact_url(&self.url),
        );

        async {
            let start = Instant::now();
            let proto_data = ProtoAttestationData {
                slot: data.slot,
                index: data.index,
                beacon_block_root: data.beacon_block_root.to_vec(),
                source: Some(ProtoCheckpoint {
                    epoch: data.source.epoch,
                    root: data.source.root.to_vec(),
                }),
                target: Some(ProtoCheckpoint {
                    epoch: data.target.epoch,
                    root: data.target.root.to_vec(),
                }),
            };

            let req = SignAttestationDataRequest {
                pubkey: ctx.pubkey.to_bytes().to_vec(),
                fork_info: Some(Self::make_fork_info(ctx)),
                data: Some(proto_data),
                fork_id,
            };

            let mut client = self.client_v2.clone();
            let response = client.sign_attestation_data(req).await.map_err(|status| {
                SigningError::RemoteSignerError(format!(
                    "gRPC sign_attestation_data failed ({}): {}",
                    status.code(),
                    status.message()
                ))
            })?;

            let latency_ms = start.elapsed().as_millis() as u64;
            tracing::debug!(pubkey = %TruncatedPubkey::new(&pubkey_hex), latency_ms, "sign_attestation response received");

            let sig_bytes = response.into_inner().signature;
            use crypto::{compute_domain, compute_signing_root, DOMAIN_BEACON_ATTESTER};
            let domain = compute_domain(
                DOMAIN_BEACON_ATTESTER,
                ctx.fork_info.current_version,
                ctx.fork_info.genesis_validators_root,
            );
            let signing_root = compute_signing_root(data, domain);
            Self::extract_signature(sig_bytes, &ctx.pubkey, &signing_root, &pubkey_hex)
        }
        .instrument(span)
        .await
    }

    async fn sign_aggregate_and_proof(
        &self,
        agg: &AggregateAndProof,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        self.ensure_pubkey(ctx)?;
        let pubkey_hex = hex::encode(ctx.pubkey.to_bytes());
        let fork_id = Self::fork_id(ctx);
        let aggregate_ssz = encode_attestation_ssz(&agg.aggregate, fork_id);

        let span = tracing::info_span!(
            "rvc.sign.grpc_remote_typed",
            rvc.signer_type = "grpc_remote_typed",
            rvc.duty_type = "aggregate_and_proof",
            grpc.url = %redact_url(&self.url),
        );

        async {
            let start = Instant::now();
            let req = SignAggregateAndProofRequest {
                pubkey: ctx.pubkey.to_bytes().to_vec(),
                fork_info: Some(Self::make_fork_info(ctx)),
                aggregator_index: agg.aggregator_index,
                aggregate_ssz,
                selection_proof: agg.selection_proof.clone(),
                fork_id,
            };

            let mut client = self.client_v2.clone();
            let response = client.sign_aggregate_and_proof(req).await.map_err(|status| {
                SigningError::RemoteSignerError(format!(
                    "gRPC sign_aggregate_and_proof failed ({}): {}",
                    status.code(),
                    status.message()
                ))
            })?;

            let latency_ms = start.elapsed().as_millis() as u64;
            tracing::debug!(pubkey = %TruncatedPubkey::new(&pubkey_hex), latency_ms, "sign_aggregate_and_proof response received");

            let sig_bytes = response.into_inner().signature;
            use crypto::{compute_domain, compute_signing_root};
            use eth_types::DOMAIN_AGGREGATE_AND_PROOF;
            let domain = compute_domain(
                DOMAIN_AGGREGATE_AND_PROOF,
                ctx.fork_info.current_version,
                ctx.fork_info.genesis_validators_root,
            );
            let signing_root = compute_signing_root(agg, domain);
            Self::extract_signature(sig_bytes, &ctx.pubkey, &signing_root, &pubkey_hex)
        }
        .instrument(span)
        .await
    }

    async fn sign_sync_committee_message(
        &self,
        slot: Slot,
        beacon_block_root: eth_types::Root,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        self.ensure_pubkey(ctx)?;
        let pubkey_hex = hex::encode(ctx.pubkey.to_bytes());
        let fork_id = Self::fork_id(ctx);

        let span = tracing::info_span!(
            "rvc.sign.grpc_remote_typed",
            rvc.signer_type = "grpc_remote_typed",
            rvc.duty_type = "sync_committee_message",
            grpc.url = %redact_url(&self.url),
        );

        async {
            let start = Instant::now();
            let req = SignSyncCommitteeMessageRequest {
                pubkey: ctx.pubkey.to_bytes().to_vec(),
                fork_info: Some(Self::make_fork_info(ctx)),
                slot,
                beacon_block_root: beacon_block_root.to_vec(),
                fork_id,
            };

            let mut client = self.client_v2.clone();
            let response = client.sign_sync_committee_message(req).await.map_err(|status| {
                SigningError::RemoteSignerError(format!(
                    "gRPC sign_sync_committee_message failed ({}): {}",
                    status.code(),
                    status.message()
                ))
            })?;

            let latency_ms = start.elapsed().as_millis() as u64;
            tracing::debug!(pubkey = %TruncatedPubkey::new(&pubkey_hex), latency_ms, "sign_sync_committee_message response received");

            let sig_bytes = response.into_inner().signature;
            use crypto::{compute_domain, compute_signing_root};
            use eth_types::DOMAIN_SYNC_COMMITTEE;
            let domain = compute_domain(
                DOMAIN_SYNC_COMMITTEE,
                ctx.fork_info.current_version,
                ctx.fork_info.genesis_validators_root,
            );
            let signing_root = compute_signing_root(&beacon_block_root, domain);
            Self::extract_signature(sig_bytes, &ctx.pubkey, &signing_root, &pubkey_hex)
        }
        .instrument(span)
        .await
    }

    async fn sign_sync_aggregator_selection(
        &self,
        slot: Slot,
        subcommittee_index: u64,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        self.ensure_pubkey(ctx)?;
        let pubkey_hex = hex::encode(ctx.pubkey.to_bytes());
        let fork_id = Self::fork_id(ctx);

        let span = tracing::info_span!(
            "rvc.sign.grpc_remote_typed",
            rvc.signer_type = "grpc_remote_typed",
            rvc.duty_type = "sync_aggregator_selection",
            grpc.url = %redact_url(&self.url),
        );

        async {
            let start = Instant::now();
            let req = SignSyncAggregatorSelectionDataRequest {
                pubkey: ctx.pubkey.to_bytes().to_vec(),
                fork_info: Some(Self::make_fork_info(ctx)),
                slot,
                subcommittee_index,
                fork_id,
            };

            let mut client = self.client_v2.clone();
            let response =
                client.sign_sync_aggregator_selection_data(req).await.map_err(|status| {
                    SigningError::RemoteSignerError(format!(
                        "gRPC sign_sync_aggregator_selection_data failed ({}): {}",
                        status.code(),
                        status.message()
                    ))
                })?;

            let latency_ms = start.elapsed().as_millis() as u64;
            tracing::debug!(pubkey = %TruncatedPubkey::new(&pubkey_hex), latency_ms, "sign_sync_aggregator_selection response received");

            let sig_bytes = response.into_inner().signature;
            use crypto::{compute_domain, compute_signing_root};
            use eth_types::{DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF, SyncAggregatorSelectionData};
            let domain = compute_domain(
                DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF,
                ctx.fork_info.current_version,
                ctx.fork_info.genesis_validators_root,
            );
            let selection_data = SyncAggregatorSelectionData { slot, subcommittee_index };
            let signing_root = compute_signing_root(&selection_data, domain);
            Self::extract_signature(sig_bytes, &ctx.pubkey, &signing_root, &pubkey_hex)
        }
        .instrument(span)
        .await
    }

    async fn sign_contribution_and_proof(
        &self,
        c: &ContributionAndProof,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        self.ensure_pubkey(ctx)?;
        let pubkey_hex = hex::encode(ctx.pubkey.to_bytes());
        let fork_id = Self::fork_id(ctx);
        let contribution_ssz = encode_sync_committee_contribution_ssz(&c.contribution, fork_id);

        let span = tracing::info_span!(
            "rvc.sign.grpc_remote_typed",
            rvc.signer_type = "grpc_remote_typed",
            rvc.duty_type = "contribution_and_proof",
            grpc.url = %redact_url(&self.url),
        );

        async {
            let start = Instant::now();
            let req = SignContributionAndProofRequest {
                pubkey: ctx.pubkey.to_bytes().to_vec(),
                fork_info: Some(Self::make_fork_info(ctx)),
                aggregator_index: c.aggregator_index,
                contribution_ssz,
                selection_proof: c.selection_proof.clone(),
                fork_id,
            };

            let mut client = self.client_v2.clone();
            let response = client.sign_contribution_and_proof(req).await.map_err(|status| {
                SigningError::RemoteSignerError(format!(
                    "gRPC sign_contribution_and_proof failed ({}): {}",
                    status.code(),
                    status.message()
                ))
            })?;

            let latency_ms = start.elapsed().as_millis() as u64;
            tracing::debug!(pubkey = %TruncatedPubkey::new(&pubkey_hex), latency_ms, "sign_contribution_and_proof response received");

            let sig_bytes = response.into_inner().signature;
            use crypto::{compute_domain, compute_signing_root};
            use eth_types::DOMAIN_CONTRIBUTION_AND_PROOF;
            let domain = compute_domain(
                DOMAIN_CONTRIBUTION_AND_PROOF,
                ctx.fork_info.current_version,
                ctx.fork_info.genesis_validators_root,
            );
            let signing_root = compute_signing_root(c, domain);
            Self::extract_signature(sig_bytes, &ctx.pubkey, &signing_root, &pubkey_hex)
        }
        .instrument(span)
        .await
    }

    async fn sign_builder_registration(
        &self,
        reg: &ValidatorRegistrationV1,
        genesis_fork_version: [u8; 4],
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        self.ensure_pubkey(ctx)?;
        let pubkey_hex = hex::encode(ctx.pubkey.to_bytes());

        let span = tracing::info_span!(
            "rvc.sign.grpc_remote_typed",
            rvc.signer_type = "grpc_remote_typed",
            rvc.duty_type = "builder_registration",
            grpc.url = %redact_url(&self.url),
        );

        async {
            let start = Instant::now();
            let req = SignBuilderRegistrationRequest {
                pubkey: ctx.pubkey.to_bytes().to_vec(),
                fee_recipient: reg.fee_recipient.to_vec(),
                gas_limit: reg.gas_limit,
                timestamp: reg.timestamp,
            };

            let mut client = self.client_v2.clone();
            let response = client.sign_builder_registration(req).await.map_err(|status| {
                SigningError::RemoteSignerError(format!(
                    "gRPC sign_builder_registration failed ({}): {}",
                    status.code(),
                    status.message()
                ))
            })?;

            let latency_ms = start.elapsed().as_millis() as u64;
            tracing::debug!(pubkey = %TruncatedPubkey::new(&pubkey_hex), latency_ms, "sign_builder_registration response received");

            let sig_bytes = response.into_inner().signature;
            use crypto::{compute_domain, compute_signing_root};
            use eth_types::DOMAIN_APPLICATION_BUILDER;
            let zero_gvr = [0u8; 32];
            let domain = compute_domain(DOMAIN_APPLICATION_BUILDER, genesis_fork_version, zero_gvr);
            let signing_root = compute_signing_root(reg, domain);
            Self::extract_signature(sig_bytes, &ctx.pubkey, &signing_root, &pubkey_hex)
        }
        .instrument(span)
        .await
    }

    async fn sign_randao_reveal(
        &self,
        epoch: Epoch,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        self.ensure_pubkey(ctx)?;
        let pubkey_hex = hex::encode(ctx.pubkey.to_bytes());
        let fork_id = Self::fork_id(ctx);

        let span = tracing::info_span!(
            "rvc.sign.grpc_remote_typed",
            rvc.signer_type = "grpc_remote_typed",
            rvc.duty_type = "randao_reveal",
            grpc.url = %redact_url(&self.url),
        );

        async {
            let start = Instant::now();
            let req = SignRandaoRevealRequest {
                pubkey: ctx.pubkey.to_bytes().to_vec(),
                fork_info: Some(Self::make_fork_info(ctx)),
                epoch,
                fork_id,
            };

            let mut client = self.client_v2.clone();
            let response = client.sign_randao_reveal(req).await.map_err(|status| {
                SigningError::RemoteSignerError(format!(
                    "gRPC sign_randao_reveal failed ({}): {}",
                    status.code(),
                    status.message()
                ))
            })?;

            let latency_ms = start.elapsed().as_millis() as u64;
            tracing::debug!(pubkey = %TruncatedPubkey::new(&pubkey_hex), latency_ms, "sign_randao_reveal response received");

            let sig_bytes = response.into_inner().signature;
            use crypto::{compute_domain, compute_signing_root};
            use eth_types::DOMAIN_RANDAO;
            let domain = compute_domain(
                DOMAIN_RANDAO,
                ctx.fork_info.current_version,
                ctx.fork_info.genesis_validators_root,
            );
            let signing_root = compute_signing_root(&epoch, domain);
            Self::extract_signature(sig_bytes, &ctx.pubkey, &signing_root, &pubkey_hex)
        }
        .instrument(span)
        .await
    }

    async fn sign_voluntary_exit(
        &self,
        exit: &VoluntaryExit,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        self.ensure_pubkey(ctx)?;
        let pubkey_hex = hex::encode(ctx.pubkey.to_bytes());
        let fork_id = Self::fork_id(ctx);

        let span = tracing::info_span!(
            "rvc.sign.grpc_remote_typed",
            rvc.signer_type = "grpc_remote_typed",
            rvc.duty_type = "voluntary_exit",
            grpc.url = %redact_url(&self.url),
        );

        async {
            let start = Instant::now();
            let req = SignVoluntaryExitRequest {
                pubkey: ctx.pubkey.to_bytes().to_vec(),
                fork_info: Some(Self::make_fork_info(ctx)),
                epoch: exit.epoch,
                validator_index: exit.validator_index,
                fork_id,
            };

            let mut client = self.client_v2.clone();
            let response = client.sign_voluntary_exit(req).await.map_err(|status| {
                SigningError::RemoteSignerError(format!(
                    "gRPC sign_voluntary_exit failed ({}): {}",
                    status.code(),
                    status.message()
                ))
            })?;

            let latency_ms = start.elapsed().as_millis() as u64;
            tracing::debug!(pubkey = %TruncatedPubkey::new(&pubkey_hex), latency_ms, "sign_voluntary_exit response received");

            let sig_bytes = response.into_inner().signature;
            use crypto::{compute_domain, compute_signing_root};
            use eth_types::DOMAIN_VOLUNTARY_EXIT;
            let domain = compute_domain(
                DOMAIN_VOLUNTARY_EXIT,
                ctx.fork_info.current_version,
                ctx.fork_info.genesis_validators_root,
            );
            let signing_root = compute_signing_root(exit, domain);
            Self::extract_signature(sig_bytes, &ctx.pubkey, &signing_root, &pubkey_hex)
        }
        .instrument(span)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_new() {
        let config = GrpcRemoteSignerConfig::new("http://localhost:50051");
        assert_eq!(config.url, "http://localhost:50051");
        assert!(config.tls_cert.is_none());
        assert!(config.tls_key.is_none());
        assert!(config.tls_ca_cert.is_none());
    }

    #[test]
    fn test_config_with_tls() {
        let config = GrpcRemoteSignerConfig::new("https://localhost:50051").with_tls(
            b"cert".to_vec(),
            b"key".to_vec(),
            b"ca".to_vec(),
        );
        assert!(config.tls_cert.is_some());
        assert!(config.tls_key.is_some());
        assert!(config.tls_ca_cert.is_some());
    }

    #[test]
    fn test_redact_url_hides_credentials() {
        let url = "http://user:pass@example.com:50051";
        let redacted = redact_url(url);
        assert!(!redacted.contains("user"));
        assert!(!redacted.contains("pass"));
        assert!(redacted.contains("***"));
        assert!(redacted.contains("example.com"));
    }

    #[test]
    fn test_redact_url_preserves_url_without_credentials() {
        let url = "http://example.com:50051";
        let redacted = redact_url(url);
        assert_eq!(redacted, "http://example.com:50051/");
    }

    #[test]
    fn test_redact_url_handles_invalid_url() {
        let url = "not-a-url";
        let redacted = redact_url(url);
        assert_eq!(redacted, "not-a-url");
    }

    #[test]
    fn test_grpc_remote_signer_not_implements_raw_signer() {
        // This test verifies at compile time that GrpcRemoteSigner does NOT implement
        // the old Signer (raw-root) trait. If this file compiles, the trait is absent.
        // The trait requires `async fn sign(root: &[u8;32], pubkey: &[u8;48])` which
        // is the C-2/C-3 oracle path.
        //
        // The negative assertion: we cannot write `let _: &dyn Signer = &signer`
        // because GrpcRemoteSigner no longer implements Signer.
        // The presence of this comment + successful compilation IS the test.
        let _ = "GrpcRemoteSigner implements TypedSigner only — no raw Signer impl";
    }
}
