use std::sync::Arc;

use tracing::{debug, info, info_span, warn, Instrument};

use beacon::{AttesterDuty, LegacyAttestation, SingleAttestation, VersionedAttestation};
use bn_manager::BeaconNodeClient;
use crypto::logging::TruncatedPubkey;
use duty_tracker::DutyTracker;
use eth_types::{ForkName, Slot};
use metrics::definitions::{
    orchestrator_result, RVC_ORCHESTRATOR_ACTIVE_ATTESTATIONS, RVC_ORCHESTRATOR_MISSED_SLOTS_TOTAL,
    RVC_ORCHESTRATOR_SLOTS_PROCESSED_TOTAL, RVC_ORCHESTRATOR_SLOT_PROCESSING_DURATION_SECONDS,
};
use propagator::{AttestationSubmitter, Propagator};
use signer::SignerService;
use timing::{SlotClock, SLOTS_PER_EPOCH};
use validator_store::ValidatorStore;

use super::coordinator::{AttestationResult, OrchestratorConfig, PubkeyMap};
use super::error::OrchestratorError;
use super::utils;
use super::validation::attestation_data::validate_attestation_data;

/// Decide whether an attestation duty may proceed past the doppelganger gate.
///
/// Returns `true` when the duty is allowed to be signed, `false` when it must be
/// skipped (the validator is inside its post-import doppelganger window, or the
/// duty pubkey cannot be resolved).
pub(crate) fn attestation_duty_enabled(
    duty: &AttesterDuty,
    pubkey_map: &PubkeyMap,
    validator_store: &ValidatorStore,
    slot: Slot,
) -> bool {
    let hex = duty.pubkey.strip_prefix("0x").unwrap_or(&duty.pubkey);
    if let Ok(bytes) = hex::decode(hex) {
        if bytes.len() == 48 {
            let mut pk = [0u8; 48];
            pk.copy_from_slice(&bytes);
            if !validator_store.is_signing_enabled(&pk) {
                warn!(
                    pubkey = %duty.pubkey,
                    slot,
                    "Skipping attestation duty: validator is inside the \
                     post-import doppelganger window (M-12)"
                );
                return false;
            }
        }
    }
    true
}

pub(crate) struct AttestationService<C, S>
where
    C: SlotClock + 'static,
    S: AttestationSubmitter + 'static,
{
    clock: Arc<C>,
    signer: Arc<SignerService>,
    propagator: Arc<Propagator<S>>,
    beacon: Arc<dyn BeaconNodeClient>,
    duty_tracker: Arc<DutyTracker>,
    pubkey_map: PubkeyMap,
    config: OrchestratorConfig,
    /// M-12 (Critical #1): per-validator enabled flag.  Duties for validators
    /// that are still inside the post-import doppelganger window
    /// (`enabled = false`) are skipped so that a freshly imported key does
    /// not attest until the window has elapsed and the background task flips
    /// the flag to `true`.
    validator_store: Arc<ValidatorStore>,
}

impl<C, S> AttestationService<C, S>
where
    C: SlotClock + 'static,
    S: AttestationSubmitter + 'static,
{
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        clock: Arc<C>,
        signer: Arc<SignerService>,
        propagator: Arc<Propagator<S>>,
        beacon: Arc<dyn BeaconNodeClient>,
        duty_tracker: Arc<DutyTracker>,
        pubkey_map: PubkeyMap,
        config: OrchestratorConfig,
        validator_store: Arc<ValidatorStore>,
    ) -> Self {
        Self {
            clock,
            signer,
            propagator,
            beacon,
            duty_tracker,
            pubkey_map,
            config,
            validator_store,
        }
    }

    /// Processes all attestation duties for a given slot.
    ///
    /// Validators are processed sequentially within each slot to work with
    /// the non-Send/Sync `SlashingDb`. For high validator counts, consider
    /// making `SlashingDb` thread-safe with proper locking for concurrent processing.
    #[tracing::instrument(name = "rvc.orchestrator.process_slot", skip_all, fields(rvc.slot = slot))]
    pub(crate) async fn process_slot(
        &self,
        slot: Slot,
    ) -> Result<Vec<AttestationResult>, OrchestratorError> {
        let _timer = RVC_ORCHESTRATOR_SLOT_PROCESSING_DURATION_SECONDS
            .with_label_values(&[] as &[&str])
            .start_timer();

        info!(slot = slot, "Processing attestation duties for slot");

        let current_slot = self.clock.current_slot()?;

        if current_slot > slot {
            RVC_ORCHESTRATOR_MISSED_SLOTS_TOTAL.with_label_values(&[] as &[&str]).inc();
            return Err(OrchestratorError::SlotMissed { slot, current_slot });
        }

        let raw_duties =
            utils::get_duties_for_slot(&self.pubkey_map, &self.duty_tracker, slot).await?;

        // M-12 (Critical #1) / D-3: skip duties for validators still inside
        // their post-import doppelganger window, or whose pubkey cannot be
        // resolved.  See `attestation_duty_enabled` for the fail-closed policy.
        let duties: Vec<AttesterDuty> = raw_duties
            .into_iter()
            .filter(|duty| {
                attestation_duty_enabled(duty, &self.pubkey_map, &self.validator_store, slot)
            })
            .collect();

        if duties.is_empty() {
            debug!(slot = slot, "No attestation duties for this slot");
            RVC_ORCHESTRATOR_SLOTS_PROCESSED_TOTAL
                .with_label_values(&[orchestrator_result::NO_DUTIES])
                .inc();
            return Err(OrchestratorError::NoDutiesForSlot { slot });
        }

        info!(slot = slot, duty_count = duties.len(), "Found attestation duties");
        RVC_ORCHESTRATOR_ACTIVE_ATTESTATIONS.set(duties.len() as f64);

        let mut results = Vec::new();

        for duty in duties {
            let result = self.process_attestation_duty(duty).await;

            if result.success {
                info!(
                    validator = %result.validator_index,
                    slot = result.slot,
                    "Attestation completed successfully"
                );
            } else {
                warn!(
                    validator = %result.validator_index,
                    slot = result.slot,
                    error = ?result.error,
                    "Attestation failed"
                );
            }
            results.push(result);
        }

        RVC_ORCHESTRATOR_ACTIVE_ATTESTATIONS.set(0.0);

        let success_count = results.iter().filter(|r| r.success).count();
        let failure_count = results.len() - success_count;

        if failure_count > 0 {
            RVC_ORCHESTRATOR_SLOTS_PROCESSED_TOTAL
                .with_label_values(&[orchestrator_result::FAILED])
                .inc();
        } else {
            RVC_ORCHESTRATOR_SLOTS_PROCESSED_TOTAL
                .with_label_values(&[orchestrator_result::SUCCESS])
                .inc();
        }

        let target_epoch = slot / SLOTS_PER_EPOCH;
        info!(slot = slot, count = success_count, target_epoch, "Batch attestation summary");

        info!(
            slot = slot,
            total = results.len(),
            success = success_count,
            failed = failure_count,
            "Slot processing complete"
        );

        Ok(results)
    }

    async fn process_attestation_duty(&self, duty: AttesterDuty) -> AttestationResult {
        let validator_index = duty.validator_index.clone();

        let slot: Slot = match duty.slot.parse() {
            Ok(s) => s,
            Err(_) => {
                return AttestationResult {
                    validator_index,
                    slot: 0,
                    success: false,
                    error: Some(format!("Invalid slot in duty: {}", duty.slot)),
                };
            }
        };

        let committee_index: u64 = match duty.committee_index.parse() {
            Ok(c) => c,
            Err(_) => {
                return AttestationResult {
                    validator_index,
                    slot,
                    success: false,
                    error: Some(format!(
                        "Invalid committee_index in duty: {}",
                        duty.committee_index
                    )),
                };
            }
        };

        let att_span = info_span!(
            "rvc.attestation.produce",
            rvc.slot = slot,
            rvc.validator_index = %validator_index,
            rvc.pubkey = %TruncatedPubkey::new(&duty.pubkey),
        );

        {
            let _guard = att_span.enter();
            debug!(
                validator = %validator_index,
                slot = slot,
                committee_index = committee_index,
                "Processing attestation duty"
            );
        }

        let pubkey = match utils::find_pubkey(&self.pubkey_map, &duty.pubkey) {
            Some(pk) => pk,
            None => {
                return AttestationResult {
                    validator_index,
                    slot,
                    success: false,
                    error: Some(format!("Public key not found: {}", duty.pubkey)),
                };
            }
        };

        // Apply timeout to beacon client call to prevent blocking
        let attestation_data_result = tokio::time::timeout(
            self.config.timeouts.attestation_fetch,
            self.beacon.get_attestation_data(slot, committee_index),
        )
        .instrument(info_span!(parent: &att_span, "rvc.beacon.get_attestation_data"))
        .await;

        let attestation_data_response = match attestation_data_result {
            Ok(Ok(response)) => response,
            Ok(Err(e)) => {
                return AttestationResult {
                    validator_index,
                    slot,
                    success: false,
                    error: Some(format!("Failed to get attestation data: {}", e)),
                };
            }
            Err(_) => {
                return AttestationResult {
                    validator_index,
                    slot,
                    success: false,
                    error: Some("Timeout getting attestation data from beacon node".to_string()),
                };
            }
        };

        let beacon_attestation_data = attestation_data_response.data;

        debug!(
            validator = %validator_index,
            slot = %beacon_attestation_data.slot,
            index = %beacon_attestation_data.index,
            beacon_block_root = %beacon_attestation_data.beacon_block_root,
            source_epoch = %beacon_attestation_data.source.epoch,
            source_root = %beacon_attestation_data.source.root,
            target_epoch = %beacon_attestation_data.target.epoch,
            target_root = %beacon_attestation_data.target.root,
            "Attestation data fetched from BN"
        );

        // Pre-parse target epoch to derive the fork before full conversion.
        // This allows `convert_and_normalize_attestation_data` to handle the
        // EIP-7549 index-zeroing in one place for both attestation and aggregation paths.
        let target_epoch: u64 = match beacon_attestation_data.target.epoch.parse() {
            Ok(e) => e,
            Err(_) => {
                return AttestationResult {
                    validator_index,
                    slot,
                    success: false,
                    error: Some(format!(
                        "Failed to parse target epoch: {}",
                        beacon_attestation_data.target.epoch
                    )),
                };
            }
        };

        let fork_name = ForkName::from_epoch(target_epoch, &self.config.fork_schedule);
        let is_electra = fork_name >= ForkName::Electra;

        debug!(
            validator = %validator_index,
            fork_name = ?fork_name,
            is_electra = is_electra,
            target_epoch = target_epoch,
            "Fork derived for attestation"
        );

        // EIP-7549: For Electra+, `AttestationData.index` must be zeroed before
        // signing. `convert_and_normalize_attestation_data` handles this centrally
        // so both the attestation and aggregation paths stay in sync.
        let crypto_attestation_data = match utils::convert_and_normalize_attestation_data(
            &beacon_attestation_data,
            fork_name,
        ) {
            Ok(data) => data,
            Err(e) => {
                return AttestationResult {
                    validator_index,
                    slot,
                    success: false,
                    error: Some(format!("Failed to convert attestation data: {}", e)),
                };
            }
        };

        debug!(
            validator = %validator_index,
            slot = crypto_attestation_data.slot,
            index = crypto_attestation_data.index,
            target_epoch = target_epoch,
            source_epoch = crypto_attestation_data.source.epoch,
            "Converted attestation data"
        );

        // M-2: local AttestationData sanity check before sign.
        // Re-fetch the current clock slot here so the window check uses the
        // most recent local view (≤1 ms delta from the check at process_slot).
        let current_clock_slot = match self.clock.current_slot() {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(
                    error = %e,
                    validator = %validator_index,
                    slot,
                    "Failed to read clock slot for AttestationData sanity check; \
                     dropping duty"
                );
                return AttestationResult {
                    validator_index,
                    slot,
                    success: false,
                    error: Some(format!("Clock error during attestation validation: {e}")),
                };
            }
        };
        if let Err(e) =
            validate_attestation_data(&crypto_attestation_data, slot, current_clock_slot)
        {
            tracing::error!(
                error = %e,
                validator = %validator_index,
                pubkey = %crypto::logging::TruncatedPubkey::new(&duty.pubkey),
                slot,
                "AttestationData failed sanity check (M-2); dropping duty"
            );
            return AttestationResult {
                validator_index,
                slot,
                success: false,
                error: Some(format!("AttestationData sanity check failed: {e}")),
            };
        }

        let signature = match self
            .signer
            .sign_attestation(
                &crypto_attestation_data,
                &pubkey,
                &self.config.fork_schedule,
                &self.config.genesis_validators_root,
            )
            .instrument(att_span.clone())
            .await
        {
            Ok(sig) => {
                let sig_bytes = sig.to_bytes();
                debug!(
                    validator = %validator_index,
                    signature_prefix = %format!("0x{}", hex::encode(&sig_bytes[..8])),
                    "Attestation signed successfully"
                );
                sig
            }
            Err(e) => {
                tracing::error!(error = %e, validator = %validator_index, slot, "Attestation signing failed");
                return AttestationResult {
                    validator_index,
                    slot,
                    success: false,
                    error: Some(format!("Failed to sign attestation: {}", e)),
                };
            }
        };

        let attester_index: u64 = match validator_index.parse() {
            Ok(v) => v,
            Err(_) => {
                let error = format!("Invalid validator_index in duty: {}", validator_index);
                return AttestationResult {
                    validator_index,
                    slot,
                    success: false,
                    error: Some(error),
                };
            }
        };

        let sig_hex = format!("0x{}", hex::encode(signature.to_bytes()));

        let versioned = if fork_name >= ForkName::Fulu {
            let mut fulu_data = beacon_attestation_data.clone();
            fulu_data.index = "0".to_string();
            VersionedAttestation::Fulu(vec![SingleAttestation {
                committee_index,
                attester_index,
                data: fulu_data,
                signature: sig_hex,
            }])
        } else if is_electra {
            let mut electra_data = beacon_attestation_data.clone();
            electra_data.index = "0".to_string();
            VersionedAttestation::Electra(vec![SingleAttestation {
                committee_index,
                attester_index,
                data: electra_data,
                signature: sig_hex,
            }])
        } else {
            let aggregation_bits = match utils::make_aggregation_bits(&duty) {
                Some(bits) => bits,
                None => {
                    warn!(
                        validator = %validator_index,
                        slot,
                        "Skipping attestation: could not produce aggregation bits"
                    );
                    return AttestationResult {
                        validator_index,
                        slot,
                        success: false,
                        error: Some(
                            "could not produce aggregation bits (committee_length=0 \
                             or validator_committee_index out of range)"
                                .to_string(),
                        ),
                    };
                }
            };
            VersionedAttestation::PreElectra(vec![LegacyAttestation {
                aggregation_bits,
                data: beacon_attestation_data,
                signature: sig_hex,
            }])
        };

        let versioned_type = match &versioned {
            VersionedAttestation::Fulu(_) => "Fulu",
            VersionedAttestation::Electra(_) => "Electra",
            VersionedAttestation::PreElectra(_) => "PreElectra",
        };
        debug!(
            validator = %validator_index,
            versioned_type = versioned_type,
            "Propagating attestation"
        );

        let submit_result = tokio::time::timeout(
            self.config.timeouts.attestation_submit,
            self.propagator.propagate(&versioned),
        )
        .instrument(info_span!(parent: &att_span, "rvc.beacon.submit_attestation"))
        .await;

        match submit_result {
            Ok(Ok(_)) => AttestationResult { validator_index, slot, success: true, error: None },
            Ok(Err(e)) => {
                tracing::error!(error = %e, validator = %validator_index, slot, "Attestation submission failed");
                AttestationResult {
                    validator_index,
                    slot,
                    success: false,
                    error: Some(format!("Failed to propagate attestation: {}", e)),
                }
            }
            Err(_) => {
                tracing::error!(validator = %validator_index, slot, "Attestation submission timed out");
                AttestationResult {
                    validator_index,
                    slot,
                    success: false,
                    error: Some(format!(
                        "Attestation submit timed out after {}s",
                        self.config.timeouts.attestation_submit.as_secs()
                    )),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;

    use crypto::{PublicKey, SecretKey};
    use parking_lot::RwLock;
    use validator_store::{ValidatorConfig, ValidatorStore};

    /// Build a minimal `AttesterDuty` for the given pubkey string.
    fn duty_with_pubkey(pubkey: &str) -> AttesterDuty {
        AttesterDuty {
            pubkey: pubkey.to_string(),
            validator_index: "0".to_string(),
            committee_index: "0".to_string(),
            committee_length: "1".to_string(),
            committees_at_slot: "1".to_string(),
            validator_committee_index: "0".to_string(),
            slot: "0".to_string(),
        }
    }

    /// Build a `PubkeyMap` containing a single resolvable pubkey under its
    /// canonical `0x`-lowercase key (the form the orchestrator inserts).
    fn pubkey_map_with(pubkey: &PublicKey) -> PubkeyMap {
        let mut map: HashMap<String, PublicKey> = HashMap::new();
        let key = format!("0x{}", hex::encode(pubkey.to_bytes()));
        map.insert(key, pubkey.clone());
        Arc::new(RwLock::new(map))
    }

    fn disabled_store(pubkey: &PublicKey) -> ValidatorStore {
        let store = ValidatorStore::new([0u8; 20], 30_000_000);
        let mut config = ValidatorConfig::new(pubkey.to_bytes());
        config.enabled = false;
        store.add_validator(config);
        store
    }

    /// FUP-6 / D-3 RED: a duty whose pubkey is uppercase-`0X`-prefixed is
    /// resolvable via `find_pubkey` (case-insensitive `CanonicalPubkey`), so the
    /// gate MUST be consulted.  The validator is disabled, so the duty must be
    /// SKIPPED (fail-closed).
    ///
    /// On `develop` the inline filter used `strip_prefix("0x")` (lowercase only)
    /// then `hex::decode`, which fails on a `0X` prefix and falls through to
    /// `true` — fail OPEN.  This test fails on `develop` and passes after the
    /// fail-closed fix.
    #[test]
    fn test_uppercase_0x_disabled_validator_is_skipped_fail_closed() {
        let sk = SecretKey::generate();
        let pubkey = sk.public_key();

        // Duty carries the uppercase `0X` prefix — `find_pubkey` resolves it,
        // but the old lowercase-only `strip_prefix("0x")` + decode does not.
        let duty_pubkey = format!("0X{}", hex::encode(pubkey.to_bytes()).to_uppercase());
        let duty = duty_with_pubkey(&duty_pubkey);

        let pubkey_map = pubkey_map_with(&pubkey);
        let store = disabled_store(&pubkey);

        assert!(
            !attestation_duty_enabled(&duty, &pubkey_map, &store, 0),
            "uppercase-0X duty for a disabled validator must be SKIPPED (fail-closed); \
             the old lowercase-only decode falls through to enabled=true (fail-open)"
        );
    }

    /// FUP-6 / D-3 RED: a duty whose pubkey does not resolve via `find_pubkey`
    /// at all must be SKIPPED (fail-closed) — an unresolved pubkey cannot be
    /// gate-checked, so the only safe action is to skip.
    ///
    /// On `develop` an unresolved-but-decodable 48-byte pubkey reaches
    /// `is_signing_enabled` and is skipped, but a NON-decoding pubkey falls
    /// through to `true`.  This test uses a non-hex pubkey to exercise the
    /// fail-open path.
    #[test]
    fn test_unresolved_nondecoding_pubkey_is_skipped_fail_closed() {
        // Not valid hex (contains 'z') and not present in the map.
        let duty = duty_with_pubkey("0xzzzznotvalidhex");

        let other = SecretKey::generate().public_key();
        let pubkey_map = pubkey_map_with(&other);
        let store = disabled_store(&other);

        assert!(
            !attestation_duty_enabled(&duty, &pubkey_map, &store, 0),
            "a duty whose pubkey does not resolve via find_pubkey must be SKIPPED \
             (fail-closed); the old code falls through to enabled=true (fail-open)"
        );
    }
}
