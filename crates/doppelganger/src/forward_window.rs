//! Forward-window doppelganger state machine (D-1/D-2, Issues 2.6/2.7).
//!
//! Implements the Lighthouse v5.3.0 forward-window pattern: a validator is
//! withheld from signing for `monitoring_epochs` epochs after registration.
//! The monitoring window closes — and signing is permitted — only at or after
//! the LAST slot of `start_epoch + monitoring_epochs`.  Any unexplained
//! `is_live` observation during the window transitions the validator to
//! `Detected`, which permanently denies signing (fail-closed).
//!
//! # D-2: Fail-closed on incomplete liveness (Issue 2.7)
//!
//! A validator reaches `Safe` ONLY if EVERY epoch in its monitoring window
//! `[start_epoch, end_epoch]` had a COMPLETE liveness observation — i.e. the
//! validator's index was present in the beacon-node response for that epoch.
//! An epoch whose response omits the validator's index is NOT recorded as
//! observed; the validator remains `Pending` through the satisfaction boundary.
//! This is "fail-closed": missing data never grants signing permission.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use eth_types::{Epoch, Root, SLOTS_PER_EPOCH};
use parking_lot::Mutex;

use crate::enablement::SigningEnablement;
use crate::error::DoppelgangerError;
use crate::state::{ForwardWindowStatus, ValidatorState};
use crate::traits::ValidatorLivenessData;

/// Forward-window doppelganger state machine.
///
/// Thread-safe via an internal `parking_lot::Mutex`.
pub struct ForwardWindowMachine {
    states: Mutex<HashMap<String, ValidatorState>>,
    monitoring_epochs: u64,
    slashing_reader: Arc<dyn slashing::SlashingDbReader>,
    gvr: Root,
}

impl ForwardWindowMachine {
    /// Create a new machine.
    ///
    /// # Panics
    ///
    /// Panics if `monitoring_epochs` is zero.
    pub fn new(
        slashing_reader: Arc<dyn slashing::SlashingDbReader>,
        monitoring_epochs: u64,
        gvr: Root,
    ) -> Self {
        assert!(monitoring_epochs >= 1, "monitoring_epochs must be >= 1");
        Self { states: Mutex::new(HashMap::new()), monitoring_epochs, slashing_reader, gvr }
    }

    /// Register a validator for monitoring, starting at `current_epoch`.
    ///
    /// IDEMPOTENT: calling twice for the same pubkey does NOT reset state.  A
    /// validator that is already `Pending`, `Safe`, or `Detected` is left
    /// unchanged.
    ///
    /// Restart-aware safe-skip (Layer 4): if `last_signed_attestation` returns a
    /// target epoch that is RECENT (within the monitoring window), the validator
    /// transitions straight to `Safe` without waiting for the full window.
    /// A stale attestation (outside the window) does NOT trigger the skip —
    /// mirroring `DoppelgangerService::check_validators` (service.rs:129-131).
    ///
    /// The recency guard `current_epoch > monitoring_epochs` prevents the
    /// pre-genesis-clock-skew bypass (same guard as the service M-7 fix):
    /// when `current_epoch == 0`, saturating arithmetic would make every
    /// validator with any history look recent.
    pub fn register(&self, pubkey: &crypto::PublicKey, current_epoch: Epoch) {
        let pubkey_hex = hex::encode(pubkey.to_bytes());
        let mut states = self.states.lock();

        // Idempotency guard: any state other than Unmonitored stays as-is.
        if let Some(state) = states.get(&pubkey_hex) {
            if !matches!(state, ValidatorState::Unmonitored) {
                return;
            }
        }

        // Restart-aware safe-skip: only skip if the prior attestation is RECENT.
        let prior = self.slashing_reader.last_signed_attestation(&pubkey_hex, &self.gvr);
        if let Some(target_epoch) = prior {
            if current_epoch > self.monitoring_epochs
                && current_epoch.saturating_sub(target_epoch) <= self.monitoring_epochs
            {
                states.insert(pubkey_hex, ValidatorState::Safe);
                return;
            }
        }

        let end_epoch = current_epoch.saturating_add(self.monitoring_epochs);
        states.insert(
            pubkey_hex,
            ValidatorState::Pending {
                start_epoch: current_epoch,
                end_epoch,
                detected_live: false,
                observed_epochs: BTreeSet::new(),
            },
        );
    }

    /// Advance the state machine by one slot tick.
    ///
    /// A `Pending` validator transitions to `Safe` when ALL of the following hold:
    ///
    /// - The satisfaction boundary has been reached: `current_epoch > end_epoch`,
    ///   OR `current_epoch == end_epoch && slot_in_epoch >= SLOTS_PER_EPOCH - 1`.
    ///   This "at-or-after" semantics means a missed tick (e.g. after a restart)
    ///   does not leave the validator stuck `Pending` forever.
    /// - `detected_live == false` (no unexplained liveness was observed).
    /// - Every epoch in the monitoring window `[start_epoch, end_epoch]` has a
    ///   COMPLETE liveness observation recorded in `observed_epochs` (D-2, Issue
    ///   2.7).  A missing-entry epoch prevents the Safe transition (fail-closed).
    ///
    /// Returns the current status of every registered validator.
    pub fn tick(&self, current_epoch: Epoch, slot_in_epoch: u64) -> Vec<ForwardWindowStatus> {
        let mut states = self.states.lock();
        let mut statuses = Vec::with_capacity(states.len());

        for state in states.values_mut() {
            if let ValidatorState::Pending {
                start_epoch,
                end_epoch,
                detected_live,
                observed_epochs,
            } = state
            {
                let at_boundary =
                    current_epoch == *end_epoch && slot_in_epoch >= SLOTS_PER_EPOCH - 1;
                let past_boundary = current_epoch > *end_epoch;

                if (at_boundary || past_boundary) && !*detected_live {
                    // D-2: Safe requires complete observation of every window epoch.
                    let window_fully_observed =
                        (*start_epoch..=*end_epoch).all(|e| observed_epochs.contains(&e));
                    if window_fully_observed {
                        *state = ValidatorState::Safe;
                    }
                }
            }

            statuses.push(Self::status_of(state));
        }

        statuses
    }

    /// Record liveness observations for a given epoch.
    ///
    /// For each `Pending` validator whose monitoring window includes `epoch`:
    ///
    /// - If the validator's index **is present** in `samples`:
    ///   - The epoch is recorded as completely observed in `observed_epochs`.
    ///   - If `is_live == true`, the validator transitions to `Detected`.
    /// - If the validator's index **is absent** from `samples`:
    ///   - The epoch is NOT recorded (incomplete response — fail-closed per D-2).
    ///   - The validator stays `Pending` and cannot satisfy the window.
    ///
    /// After processing all in-window validators, the method returns
    /// `Err(DoppelgangerError::IncompleteLiveness)` if ANY expected validator
    /// was absent from the response.  Callers should log this error and retry
    /// the liveness check; they must NOT suppress it.
    ///
    /// Out-of-window epochs (before `start_epoch` or after `end_epoch`) are
    /// ignored for any specific validator; if no `Pending` in-window validator
    /// is expected for `epoch` at all, the method returns `Ok(())` regardless
    /// of what `samples` contains.
    pub fn observe_liveness(
        &self,
        epoch: Epoch,
        samples: &[ValidatorLivenessData],
    ) -> Result<(), DoppelgangerError> {
        // Build a fast-lookup map of index → is_live for the response.
        let response: std::collections::HashMap<&str, bool> =
            samples.iter().map(|s| (s.index.as_str(), s.is_live)).collect();

        let mut states = self.states.lock();

        // Phase 1: collect keys of Pending validators whose window includes epoch.
        // We gather keys first so that Phase 2 can use get_mut without borrow conflicts.
        let pending_in_window_keys: Vec<String> = states
            .iter()
            .filter_map(|(key, state)| {
                if let ValidatorState::Pending { start_epoch, end_epoch, .. } = state {
                    if epoch >= *start_epoch && epoch <= *end_epoch {
                        return Some(key.clone());
                    }
                }
                None
            })
            .collect();

        // Phase 2: process each in-window Pending validator.
        let mut any_missing = false;
        for key in &pending_in_window_keys {
            let Some(state) = states.get_mut(key) else { continue };

            match response.get(key.as_str()) {
                Some(&is_live) => {
                    // Index is present → record the epoch as completely observed.
                    if let ValidatorState::Pending { observed_epochs, .. } = state {
                        observed_epochs.insert(epoch);
                    }
                    // Transition to Detected if the validator is live.
                    if is_live {
                        *state = ValidatorState::Detected;
                    }
                }
                None => {
                    // Index is absent from the response → incomplete (fail-closed D-2).
                    any_missing = true;
                }
            }
        }

        if any_missing {
            Err(DoppelgangerError::IncompleteLiveness)
        } else {
            Ok(())
        }
    }

    /// Remove the validator from the state map.
    ///
    /// The next `register` call will start fresh (KM-2 / Issue 2.12).
    pub fn cancel(&self, pubkey: &crypto::PublicKey) {
        let pubkey_hex = hex::encode(pubkey.to_bytes());
        self.states.lock().remove(&pubkey_hex);
    }

    /// Read-only status inspection for a single validator.
    pub fn status(&self, pubkey: &crypto::PublicKey) -> ForwardWindowStatus {
        let pubkey_hex = hex::encode(pubkey.to_bytes());
        let states = self.states.lock();
        match states.get(&pubkey_hex) {
            None => ForwardWindowStatus::Unmonitored,
            Some(state) => Self::status_of(state),
        }
    }

    fn status_of(state: &ValidatorState) -> ForwardWindowStatus {
        match state {
            ValidatorState::Unmonitored => ForwardWindowStatus::Unmonitored,
            ValidatorState::Pending { .. } => ForwardWindowStatus::Pending,
            ValidatorState::Safe => ForwardWindowStatus::Safe,
            ValidatorState::Detected => ForwardWindowStatus::Detected,
        }
    }
}

impl SigningEnablement for ForwardWindowMachine {
    /// Returns `true` ONLY when the validator state is `Safe`.
    ///
    /// All other states (`Pending`, `Detected`, `Unmonitored`) return `false`
    /// (fail-closed by construction, per PRD §6.3).
    fn is_signing_enabled(&self, pubkey: &crypto::PublicKey) -> bool {
        matches!(self.status(pubkey), ForwardWindowStatus::Safe)
    }
}
