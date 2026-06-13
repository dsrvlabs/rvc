//! Forward-window doppelganger state machine (D-1, Issue 2.6).
//!
//! Implements the Lighthouse v5.3.0 forward-window pattern: a validator is
//! withheld from signing for `monitoring_epochs` epochs after registration.
//! The monitoring window closes — and signing is permitted — only at the LAST
//! slot of `start_epoch + monitoring_epochs`.  Any unexplained `is_live`
//! observation during the window transitions the validator to `Detected`,
//! which permanently denies signing (fail-closed).

use std::collections::HashMap;
use std::sync::Arc;

use eth_types::{Epoch, Root, SLOTS_PER_EPOCH};
use parking_lot::Mutex;

use crate::enablement::SigningEnablement;
use crate::error::DoppelgangerError;
use crate::state::{DoppelgangerStatus, ValidatorState};
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
    /// IDEMPOTENT: calling twice for the same pubkey (regardless of epoch) does
    /// NOT reset state.  A validator that is already `Pending`, `Safe`, or
    /// `Detected` is left unchanged.
    ///
    /// Restart-aware safe-skip (Layer 4): if `last_signed_attestation` returns
    /// `Some(_)` (indicating the validator already attested within this chain's
    /// history), the validator is transitioned straight to `Safe` without
    /// waiting for the full monitoring window.
    pub fn register(&self, pubkey: &crypto::PublicKey, current_epoch: Epoch) {
        let pubkey_hex = hex::encode(pubkey.to_bytes());
        let mut states = self.states.lock();

        // Idempotency guard: any state other than Unmonitored stays as-is.
        if let Some(state) = states.get(&pubkey_hex) {
            if !matches!(state, ValidatorState::Unmonitored) {
                return;
            }
        }

        // Restart-aware safe-skip: query the slashing DB for prior attestations.
        let prior = self.slashing_reader.last_signed_attestation(&pubkey_hex, &self.gvr);
        if prior.is_some() {
            states.insert(pubkey_hex, ValidatorState::Safe);
            return;
        }

        let end_epoch = current_epoch + self.monitoring_epochs;
        states.insert(
            pubkey_hex,
            ValidatorState::Pending { start_epoch: current_epoch, end_epoch, detected_live: false },
        );
    }

    /// Advance the state machine by one slot tick.
    ///
    /// A `Pending` validator transitions to `Safe` ONLY when ALL of the
    /// following hold:
    ///
    /// - `current_epoch == end_epoch` (the satisfaction epoch)
    /// - `slot_in_epoch == SLOTS_PER_EPOCH - 1` (the LAST slot of that epoch)
    /// - `detected_live == false` (no unexplained liveness observed)
    ///
    /// Returns the current status of every registered validator.
    pub fn tick(&self, current_epoch: Epoch, slot_in_epoch: u64) -> Vec<DoppelgangerStatus> {
        let mut states = self.states.lock();
        let mut statuses = Vec::with_capacity(states.len());

        for state in states.values_mut() {
            if let ValidatorState::Pending { end_epoch, detected_live, .. } = state {
                // Satisfy only on the exact last slot of end_epoch.
                if current_epoch == *end_epoch
                    && slot_in_epoch == SLOTS_PER_EPOCH - 1
                    && !*detected_live
                {
                    *state = ValidatorState::Safe;
                }
            }

            statuses.push(Self::status_of(state));
        }

        statuses
    }

    /// Record liveness observations for a given epoch.
    ///
    /// For each `ValidatorLivenessData` entry with `is_live == true`, if the
    /// corresponding validator is `Pending`, it transitions to `Detected`
    /// (`detected_live = true` is set before the transition so it is preserved
    /// if the caller inspects intermediate state, though the final state is
    /// `Detected`).
    ///
    /// # D-2 (Issue 2.7)
    ///
    /// Missing-entry fail-closed behavior (absent entries treated as `is_live =
    /// true` for Pending validators) is deferred to Issue 2.7.  Leave a marker:
    // D-2 (Issue 2.7): missing-entry fail-closed lands here
    pub fn observe_liveness(
        &self,
        _epoch: Epoch,
        samples: &[ValidatorLivenessData],
    ) -> Result<(), DoppelgangerError> {
        let mut states = self.states.lock();

        for sample in samples {
            if !sample.is_live {
                continue;
            }
            // The ValidatorLivenessData.index field carries the pubkey hex in
            // this machine (the caller uses pubkey_hex as the index key).
            if let Some(state) = states.get_mut(&sample.index) {
                if let ValidatorState::Pending { detected_live, .. } = state {
                    *detected_live = true;
                    *state = ValidatorState::Detected;
                }
            }
        }

        Ok(())
    }

    /// Remove the validator from the state map.
    ///
    /// The next `register` call will start fresh (KM-2 / Issue 2.12).
    pub fn cancel(&self, pubkey: &crypto::PublicKey) {
        let pubkey_hex = hex::encode(pubkey.to_bytes());
        self.states.lock().remove(&pubkey_hex);
    }

    /// Read-only status inspection for a single validator.
    pub fn status(&self, pubkey: &crypto::PublicKey) -> DoppelgangerStatus {
        let pubkey_hex = hex::encode(pubkey.to_bytes());
        let states = self.states.lock();
        match states.get(&pubkey_hex) {
            None => DoppelgangerStatus::Unmonitored,
            Some(state) => Self::status_of(state),
        }
    }

    fn status_of(state: &ValidatorState) -> DoppelgangerStatus {
        match state {
            ValidatorState::Unmonitored => DoppelgangerStatus::Unmonitored,
            ValidatorState::Pending { .. } => DoppelgangerStatus::Pending,
            ValidatorState::Safe => DoppelgangerStatus::Safe,
            ValidatorState::Detected => DoppelgangerStatus::Detected,
        }
    }
}

impl SigningEnablement for ForwardWindowMachine {
    /// Returns `true` ONLY when the validator state is `Safe`.
    ///
    /// All other states (`Pending`, `Detected`, `Unmonitored`) return `false`
    /// (fail-closed by construction, per PRD §6.3).
    fn is_signing_enabled(&self, pubkey: &crypto::PublicKey) -> bool {
        matches!(self.status(pubkey), DoppelgangerStatus::Safe)
    }
}
