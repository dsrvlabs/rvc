//! Validator state for the forward-window doppelganger state machine.

use eth_types::Epoch;

/// Per-validator state in the forward-window doppelganger machine.
pub enum ValidatorState {
    /// Pubkey has never been registered with this machine.
    Unmonitored,
    /// Validator is in the monitoring window.
    ///
    /// `detected_live` is set when `observe_liveness` finds an unexplained
    /// `is_live == true` while in this state, transitioning to `Detected`.
    Pending { start_epoch: Epoch, end_epoch: Epoch, detected_live: bool },
    /// Monitoring window completed with no unexplained liveness → safe to sign.
    Safe,
    /// An unexplained `is_live` was observed during the monitoring window.
    Detected,
}

/// Observable status returned by `tick` and `status`.
///
/// `Copy` so callers can cheaply pass it around without cloning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DoppelgangerStatus {
    /// Pubkey is unknown to this machine.
    Unmonitored,
    /// Monitoring window is active.
    Pending,
    /// Monitoring complete; signing allowed.
    Safe,
    /// Doppelganger detected; signing denied.
    Detected,
}
