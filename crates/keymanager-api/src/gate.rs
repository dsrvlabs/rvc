//! Time-based doppelganger gate for newly imported validator keys.
//!
//! # M-12 — Post-import doppelganger window
//!
//! After `POST /eth/v1/keystores`, each imported key enters the gate via
//! [`DoppelgangerGate::start_monitoring`]. The gate records the import time and
//! returns `false` from [`DoppelgangerGate::is_doppelganger_safe`] until the
//! configured `window` has elapsed.
//!
//! Concurrently, the import handler spawns a background task that sleeps for
//! `window` and then calls [`ValidatorManager::set_validator_enabled`] to flip
//! the key to attesting-enabled once the window is clear.
//!
//! **Behavior change (GA release):** imported keys are no longer immediately
//! active; they are held for the doppelganger window (default: 2 epochs ≈
//! 768 s on mainnet). Operators who relied on instant activation must account
//! for this delay.

use std::collections::HashMap;
use std::time::Duration;

use parking_lot::Mutex;

use crate::traits::{DoppelgangerMonitor, Pubkey};

/// A time-based per-key doppelganger gate.
///
/// Internally stores the [`tokio::time::Instant`] at which each key's
/// monitoring window started. The tokio mock-clock is honoured, so unit tests
/// can use [`tokio::time::pause`] + [`tokio::time::advance`] to control the
/// window without real-time delays.
///
/// # Example
///
/// ```no_run
/// use std::time::Duration;
/// use rvc_keymanager_api::gate::DoppelgangerGate;
/// use rvc_keymanager_api::traits::{DoppelgangerMonitor, Pubkey};
///
/// let gate = DoppelgangerGate::new(Duration::from_secs(2 * 32 * 12));
/// let pubkey = [0u8; 48];
/// gate.start_monitoring(pubkey);
/// assert!(!gate.is_doppelganger_safe(&pubkey)); // window not yet elapsed
/// ```
pub struct DoppelgangerGate {
    window: Duration,
    /// `pubkey → Instant` at which monitoring began.  Access is serialised via
    /// a `std::sync::Mutex` so the struct is `Send + Sync` without requiring an
    /// async runtime at construction time.
    pending: Mutex<HashMap<Pubkey, tokio::time::Instant>>,
}

impl DoppelgangerGate {
    /// Create a new gate with the given monitoring `window`.
    ///
    /// When `window == Duration::ZERO` every key is immediately safe (equivalent
    /// to disabled doppelganger detection).
    pub fn new(window: Duration) -> Self {
        Self { window, pending: Mutex::new(HashMap::new()) }
    }
}

impl DoppelgangerMonitor for DoppelgangerGate {
    /// Record the start of the doppelganger window for `pubkey`.
    fn start_monitoring(&self, pubkey: Pubkey) {
        let now = tokio::time::Instant::now();
        self.pending.lock().insert(pubkey, now);
    }

    /// Remove `pubkey` from active monitoring (e.g. on key deletion).
    fn stop_monitoring(&self, pubkey: &Pubkey) {
        self.pending.lock().remove(pubkey);
    }

    /// Returns `true` once the doppelganger window has elapsed for `pubkey`.
    ///
    /// Keys not under active monitoring (started before this gate was created,
    /// or never imported via the API) return `true` immediately.
    fn is_doppelganger_safe(&self, pubkey: &Pubkey) -> bool {
        let map = self.pending.lock();
        match map.get(pubkey) {
            None => true, // not monitored → safe by default
            Some(started_at) => started_at.elapsed() >= self.window,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn test_pubkey(seed: u8) -> Pubkey {
        let mut pk = [0u8; 48];
        pk[0] = seed;
        pk
    }

    #[test]
    fn test_unknown_pubkey_is_safe() {
        let gate = DoppelgangerGate::new(Duration::from_secs(60));
        assert!(gate.is_doppelganger_safe(&test_pubkey(1)));
    }

    #[tokio::test]
    async fn test_freshly_monitored_key_is_not_safe() {
        tokio::time::pause();
        let gate = DoppelgangerGate::new(Duration::from_secs(60));
        gate.start_monitoring(test_pubkey(2));
        assert!(!gate.is_doppelganger_safe(&test_pubkey(2)));
    }

    #[tokio::test]
    async fn test_key_safe_after_window_elapses() {
        tokio::time::pause();
        let window = Duration::from_secs(60);
        let gate = DoppelgangerGate::new(window);
        gate.start_monitoring(test_pubkey(3));

        tokio::time::advance(window + Duration::from_millis(1)).await;

        assert!(gate.is_doppelganger_safe(&test_pubkey(3)));
    }

    #[tokio::test]
    async fn test_key_not_safe_just_before_window() {
        tokio::time::pause();
        let window = Duration::from_secs(60);
        let gate = DoppelgangerGate::new(window);
        gate.start_monitoring(test_pubkey(4));

        // Advance to just before the window ends
        tokio::time::advance(window - Duration::from_millis(1)).await;

        assert!(!gate.is_doppelganger_safe(&test_pubkey(4)));
    }

    #[tokio::test]
    async fn test_zero_window_is_immediately_safe() {
        tokio::time::pause();
        // A zero-length window means doppelganger detection is disabled
        let gate = DoppelgangerGate::new(Duration::ZERO);
        gate.start_monitoring(test_pubkey(5));
        // elapsed() >= Duration::ZERO is always true
        assert!(gate.is_doppelganger_safe(&test_pubkey(5)));
    }

    #[tokio::test]
    async fn test_stop_monitoring_removes_pending() {
        tokio::time::pause();
        let gate = DoppelgangerGate::new(Duration::from_secs(60));
        gate.start_monitoring(test_pubkey(6));
        assert!(!gate.is_doppelganger_safe(&test_pubkey(6)));

        gate.stop_monitoring(&test_pubkey(6));
        // Key is no longer monitored → treated as safe by default
        assert!(gate.is_doppelganger_safe(&test_pubkey(6)));
    }
}
