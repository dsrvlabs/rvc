use std::collections::HashMap;
use std::time::{Duration, Instant};

use tracing::warn;

/// Tracks decryption attempts per public key to detect and rate-limit potential brute-force attacks.
///
/// While offline attacks cannot be fully prevented when an attacker has access to keystore files,
/// this tracker provides:
/// - Logging of failed attempts with timestamps for audit/alerting
/// - Rate limiting to slow down automated attacks
pub struct DecryptionAttemptTracker {
    attempts: HashMap<String, Vec<Instant>>,
    max_attempts: usize,
    window: Duration,
}

impl DecryptionAttemptTracker {
    /// Creates a new tracker with the specified rate limiting parameters.
    ///
    /// # Arguments
    /// * `max_attempts` - Maximum number of attempts allowed within the time window
    /// * `window` - Time window for rate limiting
    pub fn new(max_attempts: usize, window: Duration) -> Self {
        Self { attempts: HashMap::new(), max_attempts, window }
    }

    /// Checks if an attempt is allowed and records it if so.
    ///
    /// Returns `true` if the attempt is allowed, `false` if rate limit exceeded.
    pub fn check_and_record(&mut self, pubkey: &str) -> bool {
        let now = Instant::now();
        let attempts = self.attempts.entry(pubkey.to_string()).or_default();

        // Remove old attempts outside window
        attempts.retain(|t| now.duration_since(*t) < self.window);

        if attempts.len() >= self.max_attempts {
            warn!(
                pubkey = %pubkey,
                attempts = attempts.len(),
                "Rate limit exceeded for keystore decryption"
            );
            return false;
        }

        attempts.push(now);
        true
    }

    /// Records a failed decryption attempt and logs a warning.
    pub fn record_failure(&mut self, pubkey: &str) {
        warn!(
            pubkey = %pubkey,
            "Failed decryption attempt for keystore"
        );
    }

    /// Clears expired entries from the tracker to free memory.
    pub fn clear_expired(&mut self) {
        let now = Instant::now();
        self.attempts.retain(|_, attempts| {
            attempts.retain(|t| now.duration_since(*t) < self.window);
            !attempts.is_empty()
        });
    }

    /// Returns the number of recent attempts for a given public key.
    pub fn attempt_count(&self, pubkey: &str) -> usize {
        self.attempts
            .get(pubkey)
            .map(|attempts| {
                let now = Instant::now();
                attempts.iter().filter(|t| now.duration_since(**t) < self.window).count()
            })
            .unwrap_or(0)
    }
}

impl Default for DecryptionAttemptTracker {
    fn default() -> Self {
        // Default: 5 attempts per 60 seconds
        Self::new(5, Duration::from_secs(60))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_tracker_allows_attempts_within_limit() {
        let mut tracker = DecryptionAttemptTracker::new(3, Duration::from_secs(60));
        let pubkey = "abc123";

        assert!(tracker.check_and_record(pubkey));
        assert!(tracker.check_and_record(pubkey));
        assert!(tracker.check_and_record(pubkey));
    }

    #[test]
    fn test_tracker_blocks_after_max_attempts() {
        let mut tracker = DecryptionAttemptTracker::new(3, Duration::from_secs(60));
        let pubkey = "abc123";

        assert!(tracker.check_and_record(pubkey));
        assert!(tracker.check_and_record(pubkey));
        assert!(tracker.check_and_record(pubkey));
        // Fourth attempt should be blocked
        assert!(!tracker.check_and_record(pubkey));
    }

    #[test]
    fn test_tracker_resets_after_window_expires() {
        let mut tracker = DecryptionAttemptTracker::new(2, Duration::from_millis(50));
        let pubkey = "abc123";

        assert!(tracker.check_and_record(pubkey));
        assert!(tracker.check_and_record(pubkey));
        // Should be blocked
        assert!(!tracker.check_and_record(pubkey));

        // Wait for window to expire
        thread::sleep(Duration::from_millis(60));

        // Should be allowed again
        assert!(tracker.check_and_record(pubkey));
    }

    #[test]
    fn test_tracker_handles_multiple_pubkeys_independently() {
        let mut tracker = DecryptionAttemptTracker::new(2, Duration::from_secs(60));
        let pubkey1 = "abc123";
        let pubkey2 = "def456";

        // Fill up pubkey1
        assert!(tracker.check_and_record(pubkey1));
        assert!(tracker.check_and_record(pubkey1));
        assert!(!tracker.check_and_record(pubkey1));

        // pubkey2 should still be allowed
        assert!(tracker.check_and_record(pubkey2));
        assert!(tracker.check_and_record(pubkey2));
    }

    #[test]
    fn test_attempt_count() {
        let mut tracker = DecryptionAttemptTracker::new(5, Duration::from_secs(60));
        let pubkey = "abc123";

        assert_eq!(tracker.attempt_count(pubkey), 0);
        tracker.check_and_record(pubkey);
        assert_eq!(tracker.attempt_count(pubkey), 1);
        tracker.check_and_record(pubkey);
        assert_eq!(tracker.attempt_count(pubkey), 2);
    }

    #[test]
    fn test_clear_expired() {
        let mut tracker = DecryptionAttemptTracker::new(5, Duration::from_millis(50));
        let pubkey = "abc123";

        tracker.check_and_record(pubkey);
        tracker.check_and_record(pubkey);
        assert_eq!(tracker.attempt_count(pubkey), 2);

        // Wait for window to expire
        thread::sleep(Duration::from_millis(60));

        tracker.clear_expired();
        assert_eq!(tracker.attempt_count(pubkey), 0);
    }

    #[test]
    fn test_default_tracker() {
        let tracker = DecryptionAttemptTracker::default();
        // Default is 5 attempts per 60 seconds
        assert_eq!(tracker.max_attempts, 5);
        assert_eq!(tracker.window, Duration::from_secs(60));
    }

    #[test]
    fn test_record_failure_does_not_panic() {
        let mut tracker = DecryptionAttemptTracker::new(5, Duration::from_secs(60));
        // Should not panic
        tracker.record_failure("abc123");
    }
}
