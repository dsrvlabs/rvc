//! Shared HTTP retry / backoff policy for beacon client and other callers
//! (e.g. monitoring push).

use std::time::Duration;

/// Exponential backoff + `Retry-After` policy shared by beacon HTTP and monitoring.
///
/// `max_retries` is the number of *retries after the first attempt* (beacon's
/// engine loops `0..=max_retries`). Callers that budget total attempts
/// independently (e.g. monitoring) still use [`Self::calculate_backoff`] and
/// [`Self::retry_after_delay`] for delay computation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    pub max_retries: u32,
    pub initial_backoff: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self { max_retries: 3, initial_backoff: Duration::from_millis(100) }
    }
}

impl RetryPolicy {
    pub fn new(max_retries: u32, initial_backoff: Duration) -> Self {
        Self { max_retries, initial_backoff }
    }

    /// Exponential backoff with ±25% jitter. `attempt` is 0-based (first retry = 0).
    pub fn calculate_backoff(&self, attempt: u32) -> Duration {
        // Cap the exponent to prevent overflow. 2^20 * 100ms ≈ 27 hours.
        let capped_attempt = attempt.min(20);
        let multiplier = 2u32.saturating_pow(capped_attempt);
        let base = self.initial_backoff.saturating_mul(multiplier);
        let base_ms = base.as_millis() as u64;
        let jitter_range = base_ms / 4; // 25%
        if jitter_range == 0 {
            return base;
        }
        let jitter = rand::Rng::gen_range(&mut rand::thread_rng(), 0..=jitter_range * 2);
        let jittered_ms = base_ms.saturating_sub(jitter_range).saturating_add(jitter);
        Duration::from_millis(jittered_ms)
    }

    /// Parses `Retry-After` (seconds) from a 429 response, capped at 120s.
    /// Falls back to `fallback` if the header is missing or unparseable.
    pub fn retry_after_delay(response: &reqwest::Response, fallback: Duration) -> Duration {
        const MAX_RETRY_AFTER: Duration = Duration::from_secs(120);
        response
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
            .map(|secs| Duration::from_secs(secs).min(MAX_RETRY_AFTER))
            .unwrap_or(fallback)
    }

    /// Transient statuses that should be retried: 429 and 5xx.
    pub fn is_retryable_status(status: reqwest::StatusCode) -> bool {
        status.as_u16() == 429 || status.is_server_error()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_matches_beacon_historical_defaults() {
        let p = RetryPolicy::default();
        assert_eq!(p.max_retries, 3);
        assert_eq!(p.initial_backoff, Duration::from_millis(100));
    }

    #[test]
    fn test_calculate_backoff_jitter_ranges() {
        let p = RetryPolicy::default();
        let b0 = p.calculate_backoff(0).as_millis() as u64;
        assert!((75..=125).contains(&b0), "attempt 0: {b0}");
        let b1 = p.calculate_backoff(1).as_millis() as u64;
        assert!((150..=250).contains(&b1), "attempt 1: {b1}");
        let b2 = p.calculate_backoff(2).as_millis() as u64;
        assert!((300..=500).contains(&b2), "attempt 2: {b2}");
    }

    #[test]
    fn test_is_retryable_status() {
        assert!(RetryPolicy::is_retryable_status(reqwest::StatusCode::TOO_MANY_REQUESTS));
        assert!(RetryPolicy::is_retryable_status(reqwest::StatusCode::INTERNAL_SERVER_ERROR));
        assert!(RetryPolicy::is_retryable_status(reqwest::StatusCode::SERVICE_UNAVAILABLE));
        assert!(!RetryPolicy::is_retryable_status(reqwest::StatusCode::BAD_REQUEST));
        assert!(!RetryPolicy::is_retryable_status(reqwest::StatusCode::NOT_FOUND));
        assert!(!RetryPolicy::is_retryable_status(reqwest::StatusCode::OK));
    }
}
