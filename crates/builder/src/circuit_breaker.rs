use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// Lock-free circuit breaker for builder block production.
///
/// Uses atomics for zero-overhead checking on the block production hot path.
/// The breaker tracks two independent conditions:
/// - Consecutive missed builder slots
/// - Total missed builder slots in the current epoch
///
/// Either condition exceeding its threshold trips the breaker.
pub struct CircuitBreakerState {
    consecutive_misses: AtomicU32,
    epoch_misses: AtomicU32,
    current_epoch: AtomicU64,
    consecutive_limit: u32,
    epoch_limit: u32,
}

impl CircuitBreakerState {
    pub fn new(consecutive_limit: u32, epoch_limit: u32) -> Self {
        Self {
            consecutive_misses: AtomicU32::new(0),
            epoch_misses: AtomicU32::new(0),
            current_epoch: AtomicU64::new(0),
            consecutive_limit,
            epoch_limit,
        }
    }

    /// Returns true if builder should be bypassed for this slot.
    /// Cost: two atomic loads (~1ns on x86).
    pub fn is_tripped(&self) -> bool {
        if self.consecutive_limit == 0 && self.epoch_limit == 0 {
            return false;
        }
        // Acquire: pairs with the Release/AcqRel stores in record_miss,
        // record_success, and reset_epoch, ensuring we observe their writes on
        // all platforms (including ARM weak-memory-order targets).
        let consec = self.consecutive_misses.load(Ordering::Acquire);
        let epoch = self.epoch_misses.load(Ordering::Acquire);
        (self.consecutive_limit > 0 && consec >= self.consecutive_limit)
            || (self.epoch_limit > 0 && epoch >= self.epoch_limit)
    }

    /// Record a builder miss (failed or empty response).
    pub fn record_miss(&self) {
        // AcqRel: the Release half makes the incremented value visible to any
        // subsequent Acquire load on other threads.
        self.consecutive_misses.fetch_add(1, Ordering::AcqRel);
        self.epoch_misses.fetch_add(1, Ordering::AcqRel);
    }

    /// Record a builder success. Resets consecutive counter only.
    pub fn record_success(&self) {
        // Release: pairs with Acquire loads in is_tripped / consecutive_misses.
        self.consecutive_misses.store(0, Ordering::Release);
    }

    /// Reset at epoch boundary. Zeroes both counters.
    pub fn reset_epoch(&self, new_epoch: u64) {
        // AcqRel on the swap: the Release half ensures the subsequent stores are
        // not reordered before the swap on weak-memory-order CPUs; the Acquire
        // half lets us observe prior writes from other threads.
        let prev = self.current_epoch.swap(new_epoch, Ordering::AcqRel);
        if new_epoch != prev {
            // Release: zeroing is visible to any thread that later does an
            // Acquire load on these counters.
            self.consecutive_misses.store(0, Ordering::Release);
            self.epoch_misses.store(0, Ordering::Release);
        }
    }

    pub fn consecutive_misses(&self) -> u32 {
        // Acquire: pairs with Release/AcqRel stores so the returned value
        // reflects the latest write from any thread.
        self.consecutive_misses.load(Ordering::Acquire)
    }

    pub fn epoch_misses(&self) -> u32 {
        // Acquire: see consecutive_misses() above.
        self.epoch_misses.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_breaker_not_tripped() {
        let cb = CircuitBreakerState::new(3, 5);
        assert!(!cb.is_tripped());
    }

    #[test]
    fn test_consecutive_limit_trips() {
        let cb = CircuitBreakerState::new(3, 5);
        cb.record_miss();
        cb.record_miss();
        assert!(!cb.is_tripped());
        cb.record_miss();
        assert!(cb.is_tripped());
    }

    #[test]
    fn test_epoch_limit_trips() {
        let cb = CircuitBreakerState::new(3, 5);
        for _ in 0..4 {
            cb.record_miss();
            cb.record_success(); // resets consecutive but not epoch
        }
        assert!(!cb.is_tripped());
        assert_eq!(cb.consecutive_misses(), 0);
        assert_eq!(cb.epoch_misses(), 4);

        cb.record_miss(); // epoch_misses = 5
        assert!(cb.is_tripped());
    }

    #[test]
    fn test_record_success_resets_consecutive_only() {
        let cb = CircuitBreakerState::new(3, 5);
        cb.record_miss();
        cb.record_miss();
        assert_eq!(cb.consecutive_misses(), 2);
        assert_eq!(cb.epoch_misses(), 2);

        cb.record_success();
        assert_eq!(cb.consecutive_misses(), 0);
        assert_eq!(cb.epoch_misses(), 2);
    }

    #[test]
    fn test_reset_epoch_zeroes_both_counters() {
        let cb = CircuitBreakerState::new(3, 5);
        cb.record_miss();
        cb.record_miss();
        cb.record_miss();
        assert!(cb.is_tripped());

        cb.reset_epoch(1);
        assert!(!cb.is_tripped());
        assert_eq!(cb.consecutive_misses(), 0);
        assert_eq!(cb.epoch_misses(), 0);
    }

    #[test]
    fn test_reset_epoch_same_epoch_noop() {
        let cb = CircuitBreakerState::new(3, 5);
        cb.reset_epoch(1);
        cb.record_miss();
        cb.record_miss();
        assert_eq!(cb.consecutive_misses(), 2);

        cb.reset_epoch(1); // same epoch, should not reset
        assert_eq!(cb.consecutive_misses(), 2);
        assert_eq!(cb.epoch_misses(), 2);
    }

    #[test]
    fn test_disabled_when_both_limits_zero() {
        let cb = CircuitBreakerState::new(0, 0);
        for _ in 0..100 {
            cb.record_miss();
        }
        assert!(!cb.is_tripped());
    }

    #[test]
    fn test_only_consecutive_limit_set() {
        let cb = CircuitBreakerState::new(2, 0);
        cb.record_miss();
        assert!(!cb.is_tripped());
        cb.record_miss();
        assert!(cb.is_tripped());
    }

    #[test]
    fn test_only_epoch_limit_set() {
        let cb = CircuitBreakerState::new(0, 3);
        cb.record_miss();
        cb.record_miss();
        assert!(!cb.is_tripped());
        cb.record_miss();
        assert!(cb.is_tripped());
    }

    #[test]
    fn test_concurrent_access() {
        use std::sync::Arc;
        let cb = Arc::new(CircuitBreakerState::new(100, 200));
        let mut handles = vec![];

        for _ in 0..10 {
            let cb = cb.clone();
            handles.push(std::thread::spawn(move || {
                for _ in 0..50 {
                    cb.record_miss();
                    cb.is_tripped();
                    cb.record_success();
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        // No panics or data races — counters may be any consistent value
        let _ = cb.is_tripped();
    }
}
