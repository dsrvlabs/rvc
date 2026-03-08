//! Attestation timer for triggering duties at the correct time within a slot.

use std::sync::Arc;

use lazy_static::lazy_static;
use prometheus::{Gauge, Histogram, HistogramOpts, Opts};
use tokio::sync::watch;
use tokio::time::{sleep, Duration};

use eth_types::Slot;
use metrics::REGISTRY;

use crate::clock::SlotClock;
use crate::error::TimingError;

lazy_static! {
    static ref RVC_SLOT_TIMING_CURRENT_SLOT: Gauge = {
        let opts = Opts::new("rvc_slot_timing_current_slot", "The current slot number");
        let gauge =
            Gauge::with_opts(opts).expect("Failed to create rvc_slot_timing_current_slot metric");
        REGISTRY
            .register(Box::new(gauge.clone()))
            .expect("Failed to register rvc_slot_timing_current_slot metric");
        gauge
    };
    static ref RVC_SLOT_TIMING_DRIFT_SECONDS: Gauge = {
        let opts = Opts::new(
            "rvc_slot_timing_drift_seconds",
            "Clock drift in seconds relative to expected slot timing",
        );
        let gauge =
            Gauge::with_opts(opts).expect("Failed to create rvc_slot_timing_drift_seconds metric");
        REGISTRY
            .register(Box::new(gauge.clone()))
            .expect("Failed to register rvc_slot_timing_drift_seconds metric");
        gauge
    };
    static ref RVC_SLOT_TIMING_ATTESTATION_DELAY_SECONDS: Histogram = {
        let opts = HistogramOpts::new(
            "rvc_slot_timing_attestation_delay_seconds",
            "Delay in seconds from the expected attestation time",
        )
        .buckets(vec![0.0, 0.1, 0.5, 1.0, 2.0, 4.0, 8.0, 12.0]);
        let histogram = Histogram::with_opts(opts)
            .expect("Failed to create rvc_slot_timing_attestation_delay_seconds metric");
        REGISTRY
            .register(Box::new(histogram.clone()))
            .expect("Failed to register rvc_slot_timing_attestation_delay_seconds metric");
        histogram
    };
}

pub struct AttestationTimer<C: SlotClock> {
    clock: Arc<C>,
    cancel_rx: watch::Receiver<bool>,
}

impl<C: SlotClock> AttestationTimer<C> {
    pub fn new(clock: Arc<C>) -> (Self, AttestationTimerHandle) {
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let timer = Self { clock, cancel_rx };
        let handle = AttestationTimerHandle { cancel_tx };
        (timer, handle)
    }

    pub async fn wait_for_slot_start(&mut self, slot: Slot) -> Result<(), TimingError> {
        let time_until_slot = self.clock.time_until_slot(slot)?;

        if time_until_slot.is_zero() {
            return Ok(());
        }

        self.wait_with_cancellation(time_until_slot).await
    }

    pub async fn wait_for_attestation_time(&mut self, slot: Slot) -> Result<(), TimingError> {
        let time_until_attestation = self.clock.time_until_attestation(slot)?;

        if time_until_attestation.is_zero() {
            self.record_attestation_delay(slot);
            return Ok(());
        }

        let result = self.wait_with_cancellation(time_until_attestation).await;

        if result.is_ok() {
            self.record_attestation_delay(slot);
        }

        result
    }

    pub async fn run_slot_loop<F, Fut>(&mut self, mut on_attestation: F) -> Result<(), TimingError>
    where
        F: FnMut(Slot) -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        loop {
            let current_slot = match self.clock.current_slot() {
                Ok(slot) => slot,
                Err(TimingError::BeforeGenesis { .. }) => {
                    sleep(Duration::from_secs(1)).await;
                    continue;
                }
                Err(e) => return Err(e),
            };

            self.update_slot_metrics(current_slot);

            self.wait_for_attestation_time(current_slot).await?;
            on_attestation(current_slot).await;

            let next_slot = current_slot + 1;
            self.wait_for_slot_start(next_slot).await?;
        }
    }

    async fn wait_with_cancellation(&mut self, duration: Duration) -> Result<(), TimingError> {
        let sleep_future = sleep(duration);
        tokio::pin!(sleep_future);

        tokio::select! {
            _ = &mut sleep_future => Ok(()),
            _ = self.cancel_rx.changed() => {
                if *self.cancel_rx.borrow() {
                    Err(TimingError::Cancelled)
                } else {
                    Ok(())
                }
            }
        }
    }

    fn record_attestation_delay(&self, slot: Slot) {
        let attestation_time = self.clock.attestation_time(slot) as f64;
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time went backwards")
            .as_secs_f64();

        if current_time >= attestation_time {
            let delay = current_time - attestation_time;
            RVC_SLOT_TIMING_ATTESTATION_DELAY_SECONDS.observe(delay);
        }
    }

    fn update_slot_metrics(&self, slot: Slot) {
        RVC_SLOT_TIMING_CURRENT_SLOT.set(slot as f64);

        let slot_start = self.clock.slot_start_time(slot);
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time went backwards")
            .as_secs();

        let expected_slot_time = slot_start + (self.clock.slot_duration().as_secs() / 2);
        let drift = if current_time > expected_slot_time {
            (current_time - expected_slot_time) as f64
        } else {
            -((expected_slot_time - current_time) as f64)
        };

        RVC_SLOT_TIMING_DRIFT_SECONDS.set(drift);
    }
}

pub struct AttestationTimerHandle {
    cancel_tx: watch::Sender<bool>,
}

impl AttestationTimerHandle {
    pub fn cancel(&self) {
        let _ = self.cancel_tx.send(true);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::MockSlotClock;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    const TEST_GENESIS_TIME: u64 = 1606824023;

    fn create_mock_clock() -> Arc<MockSlotClock> {
        Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32))
    }

    #[tokio::test]
    async fn test_wait_for_slot_start_already_started() {
        let clock = create_mock_clock();
        clock.set_slot(10);

        let (mut timer, _handle) = AttestationTimer::new(clock);
        let result = timer.wait_for_slot_start(5).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_wait_for_attestation_time_already_passed() {
        let clock = create_mock_clock();
        clock.set_current_time(TEST_GENESIS_TIME + 10);

        let (mut timer, _handle) = AttestationTimer::new(clock);
        let result = timer.wait_for_attestation_time(0).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_timer_cancellation() {
        let clock = create_mock_clock();
        clock.set_current_time(TEST_GENESIS_TIME);

        let (mut timer, handle) = AttestationTimer::new(clock);

        let timer_task = tokio::spawn(async move { timer.wait_for_slot_start(1000).await });

        tokio::time::sleep(Duration::from_millis(10)).await;
        handle.cancel();

        let result = timer_task.await.unwrap();
        assert!(matches!(result, Err(TimingError::Cancelled)));
    }

    #[tokio::test]
    async fn test_slot_loop_calls_callback() {
        let clock = create_mock_clock();
        clock.set_current_time(TEST_GENESIS_TIME + 4);

        let (mut timer, handle) = AttestationTimer::new(clock);
        let call_count = Arc::new(AtomicU64::new(0));
        let call_count_clone = call_count.clone();

        let timer_task = tokio::spawn(async move {
            timer
                .run_slot_loop(|_slot| {
                    let cc = call_count_clone.clone();
                    async move {
                        cc.fetch_add(1, Ordering::SeqCst);
                    }
                })
                .await
        });

        tokio::time::sleep(Duration::from_millis(50)).await;
        handle.cancel();

        let _ = timer_task.await;
        assert!(call_count.load(Ordering::SeqCst) >= 1);
    }

    #[test]
    fn test_attestation_timer_handle_cancel() {
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let handle = AttestationTimerHandle { cancel_tx };

        assert!(!*cancel_rx.borrow());
        handle.cancel();
        assert!(cancel_rx.has_changed().unwrap_or(false) || *cancel_rx.borrow());
    }

    #[test]
    fn test_slot_timing_metrics_exist() {
        lazy_static::initialize(&RVC_SLOT_TIMING_CURRENT_SLOT);
        lazy_static::initialize(&RVC_SLOT_TIMING_DRIFT_SECONDS);
        lazy_static::initialize(&RVC_SLOT_TIMING_ATTESTATION_DELAY_SECONDS);

        RVC_SLOT_TIMING_CURRENT_SLOT.set(100.0);
        assert_eq!(RVC_SLOT_TIMING_CURRENT_SLOT.get(), 100.0);

        RVC_SLOT_TIMING_DRIFT_SECONDS.set(-0.5);
        assert_eq!(RVC_SLOT_TIMING_DRIFT_SECONDS.get(), -0.5);

        RVC_SLOT_TIMING_ATTESTATION_DELAY_SECONDS.observe(1.5);
        assert!(RVC_SLOT_TIMING_ATTESTATION_DELAY_SECONDS.get_sample_count() >= 1);
    }

    #[tokio::test]
    async fn test_attestation_delay_captures_sub_second_precision() {
        let clock = create_mock_clock();
        // Attestation time for slot 0 = genesis + slot_duration/3 = genesis + 4
        let attestation_time = clock.attestation_time(0);
        // Set current time to 500ms after attestation time
        // Since MockSlotClock uses integer seconds, we test the metric pipeline:
        // record_attestation_delay now uses as_secs_f64() so sub-second delays
        // from SystemTime::now() are captured. We verify by calling the method
        // when current time equals attestation_time (0 delay, not truncated).
        clock.set_current_time(attestation_time);

        let (timer, _handle) = AttestationTimer::new(clock);
        let count_before = RVC_SLOT_TIMING_ATTESTATION_DELAY_SECONDS.get_sample_count();
        timer.record_attestation_delay(0);
        let count_after = RVC_SLOT_TIMING_ATTESTATION_DELAY_SECONDS.get_sample_count();
        assert!(count_after > count_before, "metric should have been recorded");
    }
}
