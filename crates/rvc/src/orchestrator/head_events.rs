//! Latest-wins head-event bridge (ARCH-3l / C7).
//!
//! ADR-013 said the trigger "adds no channel" and would consume the existing
//! `mpsc(64)` inside `subscribe_events`. That callback is sync (`Fn(SseEvent)`),
//! so a bridge is required (VD-33). `watch` is bounded (one slot); `send_replace`
//! never blocks; losing an intermediate value is the C7 policy.

use std::time::Duration;

use bn_manager::{HeadEvent, SseEvent};
use eth_types::Slot;
use metrics::definitions::RVC_SSE_EVENTS_DROPPED_TOTAL;
use tokio::sync::watch;

/// Why [`HeadEventGate::wait_for_head_or`] returned. ARCH-3m races the two arms;
/// this issue is timer-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TriggerReason {
    Timer,
    HeadEvent,
}

/// Producer half of the SSE → orchestrator bridge. `publish` is the sync callback.
pub struct HeadEventBridge {
    tx: watch::Sender<Option<HeadEvent>>,
}

impl HeadEventBridge {
    /// Publish a head event. Non-head events are ignored. Never blocks, never
    /// panics if every receiver has been dropped (C7 / C9).
    pub fn publish(&self, event: SseEvent) {
        let SseEvent::Head(head) = event else {
            return;
        };
        let previous = self.tx.send_replace(Some(head));
        // Latest-wins: a superseded head is a C7 drop, not a failure.
        if previous.is_some() {
            record_expected_sse_drop();
        }
    }

    /// Convert into the `Fn(SseEvent)` `BnManager::start_sse` expects.
    pub fn into_callback(self) -> impl Fn(SseEvent) + Send + Sync + 'static {
        move |event| self.publish(event)
    }
}

/// Consumer half. ARCH-3i/3m call [`Self::wait_for_head_or`]; 3l stays timer-only.
#[derive(Clone)]
pub struct HeadEventGate {
    rx: watch::Receiver<Option<HeadEvent>>,
}

impl HeadEventGate {
    /// Build a connected bridge/gate pair.
    pub fn pair() -> (HeadEventBridge, Self) {
        let (tx, rx) = watch::channel(None);
        (HeadEventBridge { tx }, Self { rx })
    }

    /// Timer-only until ARCH-3m implements the head-event race.
    pub async fn wait_for_head_or(&self, _slot: Slot, timer: Duration) -> TriggerReason {
        tokio::time::sleep(timer).await;
        TriggerReason::Timer
    }

    /// Latest published head, if any.
    pub fn latest(&self) -> Option<HeadEvent> {
        self.rx.borrow().clone()
    }
}

/// Increment `rvc_sse_events_dropped_total{expected="true"}`. Never an error path.
pub fn record_expected_sse_drop() {
    RVC_SSE_EVENTS_DROPPED_TOTAL.inc();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    use tracing_test::traced_test;

    fn sample_head(slot: &str) -> HeadEvent {
        HeadEvent {
            slot: slot.to_string(),
            block: "0xab".to_string(),
            state: "0xcd".to_string(),
            epoch_transition: false,
            previous_duty_dependent_root: "0x00".to_string(),
            current_duty_dependent_root: "0x01".to_string(),
            execution_optimistic: false,
        }
    }

    #[test]
    fn test_head_event_bridge_publishes_the_latest_event() {
        let (bridge, gate) = HeadEventGate::pair();
        let first = sample_head("10");
        let second = sample_head("11");

        let start = Instant::now();
        bridge.publish(SseEvent::Head(first));
        bridge.publish(SseEvent::Head(second.clone()));
        assert!(
            start.elapsed() < Duration::from_millis(50),
            "watch send_replace must not block the SSE callback"
        );

        let latest = gate.latest().expect("watch must hold an event");
        assert_eq!(latest.slot, second.slot);
        assert_eq!(latest.block, second.block);
    }

    #[tokio::test]
    async fn test_wait_for_head_or_is_timer_only() {
        let (bridge, gate) = HeadEventGate::pair();
        bridge.publish(SseEvent::Head(sample_head("99")));

        let reason = tokio::time::timeout(
            Duration::from_millis(200),
            gate.wait_for_head_or(1, Duration::from_millis(10)),
        )
        .await
        .expect("timer-only wait must resolve");
        assert_eq!(reason, TriggerReason::Timer, "ARCH-3l must not race the head event");
    }

    #[test]
    #[traced_test]
    fn test_bridge_send_never_blocks_the_sse_callback() {
        let (bridge, gate) = HeadEventGate::pair();
        drop(gate);

        let start = Instant::now();
        bridge.publish(SseEvent::Head(sample_head("1")));
        bridge.publish(SseEvent::Head(sample_head("2")));
        assert!(
            start.elapsed() < Duration::from_millis(50),
            "no-receiver send_replace must return promptly"
        );
        assert!(!logs_contain("ERROR"), "C7: no-receiver must not error-log");
    }

    #[test]
    #[traced_test]
    fn test_sse_drop_counter_is_labelled_expected() {
        let before = RVC_SSE_EVENTS_DROPPED_TOTAL.get();
        let (bridge, gate) = HeadEventGate::pair();

        bridge.publish(SseEvent::Head(sample_head("1")));
        assert_eq!(
            RVC_SSE_EVENTS_DROPPED_TOTAL.get(),
            before,
            "first published head is not a drop"
        );
        bridge.publish(SseEvent::Head(sample_head("2")));

        assert!(
            RVC_SSE_EVENTS_DROPPED_TOTAL.get() > before,
            "latest-wins overwrite with a live gate is an expected-path drop"
        );
        assert_eq!(gate.latest().expect("live gate").slot, "2");
        assert!(!logs_contain("ERROR"), "C7: drop must not error-log");

        let gathered = metrics::REGISTRY.gather();
        let mf = gathered
            .iter()
            .find(|m| m.name() == "rvc_sse_events_dropped_total")
            .expect("rvc_sse_events_dropped_total must be registered");
        for metric in mf.get_metric() {
            let has_expected =
                metric.get_label().iter().any(|l| l.name() == "expected" && l.value() == "true");
            assert!(has_expected, "drop counter must be labelled expected=\"true\"");
            assert!(
                !metric.get_label().iter().any(|l| l.name() == "expected" && l.value() != "true"),
                "drop counter must not carry a non-expected label"
            );
        }
        assert!(
            !gathered.iter().any(|m| {
                let n = m.name();
                n.contains("sse") && (n.contains("fail") || n.contains("error"))
            }),
            "C7: no SSE failure/error metric on drop"
        );
    }
}
