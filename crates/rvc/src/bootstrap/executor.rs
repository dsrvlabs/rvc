//! Named, panic-containing task registry for the composition root (ADR-001).
//!
//! Every background future is registered with a static name and a [`ShutdownTier`].
//! A per-task monitor joins the work handle so a panic surfaces immediately as
//! [`ShutdownReason::Failure`] rather than as a silent leak.
//!
//! Tiered drain budgets and process metrics land in follow-on issues (ARCH-2e / 2f).
//! This module is the core: `register` / `spawn` / `register_opt` and the monitor.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::sync::mpsc;
use tokio::task::{AbortHandle, JoinHandle};
use tokio_util::sync::CancellationToken;

/// Drain order. Lower tiers drain first; each tier is fully drained (or its
/// budget expires) before the next begins.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ShutdownTier {
    /// Surfaces admitting NEW work: keymanager API, gRPC. Stopped first, so a
    /// keymanager import cannot land during orchestrator teardown.
    Ingress,
    /// Duty orchestrator and liveness loop. In-flight publishes complete here.
    Orchestrator,
    /// Refreshers and monitors, incl. registered bn-manager SSE / sync-status.
    Background,
    /// Metrics HTTP + SIGHUP log reload. Drained last so logging guards owned
    /// by `main` flush after all HTTP work is gone.
    Telemetry,
}

/// Why the process is stopping. Enum shape from Lighthouse; transport is rvc's.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ShutdownReason {
    /// Clean, operator-driven or intentional stop.
    Success(&'static str),
    /// A registered task panicked or otherwise failed fatally.
    Failure(&'static str),
}

impl ShutdownReason {
    /// Human-readable reason string (the static label carried by the variant).
    pub fn message(&self) -> &'static str {
        match self {
            Self::Success(msg) | Self::Failure(msg) => msg,
        }
    }
}

/// Per-tier wall-clock budgets. Defaults sum to A-7's 5 s total process budget:
/// Ingress 2.0 / Orchestrator 2.0 / Background 0.5 / Telemetry 0.5.
///
/// Consumed by [`TaskExecutor::shutdown`]; full tier-ordered drain is ARCH-2e.
#[derive(Copy, Clone, Debug)]
pub struct TierBudget([Duration; 4]);

impl Default for TierBudget {
    fn default() -> Self {
        Self([
            Duration::from_millis(2000),
            Duration::from_millis(2000),
            Duration::from_millis(500),
            Duration::from_millis(500),
        ])
    }
}

impl TierBudget {
    /// Budget for a single tier, indexed by [`ShutdownTier`] discriminant order.
    pub fn for_tier(&self, tier: ShutdownTier) -> Duration {
        self.0[tier as usize]
    }

    /// Sum of all tier budgets (A-7 total process budget when using [`Default`]).
    pub fn total(&self) -> Duration {
        self.0.iter().copied().sum()
    }
}

/// Result of draining every registered task.
pub struct ShutdownOutcome {
    /// Tasks whose monitors joined within their tier budget.
    pub joined: Vec<&'static str>,
    /// Tasks that exceeded their tier budget and were aborted.
    pub aborted: Vec<&'static str>,
}

struct Registered {
    name: &'static str,
    /// Drain order key; read by ARCH-2e tiered drain (unused until then).
    #[allow(dead_code)]
    tier: ShutdownTier,
    /// Aborts the work task when its tier budget expires.
    work: AbortHandle,
    /// The monitor; joining it proves the work task finished.
    monitor: JoinHandle<()>,
}

/// Composition-root task registry: named spawns, panic containment, joined shutdown.
///
/// Two entry points:
/// - [`spawn`](Self::spawn) — root owns the future (`tokio::spawn` inside).
/// - [`register`](Self::register) — primitive; wrap an existing [`JoinHandle`].
///
/// `register` has zero live *Infra-crate* callers at HEAD (VD-2d): the four ADR-001
/// Infra sites either have no production caller or are per-pubkey/C5-owned. In-crate
/// callers land in ARCH-2g (metrics server, keymanager API, liveness loop, slashing
/// monitor). Infra rows become live in Phase 3 (ADR-013) when SSE is wired in.
pub struct TaskExecutor {
    token: CancellationToken,
    shutdown_tx: mpsc::Sender<ShutdownReason>,
    registry: Arc<Mutex<Vec<Registered>>>,
    /// Exit classifications (`ok` / `panic` / `cancelled`) in completion order.
    /// Written by every monitor; read by unit tests (ARCH-2f will also drive metrics).
    exits: Arc<Mutex<Vec<(&'static str, &'static str)>>>,
}

impl TaskExecutor {
    /// Build an executor bound to the process shutdown token.
    ///
    /// Returns the executor and the single `ShutdownReason` receiver, which the
    /// composition root selects on alongside `shutdown_signal()`.
    ///
    /// The reason channel is bounded (`mpsc::channel(8)`); monitors use `try_send`
    /// only so panic reporting can never block (C9 anchor 6).
    pub fn new(token: CancellationToken) -> (Self, mpsc::Receiver<ShutdownReason>) {
        let (shutdown_tx, shutdown_rx) = mpsc::channel(8);
        let executor = Self {
            token,
            shutdown_tx,
            registry: Arc::new(Mutex::new(Vec::new())),
            exits: Arc::new(Mutex::new(Vec::new())),
        };
        (executor, shutdown_rx)
    }

    /// Clone of the process cancellation token for cooperative tasks.
    ///
    /// Identical usage to today's `shutdown.clone()` at `bootstrap/tasks.rs`.
    pub fn token(&self) -> CancellationToken {
        self.token.clone()
    }

    /// Entry point 1 — composition root owns the future.
    ///
    /// Defined as `register(name, tier, tokio::spawn(fut))`; no duplicated monitor.
    pub fn spawn<F>(&self, name: &'static str, tier: ShutdownTier, fut: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.register(name, tier, tokio::spawn(fut));
    }

    /// Entry point 2 — **the primitive**. Wrap an existing work [`JoinHandle`].
    ///
    /// Generic over `R` because real handles are not all `JoinHandle<()>` —
    /// `BackgroundTasks::metrics_handle` is `JoinHandle<Result<(), std::io::Error>>`.
    ///
    /// # Call-site status (VD-2d)
    ///
    /// Ships with **zero live Infra-crate callers**. ADR-001's DAG argument for the
    /// shape stands, but `bn-manager` SSE/sync-monitor have no production caller at
    /// HEAD and `keymanager-api` lifecycle is per-pubkey/C5-owned. ARCH-2g registers
    /// four in-crate handles; Phase 3 (ADR-013) is where Infra rows become live.
    ///
    /// # Monitor / registry split
    ///
    /// The monitor task holds the work `JoinHandle`; the registry holds the work's
    /// `AbortHandle`. Aborting the monitor would not stop the work — `shutdown`
    /// aborts `work`, then joins `monitor`.
    pub fn register<R: Send + 'static>(
        &self,
        name: &'static str,
        tier: ShutdownTier,
        handle: JoinHandle<R>,
    ) {
        let work = handle.abort_handle();
        let tx = self.shutdown_tx.clone();
        let exits = Arc::clone(&self.exits);
        let monitor = tokio::spawn(async move {
            let outcome = match handle.await {
                Ok(_) => "ok",
                Err(e) if e.is_panic() => {
                    // try_send only: a full channel means shutdown is already in
                    // flight; awaiting would make panic reporting itself blockable.
                    let _ = tx.try_send(ShutdownReason::Failure(name));
                    "panic"
                }
                Err(_) => "cancelled",
            };
            exits.lock().push((name, outcome));
        });
        self.registry.lock().push(Registered { name, tier, work, monitor });
    }

    /// Feature-disabled case. Registers nothing when `None`.
    ///
    /// Replaces the finished-no-op-handle idiom at `slashing_monitor.rs` so a
    /// disabled feature contributes zero registry entries.
    pub fn register_opt<R: Send + 'static>(
        &self,
        name: &'static str,
        tier: ShutdownTier,
        handle: Option<JoinHandle<R>>,
    ) {
        if let Some(handle) = handle {
            self.register(name, tier, handle);
        }
    }

    /// Cancel the token and join every registered monitor.
    ///
    /// Consumes `self` so a double drain cannot compile. Full tier-ordered budget
    /// drain lands in ARCH-2e; this core path cancels once, aborts unfinished work,
    /// and joins monitors so no task is left orphaned.
    pub async fn shutdown(self, _budget: TierBudget) -> ShutdownOutcome {
        self.token.cancel();

        let registered = {
            let mut guard = self.registry.lock();
            std::mem::take(&mut *guard)
        };

        let mut joined = Vec::with_capacity(registered.len());
        let aborted = Vec::new();

        for r in registered {
            if !r.work.is_finished() {
                r.work.abort();
            }
            let _ = r.monitor.await;
            joined.push(r.name);
        }

        ShutdownOutcome { joined, aborted }
    }

    #[cfg(test)]
    fn registry_len(&self) -> usize {
        self.registry.lock().len()
    }

    #[cfg(test)]
    fn registry_entries(&self) -> Vec<(&'static str, ShutdownTier)> {
        self.registry.lock().iter().map(|r| (r.name, r.tier)).collect()
    }

    #[cfg(test)]
    async fn wait_exits(&self, n: usize) {
        loop {
            if self.exits.lock().len() >= n {
                return;
            }
            tokio::task::yield_now().await;
        }
    }

    #[cfg(test)]
    fn recorded_outcomes(&self) -> Vec<(&'static str, &'static str)> {
        self.exits.lock().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::time::Duration;

    #[tokio::test]
    async fn test_panicking_task_reports_failure_reason() {
        let (exec, mut rx) = TaskExecutor::new(CancellationToken::new());
        exec.spawn("boom_task", ShutdownTier::Background, async {
            panic!("boom");
        });

        let reason = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("timeout waiting for ShutdownReason")
            .expect("channel closed without reason");

        assert_eq!(reason, ShutdownReason::Failure("boom_task"));
        assert_eq!(reason.message(), "boom_task");
    }

    #[tokio::test]
    async fn test_register_is_generic_over_handle_output() {
        let (exec, _rx) = TaskExecutor::new(CancellationToken::new());

        let io_handle: JoinHandle<Result<(), io::Error>> =
            tokio::spawn(async { Ok::<(), io::Error>(()) });
        exec.register("metrics_like", ShutdownTier::Telemetry, io_handle);

        let unit_handle: JoinHandle<()> = tokio::spawn(async {});
        exec.register("unit_task", ShutdownTier::Background, unit_handle);

        assert_eq!(exec.registry_len(), 2);
        let entries = exec.registry_entries();
        assert_eq!(
            entries,
            vec![
                ("metrics_like", ShutdownTier::Telemetry),
                ("unit_task", ShutdownTier::Background),
            ]
        );

        tokio::time::timeout(Duration::from_secs(2), exec.wait_exits(2))
            .await
            .expect("handles should finish");
        let outcomes = exec.recorded_outcomes();
        assert!(outcomes.iter().all(|(_, o)| *o == "ok"));
    }

    #[tokio::test]
    async fn test_spawn_is_register_of_tokio_spawn() {
        let (exec, _rx) = TaskExecutor::new(CancellationToken::new());

        exec.spawn("spawned_a", ShutdownTier::Ingress, async {});
        exec.spawn("spawned_b", ShutdownTier::Orchestrator, async {});

        assert_eq!(exec.registry_len(), 2);
        assert_eq!(
            exec.registry_entries(),
            vec![("spawned_a", ShutdownTier::Ingress), ("spawned_b", ShutdownTier::Orchestrator),]
        );

        tokio::time::timeout(Duration::from_secs(2), exec.wait_exits(2))
            .await
            .expect("spawned tasks should finish");
    }

    #[tokio::test]
    async fn test_register_opt_none_registers_nothing() {
        let (exec, _rx) = TaskExecutor::new(CancellationToken::new());
        assert_eq!(exec.registry_len(), 0);

        exec.register_opt::<()>("disabled_feature", ShutdownTier::Background, None);
        assert_eq!(exec.registry_len(), 0);
        assert!(exec.recorded_outcomes().is_empty());

        let handle = tokio::spawn(async {});
        exec.register_opt("enabled_feature", ShutdownTier::Background, Some(handle));
        assert_eq!(exec.registry_len(), 1);
        assert_eq!(exec.registry_entries(), vec![("enabled_feature", ShutdownTier::Background)]);
    }

    #[tokio::test]
    async fn test_monitor_try_send_never_blocks_when_channel_full() {
        let (exec, _rx) = TaskExecutor::new(CancellationToken::new());
        // Leave the receiver unread so the capacity-8 channel fills.

        const FILL: [&str; 8] =
            ["fill_0", "fill_1", "fill_2", "fill_3", "fill_4", "fill_5", "fill_6", "fill_7"];
        for name in FILL {
            exec.spawn(name, ShutdownTier::Background, async {
                panic!("fill channel");
            });
        }

        tokio::time::timeout(Duration::from_secs(2), exec.wait_exits(8))
            .await
            .expect("fill monitors must complete (try_send, not send().await)");

        exec.spawn("ninth", ShutdownTier::Background, async {
            panic!("ninth");
        });

        tokio::time::timeout(Duration::from_secs(2), exec.wait_exits(9))
            .await
            .expect("ninth monitor must complete when channel is full — proves try_send");

        let outcomes = exec.recorded_outcomes();
        assert_eq!(outcomes.len(), 9);
        assert!(outcomes.iter().all(|(_, o)| *o == "panic"));
    }

    #[tokio::test]
    async fn test_clean_exit_reports_ok_not_panic() {
        let (exec, mut rx) = TaskExecutor::new(CancellationToken::new());

        exec.spawn("clean_task", ShutdownTier::Background, async {
            // normal return
        });

        tokio::time::timeout(Duration::from_secs(2), exec.wait_exits(1))
            .await
            .expect("clean task should finish");

        assert_eq!(exec.recorded_outcomes(), vec![("clean_task", "ok")]);

        // No Failure reason must be delivered for a clean exit.
        let leftover = tokio::time::timeout(Duration::from_millis(50), rx.recv()).await;
        assert!(
            leftover.is_err(),
            "clean exit must not push ShutdownReason::Failure, got {leftover:?}"
        );
    }

    #[test]
    fn test_tier_budget_default_sums_to_five_seconds() {
        let budget = TierBudget::default();
        assert_eq!(budget.total(), Duration::from_secs(5));
        assert_eq!(budget.for_tier(ShutdownTier::Ingress), Duration::from_secs(2));
        assert_eq!(budget.for_tier(ShutdownTier::Orchestrator), Duration::from_secs(2));
        assert_eq!(budget.for_tier(ShutdownTier::Background), Duration::from_millis(500));
        assert_eq!(budget.for_tier(ShutdownTier::Telemetry), Duration::from_millis(500));
    }

    #[test]
    fn test_shutdown_tier_ord_is_drain_order() {
        assert!(ShutdownTier::Ingress < ShutdownTier::Orchestrator);
        assert!(ShutdownTier::Orchestrator < ShutdownTier::Background);
        assert!(ShutdownTier::Background < ShutdownTier::Telemetry);
    }
}
