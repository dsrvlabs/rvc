//! ARCH-1a / ADR-006: a DB-reading tracing subscriber must not wedge stage→sign→commit.
//!
//! Against the pre-ARCH-1a tree, `PubkeyScopedDb::stage_*` called `audit_log` while
//! the staged guard still held the `parking_lot` connection mutex. A subscriber that
//! re-enters the DB on every event deadlocked permanently (C2).
//!
//! Timeout is **thread-based** (`std::thread` + `mpsc::recv_timeout`), never
//! `tokio::time::timeout`: a blocking `parking_lot` lock is not an await point, so
//! an async timeout cannot cancel it and would hang the nextest run instead of failing.

mod common;

use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crypto::SecretKey;
use eth_types::Root;
use slashing::SlashingDb;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::Layer;

const GVR: Root = [0xaa; 32];
const TIMEOUT: Duration = Duration::from_secs(5);

/// Subscriber that acquires the slashing DB lock on every tracing event.
///
/// Reproduces the operator-installable landmine: an ordinary audit/observability
/// layer that reads the slashing DB from `on_event`.
struct DbReadingLayer {
    db: Arc<SlashingDb>,
}

impl<S: tracing::Subscriber> Layer<S> for DbReadingLayer {
    fn on_event(&self, _event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        // Public API that locks `conn` — deadlocks if the staged guard is held.
        let _ = self.db.get_blocks("0xdead");
    }
}

/// Drive a full stage → sign → commit under a DB-reading subscriber.
///
/// Completes within `TIMEOUT` only when `"staged"` audit emission happens
/// **after** the staged guard is released (ARCH-1b / post-fix). Against HEAD
/// pre-ARCH-1a this times out (RED). With emit-after-commit compile bridges it
/// may already pass — that is correct if emit is outside the guard.
#[test]
fn db_reading_subscriber_completes_a_full_stage_sign_commit() {
    let db = Arc::new(SlashingDb::open_in_memory().expect("open in-memory DB"));
    let sk = SecretKey::generate();
    let (pubkey, gate) = common::gate_allowed(sk, Arc::clone(&db));

    let subscriber = tracing_subscriber::registry()
        .with(LevelFilter::INFO)
        .with(DbReadingLayer { db: Arc::clone(&db) });
    let _guard = tracing::subscriber::set_default(subscriber);

    let (tx, rx) = mpsc::channel();
    let signing_root: Root = [0x11; 32];
    let slot = 42u64;

    thread::spawn(move || {
        let runtime =
            tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime");
        let result = runtime.block_on(async {
            gate.sign_block(&pubkey, slot, signing_root, GVR, "audit-deadlock-test").await
        });
        let _ = tx.send(result);
    });

    match rx.recv_timeout(TIMEOUT) {
        Ok(Ok(_sig)) => {
            // Completed without deadlock — success path under the hazardous subscriber.
        }
        Ok(Err(e)) => {
            panic!("stage→sign→commit failed (not a deadlock): {e:?}");
        }
        Err(mpsc::RecvTimeoutError::Timeout) => {
            panic!(
                "db_reading_subscriber_completes_a_full_stage_sign_commit timed out after {TIMEOUT:?}: \
                 audit emission likely still holds the slashing DB mutex (ADR-006 / C2)"
            );
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            panic!("worker thread disconnected without sending a result");
        }
    }
}
