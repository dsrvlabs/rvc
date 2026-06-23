# test-capture-design
## Summary
The PRD's precedent (`crates/secret-provider/tests/tracing_hierarchy.rs`) uses `tracing::subscriber::set_default` which returns a `DefaultGuard` — thread-local, RAII-scoped. **The PRD's Risks section says "use `with_default` (scoped)", but `with_default` is closure-scoped and incompatible with a drop-based `TestTracingGuard` design.** The correct API is `set_default`; flag this contradiction but proceed with the working design.

## `set_default` vs `with_default` vs `set_global_default`

| API | Scope | Lifetime mechanism | Correct for `TestTracingGuard`? |
|---|---|---|---|
| `tracing::dispatcher::set_default(&dispatch)` | Thread-local | Returns `DefaultGuard`; RAII on drop restores previous. | **YES.** |
| `tracing::subscriber::set_default(subscriber)` | Thread-local | Same `DefaultGuard` RAII. Preferred modern surface. | **YES.** |
| `tracing::subscriber::with_default(subscriber, f: FnOnce)` | Thread-local | Closure-scoped; reverts when closure returns. No guard. | **NO** — incompatible with `Drop`-based guard design. |
| `tracing::subscriber::set_global_default(subscriber)` | Global, program-wide | Permanent (cannot be un-set for process lifetime). | **NO** — `cargo test` runs tests in parallel threads; a global subscriber collides across tests. |

Existing `secret-provider/tests/tracing_hierarchy.rs:59` already uses `set_default` — confirmed correct pattern.

## `TestWriter` and cargo test capture

- `tracing_subscriber::fmt::TestWriter` channels fmt-layer output through `print!` / `eprint!`, which libtest captures.
- Writing to `io::stdout()` directly produces "as if `--nocapture`" behavior — visible even on passing tests.
- For `TestTracingGuard` design: **do NOT use TestWriter** for the capture mechanism. Instead, stash events+spans into an in-memory buffer owned by the guard; on `Drop` during `std::thread::panicking()`, write the buffer via `println!` so libtest captures it and displays it on test failure.

## `TestTracingGuard` design sketch

```rust
// crates/telemetry/src/test_capture.rs

use std::sync::{Arc, Mutex};
use tracing::subscriber::DefaultGuard;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::Registry;

#[derive(Clone, Default)]
struct CaptureBuffer {
    events: Arc<Mutex<Vec<CapturedEvent>>>,
    spans: Arc<Mutex<Vec<CapturedSpan>>>,
}

struct CapturedSpan { id: u64, parent_id: Option<u64>, name: &'static str, fields: Vec<(&'static str, String)> }
struct CapturedEvent { span_id: Option<u64>, level: tracing::Level, message: String, fields: Vec<(&'static str, String)> }

struct CaptureLayer { buf: CaptureBuffer }
// impl Layer<S>: on_new_span → push CapturedSpan; on_event → push CapturedEvent.

#[must_use = "dropping TestTracingGuard ends capture"]
pub struct TestTracingGuard {
    buf: CaptureBuffer,
    _default: DefaultGuard, // thread-local subscriber; reverts on drop.
}

impl TestTracingGuard {
    pub fn install() -> Self {
        let buf = CaptureBuffer::default();
        let layer = CaptureLayer { buf: buf.clone() };
        let subscriber = Registry::default().with(layer);
        let _default = tracing::subscriber::set_default(subscriber);
        Self { buf, _default }
    }

    /// Test assertions: spans by name, parent-child, fields on a span.
    pub fn spans_named(&self, name: &str) -> Vec<CapturedSpan> { /* ... */ }
    pub fn event_count_at(&self, level: tracing::Level) -> usize { /* ... */ }
    pub fn assert_span_tree(&self, expected: &[(&str, Option<&str>)]) { /* ... */ }
}

impl Drop for TestTracingGuard {
    fn drop(&mut self) {
        if std::thread::panicking() {
            // Only print on test failure.
            let spans = self.buf.spans.lock().unwrap();
            let events = self.buf.events.lock().unwrap();
            // Pretty-print span tree (indented by depth) with child events.
            println!("\n=== rvc-telemetry test span tree ===");
            print_tree(&spans, &events);
            println!("=====================================");
        }
        // DefaultGuard field drops after us — reverts the subscriber.
    }
}
```

Key points:
- `std::thread::panicking()` returns `true` when `Drop` is running because the test panicked. False for passing tests → silent drop, no noise.
- `set_default` (thread-local) — `cargo test`'s default parallel threads each get independent subscribers. No collision.
- **Never call `set_global_default`** inside `TestTracingGuard`. PRD risk mitigation is correct in spirit even if the API name is wrong.

## Standard test preamble

```rust
use telemetry::test_capture::TestTracingGuard;

#[tokio::test]
async fn test_aggregation_submits_on_schedule() {
    let _guard = TestTracingGuard::install();
    // ... test body — on panic, span tree prints via cargo test capture ...
}
```

PRD mentions an `#[rvc_test]` macro; given the PRD forbids unjustified dependency churn, recommend starting with the plain `let _guard = ...;` pattern. Add the macro later as a P2 nice-to-have (reduces one line per test; saves nothing architectural).

## Interference with existing tests

- Existing `secret-provider/tests/tracing_hierarchy.rs` **already** uses `set_default` with a custom `Layer`. The new `TestTracingGuard` uses the same mechanism, so the two don't conflict — each test sets its own thread-local.
- If a test elsewhere uses `tracing_subscriber::fmt::init()` or `set_global_default`, it installs a global fallback. Thread-local `set_default` overrides the global for that thread — safe.
- Discipline to document in `docs/observability.md`:
  - One guard per test. Do not nest or stack guards in the same test.
  - Do not call `set_global_default` anywhere in test code. Workspace `#[cfg(test)]` grep check in the forbidden-pattern test to enforce.
  - Tests that produce panics in spawned tasks may lose their span context if the task outlives the guard. For those, move the assertion logic inline.

## Sources

- [`tracing::subscriber::set_default`](https://docs.rs/tracing/0.1/tracing/subscriber/fn.set_default.html) — thread-local, DefaultGuard RAII.
- [`tracing::subscriber::with_default`](https://docs.rs/tracing/0.1/tracing/subscriber/fn.with_default.html) — closure-scoped; NOT what the PRD design needs.
- [`tracing_subscriber::fmt::TestWriter`](https://docs.rs/tracing-subscriber/0.3/tracing_subscriber/fmt/struct.TestWriter.html) — libtest-capture friendly.
- Direct source: `/Users/joonkyo.kim/git/dsrv/rvc/crates/secret-provider/tests/tracing_hierarchy.rs` — in-tree precedent.
- [`std::thread::panicking`](https://doc.rust-lang.org/std/thread/fn.panicking.html) — signal for "test is dying, dump context".

---
