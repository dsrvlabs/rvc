# Research: Does `tracing` instrumentation add measurable overhead on the rs-vc per-slot loop and sign path, and how do we GUARANTEE P0-6?

## Verdict

**Yes, we can guarantee P0-6 (zero-overhead-when-disabled + no `info`-level regression) with the patterns the codebase already uses, plus two additions.** A disabled `trace!`/`debug!` in `tracing` reduces to *"an integer load, comparison and jump"* (the same fast path `log` documents) [1], and a span created with **no active interest** costs ~**0.7 ns to construct and ~0.5 ns to enter** in the upstream `no_subscriber` benchmarks [2] — i.e. effectively free relative to a BLS sign (sub-millisecond to milliseconds) and the 12 s slot. The guarantee is **conditional on three rules**, all already partly in force in `crates/`: (a) put a `level = "..."` on every hot-path `#[instrument]` and use `skip_all`; (b) wrap any field that requires work (hashing a root, `serde_json` of a body, `format!`) behind a `tracing::enabled!` guard or a zero-alloc `Display` wrapper; and (c) **belt-and-braces: compile a `release_max_level_debug` (or `info`) static cap into the production binary** so `trace!` and the disabled-level spans are *removed from the binary entirely*, which also neutralizes the one real residual cost of a runtime `EnvFilter` (its dynamic directives defeat the per-callsite interest cache). Verification is a `criterion` microbench on the sign path + a per-slot-loop bench asserting **identical** timing and **zero allocations** between "subscriber disabled" and "no instrumentation", using `#[global_allocator]` counting.

## Context

- **Question:** What is the real runtime cost of `tracing` on rs-vc's hot paths, and what concrete techniques + verification satisfy **P0-6** ("disabled `debug!`/`trace!` must perform no allocation, formatting, or hashing … no measurable latency added to the signing/attestation path at the default `info` level")?
- **Why it matters:** rs-vc signs attestations/blocks on a hard per-slot deadline; a regression that pushes the sign past the intra-slot deadline = missed duty = lost rewards, and the project is *adding* hundreds of `trace!`/`debug!` sites under P0-4. The risk register flags "hot-path latency regression … Missed duties / slashing-deadline pressure" explicitly. We must prove the new logging is free when off and negligible at `info`.
- **Hot paths in scope (from the code):**
  - **Sign path:** `crypto::signing::compute_signing_root` → `crypto::{block_signing,signing,aggregation_signing,sync_signing}::*` (already `#[instrument(level="debug", skip_all)]`) → `crypto::bls::SecretKey::sign` (BLS) → wrapped by `signer::gate::SigningGate` (slashing-DB + doppelganger + `spawn_blocking`) and, for the Web3Signer `:9000` path, `bin/rvc-signer` HTTP handler.
  - **Per-slot loop:** `timing::timer` slot ticks (`trace!(... "slot loop tick")`) → `rvc::orchestrator::coordinator` → `SlotContext::capture` (BN `get_block_root`) → attestation/aggregation/sync/block phases → `duty-tracker::tracker` cache hit/miss (`trace!`) → `beacon::client` HTTP (already has an `enabled!`-guarded `trace!`).
- **Stack:** `tracing = "0.1"`, `tracing-subscriber = "0.3"`, OTLP via `tracing-opentelemetry`. Both binaries select level via `EnvFilter`. **No criterion/bench harness exists in the workspace today** (no `[[bench]]`, no `criterion` dep) — building one is part of satisfying P0-6.

## Findings

### What Works (the zero-cost story holds)

**1. A disabled event/span is a single branch — confirmed at the source level.**
`tracing`'s macros check `STATIC_MAX_LEVEL` (a compile-time constant) and then a cached per-callsite *interest* before constructing anything. The `log` crate — which shares this design and which `tracing` mirrors — documents the disabled-path cost as literally *"just an integer load, comparison and jump"* [1]. `tracing`'s own docs: *"For performance reasons, if no currently active subscribers express interest in a given set of metadata by returning `true`, then the corresponding `Span` or `Event` will never be constructed."* [3] Because the check happens **before** the event/span body, **the field expressions are not evaluated when disabled** — this is the property P0-6 needs ("no allocation, formatting, or hashing"). [3][4]

**2. Concrete numbers: a no-interest span is ~sub-nanosecond.** The upstream `no_subscriber` criterion benchmarks (tokio-rs/tracing PR #1974, "reduce disabled span `Drop` overhead", 2022) measure span create/enter when **no subscriber is active**:

```
no_subscriber/span        time: [696.37 ps 696.53 ps 696.73 ps]   (~0.70 ns)
no_subscriber/span_enter  time: [465.58 ps 466.35 ps 467.61 ps]   (~0.47 ns)
```
[2] For scale: a single BLS signature is on the order of ~hundreds of microseconds to low milliseconds, and the slot is 12 000 ms. A ~1 ns span is **~6 orders of magnitude** below the sign cost. The same PR shows the disabled-`Drop` path was made `#[inline(always)]` so the dispatcher call only happens when enabled [2] — i.e. modern `tracing` is specifically optimized for exactly our "spans present but disabled in prod" case.

**3. `#[instrument]` uses the same level/interest gate, so a `level="debug"` span on a hot async fn is free at `info`.** The attribute expands to the `span!`/`*_span!` machinery, which is governed by `STATIC_MAX_LEVEL` and the per-callsite interest check [5][3]. The codebase already does this correctly: every `crypto` sign fn carries `#[tracing::instrument(name=..., level = "debug", skip_all, fields(...))]` (e.g. `block_signing.rs:8`, `signing.rs:38`). With the production default at `info`, those spans are the cheap disabled-span case above. **`skip_all` is load-bearing**: without it the macro `Debug`-formats every argument into the span; `skip`/`skip_all` exist precisely *"to exclude an argument with a verbose or costly `Debug` implementation"* and let you skip args that don't implement `Debug` at all [4] — critical for `&SecretKey`, `&BeaconBlock`, signing payloads.

**4. The codebase's existing `enabled!`-guard pattern is exactly right for expensive fields.** `beacon/src/client.rs:149` already does:
```rust
if tracing::enabled!(tracing::Level::TRACE) {
    let body_size = serde_json::to_vec(body).map(|b| b.len()).unwrap_or(0);
    trace!(method = "POST", endpoint = path, body_size_bytes = body_size, "HTTP request body");
}
```
`enabled!(Level::X)` returns whether the current subscriber would record at that level, and the documented purpose is *"to guard expensive computations that should only run if logging will actually occur"* [6]. This is the sanctioned tool for the PRD's "hash a root only when trace is on" requirement: the `serde_json::to_vec` (an allocation + serialization) never runs at `info`. **Caveat:** `enabled!` can yield false negatives/positives when a subscriber filters on fields or file/line that the macro can't see [6]; for our case (level-only filtering via `EnvFilter`) it is accurate.

**5. Zero-alloc `Display` wrappers already give us "no string built when disabled".** `crypto::logging::{TruncatedPubkey, RedactedUrl}` implement `Display` and are documented "for zero-allocation use with tracing's `%` specifier. When tracing level is disabled, `Display::fmt` is never called." (`logging.rs:1-4`). Passing `%TruncatedPubkey(hex)` rather than a pre-built `format!()` string means the truncation/redaction only runs when the line is actually emitted — same principle as the PRD's "Prefer `Display` wrappers over `format!()`".

**6. Compile-time static-max-level removes verbose code from the binary entirely.** Both `log` and `tracing` expose Cargo features that set `STATIC_MAX_LEVEL`: `max_level_{off,error,warn,info,debug,trace}` and `release_max_level_{…}` (release-profile only) [7][8][1]. *"Trace instrumentation at disabled levels will be skipped and will not even be present in the resulting binary"* [8][1]. Setting e.g. `tracing = { features = ["release_max_level_debug"] }` (or `info`) on the production binary makes `trace!` (and below-cap spans) compile to **nothing** in `--release`, while debug/test builds keep full verbosity. This is the strongest possible form of P0-6 and is **independent of** the runtime `EnvFilter`.

### What Doesn't Work / The Real Residual Costs

**1. A runtime `EnvFilter` with *dynamic* directives defeats the per-callsite interest cache.** `tracing`'s cheap path depends on a callsite being cacheable as `Interest::always`/`never`. A `Filter`/subscriber that can change its decision per-event must return `Interest::sometimes()`, and then *"its `enabled` method will be called every time an event or span is created from that callsite"* [9][10]. `EnvFilter` becomes dynamic when directives reference **spans or field values** (e.g. `RUST_LOG="[span{field=x}]=trace"`); `tracing-subscriber` itself flags this by offering the lighter `Targets` filter *"without the ability to dynamically enable events based on the current span context, and without filtering on field values"* as the cheaper alternative when those features aren't needed [11]. **Implication for rs-vc:** plain level/target directives (`RUST_LOG=info`, `rvc=debug`) stay cacheable and cheap; per-field/per-span directives add a per-callsite `enabled()` call. The mitigation that makes this a non-issue is Finding #6: with `release_max_level_*` compiled in, the below-cap callsites don't exist, so there's nothing for `EnvFilter` to be called on.

**2. An `#[instrument]` async fn enters/exits its span on *every poll*, not once.** *"The attached `Span` will be entered every time the instrumented `Future` is polled … and exited whenever the future yields."* [12] When the span is **enabled**, a hot async fn that yields many times pays enter+exit each poll. At `info` (span disabled) this is the ~0.47 ns no-op enter [2], so it's free in prod — but it means **enabling** debug spans on a deeply-awaited per-slot fn is not "free for the duration of the call"; cost scales with poll count. This argues for **coarse spans** (one span around a phase, not one per inner await) on the hottest async paths, consistent with P2-1.

**3. `tracing`'s `log` feature can re-introduce cost even when statically capped.** If the `log` compatibility feature is on, *"tracing's static max level features do **not** control the log records that may be emitted"* — some code may still be generated for disabled tracing events to feed `log` consumers [8][3]. rs-vc does not appear to depend on the `log` bridge (the stack is `tracing`-native with OTLP), so this is a "don't turn it on" note, not an active problem.

**4. There is no upstream "disabled-by-filter" microbench to cite for an exact in-process number.** The upstream `no_subscriber` benches measure *no dispatcher at all*; the in-process "subscriber present but `enabled()` returns false / max-level rejects" case is not separately published [2] (the shared bench harness only has `none`, `EnabledCollector{ enabled→true }`, and a recording collector — no `enabled→false` case [13]). The disabled-by-static-cap case is *exactly* the `no_subscriber` number because the code is gone; the disabled-by-runtime-filter case adds one cached-interest branch. **We must measure rs-vc's own number** (see Verification) rather than quote a third-party figure for that path.

### Open Questions

- **Default static cap for prod:** `release_max_level_info` (most aggressive — removes `debug` too, but then `RUST_LOG=debug` does *nothing* in a release binary and an operator must use a separate build to get debug) vs `release_max_level_debug` (keeps `debug` switchable at runtime, removes only `trace`). The PRD wants operators to be able to escalate to `debug` in prod via `RUST_LOG`, which points to **`release_max_level_debug`** (trace compiled out, debug runtime-gated). Recommend confirming at the gate.
- **Does `SigningGate`'s `spawn_blocking` change span behavior?** The gate runs the sign on a blocking thread via `Handle::block_on`. Spans do **not** auto-propagate across an OS-thread boundary; if we want the `request_id` span to cover the blocking sign, we must `Span::current()` capture + `.in_scope()` on the blocking closure. This is a correctness-of-correlation question (P0-2), not a cost question, but it intersects the hot path. Flag for the architect.
- **Allocation-counting harness choice:** a custom counting `#[global_allocator]` wrapper (e.g. wrapping `System`) vs the `dhat` crate. Custom wrapper is dependency-free and gives a hard `assert_eq!(allocs_when_disabled, baseline_allocs)`; `dhat` is richer but heavier. Recommend the custom wrapper for the CI assertion.

## Proof of Concept (techniques, ready to apply)

**(a) Hot-path `#[instrument]` — already the house style; make it universal.**
```rust
#[tracing::instrument(
    name = "rvc.crypto.sign_block",
    level = "debug",          // disabled at prod `info` → ~0.7 ns no-op span [2][5]
    skip_all,                 // never Debug-formats &SecretKey / &BeaconBlock [4]
    fields(rvc.signing_type = "block", rvc.slot = slot),
)]
pub fn sign_block(block_root: &Root, slot: u64, secret_key: &SecretKey, /* … */) -> Signature { … }
```
Rule: **every** hot-path `#[instrument]` gets an explicit `level` and `skip_all` (or precise `skip`). Never let the macro auto-capture a large/secret arg.

**(b) Guard any field that costs work behind `enabled!` (extend the beacon pattern).**
```rust
// Hash a root for a trace line ONLY when trace is actually on — no hashing at info.
if tracing::enabled!(tracing::Level::TRACE) {
    let root_hex = hex::encode(signing_root);           // alloc happens only here
    tracing::trace!(signing_root = %root_hex, "computed signing root");
}
```
For values that have a cheap zero-alloc `Display`, skip the guard and pass the wrapper directly (the `Display` body won't run when disabled):
```rust
tracing::debug!(pubkey = %crypto::logging::TruncatedPubkey(pubkey_hex), "signing");
```

**(c) Static cap in the production binary (`bin/rvc/Cargo.toml`, `bin/rvc-signer/Cargo.toml`).**
```toml
[dependencies]
# trace! compiled out of --release; debug! still runtime-gated by RUST_LOG.
tracing = { workspace = true, features = ["release_max_level_debug"] }
```
(Apply to both binaries for P0-5 parity. Do **not** enable tracing's `log` feature.)

**(d) Sampling for high validator counts (P2-1) — a 1-in-N `Filter` layer.**
A sampling subscriber/filter increments a counter in `enabled` and returns `true` only every N-th call; it must return `Interest::sometimes()` so `enabled` runs per-event [9][10]. Scope it to the highest-cardinality per-validator `trace`/`debug` callsites only, so the common path stays on the cached fast filter. (This bounds *volume when verbose is on*; it does not affect the prod `info` path.)

**(e) Verification harness — `criterion` microbench + per-slot bench + zero-alloc assertion.**
```rust
// crates/crypto/benches/sign_path.rs  (criterion)
// Compare three regimes for the SAME sign call:
//   1. no_subscriber          : no dispatcher set
//   2. subscriber_info        : real subscriber, EnvFilter="info" (debug spans disabled)
//   3. subscriber_trace       : EnvFilter="trace" (everything on) — upper bound, not prod
// Pass criterion if  median(2) ≈ median(1)  within noise, and (3) is the only outlier.
fn bench_sign_block(c: &mut Criterion) {
    let (sk, root, sched, gvr) = fixture();
    let mut g = c.benchmark_group("sign_block");
    g.bench_function("no_subscriber",   |b| b.iter(|| sign_block(&root, 5, &sk, &sched, &gvr)));
    g.bench_function("subscriber_info", |b| {
        let _g = tracing::subscriber::set_default(info_level_subscriber());
        b.iter(|| sign_block(&root, 5, &sk, &sched, &gvr));
    });
    // … subscriber_trace …
}
```
```rust
// Zero-allocation assertion (the hard P0-6 gate), dependency-free counting allocator.
#[global_allocator]
static A: Counting = Counting;                  // wraps std::alloc::System, bumps an AtomicUsize
#[test]
fn disabled_trace_allocates_nothing_on_sign_path() {
    let _g = tracing::subscriber::set_default(info_level_subscriber()); // trace/debug OFF
    let before = A.allocs();
    let _sig = sign_attestation(&data, &sk, &sched, &gvr);              // hot path with debug spans
    assert_eq!(A.allocs(), before, "sign path allocated while verbose logging disabled");
}
```
A per-slot-loop bench mirrors this around one coordinator phase (or `timing::timer` tick + `duty-tracker` cache hit, which carry `trace!`), asserting `info`-regime timing equals the no-instrumentation baseline and zero incremental allocations. Run under `cargo nextest run --workspace` for the asserting tests; `criterion` benches via `cargo bench`.

## Effort Estimate

- **Apply the three rules across hot paths (level+skip_all audit, `enabled!` guards on costly fields, `Display` wrappers):** mostly mechanical and partly done; folds into the P0-4 logging work rather than being separate.
- **Static-cap features on both binaries (P0-5/P0-6):** ~1–2 lines each + a doc note; small.
- **Verification harness (new — no bench infra exists):** the bulk of the *net-new* effort. A `criterion` dev-dep, one `benches/sign_path.rs`, one per-slot bench, a counting-allocator test module, and a CI step. Estimate **~1–1.5 days** including baselining and wiring `cargo bench` into the pipeline. This harness is reusable as a permanent regression guard (satisfies the PRD success metric "Disabled `debug!`/`trace!` perform no allocation … verified by … targeted bench/test").

## Risks

- **R1 — A future contributor adds an unguarded expensive field (e.g. `format!`, `hex::encode`, `serde_json`) directly in a `trace!`/`debug!`.** Disabled-level skips the *event*, but if the expensive expression is computed *before* the macro (a local `let`), it runs regardless. *Mitigation:* the `enabled!`-guard pattern + a reviewer rule "no work in a log arg that isn't a `Copy` scalar or a zero-alloc `Display`"; the allocation-counting test catches the sign/slot paths specifically.
- **R2 — `EnvFilter` with field/span directives in prod silently re-enables per-event `enabled()` calls.** Low impact (one branch) but non-zero. *Mitigation:* `release_max_level_debug` removes below-cap callsites entirely; document that per-field `RUST_LOG` directives are a debug-build tool.
- **R3 — Enabling `debug`/`trace` in prod under large validator counts floods + the per-poll span enter/exit on async fns adds up.** This is the *enabled* cost, out of P0-6's "when disabled" scope, but operationally real. *Mitigation:* coarse spans on the hottest async fns, P2-1 sampling, and the taxonomy rule "trace is never on in prod."
- **R4 — Microbench noise hides a small regression.** A BLS sign dominates the sign-path bench, so a ~1 ns span is *below criterion's measurement floor* (criterion notes measurement overhead matters only for sub-µs functions). *Mitigation:* the zero-allocation assertion is the precise gate; the criterion bench is the latency sanity check, and an isolated micro-bench of just the instrumented wrapper (excluding the BLS op) can resolve the span cost if ever needed.

## Sources

[1] [`log` crate documentation — "Disabling logging" / compile-time filtering](https://docs.rs/log/latest/log/index.html) — docs.rs (current). Source of the verbatim disabled-path cost *"just an integer load, comparison and jump"*; lists `max_level_*` / `release_max_level_*` features and confirms disabled-level invocations *"will not even be present in the resulting binary."* `tracing` mirrors this design.
[2] [PR #1974 "tracing: reduce disabled span `Drop` overhead"](https://github.com/tokio-rs/tracing/pull/1974) — tokio-rs/tracing, 2022. The `no_subscriber` criterion results: `span` ~696 ps, `span_enter` ~466 ps; the `#[inline(always)]` Drop change. Authoritative quantitative figure for the disabled/no-interest span.
[3] [`tracing` crate top-level docs — filtering / "Recording Fields" / Subscriber interest](https://docs.rs/tracing/latest/tracing/index.html) — docs.rs (current). *"if no currently active subscribers express interest … the corresponding `Span` or `Event` will never be constructed."* Establishes that field expressions aren't evaluated when disabled.
[4] [`#[instrument]` attribute macro docs](https://docs.rs/tracing/latest/tracing/attr.instrument.html) — docs.rs (current). `level`, `skip`/`skip_all` semantics: skip *"an argument with a verbose or costly `Debug` implementation"* / args that don't implement `Debug`; `fields(...)` expressions evaluated at function start.
[5] [Static level filtering & `STATIC_MAX_LEVEL` — `tracing::level_filters`](https://docs.rs/tracing/latest/tracing/level_filters/index.html) — docs.rs (current). Twelve `max_level_*`/`release_max_level_*` features; *"The instrumentation macros check this value before recording an event or constructing a span"* — confirms `#[instrument]`/`span!` are gated by the static cap and the interest check.
[6] [`enabled!` macro docs](https://docs.rs/tracing/latest/tracing/macro.enabled.html) — docs.rs (current). Forms (`Level`, `target:+Level`, `+fields`), purpose "guard expensive computations", the `if enabled!(Level::DEBUG) { … }` pattern, and the false-positive/negative caveat for field/line-specific filters.
[7] [`#[instrument]` performance/overhead extraction (tracing-attributes)](https://docs.rs/tracing-attributes/latest/tracing_attributes/attr.instrument.html) — docs.rs (current). Cross-check of the attribute's level/skip behavior (page lacks explicit overhead prose; defers to the `span!` machinery).
[8] [`log` compile-time filtering features (cross-reference)](https://docs.rs/log/latest/log/index.html) — docs.rs (current). Confirms feature names and the "`log` feature does not control static max level" interaction noted in `tracing`'s docs [3].
[9] [`tracing-subscriber::layer::Filter` trait — Interest caching / dynamic filtering](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/layer/trait.Filter.html) — docs.rs (current). Per-callsite caching when "always or never enabled"; `Interest::sometimes()` forces `enabled` per-event; `rebuild_interest_cache` semantics.
[10] [`tracing::Subscriber` trait — Interest mechanism](https://docs.rs/tracing/latest/tracing/trait.Subscriber.html) — docs.rs (current). *"if a subscriber returns `Interest::sometimes`, then its `enabled` method will be called every time an event or span is created from that callsite."*
[11] [`tracing-subscriber::filter::EnvFilter` docs — vs `Targets`](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html) — docs.rs (current). EnvFilter supports span-context and field-value directives; `Targets` is the lighter alternative "when these features are not required" — i.e. EnvFilter's dynamic directives carry extra cost.
[12] [`tracing::Instrument` trait — async span enter/exit per poll](https://docs.rs/tracing/latest/tracing/trait.Instrument.html) — docs.rs (current). *"entered every time the instrumented `Future` is polled … exited whenever the future yields"* — basis for "cost scales with poll count when enabled" and the coarse-span recommendation.
[13] [`tracing/benches/shared.rs` benchmark harness](https://raw.githubusercontent.com/tokio-rs/tracing/master/tracing/benches/shared.rs) — tokio-rs/tracing, master. Confirms the published benches cover `none` (no dispatcher), `EnabledCollector` (`enabled→true`, discards), and a recording collector — **no** `enabled→false` case, which is why the in-process disabled-by-filter number must be measured for rs-vc.
