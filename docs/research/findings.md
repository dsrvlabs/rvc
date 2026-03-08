# Research Findings: Code Review Remediation (MEDIUM & LOW)

**Date:** 2026-03-08
**Scope:** 8 key technical questions from the PRD

---

## 1. blst SecretKey Zeroization (SEC-01)

### Verdict
The upstream `blst` crate **does** implement `Zeroize` on `SecretKey` via `#[zeroize(drop)]` on the inner `blst_scalar` field [1]. The RVC wrapper's `raw_bytes` field is already zeroized on drop. The `inner: BlstSecretKey` field is handled by blst's own Drop impl.

### Current State in RVC

```rust
// crates/crypto/src/bls.rs:53-105
pub struct SecretKey {
    inner: BlstSecretKey,       // blst handles zeroization via #[zeroize(drop)]
    raw_bytes: [u8; SECRET_KEY_BYTES_LEN],  // zeroized in Drop impl (line 101-104)
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.raw_bytes.zeroize();  // ✓ raw_bytes cleared
        // inner: BlstSecretKey is zeroized by blst's own Drop
    }
}
```

### Findings

- **blst `SecretKey` struct** is defined with `#[derive(Zeroize)]` and `#[zeroize(drop)]` in `bindings/rust/src/lib.rs` [1]. The inner `blst_scalar` value is a fixed-size byte array that gets zeroized when the struct is dropped.
- **RVC's wrapper** already zeroizes `raw_bytes` on drop. The `inner` field (blst's `SecretKey`) is also zeroized by blst's own `Drop` impl.
- **Action:** The current implementation is likely already correct. Verify by checking the blst version in `Cargo.lock` supports `#[zeroize(drop)]` (available since blst 0.3.11+). Add a doc comment explaining that blst handles inner key zeroization. Consider removing the redundant `raw_bytes` field entirely — it duplicates data that `inner.to_bytes()` can provide, and its existence means key material lives in two places.

### Recommendation

1. Verify blst version >= 0.3.11 in Cargo.lock
2. Add doc comment: `// blst::SecretKey implements Zeroize + Drop via #[zeroize(drop)]`
3. Consider removing `raw_bytes` field to reduce zeroization surface
4. If removing `raw_bytes`, change `raw_bytes()` to return `self.inner.to_bytes()` (stack-allocated, short-lived)

### Sources

[1] [blst Rust bindings source](https://github.com/supranational/blst/blob/master/bindings/rust/src/lib.rs) — Supranational. SecretKey defined with `#[zeroize(drop)]`.
[2] [zeroize crate documentation](https://docs.rs/zeroize/latest/zeroize/) — RustCrypto. `ZeroizeOnDrop` derive macro documentation.

---

## 2. SQLite WAL + synchronous=FULL (DB-01)

### Verdict
Set `PRAGMA journal_mode=WAL` and `PRAGMA synchronous=FULL` on connection open. WAL mode is safe to enable on existing databases. `synchronous=FULL` is mandatory for slashing protection durability but has a performance cost (~50% slower writes vs NORMAL).

### Current State in RVC

```rust
// crates/slashing/src/db.rs:27-36
pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, SlashingError> {
    let conn = Connection::open(path)?;
    // No PRAGMAs set — uses SQLite defaults:
    // journal_mode=delete, synchronous=FULL (for delete mode)
    let db = Self { conn: Mutex::new(conn), ... };
    db.migrate()?;
    Ok(db)
}
```

### Findings

**WAL Mode:**
- WAL (Write-Ahead Logging) provides better concurrency: readers don't block writers and vice versa [3]
- WAL mode persists per-database file — once set, it remains across connections [4]
- Setting: `PRAGMA journal_mode=WAL;` — must check return value to confirm (returns "wal" on success)
- WAL mode is safe for single-writer scenarios like slashing protection

**synchronous=FULL in WAL mode:**
- In WAL mode, `synchronous=FULL` syncs the WAL file at every commit, ensuring durability even on power loss [3]
- `synchronous=NORMAL` in WAL mode is faster (~2-3x) but risks losing the most recent committed transaction on power loss [3]
- For slashing protection, data loss = potential double-signing. `synchronous=FULL` is the only safe choice [3]
- Default SQLite synchronous for non-WAL is FULL; for WAL it's typically NORMAL in some configurations

**Performance implications:**
- WAL + FULL: ~1,000-5,000 inserts/sec on typical hardware [3]
- WAL + NORMAL: ~10,000-50,000 inserts/sec [3]
- For slashing protection, we do ~1-2 writes per slot (12 seconds), so performance is irrelevant — correctness matters

**Implementation in rusqlite:**

```rust
pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, SlashingError> {
    let conn = Connection::open(path)?;

    // Enable WAL mode for better concurrency
    let mode: String = conn.pragma_update_and_check(None, "journal_mode", "wal", |row| row.get(0))?;
    if mode != "wal" {
        return Err(SlashingError::DatabaseError("Failed to enable WAL mode".into()));
    }

    // FULL sync for crash safety — mandatory for slashing protection
    conn.pragma_update(None, "synchronous", "FULL")?;

    // ... rest of init
}
```

### Recommendation

1. Set both PRAGMAs in `open()` and `open_in_memory()` (in-memory doesn't need WAL but won't hurt)
2. Verify `journal_mode` return value equals "wal"
3. Add test: open DB, query both PRAGMAs, verify values
4. Log the mode transition at INFO level

### Sources

[3] [SQLite Pragma Cheatsheet for Performance and Consistency](https://cj.rs/blog/sqlite-pragma-cheatsheet-for-performance-and-consistency/) — Clément Joly. Comprehensive PRAGMA guide.
[4] [Write-Ahead Logging](https://sqlite.org/wal.html) — SQLite official documentation.
[5] [Rusqlite Rust Guide](https://generalistprogrammer.com/tutorials/rusqlite-rust-crate-guide) — 2025. Rusqlite usage patterns.

---

## 3. Axum CORS & Body Size Limits (SEC-06, SEC-07)

### Verdict
Use `tower-http::cors::CorsLayer` for CORS and `axum::extract::DefaultBodyLimit` (or `tower_http::limit::RequestBodyLimitLayer`) for body limits. Both are well-supported, production-ready middleware.

### Current State in RVC

```rust
// crates/keymanager-api/src/server.rs:45-61
pub fn router(&self) -> Router {
    let api = Router::new()
        .route("/eth/v1/keystores", get(...).post(...).delete(...))
        .route("/eth/v1/remotekeys", get(...).post(...).delete(...))
        .with_state(self.state.clone());
    auth::with_auth(api, self.token.clone())
    // No CORS, no body limit
}
```

### Findings

**CORS (tower-http):**

```rust
use tower_http::cors::{CorsLayer, AllowOrigin};
use http::{Method, header};

// Default: restrictive (no CORS headers = same-origin only)
let cors = CorsLayer::new();

// With explicit origins:
let cors = CorsLayer::new()
    .allow_origin(AllowOrigin::list(allowed_origins))  // Vec<HeaderValue>
    .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::OPTIONS])
    .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
    .allow_credentials(false);  // Don't allow cookies cross-origin
```

Key points [6][7]:
- `CorsLayer::new()` with no configuration = no `Access-Control-Allow-Origin` header = same-origin only (safe default)
- `CorsLayer::permissive()` allows everything — never use in production
- Preflight `OPTIONS` requests are handled automatically
- Add via `.layer(cors)` on the Router

**Body Size Limits:**

```rust
use axum::extract::DefaultBodyLimit;

// Axum's built-in default is 2MB. To change:
let app = Router::new()
    .route("/eth/v1/keystores", post(import_keystores))
    .layer(DefaultBodyLimit::max(10 * 1024 * 1024));  // 10 MB
```

Key points [8][9]:
- Axum has a built-in 2MB default body limit via `DefaultBodyLimit`
- Use `DefaultBodyLimit::max(bytes)` to set a custom limit
- Use `DefaultBodyLimit::disable()` to remove the limit (never do this)
- Exceeding the limit returns 413 Payload Too Large automatically
- Can also use `tower_http::limit::RequestBodyLimitLayer` but `DefaultBodyLimit` is simpler for Axum

**Dependency:** Add `tower-http = { version = "0.6", features = ["cors"] }` (likely already a dependency).

### Recommendation

```rust
pub fn router(&self) -> Router {
    let cors = if self.cors_origins.is_empty() {
        CorsLayer::new()  // Same-origin only
    } else {
        CorsLayer::new()
            .allow_origin(AllowOrigin::list(self.cors_origins.clone()))
            .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::OPTIONS])
            .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
    };

    let api = Router::new()
        .route("/eth/v1/keystores", get(...).post(...).delete(...))
        .route("/eth/v1/remotekeys", get(...).post(...).delete(...))
        .layer(DefaultBodyLimit::max(self.body_limit))  // default 10MB
        .layer(cors)
        .with_state(self.state.clone());

    auth::with_auth(api, self.token.clone())
}
```

### Sources

[6] [API Development in Rust: CORS, Tower Middleware, and Axum](https://dev.to/amaendeepm/api-development-in-rust-cors-tower-middleware-and-the-power-of-axum-397k) — DEV Community.
[7] [tower-http CorsLayer documentation](https://docs.rs/tower-http/latest/tower_http/cors/struct.CorsLayer.html) — docs.rs.
[8] [DefaultBodyLimit in axum::extract](https://docs.rs/axum/latest/axum/extract/struct.DefaultBodyLimit.html) — docs.rs.
[9] [RequestBodyLimitLayer in tower_http::limit](https://docs.rs/tower-http/latest/tower_http/limit/struct.RequestBodyLimitLayer.html) — docs.rs.

---

## 4. Sign-then-Record vs Record-then-Sign (COR-01)

### Verdict
The Ethereum consensus spec mandates **record-then-sign** (save to disk BEFORE signing/broadcasting). The current RVC implementation (`check_and_record` before `sign`) is **correct per spec**. The PRD's COR-01 proposal to reorder to sign-then-record would **violate the spec**.

### Current State in RVC

```rust
// crates/signer/src/lib.rs:116-146
// 1. Check AND record atomically (correct per spec)
self.slashing_db.check_and_record_attestation(&pubkey_hex, source, target, signing_root)?;

// 2. Sign (after record)
let signature = self.signer.sign(&signing_root, &pubkey_bytes).await?;
```

### Findings

The Ethereum consensus spec (phase0/validator.md) states [10]:

> "Save a record to hard disk that a beacon block has been signed for the `slot=block.slot`. Generate and broadcast the block."

> "Save a record to hard disk that an attestation has been signed for source...and target. Generate and broadcast attestation."

The ordering is explicit: **save first, then sign/broadcast**. The rationale is crash safety — if the validator crashes between recording and broadcasting, the record prevents creating a conflicting signature on restart [10].

**Phantom entries (PRD's concern):**
The PRD raises a valid concern: if signing fails after recording, a "phantom" entry exists in the slashing DB. However:
- A phantom entry is **safe** — it prevents a future sign for the same slot/epoch, but the validator simply skips that duty. Missing a duty is far less harmful than double-signing.
- The spec explicitly prioritizes this tradeoff: "the hard disk has the record of the potentially signed/broadcast attestation and can effectively avoid slashing"
- **All major validator clients** (Lighthouse, Prysm, Teku, Nimbus) follow record-before-sign [10]

**What Lighthouse does:**
Lighthouse uses `check_and_insert` which atomically checks slashing conditions and inserts the record in a single SQLite EXCLUSIVE transaction, then signs after. This matches the spec [11].

### Recommendation

**Do NOT reorder to sign-then-record.** The current implementation is correct per spec.

Instead, address the phantom entry concern differently:
1. **Document the design decision** with a comment referencing the consensus spec
2. **Log phantom entries** — if signing fails, log at WARN that a slashing DB entry exists without a broadcast
3. **Consider cleanup** — optionally allow manual cleanup of phantom entries (e.g., via CLI command), but never automatically delete them

If COR-01 must be addressed, reframe it as:
- Add a per-validator mutex to prevent concurrent check-and-record for the same validator
- This prevents the TOCTOU between two concurrent sign requests, without changing the record-first ordering

### Sources

[10] [Ethereum Consensus Specs: Phase 0 Validator](https://ethereum.github.io/consensus-specs/specs/phase0/validator/) — Ethereum Foundation. Canonical validator behavior specification.
[11] [Lighthouse Slashing Protection PR #1116](https://github.com/sigp/lighthouse/pull/1116) — sigp/lighthouse. Implementation of EIP-3076.

---

## 5. Dynamic pubkey_map (CON-03)

### Verdict
Use `Arc<RwLock<HashMap<[u8; 48], usize>>>` shared between the orchestrator and keymanager API. Trigger a duty re-poll on key change rather than waiting for the next epoch boundary.

### Current State in RVC

The `pubkey_map` is built once at startup in `main.rs:711` and passed immutably to the orchestrator. Keys added via keymanager API at runtime are invisible.

### Findings

**Pattern: Shared mutable map**

```rust
use std::sync::Arc;
use tokio::sync::RwLock;
use std::collections::HashMap;

type PubkeyMap = Arc<RwLock<HashMap<[u8; 48], usize>>>;

// In orchestrator — read path (hot, frequent):
let map = pubkey_map.read().await;
let index = map.get(&pubkey_bytes);

// In keymanager API — write path (cold, rare):
let mut map = pubkey_map.write().await;
map.insert(pubkey_bytes, validator_index);
```

**Key considerations:**

1. **Use `tokio::sync::RwLock`** (not `std::sync::RwLock`) since the map is accessed in async contexts and read locks may be held across `.await` points
2. **Read-heavy workload** — orchestrator reads the map every slot (every 12s) for all validators; writes happen only on key import/delete (rare). `RwLock` is ideal for this pattern.
3. **Validator index lookup** — when a new key is added, we need its validator index from the beacon node. This requires a beacon API call (`get_validators`) which should be done before inserting into the map.

**Triggering duty re-poll:**

Two options:
- **Option A: Epoch boundary** — simplest, duties are refreshed every epoch anyway. New keys wait up to 6.4 minutes.
- **Option B: Immediate trigger** — use a `tokio::sync::Notify` or `watch` channel to signal the orchestrator. Faster key activation.

Recommended: **Option B** — use `tokio::sync::watch<u64>` as a generation counter. Keymanager increments on key change; orchestrator checks before each slot and triggers duty refresh if changed.

```rust
// Shared state
let (key_gen_tx, key_gen_rx) = tokio::sync::watch::channel(0u64);

// Keymanager side (on import/delete):
key_gen_tx.send_modify(|gen| *gen += 1);

// Orchestrator side (each slot):
if key_gen_rx.has_changed().unwrap_or(false) {
    key_gen_rx.borrow_and_update();
    refresh_duties().await;
}
```

### Recommendation

1. Replace `HashMap<[u8;48], usize>` with `Arc<tokio::sync::RwLock<HashMap<[u8;48], usize>>>`
2. Pass the same Arc to both orchestrator and keymanager API adapters
3. Add a `watch` channel for generation-based change notification
4. On key import: call `get_validators` for index, insert into map, increment generation
5. On key delete: remove from map, increment generation
6. Orchestrator: check generation each slot, refresh duties on change

---

## 6. Async Span Patterns (LOW-25)

### Verdict
Replace all `span.enter()` / `.entered()` calls in async code with `.instrument(span)` on futures or `#[tracing::instrument]` on async functions. Using `span.enter()` across `.await` points produces incorrect traces.

### Current State in RVC

```rust
// Example from signer/lib.rs:117 — CORRECT (synchronous scope, no .await inside)
let slashing_check_result = {
    let _span = tracing::info_span!("rvc.slashing.check").entered();
    self.slashing_db.check_and_record_attestation(...)  // sync call, no .await
};

// Problem cases: doppelganger and orchestrator use span.enter() around async code
```

### Findings

**The Problem [12]:**

```rust
// WRONG — span held across .await
let _guard = span.enter();
some_async_fn().await;  // yields here, guard still held
// Another task runs inside this span!
```

When an async function yields at `.await`, the runtime switches to another task, but the span guard is still "entered." The other task's events get attributed to the wrong span.

**Correct Patterns [13][14]:**

1. **`#[tracing::instrument]` on async fn** — preferred when instrumenting an entire function:
```rust
#[tracing::instrument(name = "rvc.doppelganger.check", skip_all, fields(...))]
async fn check_validators(&self, ...) { ... }
```

2. **`.instrument(span)` on futures** — preferred for instrumenting a specific future:
```rust
async_operation()
    .instrument(tracing::info_span!("rvc.operation"))
    .await;
```

3. **`span.in_scope(|| ...)` for sync closures** — when calling sync code within async:
```rust
let result = span.in_scope(|| sync_computation());
```

**Summary table:**

| Pattern | Use When | Safe Across .await? |
|---------|----------|-------------------|
| `span.enter()` / `.entered()` | Sync code only | NO |
| `.instrument(span)` | Async futures | YES |
| `#[instrument]` | Async functions | YES |
| `span.in_scope(\|\| ...)` | Sync closure in async | YES (no .await inside) |

### Recommendation

1. Grep for `.entered()` and `span.enter()` in async code paths
2. Replace with `.instrument()` or `#[tracing::instrument]` as appropriate
3. The existing usage in `signer/lib.rs` (`.entered()` around sync `check_and_record`) is actually correct — the scope contains no `.await`
4. Focus on doppelganger and orchestrator where async operations exist

### Sources

[12] [tracing::span::EnteredSpan documentation](https://docs.rs/tracing/latest/tracing/span/struct.EnteredSpan.html) — docs.rs. Warning about async usage.
[13] [tracing::Instrument trait](https://docs.rs/tracing/latest/tracing/trait.Instrument.html) — docs.rs. Correct async span instrumentation.
[14] [Fixing Incorrect Tracing Parent Spans with Futures and JoinSet](https://chesedo.me/blog/rust-tracing-incorrect-parent-spans-async-futures-joinset/) — chesedo. Detailed async span guide.

---

## 7. HTTP 429 Retry Handling (COR-08)

### Verdict
Add 429 to retryable status codes in the existing retry loop. Parse `Retry-After` header when present. Add jitter to the existing `calculate_backoff` function.

### Current State in RVC

```rust
// crates/beacon/src/client.rs:910-912 — 429 treated as non-retryable client error
if status.is_client_error() {
    let message = response.text().await.unwrap_or_default();
    return Err(BeaconError::ApiError { status: status.as_u16(), message });
}
```

```rust
// crates/beacon/src/client.rs:1118-1124 — no jitter in backoff
fn calculate_backoff(&self, attempt: u32) -> Duration {
    let capped_attempt = attempt.min(20);
    let multiplier = 2u32.saturating_pow(capped_attempt);
    self.config.initial_backoff.saturating_mul(multiplier)
}
```

### Findings

**429 handling [15]:**
- HTTP 429 means "Too Many Requests" — the server is rate-limiting the client
- Unlike other 4xx errors, 429 is transient and SHOULD be retried
- The `Retry-After` header specifies when to retry (seconds or HTTP-date)
- If no `Retry-After`, use exponential backoff

**Implementation:**

```rust
// In execute_with_retry (and similar):
if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
    // Parse Retry-After header
    let retry_after = response.headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_secs);

    let backoff = retry_after.unwrap_or_else(|| self.calculate_backoff(attempt));
    last_error = Some(BeaconError::ApiError { status: 429, message });
    warn!(attempt, backoff_ms = ?backoff.as_millis(), "Rate limited (429), will retry");
    tokio::time::sleep(backoff).await;
    continue;
}
```

**Jitter (LOW-28) [16]:**

```rust
fn calculate_backoff(&self, attempt: u32) -> Duration {
    let capped_attempt = attempt.min(20);
    let multiplier = 2u32.saturating_pow(capped_attempt);
    let base = self.config.initial_backoff.saturating_mul(multiplier);

    // Add ±25% jitter
    let jitter_range = base.as_millis() as u64 / 4;
    let jitter = if jitter_range > 0 {
        use rand::Rng;
        let offset: u64 = rand::thread_rng().gen_range(0..=jitter_range * 2);
        Duration::from_millis(offset) - Duration::from_millis(jitter_range)
    } else {
        Duration::ZERO
    };

    base.checked_add(jitter).unwrap_or(base)
}
```

### Recommendation

1. Move the 429 check BEFORE the generic `is_client_error()` check
2. Parse `Retry-After` header (seconds format only — HTTP-date is rare for APIs)
3. Add jitter to `calculate_backoff` (separate change, LOW-28)
4. Cap `Retry-After` to a reasonable max (e.g., 120 seconds) to prevent abuse

### Sources

[15] [429 Too Many Requests — HTTP status code explained](https://http.dev/429) — http.dev. Comprehensive 429 reference.
[16] [How to Implement Exponential Backoff with Jitter in Rust](https://oneuptime.com/blog/post/2026-01-25-exponential-backoff-jitter-rust/view) — OneUptime, Jan 2026.

---

## 8. SSRF Prevention for Remote Key Imports (SEC-05)

### Verdict
Validate URL scheme (https only by default), resolve hostname, check resolved IP against private/loopback/link-local ranges before connecting. Use Rust's stable `Ipv4Addr::is_private()`, `is_loopback()`, `is_link_local()` methods.

### Current State in RVC

```rust
// crates/keymanager-api/src/handlers.rs:199-202
// Remote key import accepts arbitrary URLs without validation
```

### Findings

**SSRF attack vectors [17]:**
- `http://127.0.0.1:8080/` — access localhost services
- `http://169.254.169.254/` — cloud metadata (AWS/GCP)
- `http://[::1]/` — IPv6 loopback
- `file:///etc/passwd` — local file access
- `http://internal-service.local/` — DNS rebinding to private IPs
- `http://0x7f000001/` — hex-encoded loopback

**Layered defense [17][18]:**

1. **Scheme validation** — only allow `https://` (or `http://` with explicit `--allow-insecure-remote-signer` flag)
2. **DNS resolution + IP check** — resolve hostname, verify IP is not private/loopback/link-local BEFORE connecting
3. **Port restriction** — optionally restrict to standard ports (443, 9000)

**Rust implementation using stable APIs:**

```rust
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use url::Url;

fn validate_remote_signer_url(url_str: &str, allow_insecure: bool) -> Result<Url, String> {
    let url = Url::parse(url_str).map_err(|e| format!("Invalid URL: {e}"))?;

    // 1. Scheme check
    match url.scheme() {
        "https" => {}
        "http" if allow_insecure => {
            tracing::warn!("Remote signer URL uses plaintext HTTP");
        }
        "http" => return Err("HTTP not allowed without --allow-insecure-remote-signer".into()),
        scheme => return Err(format!("Unsupported scheme: {scheme}")),
    }

    // 2. Host check — reject IP literals that are private/loopback
    let host = url.host_str().ok_or("URL has no host")?;

    // 3. DNS resolution + IP validation (at connection time)
    // Check if host is an IP literal
    if let Ok(ip) = host.parse::<IpAddr>() {
        validate_ip(ip)?;
    }
    // For hostnames: resolve and check at connection time

    Ok(url)
}

fn validate_ip(ip: IpAddr) -> Result<(), String> {
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_loopback()        // 127.0.0.0/8
                || v4.is_private()     // 10/8, 172.16/12, 192.168/16
                || v4.is_link_local()  // 169.254/16
                || v4.is_broadcast()   // 255.255.255.255
                || v4.is_unspecified() // 0.0.0.0
                || v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64  // 100.64/10 (CGNAT)
            {
                return Err(format!("Private/reserved IP not allowed: {v4}"));
            }
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback()        // ::1
                || v6.is_unspecified() // ::
                || v6.segments()[0] == 0xfe80  // link-local
                || v6.segments()[0] & 0xfe00 == 0xfc00  // unique local (fd00::/8)
            {
                return Err(format!("Private/reserved IPv6 not allowed: {v6}"));
            }
            // Check IPv4-mapped IPv6 (::ffff:127.0.0.1)
            if let Some(v4) = v6.to_ipv4_mapped() {
                validate_ip(IpAddr::V4(v4))?;
            }
        }
    }
    Ok(())
}
```

**DNS rebinding protection:**
For hostname-based URLs, the IP check must happen at connection time, not just at validation time. Consider using a custom `reqwest::dns::Resolve` implementation that checks resolved IPs before connecting. However, for the initial implementation, checking IP literals at import time + the scheme restriction provides a good baseline.

### Recommendation

1. Validate URL scheme at import time (https only, http with flag)
2. Check IP literals against private/loopback/link-local ranges
3. Reject non-HTTP(S) schemes (file, ftp, data, etc.)
4. Add `--allow-insecure-remote-signer` CLI flag
5. Log warning for HTTP URLs even when allowed
6. Future: add DNS-resolution-time IP check for hostname URLs

### Sources

[17] [SSRF Cheat Sheet & Bypass Techniques](https://highon.coffee/blog/ssrf-cheat-sheet/) — High On Coffee. Comprehensive SSRF attack vectors.
[18] [Securing Identity APIs Against SSRF](https://stytch.com/blog/securing-identity-apis-against-ssrf/) — Stytch, 2025. Production SSRF prevention patterns.
[19] [IpAddr in std::net](https://doc.rust-lang.org/std/net/enum.IpAddr.html) — Rust std documentation. Stable IP address methods.

---

## Summary of Key Decisions

| # | Topic | Recommendation | Risk if Ignored |
|---|-------|---------------|-----------------|
| 1 | blst zeroization | Likely already handled by blst; verify + document | LOW — blst does it |
| 2 | SQLite WAL+FULL | Add PRAGMAs on open; mandatory for slashing safety | HIGH — data loss on crash |
| 3 | CORS + body limit | Add tower-http layers; straightforward | MEDIUM — SSRF via browser |
| 4 | Sign ordering | **Keep current record-then-sign** (spec-compliant) | HIGH if changed — violates spec |
| 5 | Dynamic pubkey_map | Arc<RwLock> + watch channel | MEDIUM — runtime keys broken |
| 6 | Async spans | Replace span.enter() in async with .instrument() | LOW — incorrect traces |
| 7 | 429 retry | Add before is_client_error() check; add jitter | MEDIUM — silent rate limiting |
| 8 | SSRF prevention | Scheme + IP validation on URL import | HIGH — internal network access |

## Critical Finding: COR-01 Sign Ordering

**The PRD's COR-01 recommendation to reorder signing to sign-then-record would violate the Ethereum consensus specification.** The current implementation (check-and-record-then-sign) is correct. The PRD should be updated to:
1. Document the current ordering as correct per spec
2. Reframe the issue as "add per-validator mutex to prevent concurrent TOCTOU"
3. Accept phantom entries as the spec-intended safety tradeoff
