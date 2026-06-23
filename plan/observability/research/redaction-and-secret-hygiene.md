# redaction-and-secret-hygiene
## Summary
**Pre-existing risk:** `crates/crypto/src/bls.rs:170` has `impl fmt::Debug for Signature` that emits the full 96-byte hex via `{self}`, and `:41` has `impl fmt::Debug for PublicKey` that emits the full 48-byte hex. Any contributor who writes `debug!(?sig)` or `error!(?pubkey)` today produces untruncated output. Fix direction: update these Debug impls in place to use `TruncatedPubkey` / `TruncatedSignature`, keep `Display` = full hex for deliberate use.

## Audit — existing Debug/Display impls on sensitive types

### `crates/crypto`

| Type | File:line | Debug shape | Status |
|---|---|---|---|
| `SecretKey` | `bls.rs:100` | `"SecretKey([REDACTED])"` | Safe. |
| `Signature` | `bls.rs:170` | `"Signature(0x<96 hex>)"` (full) | **LEAKY.** Retrofit: use `TruncatedSignature` (first 8 + last 8 hex). |
| `PublicKey` | `bls.rs:41` | `"PublicKey(0x<48 hex>)"` (full) | **LEAKY** per PRD's pubkey-short-form rule. Retrofit: use `TruncatedPubkey`. |
| `Display` impls on `PublicKey` / `Signature` | `bls.rs:35,164` | full hex via `hex::encode` | Acceptable — `Display` is deliberate; `?` is the accident. |
| `RemoteSignerConfig` | `remote_signer.rs:28` | derive Debug | Check if it includes auth/URLs — likely contains URLs, which should be `%RedactedUrl`. |
| `Keystore` | `keystore.rs:*` | derive Debug | EIP-2335 JSON only contains encrypted ciphertext + KDF params — not plaintext — so derive Debug is OK. Still, promote a `RedactedKeystore` that strips cipher payload bytes to reduce log noise. |
| `Mnemonic` | `mnemonic.rs` | `bip39::Mnemonic` — upstream derives Debug which prints the words | **LEAKY** if ever logged. Ensure no `{:?}` of mnemonic anywhere in our tree. PRD P0-2 forbidden-pattern test catches it. |

### `crates/signer`

| Type | File:line | Status |
|---|---|---|
| `SignerError` | `lib.rs:34` | `#[derive(Debug, Error)]` — Display is via `thiserror`, Debug leaks only field names. OK. |
| `SignerService` | no Debug impl | N/A. |

### `crates/validator-store`

| Type | File:line | Status |
|---|---|---|
| `Config`, `ValidatorOverride`, etc. | `store.rs:13,21,28,53` | derive Debug — these are config types (fee recipient, graffiti, builder prefs); no secrets. Safe. |
| `ValidatorStoreError` | `error.rs` | `#[derive(Debug, thiserror::Error)]` — safe, Display used. |

### `crates/keymanager-api`

| Type | File:line | Status |
|---|---|---|
| `ImportKeystoreRequest`, etc. | `types.rs:*` | Many derive Debug. Most include keystore JSON + a `SecretString` password. **RISK**: if anyone ever `debug!(?req)` on an `ImportKeystoreRequest`, and `secrecy::SecretString`'s Debug renders `"***"` — actually fine, `secrecy = 0.10` does redact. Still, the request contains the keystore JSON body as a string — audit whether it ever hits a log. |
| Request `Bearer` token — `auth.rs` | Zeroizing/secrecy based — confirm none of the handler logs include the raw token. |

### `crates/grpc-signer`

| Type | File:line | Status |
|---|---|---|
| `SignRequest` (proto) | `lib.rs:14` | Contains `signing_root` (safe: it's a hash) and `pubkey` (48 bytes). tonic auto-derives Debug on protobuf types — pubkey will appear as raw `Vec<u8>` in Debug output, which is at least not hex but still full bytes. **Retrofit:** never `{:?}` a `SignRequest`; log pubkey via `TruncatedPubkey::new(&hex::encode(req.pubkey))`. |

## Idiomatic patterns for our stack

- **`secrecy::SecretString` / `secrecy::Secret<T>`** (workspace dep `secrecy = 0.10`) — already used for bearer tokens and passwords. Exposes via `.expose_secret()`; Debug prints `"Secret([REDACTED])"`. **Prefer this for any newly-introduced secret string field.**
- **`zeroize::Zeroizing<T>` / `#[derive(Zeroize, ZeroizeOnDrop)]`** — already used for key material bytes. Debug does NOT redact by default — `Zeroizing<[u8; 32]>` prints the byte array. **Do not rely on Zeroizing for Debug safety**; use it for memory hygiene. For display safety, wrap in a newtype with a redacting Debug impl.
- **Newtype with custom Debug** — the `TruncatedPubkey` / `RedactedUrl` pattern in `crates/crypto/src/logging.rs`. Zero-alloc via `Display`, safe in tracing `%` position. Recommend: **promote to `crates/telemetry/src/redaction.rs`** as planned, add `TruncatedSignature`, `RedactedKeystore`, `RedactedSecret`, and provide a `//!` module-level doc example showing canonical usage in `tracing::info!(pubkey = %TruncatedPubkey::new(&hex), ...)`.

## Forbidden-pattern test — recommend regex-over-source

**Regex wins vs `syn`:**
- **Simplicity.** Regex over raw bytes ≈ 100 LOC total. `syn` full-tree visitor ≈ 400+ LOC for the same coverage.
- **Performance.** `syn` parsing on 23 crates per `cargo test` run ≈ 1–5 s overhead. Regex on N MB of source ≈ <100 ms.
- **Surface is shallow.** The PRD's forbidden patterns (P0-2) all live in macro invocations and format strings — regex sees exactly that textual form.
- **`syn` escape hatch.** Note it as a fallback if false positives become unmanageable; keep `proc-macro-regex`/`syn` out for now.

### Concrete regex set

```rust
// tests/forbidden_log_patterns.rs at workspace root

// (1) Log macros referencing secret-like names in fields or format strings.
// Matches: tracing::info!(..., secret = ..., ...) and similar for debug/warn/error/trace.
const BAD_FIELD: &str = r#"(?m)^[^/]*\btracing::(?:info|debug|warn|error|trace)!\([^)]*\b(?:secret|sk|private_key|mnemonic|passphrase|password)\b"#;

// (2) Format-string brace references to secret-like variables.
// Matches: info!("... {secret_key} ...") or info!("... {sk:?} ...")
const BAD_FMT: &str = r#"(?m)tracing::(?:info|debug|warn|error|trace)!\([^)]*\{(?:secret|sk|private_key|mnemonic|passphrase|password)(?:[:?][^}]*)?\}"#;

// (3) Literal Zeroizing in a log call.
const BAD_ZEROIZING: &str = r#"(?m)tracing::(?:info|debug|warn|error|trace)!\([^)]*\bZeroizing\b"#;

// (4) Debug-formatting of a Signature via ? sigil.
const BAD_SIG_DEBUG: &str = r#"(?m)tracing::(?:info|debug|warn|error|trace)!\([^)]*\?(?:sig|signature)\b"#;

// (5) #[instrument] without skip_all on fns mentioning SecretKey/SigningRequest/etc.
// Two-stage: regex to find instrument attr, then check surrounding fn signature for sensitive types.
const INSTRUMENT_NO_SKIPALL: &str = r#"(?m)#\[tracing::instrument\([^)]*\)\]\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+[a-zA-Z_0-9]+\s*(?:<[^>]*>)?\s*\([^)]*\b(?:SecretKey|SecretString|Zeroizing|Mnemonic|SignRequest|SigningRequest)\b"#;
```

Walk the file tree with `walkdir` (dev-dep) or a hand rolled recursive glob, filter `**/*.rs` excluding `target/`, skip lines prefixed by `// observability:allow` on the current or preceding line.

### Allowlist comment syntax

Recommend a **line-prefix** comment on the line directly above the offending line, because test code and error-path tests may legitimately include these patterns:

```rust
// observability: allow sensitive-log — intentionally exercising failure path in test
tracing::debug!("got secret: {secret}");
```

Parser sketch:
```rust
fn is_allowlisted(source: &str, match_offset: usize) -> bool {
    // Find the line containing match_offset, and the line directly above it.
    let line_start = source[..match_offset].rfind('\n').map(|n| n + 1).unwrap_or(0);
    let prev_line_end = source[..line_start].trim_end_matches('\n').rfind('\n').unwrap_or(0);
    let prev_line = &source[prev_line_end..line_start];
    prev_line.contains("// observability: allow")
}
```

Require every allowlist comment to include a free-text reason (`"// observability: allow <reason>"`); enforce the reason tail via regex.

## Sources

- [`secrecy` crate docs](https://docs.rs/secrecy/0.10) — `SecretString`, `Secret<T>`, Debug redaction.
- [`zeroize` crate docs](https://docs.rs/zeroize/1.8) — `Zeroizing<T>`, `ZeroizeOnDrop`. Note: no Debug redaction.
- Direct source reads: `/Users/joonkyo.kim/git/dsrv/rvc/crates/crypto/src/bls.rs`, `crates/crypto/src/logging.rs`, `crates/crypto/src/keystore.rs`, `crates/crypto/src/remote_signer.rs`, `crates/keymanager-api/src/types.rs`.

---
