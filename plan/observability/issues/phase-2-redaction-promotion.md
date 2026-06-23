# Phase 2: Redaction Promotion + `bls.rs` Debug Fix

**Goal:** Canonicalize redaction helpers in `crates/telemetry` and close the `bls.rs` Debug leak
so the Phase 3 forbidden-pattern test can go green without false negatives.
**Total points:** 5
**Total issues:** 3
**Depends on:** Phase 1 (issues 1.1, 1.2, 1.3 in particular)
**Unblocks:** Phase 3, Phase 4, Phase 5, Phase 6, Phase 7, Phase 8

The main security win here is the `bls.rs` Debug fix: today any accidental `{:?}` on a `PublicKey`
or `Signature` leaks the full 96-/192-hex body. After this phase a stray `?sig` still compiles but
outputs short-form only; the forbidden-pattern test (Phase 3) additionally bans the syntax.

---

## Issue 2.1: Shrink `crates/crypto/src/logging.rs` to a thin re-export

- **Points:** 1
- **Depends on:** 1.1
- **Files touched:**
  - `crates/crypto/src/logging.rs`
  - `crates/crypto/Cargo.toml` (add `telemetry = { workspace = true }` as a normal dependency —
    architecture §1.2 pre-verifies the cycle is clean: `telemetry` does not depend on `crypto`)
- **Summary:** Replace the inlined `TruncatedPubkey` / `RedactedUrl` with `pub use telemetry::{
  TruncatedPubkey, RedactedUrl};`. Mark the module `#[deprecated(note = "import from telemetry
  directly")]`. Existing downstream importers continue to compile during the grace period
  (removed in Phase 6).
- **Acceptance criteria:**
  - [ ] `crates/crypto/src/logging.rs` contains only the re-export block and the module-level
        `#![deprecated(...)]` attribute; old tests move to `crates/telemetry/src/redact.rs` in
        Issue 1.1 (do not duplicate).
  - [ ] `telemetry` appears in `crates/crypto/Cargo.toml` `[dependencies]`.
  - [ ] `cargo build --workspace` succeeds (cycle-clean).
  - [ ] `cargo check -p crypto` succeeds; `cargo clippy -p crypto` emits only the deprecation
        note (expected — stays suppressed inside crypto by a module-level
        `#![allow(deprecated)]` on the module only).
- **Tests:**
  - `crates/crypto/src/logging.rs::tests::reexports_resolve` — assert
    `crypto::logging::TruncatedPubkey` and `crypto::logging::RedactedUrl` resolve by importing
    them and calling `.to_string()` once each. The test primarily guards the re-export wiring.
- **Non-goals:**
  - Removing `crates/crypto/src/logging.rs` entirely (Phase 6).
  - Sweeping every importer in the tree (Issue 2.3).

---

## Issue 2.2: Replace `bls.rs` Debug impls for `PublicKey` and `Signature`

- **Points:** 2
- **Depends on:** 1.1, 2.1
- **Files touched:**
  - `crates/crypto/src/bls.rs` (Debug impls only — Display impls unchanged)
- **Summary:** Today `impl Debug for PublicKey` and `impl Debug for Signature` delegate to
  `Display`, which prints the full hex. Replace with short-form output via the
  `TruncatedPubkeyBytes` / `TruncatedSignature` helpers promoted in Phase 1. This closes the
  primary `BAD_SIG_DEBUG` leak so the Phase 3 ratchet does not need a seeded allowlist entry for
  normal rs-vc code paths. TDD: start RED with assertions against the short-form regex, confirm
  current code fails, then flip the Debug impls GREEN.
- **Acceptance criteria:**
  - [ ] `impl fmt::Debug for PublicKey` prints `PublicKey({})` where the body is
        `TruncatedPubkeyBytes(&self.to_bytes())` (architecture §1.2).
  - [ ] `impl fmt::Debug for Signature` prints `Signature({})` where the body is
        `TruncatedSignature::from_bytes(&self.to_bytes())`.
  - [ ] `impl fmt::Display for PublicKey` unchanged (full hex still available via `%`).
  - [ ] `impl fmt::Display for Signature` unchanged.
  - [ ] `SecretKey` Debug impl remains `"SecretKey([REDACTED])"` — no regression.
  - [ ] `cargo test -p crypto` passes (including the new short-form assertions below).
- **Tests:**
  - `crates/crypto/src/bls.rs::tests::public_key_debug_is_short_form` (RED→GREEN) — asserts
    `format!("{:?}", pk)` matches the regex
    `^PublicKey\(0x[0-9a-f]{10}\.\.\.[0-9a-f]{8}\)$` (using `regex` — if adding the dep to
    `crypto` dev-deps is undesirable, use a manual check: starts with `PublicKey(0x`, contains
    `...`, ends with `)`, and `len() < 60`).
  - `crates/crypto/src/bls.rs::tests::signature_debug_is_short_form` — asserts
    `format!("{:?}", sig)` matches `^Signature\(0x[0-9a-f]{8}\.\.\.[0-9a-f]{8}\)$`.
  - `crates/crypto/src/bls.rs::tests::public_key_display_unchanged` — asserts
    `format!("{}", pk)` still starts with `0x` and has length `2 + PUBLIC_KEY_BYTES_LEN * 2`
    (existing test `test_public_key_hex_display` stays green).
  - `crates/crypto/src/bls.rs::tests::signature_display_unchanged` — existing test
    `test_signature_hex_display` stays green.
  - `crates/crypto/src/bls.rs::tests::secret_key_debug_still_redacted` — existing test
    `test_secret_key_debug_redacted` stays green (asserts `"SecretKey([REDACTED])"`).
- **Non-goals:**
  - Changing Display impls.
  - Changing `SecretKey` Debug.
  - Removing the `hex::encode(self.to_bytes())` call from `Display` (stays for explicit
    `%` formatting).

---

## Issue 2.3: Sweep importers of `crypto::logging::*` to `telemetry::*`

- **Points:** 2
- **Depends on:** 2.1
- **Files touched:** All crates that currently do
  `use crypto::logging::{TruncatedPubkey, RedactedUrl}` — discover via
  `grep -rn "crypto::logging::" crates/ bin/`. Based on architecture §1.5, expected sites include:
  - `crates/rvc/src/**/*.rs`
  - `crates/beacon/src/**/*.rs`
  - `crates/bn-manager/src/**/*.rs`
  - `crates/signer/src/**/*.rs`
  - `crates/slashing/src/**/*.rs`
  - `crates/validator-store/src/**/*.rs`
  - `crates/duty-tracker/src/**/*.rs`
  - `crates/propagator/src/**/*.rs`
  - `crates/doppelganger/src/**/*.rs`
  - `crates/secret-provider/src/**/*.rs`
  - `crates/keymanager-api/src/**/*.rs`
  - `crates/grpc-signer/src/**/*.rs`
  - `bin/rvc/src/**/*.rs`, `bin/rvc-signer/src/**/*.rs`
  - Add `telemetry = { workspace = true }` to the `Cargo.toml` of each affected crate that
    doesn't already have it.
- **Summary:** Flip import paths from `crypto::logging::{TruncatedPubkey, RedactedUrl}` to
  `telemetry::{TruncatedPubkey, RedactedUrl}`. The `crypto::logging` re-export stays in place as a
  grace period (removed in Phase 6). Goal is to stop adding fresh references to the deprecated
  module.
- **Acceptance criteria:**
  - [ ] `grep -rn "crypto::logging::" crates/ bin/` returns only matches inside
        `crates/crypto/src/logging.rs` itself plus any intentional grandfathered imports
        (expected: zero grandfathered).
  - [ ] Every touched `Cargo.toml` has `telemetry = { workspace = true }` if a source file in
        that crate now imports from `telemetry::`.
  - [ ] `cargo build --workspace` and `cargo clippy --workspace --all-targets -- -D warnings` are
        clean.
  - [ ] No new deprecation warnings surface outside `crates/crypto/src/logging.rs` itself.
  - [ ] Commit is grouped by crate to keep diffs under ~500 LOC per PRD constraint.
- **Tests:**
  - `cargo test --workspace` passes. No new tests are required; the change is mechanical.
- **Non-goals:**
  - Removing the `crypto::logging` re-export (Phase 6).
  - Adding new `TruncatedPubkey` call sites that didn't exist before.
  - Converting existing callsites to use `TruncatedPubkeyBytes` or `TruncatedSignature` — those
    arrive in Phases 4/5 as part of the retrofit.
