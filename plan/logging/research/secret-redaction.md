# Research: Structurally Preventing Secret Leakage in Logs — Best Practices

> Angle for the rs-vc logging initiative (`plan/logging/prd.md`, Secret Redaction Policy P0-3).
> Researcher Template D (best practices). Scope: BLS private keys, keystore passwords,
> mnemonics/seed phrases, and signing payloads across the `crypto` / `secret-provider` / `signer`
> crates and the Web3Signer `:9000` path.

## Recommended Approach

**Defense in depth across three layers, because no single layer is sufficient.** The hard truth
(confirmed by the Azure SDK Rust guidelines and the `secrecy`/`tracing` docs alike) is that a Rust
type wrapper makes a secret *harder* to leak but **cannot make it impossible** — a developer can
always call `.expose_secret()` and pass the result straight to `info!`. So the policy must combine:

1. **Layer 1 — Type-level redaction (reduces accidents).** Every secret lives in a type whose
   `Debug` is redacted and whose `Display` is *not implemented at all*, so `{}`, `?`, `%`, and
   `#[instrument]` auto-capture cannot print it. rs-vc already does this well (`SecretKey([REDACTED])`,
   `secrecy::SecretString`, `SecretDataFormat` → `<redacted>`, `Zeroizing<[u8;32]>`); the policy
   standardizes and *closes the gaps* (notably `#[instrument(skip_all)]` discipline on the sign
   path) rather than redesigning. [1][2][3][6]
2. **Layer 2 — A `#[forbid]`-style CI lint gate (catches the obvious bypasses).** A
   `clippy.toml` `disallowed-methods`/`disallowed-types`/`disallowed-macros` config that bans the
   known *unsafe* sinks (e.g. `expose_secret`, `SecretKey::to_bytes`/`raw_bytes`, `bls::SecretKey`,
   raw `Url`) plus a cheap `grep`/regex source scan run in CI. This is the **primary enforcement
   recommendation** because it needs no compiler-plugin and rides the existing
   `cargo clippy --workspace --all-targets -- -D warnings` step. [9][10][13]
3. **Layer 3 — Captured-subscriber behavioral tests + an emitted-log scan (proves it).** Per-event
   `tracing_test::traced_test` tests in `crypto`/`signer`/`bin/rvc-signer` that fire each high-risk
   log line under a capturing subscriber and assert the output is **truncated/redacted and does not
   contain the raw secret**, plus a gitleaks/trufflehog pass over a *captured sample of real
   emitted log output* (not just source). This is the only layer that tests the *runtime* result.
   [11][12][14][15]

If a fully robust automated **source** scan proves impractical (it will — see the regex-fragility
analysis below), the **sanctioned fallback** is: keep Layers 1 and the clippy `disallowed-*` gate
(both are robust and cheap), keep the captured-subscriber tests as the runtime proof, and add a
**documented reviewer checklist** for the four high-risk crates in place of a perfect grep. This
matches the PRD's Open Question 3 fallback and is *stronger* than the PRD's minimum because the
clippy `disallowed-*` gate is itself automated.

---

## Approach Overview

### Option 1: [Recommended] — Redacted newtype + `skip_all` + clippy `disallowed-*` gate + captured-subscriber tests

**How it works:** Secrets only ever exist behind types that refuse to `Display` and redact `Debug`
(Layer 1). The sign/keystore entry points use `#[instrument(skip_all)]` (never bare `#[instrument]`,
which captures every argument by `Debug` by default [2]). CI bans the dangerous sinks via
`clippy.toml` and a grep, and asserts redacted output with capturing-subscriber tests + a scan of
emitted samples.

**Why this one:** It is the only combination that is *additive* to rs-vc's current state (the
primitives, `tracing_test`, the `architecture-tests` crate, and the clippy `-D warnings` CI step all
already exist), needs no nightly/compiler-plugin toolchain, and produces a gate that fails *closed*
with 0 findings as the PRD requires.

**Trade-offs:** The clippy `disallowed-*` gate only catches *named* method/type paths — it cannot
see an arbitrary expression or a value already laundered into a `String`/`&str`. So it must be paired
with the type-level guarantee (which *is* total for `Display`) and the runtime tests. Maintaining the
disallowed list and the test corpus is ongoing work.

### Option 2: [Alternative] — Custom dylint lint that flags secret-typed values reaching a log macro

**How it works:** Write a Dylint library (a Rust lint in a dynamic library, no Clippy fork needed)
that walks the HIR/MIR, recognizes the secret newtypes, and fires when one flows into a `tracing`
macro expansion. Dylint is purpose-built for exactly this "maintain your own lint collection" use
case and ships `clippy_utils` helpers. [7][8]

**When to prefer this:** If the project later wants *dataflow-aware* enforcement that survives
laundering through locals/`String` — something `disallowed-methods` fundamentally cannot do — a
dylint lint is the principled upgrade. Trail of Bits explicitly motivates dylint as the
fork-free way to write security lints. [7]

**Trade-offs:** Dylint lints pin to a specific nightly `rustc` internal API, so they are brittle
across toolchain bumps and add a CI toolchain dependency. This is real maintenance cost for a 23-crate
workspace on stable. Recommend deferring to a P2 "conformance lint" item (the PRD already lists
P2-4) rather than blocking P0 on it.

### Option 3: [Alternative] — `valuable`-based structured field redaction (`redactable` / custom `Visit`)

**How it works:** Instead of redacting at `Debug`, register secret-bearing structs as
`valuable::Valuable` and emit them through `tracing`'s (unstable) `valuable` support so a
subscriber/visitor redacts designated fields structurally — the `redactable` crate's
`.tracing_redacted_valuable()` is exactly this. Its `Sensitive`/`SensitiveValue<T,P>` derive even
*declines to implement `Display`* so accidental formatting won't compile. [16][4][5]

**When to prefer this:** When you need the *structured JSON* log path (P2-3) to carry rich
objects with per-field policies (`Token`, `Pii`, …) and want redaction to live in one derive rather
than scattered `Display` wrappers.

**Trade-offs:** It requires `tracing`'s **unstable** `valuable` feature
(`RUSTFLAGS="--cfg tracing_unstable"`), which the PRD's "do not destabilize the telemetry stack"
constraint disfavors for P0. rs-vc's values are also mostly scalars (pubkey hex, URL) where the
existing zero-alloc `Display` wrappers are simpler and cheaper. Keep `valuable` in reserve for the
JSON profile, not the P0 gate.

---

## How the leakage surfaces map to primitives (rs-vc-specific)

| Secret | Today in rs-vc | Mandated handling | Notes |
|---|---|---|---|
| BLS private key | `crypto::bls::SecretKey` — `Debug` = `SecretKey([REDACTED])`; inner `blst` is `ZeroizeOnDrop`; no `Display` [code: `crates/crypto/src/bls.rs`] | Never log. Ban `SecretKey::to_bytes`/`raw_bytes` and `blst::SecretKey` from log-adjacent code via clippy. | `raw_bytes()` returns a bare `[u8;32]` — the **highest-risk laundering path**; once it's a byte array the type guarantee is gone. Gate it. |
| Keystore password | `secrecy::SecretString` (via `*=pw` map) — redacted `Debug`, **no `Display`**, no `Serialize` by default [1] | Never log. Ban `expose_secret` outside `crypto::keystore`/`key_manager` decrypt call sites. | `secrecy` 0.10 renamed `Secret<T>`→`SecretBox`; `SecretString` stays. Reading requires explicit `ExposeSecret::expose_secret`. [1][6] |
| Mnemonic / seed | `bip39` mnemonic + `Zeroizing` in `rvc-keygen`/`crypto::mnemonic` | Never log, not even length. Wrap in a redacted newtype or `SecretString`; ban its `Display`. | `bip39::Mnemonic` *does* `Display` to the phrase — treat the bare type as a secret-bearing sink; never pass it to a macro. |
| Full signing payload / root | passed through `signer`/`gate`/Web3Signer `:9000` | Omit or **truncate** at `trace`; full root only behind explicit approval (PRD Open Q1, resolved: truncate). | Reuse a `TruncatedHex`-style `Display` wrapper analogous to `TruncatedPubkey`. |
| Full signature | produced by `bls::Signature` | Truncate/omit by default. | `Signature` currently `Display`s the full hex — fine for return values, **not** for logs; truncate. |
| Public key | `crypto::logging::TruncatedPubkey` → `0x{first10}...{last8}`, zero-alloc `Display` [code] | **Always** `TruncatedPubkey` + `%`, never the full key, *even at `trace`* (PRD Open Q2). | Settled format; see truncation conventions below. |
| Credentials in URL | `crypto::logging::RedactedUrl` (strips `user:pass@`) / `telemetry::config::redact_endpoint` [code] | **Always** `RedactedUrl`/`redact_endpoint`; ban logging a raw `url::Url`/`&str` BN endpoint. | `RedactedUrl` falls back to raw string on parse failure — acceptable since a non-URL has no credentials to leak. |

---

## Why type-level redaction alone is *not* "impossible-to-leak" (the central caveat)

Four independent docs confirm the same boundary, and the policy must be built around it:

- **`#[instrument]` captures everything by default.** "By default, all arguments to the function are
  included as fields on the span," recorded via `Value` or else `Debug`. [2] So a bare
  `#[tracing::instrument]` on `fn sign(&self, key: &SecretKey, …)` would try to `Debug`-format the
  key. The *only* safe forms on a secret-handling fn are `skip(key, …)` or `skip_all` — and
  `skip_all` is the safer default because adding a new secret arg later doesn't silently start
  capturing it. rs-vc already uses `#[instrument(skip_all)]` on the `:9000` routes
  (`bin/rvc-signer/src/http_api/routes.rs`); the policy makes that **mandatory** for every fn that
  takes a secret argument.
- **`skip` is macro-level only.** It stops *auto-capture*; it does **not** stop a developer writing
  `info!(?key)` in the body. [2] This is why a CI gate is non-negotiable.
- **`secrecy` itself only claims to "prevent *accidental* leakage."** Its protection is the redacted
  `Debug` + the deliberate absence of `Serialize`/`Display`; `expose_secret()` is the documented,
  intentional escape hatch. [1][6]
- **Azure's own SDK guidance states it plainly:** `SafeDebug` "cannot otherwise prevent developers
  from tracing or telemetering PII directly," and pairs the type with a hard rule —
  "DO NOT trace or telemeter Personally-Identifiable Information." [3]

**Conclusion:** "impossible" is achievable only for the *implicit* paths (`Display`/`Debug`/auto-capture),
and only if the secret never escapes its wrapper as a plain `String`/`[u8]`. The *explicit* path
(`expose_secret()` → macro) can only be made *detectable* (lint/grep/test), not impossible. The
redacted-`Debug`-and-no-`Display` newtype + a CI detector for the explicit sinks is therefore the
realistic ceiling.

---

## `#[derive(Debug)]` hazards (and the fix)

- A plain `#[derive(Debug)]` on any struct that *contains* a secret field prints the secret. This is
  the classic leak: `#[derive(Debug)] struct DecryptCtx { pw: String, … }` → `?ctx` dumps `pw`. The
  defense is to never hold a secret as a bare `String`/`[u8]` inside a `Debug`-derived struct — hold
  it as `SecretString`/`Zeroizing`/a redacted newtype, whose redacted `Debug` makes the *derived*
  outer `Debug` safe automatically. rs-vc already does this in `SecretDataFormat` (manual `Debug` →
  `<redacted>`) and could equally use `secrecy`/`redact`'s "safe to `#[derive(Debug)]` around"
  property. [1][13]
- **Two zero-cost derive options** if a manual `Debug` is tedious: `veil` (`#[derive(Redact)]` +
  `#[redact]`/`#[redact(partial)]`/`#[redact(fixed = N)]` per field — redacts **`Debug` only**, leaves
  `Display` alone, with a `VEIL_DISABLE_REDACTION` test escape hatch) [17], or `redact`'s `Secret<T>`
  which prints `[REDACTED <type>]` and (unlike `secrecy`) does **not** require `Zeroize`, so it can
  wrap types `secrecy` can't. [13] For rs-vc, prefer keeping `secrecy` for material that *must* be
  zeroized (keys, passwords) and reserve `veil`/`redact` for *aggregate request/response structs* on
  the `:9000` path that merely *embed* a secret and want a one-line redacted `Debug`.
- **Hazard checklist for the redaction policy doc:** no `#[derive(Debug)]` on a type with a raw-secret
  field; no `#[derive(Serialize)]` on a secret type (`secrecy` blocks this by default — *keep* that,
  don't add `SerializableSecret`) [1]; no bare `#[instrument]` on a secret-taking fn (use `skip_all`);
  no `to_bytes()`/`raw_bytes()`/`expose_secret()` result passed to a macro.

---

## Pubkey / payload truncation conventions

- **rs-vc settled format (do not redesign):** `TruncatedPubkey` →
  `0x{first 10 hex}...{last 8 hex}` (e.g. `0x93247f2209...611df74a`), zero-allocation `Display` so
  **nothing is formatted when the level is disabled** — the central P0-6 mechanic. It strips at most
  one `0x`, warns + falls back to raw on a double-`0x`, and falls back to raw on non-ASCII. [code:
  `crates/crypto/src/logging.rs`]
- **Ecosystem precedent:** truncating long hex for log readability is the Ethereum-client norm —
  Lighthouse truncates block roots/hashes to forms like `0xa208…7fd5` in publication logs (though it
  notably logs the *full* `voting_pubkey` at enable-time, a choice rs-vc deliberately does **not**
  copy — rs-vc truncates pubkeys at every level including `trace`, PRD Open Q2). [18] The `...`-in-the-
  middle "first N / last M" shape is the standard because it preserves both the discriminating prefix
  and a verification suffix.
- **Extend the same pattern to roots/signatures:** add a `TruncatedHex`-style wrapper for signing
  roots and signatures at `trace` (mirroring `TruncatedPubkey`'s zero-alloc `Display` + `%`), so the
  Open-Q1 "truncate, don't omit" resolution has a primitive. Keep the *full* root/signature only on
  return values, never in a macro.

---

## Implementation Guidelines (enforceable redaction policy for rs-vc)

The policy doc (PRD P0-1) should state these as **normative MUST/MUST-NOT** rules:

1. **MUST** keep every secret in a type that (a) redacts `Debug` and (b) does **not** implement
   `Display`: BLS keys (`SecretKey`), passwords (`SecretString`), mnemonics (newtype/`SecretString`),
   raw key bytes (`Zeroizing<[u8;N]>`). [1][13][17]
2. **MUST NOT** pass the result of `expose_secret()`, `SecretKey::to_bytes()`/`raw_bytes()`,
   `bip39::Mnemonic::to_string()/Display`, or a full signing root/signature into any `tracing` macro
   (`error!`/`warn!`/`info!`/`debug!`/`trace!`/`event!`) or `#[instrument]` field — at **any** level.
3. **MUST** annotate every fn taking a secret argument with `#[instrument(skip_all)]` (or explicit
   `skip(secret_arg, …)`); **MUST NOT** use bare `#[instrument]` on such a fn. [2]
4. **MUST** log pubkeys only via `TruncatedPubkey` + `%`, URLs only via `RedactedUrl`/`redact_endpoint`,
   and roots/signatures only via the truncating wrapper — never the raw value. [code]
5. **MUST NOT** add `#[derive(Serialize)]` to a secret type or add the `secrecy` `SerializableSecret`
   marker — the default no-`Serialize` is a feature, not a gap. [1]
6. The four high-risk crates — `crypto`, `secret-provider`, `signer`, and the `bin/rvc-signer` `:9000`
   path — get **explicit reviewer sign-off** on every PR that adds/changes a log statement; no added
   statement may widen secret exposure (PRD risk table).

---

## Concrete CI-gate recommendation

**Tiered, fail-closed, 0-findings, all on the existing CI runners.** Land these in order; Tier 1+2
satisfy P0-3 even if Tier 3's source scan is dropped.

**Tier 1 — clippy `disallowed-*` (primary, cheapest, already wired).** Extend the repo
`clippy.toml` (currently only `msrv`) and rely on the existing
`cargo clippy --workspace --all-targets -- -D warnings` CI step, which already fails the build on any
warning. [9][10] Sketch:

```toml
msrv = "1.92"

disallowed-methods = [
  { path = "secrecy::ExposeSecret::expose_secret",
    reason = "expose_secret() output must never reach a log macro; decrypt at the call site only" },
  { path = "rvc_crypto::bls::SecretKey::raw_bytes",
    reason = "raw key bytes escape the redacted newtype; do not log or format" },
  { path = "rvc_crypto::bls::SecretKey::to_bytes",
    reason = "raw key bytes escape the redacted newtype; do not log or format" },
]

disallowed-types = [
  # if any non-redacted secret carrier is introduced, list it here
]

disallowed-macros = [
  # optionally ban a project-local unsafe logging shim if one is ever added
]
```

Caveat (state it in the policy): `disallowed-methods` matches **named paths only** — it does not see
a value already laundered into a `String`, nor arbitrary expressions or free functions. [10][14] That
is *acceptable* because the type layer makes the *implicit* path impossible and Tier 3 tests the
*runtime* result; the clippy gate's job is to catch the obvious explicit bypasses (`expose_secret`,
`raw_bytes`) at compile time. Because `expose_secret` is *legitimately* needed at the decrypt call
sites, scope it with a local `#[allow(clippy::disallowed_methods)]` on exactly those lines (a small,
reviewable, greppable allow-list) — the lint then flags any *new* use elsewhere.

**Tier 2 — captured-subscriber behavioral tests (runtime proof, model already exists).** Add
`#[tracing_test::traced_test]` tests in `crypto`, `signer`, and `bin/rvc-signer` that exercise each
high-risk log line and assert with `logs_contain(...)` that the output **does** contain the
truncated/redacted form and **does NOT** contain the raw secret. [11][12] The existing
`test_truncated_pubkey_double_0x_prefix_warns_and_falls_back` test (uses `traced_test` +
`logs_contain`) is the proven model. Run under the workspace runner of record
`cargo nextest run --workspace`. Make these tests assert the *negative* (raw secret absent), which is
the property the PRD actually cares about.

**Tier 3 — secret scan over BOTH source and a captured log sample (the belt-and-braces backstop).**
Add a CI job that (a) runs `gitleaks` (rule+entropy, fast, SARIF, blocking on every PR — the standard
pre-merge gate) over the source tree, and (b) **emits a representative log sample** — run the
captured-subscriber tests (or a tiny harness) with verbose levels at `trace`, capture stdout to a
file, and run `gitleaks`/`trufflehog` over *that emitted output*. [14][15] Scanning the emitted log,
not just source, is what actually verifies "no secret reached a sink." `trufflehog`'s
verification-first mode is better as a *scheduled* full sweep; `gitleaks` is the right *blocking* PR
gate. [14][15] A grep/regex source scan for `(info|debug|trace|warn|error)!\s*\(.*(expose_secret|raw_bytes|to_bytes|mnemonic|password|secret_key)`
can supplement, but treat it as advisory — regexes over Rust are fragile (multiline macro args, field
laundering, false positives on test code) and **should not be the sole gate**.

**Fallback if a robust automated *source* scan is impractical (PRD Open Q3):** drop the Tier-3 regex
source scan, **keep** Tier 1 (clippy `disallowed-*`, fully automated), Tier 2 (captured-subscriber
tests, fully automated), and Tier 3a/3b (`gitleaks` on source + emitted sample). Add a **documented
reviewer checklist** (the six MUST/MUST-NOT rules above) gating PRs to the four high-risk crates. This
fallback is *stronger* than the PRD's stated minimum (reviewer checklist + captured-subscriber tests)
because it retains two automated gates, and it avoids shipping a brittle grep that lulls reviewers
into false confidence.

---

## Common Pitfalls

- **Bare `#[instrument]` on a sign/decrypt fn.** Silently `Debug`-captures every arg, including a
  later-added secret. Always `skip_all`. [2]
- **Laundering a secret into a `String`/`[u8]` before logging.** Defeats both the type guarantee and
  the clippy path-match. `raw_bytes()` is the prime offender in rs-vc — gate it explicitly.
- **`#[derive(Debug)]` on a struct holding a raw-secret field.** Holds the secret as
  `SecretString`/`Zeroizing`/redacted-newtype instead, so the derived `Debug` is safe. [1][13]
- **Adding `Serialize`/`Display` to a secret type "for convenience."** Re-opens the JSON/format leak
  that `secrecy` deliberately closes; never do it. [1]
- **Trusting a regex source scan as the *only* gate.** Multiline macro args and value laundering make
  it both leaky and noisy; it is advisory, not authoritative. [14]
- **Logging the *length* of a mnemonic/password.** Even metadata can be sensitive; the policy forbids
  the value, and length adds no operational value — omit it.
- **Dylint toolchain drift.** A custom lint pinned to nightly `rustc` internals breaks on toolchain
  bumps; keep it P2, not a P0 blocker. [7][8]
- **`tracing` `valuable` is unstable.** Needs `--cfg tracing_unstable`; don't put the P0 gate on an
  unstable cfg. [16][4]

## Real-World Examples

- **Azure SDK for Rust** ships `azure_core::fmt::SafeDebug` (redacted `Debug`) and pairs it with a
  hard "DO NOT trace PII" rule — explicitly acknowledging the type can't stop direct logging, exactly
  the layered stance recommended here. [3]
- **`secrecy`** (widely used, already a rs-vc dependency) redacts `Debug`, omits `Serialize`/`Display`
  by default, and zeroizes on drop — the canonical "reduce accidents" primitive. [1][6]
- **`veil`** (prima.it) uses `#[derive(Redact)]` for per-field `Debug` redaction with partial/fixed
  modes — a drop-in for aggregate request structs on the `:9000` path. [17]
- **`redactable`** integrates redaction with `tracing`+`valuable`, and its `SensitiveValue<T,P>`
  deliberately *won't compile* if you try to `Display` it — the strongest "make it impossible"
  structural stance available, for the future JSON profile. [16][5]
- **Trail of Bits / Dylint** is the established fork-free path for project-specific security lints
  like "secret reaches a log macro," if rs-vc later wants dataflow-aware enforcement. [7][8]

## Assumptions

- rs-vc stays on `tracing`/`tracing-subscriber` (PRD Non-Goal: no new framework), so all
  recommendations compose into it; `valuable`/unstable-cfg options are reserved, not adopted for P0.
- The existing primitives (`TruncatedPubkey` `0x{first10}...{last8}`, `RedactedUrl`,
  `redact_endpoint`, `secrecy::SecretString`, `zeroize`) are the accepted, *settled* base and are
  standardized/extended, not redesigned (PRD Assumptions + Technical Considerations).
- The CI gate must run on the current GitHub Actions runners and ride the existing
  `cargo clippy --workspace --all-targets -- -D warnings` and `cargo nextest run --workspace` steps;
  no new mandatory toolchain (nightly/dylint) for P0.
- "0 findings" means: 0 from the clippy `disallowed-*` gate, 0 raw-secret hits in captured-subscriber
  tests, and 0 `gitleaks` findings over source + the emitted-log sample — with `expose_secret` allowed
  only on an explicit, reviewed allow-list at the decrypt call sites.
- `secrecy` is at the 0.x line where `Secret<T>` is renamed to `SecretBox` but `SecretString`/
  `ExposeSecret` remain the surface rs-vc uses; the policy references `SecretString`/`expose_secret`
  to match the existing code (`crates/crypto/src/key_manager.rs`).
- The four crates the PRD names high-risk (`crypto`, `secret-provider`, `signer`, `:9000` path) are
  the correct review boundary; `rvc-keygen` (mnemonic/`bip39`) is treated as equally high-risk for
  the mnemonic rule even though the PRD lists it under P1 breadth.
- Full pubkeys are truncated even at `trace` and full signing roots/signatures are truncated/omitted
  by default (PRD Open Qs 1 & 2, taken as resolved-to-stricter).

## Sources

[1] [secrecy — docs.rs](https://docs.rs/secrecy) — Crate docs. `SecretBox`/`SecretString` redact `Debug`, do **not** implement `Display`, and (to prevent serde exfiltration) do **not** derive `Serialize` by default — `SerializableSecret` must be opted into; secrets read via `ExposeSecret::expose_secret`; zeroized on drop. Confirms 0.10 `Secret<T>`→`SecretBox` rename, `CloneableSecret`.
[2] [`#[instrument]` — tracing docs.rs](https://docs.rs/tracing/latest/tracing/attr.instrument.html) — Crate docs. "By default, all arguments to the function are included as fields on the span," via `Value` or `Debug`; `skip()`/`skip_all` exclude args from *auto-capture* only; `fields(...)` records selected struct properties; `skip` does **not** prevent manual logging in the body (macro-level filtering only); `%`=Display, `?`=Debug.
[3] [Azure SDK for Rust — Implementation Guidelines](https://azure.github.io/azure-sdk/rust_implementation.html) — Microsoft, accessed 2026-06-22. DO derive/impl `Debug` only if no PII leaks; SHOULD use `azure_core::fmt::SafeDebug` otherwise; **DO NOT** trace/telemeter PII; `SafeDebug` "cannot otherwise prevent developers from tracing or telemetering PII directly."
[4] [Announcing Valuable — Tokio blog](https://tokio.rs/blog/2021-05-valuable) — Tokio, 2021. `valuable` provides object-safe inspection of structured values for `tracing` field recording; basis for structured (JSON) field handling.
[5] [redactable — GitHub (sformisano)](https://github.com/sformisano/redactable) — README, accessed 2026-06-22. `Sensitive`/`SensitiveDisplay`/`NotSensitive` derives; `#[sensitive(Policy)]` fields; `.tracing_redacted_debug()` (no unstable feature) and `.tracing_redacted_valuable()` (needs `tracing::field::valuable` unstable); `SensitiveValue<T,P>` deliberately does **not** implement `Display` so accidental formatting won't compile.
[6] [secrecy — crates.io](https://crates.io/crates/secrecy) — Package page, accessed 2026-06-22. Prevents accidental leakage via debug logging; wipes memory on drop via `zeroize`; explicit, auditable access via `ExposeSecret`/`ExposeSecretMut`.
[7] [Write Rust lints without forking Clippy — Trail of Bits blog](https://blog.trailofbits.com/2021/11/09/write-rust-lints-without-forking-clippy/) — Trail of Bits, 2021. Motivates Dylint for maintaining project-specific (incl. security) lints without forking Clippy; uses `clippy_utils`.
[8] [Dylint — GitHub (trailofbits)](https://github.com/trailofbits/dylint) — README, accessed 2026-06-22. Runs Rust lints from dynamic libraries; `cargo dylint new` scaffolds a loadable lint library; lints pin to a nightly `rustc` API.
[9] [Lint Configuration — Clippy book](https://doc.rust-lang.org/clippy/lint_configuration.html) — rust-lang, accessed 2026-06-22. `clippy.toml` config incl. `disallowed-methods`, `disallowed-types`, `disallowed-macros`, `disallowed-names`; entries as path strings or inline tables with `reason`/`replacement`.
[10] [Disallow code usage with a custom clippy.toml — schneems.com](https://www.schneems.com/2025/11/19/find-accidental-code-usage-with-a-custom-clippytoml/) — Richard Schneeman, 2025-11-19. Practical workflow: define `disallowed-methods`/`-types` with `path`/`reason`/`replacement`, enforce via `cargo clippy --all-targets … -- --deny warnings`; **caveat**: matches named method/type paths only, not arbitrary expressions/free functions/macro args.
[11] [tracing-test — docs.rs](https://docs.rs/tracing-test/latest/tracing_test/) — Crate docs, accessed 2026-06-22. In-memory capturing subscriber; injects a `logs_contain(...)` local fn to assert on captured output; default `RUST_LOG=<crate>=trace` filter; works for async tests.
[12] [traced_test — tracing-test docs.rs](https://docs.rs/tracing-test/latest/tracing_test/attr.traced_test.html) — Crate docs, accessed 2026-06-22. `#[traced_test]` attribute macro setup for the capturing subscriber + `logs_contain` assertions (the model rs-vc already uses in `crypto::logging` tests).
[13] [redact — docs.rs](https://docs.rs/redact/) — Crate docs, accessed 2026-06-22. `Secret<T>` prints `[REDACTED <type>]` for `Debug`, no `Display`; access only via `expose_secret()`; unlike `secrecy`, does **not** require `Zeroize`, so it can wrap any type; makes `#[derive(Debug)]` around a secret safe.
[14] [TruffleHog vs Gitleaks — Jit](https://www.jit.io/resources/appsec-tools/trufflehog-vs-gitleaks-a-detailed-comparison-of-secret-scanning-tools) — Jit, accessed 2026-06-22. Gitleaks = rule+entropy regex, no network, fast, SARIF, strong *blocking* PR/pre-commit gate; TruffleHog = verification-first (live API check), slower, better as scheduled full-history sweep; recommends Gitleaks pre-commit + TruffleHog in CI.
[15] [trufflehog — GitHub (trufflesecurity)](https://github.com/trufflesecurity/trufflehog) — README, accessed 2026-06-22. Finds/verifies/analyzes leaked credentials across 800+ types and many sources (incl. arbitrary text/files), supporting scanning of emitted artifacts, not just git source.
[16] [Experimental valuable support — tokio-rs/tracing Discussion #1906](https://github.com/tokio-rs/tracing/discussions/1906) — tokio-rs, accessed 2026-06-22. `tracing`'s `valuable` support is gated behind the unstable `--cfg tracing_unstable` flag; enables structured field recording/redaction via `valuable::Valuable`.
[17] [veil — GitHub (primait)](https://github.com/primait/veil) — README, accessed 2026-06-22. `#[derive(Redact)]` + `#[redact]`/`#[redact(partial)]`/`#[redact(fixed = N)]`/`#[redact(skip)]` redacts **`Debug` only** (leaves `Display`); optional `toggle` feature exposes `VEIL_DISABLE_REDACTION` env var / `veil::disable()` for tests.
[18] [sigp/lighthouse — GitHub](https://github.com/sigp/lighthouse) — Ethereum consensus client (Rust), accessed 2026-06-22. Ethereum-client precedent for truncating long hex (block roots/hashes) to `0x{prefix}…{suffix}` for log readability; note Lighthouse logs full `voting_pubkey` at enable-time — a choice rs-vc deliberately does not copy (truncates pubkeys at all levels).
