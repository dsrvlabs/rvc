//! rustls crypto-provider install for the HTTP signing transport.
//!
//! rustls 0.23 resolves a process-global default
//! [`CryptoProvider`](rustls::crypto::CryptoProvider) when
//! [`rustls::ServerConfig::builder`] is called. Its automatic resolution
//! `panic!`s when the number of provider features compiled into the shared
//! `rustls` crate is **not exactly one** — i.e. with **zero or ≥2** providers.
//!
//! In the committed build the shared `rustls` carries **exactly one** provider
//! (`ring`, see the dependency notes below), so `builder()` auto-resolves it and
//! does **not** panic today. We still install an explicit default once at
//! startup as **forward-defense (ADR-006, R1)**: if a future dependency ever
//! unifies a second provider (`aws_lc_rs`) onto the shared `rustls` crate, the
//! automatic resolution becomes ambiguous and `ServerConfig::builder()` would
//! panic — an installed default keeps provider selection deterministic and the
//! Phase-3 HTTP builder path panic-free regardless of how the feature graph
//! evolves. tonic sidesteps the same trap via explicit-provider paths; the HTTP
//! server's plain `ServerConfig::builder()` (Phase 3) does not.
//!
//! ## Provider choice — `ring`, not `aws_lc_rs` (deviation from ADR-006)
//!
//! ADR-006 names the `aws_lc_rs` provider. We install **`ring`** instead, for a
//! reason discovered while implementing this issue and verified against the
//! suite:
//!
//! The workspace already builds the shared `rustls` crate with **only** the
//! `ring` provider feature enabled (it reaches `rustls` via rcgen / quinn /
//! reqwest, none of which turn on rustls's `aws_lc_rs` feature). To call
//! `rustls::crypto::aws_lc_rs::default_provider()` we would have to enable
//! rustls's `aws_lc_rs` feature here — and because Cargo unifies features across
//! the workspace, that would turn on **both** providers on the single shared
//! `rustls` crate. Automatic provider detection then becomes ambiguous, and
//! every gRPC mTLS path that lets tonic build a rustls config *without* an
//! installed default would panic. (Verified empirically while implementing this
//! issue: declaring `rustls`/`tokio-rustls` with default features broke the
//! `rvc-grpc-signer` integration and `rvc-signer-bin` `dvt` mTLS tests on a
//! `--workspace` run.) It would also violate this issue's "existing suite stays
//! green / no graph perturbation / zero net-new compiled crates" exit criteria
//! and add `aws-lc-rs` / `aws-lc-sys` / `cmake` to this crate's build graph.
//!
//! Installing the **`ring`** provider achieves ADR-006's actual goal — a single
//! deterministic installed default — while keeping the shared rustls feature set
//! byte-identical to `develop`. The `aws_lc_rs` vs `ring` choice is immaterial
//! to the install-default purpose; `ring` is the backend the rest of the
//! workspace already uses. (Flag for reviewer: this deviates from the literal
//! ADR-006 wording; recommend updating the ADR.)
//!
//! rustls types are reached through the `tokio_rustls::rustls` re-export so the
//! HTTP transport binds the *same* rustls as the gRPC/tonic stack.

use tokio_rustls::rustls;

/// Install the `ring` rustls provider as the process-global default.
///
/// Idempotent: [`install_default`](rustls::crypto::CryptoProvider::install_default)
/// returns `Err` once a provider is already installed, which we deliberately
/// ignore so this is safe to call from both `run_serve` and tests without
/// ordering constraints.
///
/// See the module docs for why this installs `ring` rather than the
/// ADR-006-named `aws_lc_rs` provider.
pub fn install_crypto_provider() {
    // `install_default` returns `Err` if a provider is already installed; we
    // ignore it for idempotency. After this call a default is guaranteed to
    // exist (ours, or one a prior caller installed) — assert that invariant in
    // debug builds so a future regression that leaves no default is caught.
    let _ = rustls::crypto::ring::default_provider().install_default();
    debug_assert!(
        rustls::crypto::CryptoProvider::get_default().is_some(),
        "a default CryptoProvider must be installed after install_crypto_provider()"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::crypto::CryptoProvider;

    /// After the install a process-global default provider is available.
    ///
    /// Weaker than [`install_selects_the_ring_provider`]: under a single-process
    /// test runner this assertion can pass even if the install is a no-op,
    /// because `ServerConfig::builder()`'s own auto-resolution (run by any other
    /// test in the process) installs a default as a side effect. It is the
    /// ring-provider coupling test that actually pins the function body; this one
    /// documents the post-install invariant the call site relies on.
    #[test]
    fn install_makes_provider_default_available() {
        install_crypto_provider();
        assert!(
            CryptoProvider::get_default().is_some(),
            "a default CryptoProvider must be installed after install_crypto_provider()"
        );
    }

    /// Calling the install twice runs without panicking or aborting the process.
    ///
    /// The second call's [`install_default`](CryptoProvider::install_default)
    /// returns `Err` (a default is already set) and the function discards it, so
    /// the fn is safe to call from both `run_serve` and tests without ordering
    /// constraints. (This is a cheap smoke test; it cannot fail on an empty body
    /// either, so it is not a coupling test.)
    #[test]
    fn install_is_idempotent() {
        install_crypto_provider();
        install_crypto_provider();
    }

    /// Smoke test of the Phase-3 `ServerConfig::builder()` path after the install.
    ///
    /// NOTE: this is *not* a panic-proof for R1 in the committed build. With only
    /// the `ring` provider compiled in, `builder()` auto-resolves that single
    /// provider and does not panic whether or not the install ran — the panic
    /// only fires with **zero or ≥2** providers compiled. It guards that the
    /// downstream builder chain stays usable after the install; the R1 forward-
    /// defense (deterministic provider selection) is exercised by
    /// [`install_selects_the_ring_provider`].
    #[test]
    fn server_config_builder_is_usable_after_install() {
        install_crypto_provider();
        let builder = rustls::ServerConfig::builder();
        let _ = builder.with_no_client_auth();
    }

    /// Couples directly to `install_crypto_provider()`'s body: it must install
    /// the **ring** provider as the process-global default.
    ///
    /// This is the test that fails if the function is gutted. nextest runs each
    /// test in its own process and this test calls `install_crypto_provider()`
    /// as its first action, so the install (first-wins) decides the default here
    /// — nothing else has run to set it. If the body is a no-op,
    /// [`CryptoProvider::get_default`] is `None` and the `expect` fails; if the
    /// body installed a *different* provider, the cipher-suite identities would
    /// diverge from `ring::default_provider()` and the comparison fails. (The
    /// `aws_lc_rs` provider module is not even compiled in this `ring`-only
    /// build, so the realistic regressions are "no install" or "wrong config".)
    #[test]
    fn install_selects_the_ring_provider() {
        install_crypto_provider();

        let installed =
            CryptoProvider::get_default().expect("install_crypto_provider must install a default");
        let ring = rustls::crypto::ring::default_provider();

        let installed_suites: Vec<_> = installed.cipher_suites.iter().map(|s| s.suite()).collect();
        let ring_suites: Vec<_> = ring.cipher_suites.iter().map(|s| s.suite()).collect();

        assert_eq!(
            installed_suites, ring_suites,
            "the installed default provider must be ring (cipher-suite set diverged)"
        );
    }
}
