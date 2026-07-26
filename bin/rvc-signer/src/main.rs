//! rvc-signer binary entry point.
//!
//! Thin CLI shim: parse args, init logging, call [`signer_server::server::run`].
//! Server assembly lives in the `signer_server` crate.

use signer_server::config::ServeArgs;
use signer_server::{config, server, ServerError};

use clap::{Parser, Subcommand};
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

#[derive(Parser)]
#[command(name = "rvc-signer")]
#[command(version)]
#[command(about = "Remote BLS signer for rvc validator client", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
// `Serve` carries the full server-config arg set and is necessarily larger than
// `SplitKey`. This enum is parsed exactly once at startup and immediately
// matched/consumed, so the variant-size disparity costs nothing — boxing the
// variant is not an option because clap's `Subcommand` derive requires the field
// to implement `Args`, which `Box<ServeArgs>` does not.
#[allow(clippy::large_enum_variant)]
enum Command {
    /// Start the gRPC signing server
    Serve(ServeArgs),

    /// Split a BLS secret key into Shamir shares stored as EIP-2335 keystores
    #[cfg(feature = "dvt")]
    SplitKey(SplitKeyCliArgs),
}

#[cfg(feature = "dvt")]
#[derive(Parser)]
struct SplitKeyCliArgs {
    /// Path to the source EIP-2335 keystore
    #[arg(long)]
    keystore: std::path::PathBuf,

    /// Password for the source keystore
    #[arg(long, group = "src_password")]
    password: Option<String>,

    /// Path to a file containing the source keystore password
    #[arg(long, group = "src_password")]
    password_file: Option<std::path::PathBuf>,

    /// Threshold (t) for Shamir secret sharing
    #[arg(long)]
    threshold: u64,

    /// Total number of shares (n) to generate
    #[arg(long)]
    shares: u64,

    /// Output directory for share keystores
    #[arg(long)]
    output_dir: std::path::PathBuf,

    /// Password for the output share keystores
    #[arg(long, group = "out_password")]
    output_password: Option<String>,

    /// Path to a file containing the password for output share keystores
    #[arg(long, group = "out_password")]
    output_password_file: Option<std::path::PathBuf>,
}

#[tokio::main]
async fn main() {
    // Logging output is console-only (stdout/stderr); operators collect rvc-signer
    // logs from the process's standard streams. Unlike `bin/rvc`, rvc-signer does
    // NOT wire the telemetry file appender, so there is no independent file level:
    // file == console (ADR-004 "file more verbose than console" does not apply here).
    //
    // Phase-3 issue 3.5 spike conclusion: the appender itself *is* capable of an
    // independent file level — `telemetry::create_file_layer` filters each file
    // layer with its own `EnvFilter::new(config.level)` (see
    // `crates/telemetry/src/file_appender.rs`), exactly as `bin/rvc` uses it.
    // Delivering it for rvc-signer would require a new `--logfile`/`logfile_level`
    // CLI + `ResolvedConfig` surface (it has none today); per 3.5's bounded scope
    // it is deferred as a documented fallback rather than a rushed file path in a
    // security-sensitive signer; the console-only status is stated in the Phase-5
    // OPERATOR_GUIDE.
    // Parse the CLI BEFORE initializing logging so the `Serve` subcommand's
    // `--log-format` flag can select the console format (issue 5.5). Nothing logs
    // between parse and init, so the Phase-3 init parity (the reconciled filter is
    // still the first subscriber installed) is preserved. One-shot subcommands
    // without the flag (e.g. `split-key`) resolve the format from `RVC_LOG_FORMAT`
    // env only (default pretty) via `resolve(None)`.
    let cli = Cli::parse();

    let log_format = match &cli.command {
        Command::Serve(args) => telemetry::LogFormat::resolve(args.log_format.as_deref()),
        #[cfg(feature = "dvt")]
        Command::SplitKey(_) => telemetry::LogFormat::resolve(None),
    };

    let reload_handle = init_logging(log_format);

    match cli.command {
        Command::Serve(args) => {
            let enable_log_reload = args.enable_log_reload;
            let resolved = match config::resolve_config(&args) {
                Ok(r) => r,
                Err(e) => {
                    error!(error = %e, "rvc-signer failed");
                    std::process::exit(1);
                }
            };

            // Runtime log-level reload (issue 5.4): owned by main because the
            // reload handle is created by `init_logging`. Cancelled after serve.
            let log_reload_shutdown = CancellationToken::new();
            spawn_log_reload_handler(enable_log_reload, reload_handle, log_reload_shutdown.clone());

            let shutdown = CancellationToken::new();
            let shutdown_for_signal = shutdown.clone();
            tokio::spawn(async move {
                shutdown_signal().await;
                shutdown_for_signal.cancel();
            });

            let result = server::run(resolved, shutdown).await;
            log_reload_shutdown.cancel();

            if let Err(e) = result {
                error!(error = %e, "rvc-signer failed");
                // Exit code unchanged: every ServerError class maps to 1.
                let _ = classify_exit_code(&e);
                std::process::exit(1);
            }

            info!("Shutting down rvc-signer");
        }
        #[cfg(feature = "dvt")]
        Command::SplitKey(args) => {
            if let Err(e) = run_split_key(args) {
                error!(error = %e, "split-key failed");
                std::process::exit(1);
            }
        }
    }
}

/// Initialize the console-only tracing subscriber and return a type-erased
/// handle to the runtime-reloadable log filter (issue 5.4 / P2-2).
///
/// The reconciled `EnvFilter` (unset/empty/malformed `RUST_LOG` → `info`, env
/// otherwise wins — ADR-003) is wrapped in a `reload::Layer` so its value can be
/// swapped at runtime. The **initial value is exactly `env_filter_or("info")`**,
/// so this produces byte-for-byte identical *user-visible* output to the previous
/// bare `fmt().with_env_filter(env_filter_or("info"))` — the Phase-3 cross-binary
/// init parity is preserved.
///
/// Moving from the `fmt()` builder to a `registry()` + `fmt::layer()` composition
/// flips `log_internal_errors` from `true` to `false`; this is now `false`,
/// matching `bin/rvc` (which already composes via `registry()`). The only
/// behavioral difference is the rare diagnostic emitted when the fmt writer
/// itself errors — intentionally consistent across both binaries, not an operator
/// path. The reload layer is the outer global filter over a single `fmt::layer`;
/// a disabled `debug!`/`trace!` callsite short-circuits in the macro before
/// reaching it (Gate 4 / P0-6 unaffected). The opt-in `SIGHUP` trigger (gated by
/// `--enable-log-reload`) is wired from `main` after `init_logging`.
///
/// `log_format` selects the CONSOLE rendering (issue 5.5): `Pretty` (default,
/// byte-identical to the previous bare `fmt::layer()`) or `Json` (one structured
/// object per event, for log aggregation). Both arms keep the same reload
/// composition — the 5.4 reload-wrapped reconciled filter is the outer global
/// layer over a single console `fmt` layer — so Phase-3 init parity holds for
/// either format.
fn init_logging(log_format: telemetry::LogFormat) -> telemetry::LogReloadHandle {
    use tracing_subscriber::prelude::*;

    let (filter, handle) = telemetry::reloadable_env_filter("info");
    let console_layer = telemetry::console_fmt_layer(log_format, std::io::stdout);
    tracing_subscriber::registry().with(console_layer).with(filter).init();
    telemetry::LogReloadHandle::new("info", handle)
}

/// Spawn the opt-in `SIGHUP` log-reload handler (issue 5.4 / P2-2).
///
/// No-op unless `enabled` (the `--enable-log-reload` opt-in). When enabled on a
/// Unix host, each `SIGHUP` re-reads `RUST_LOG` through the same
/// [`telemetry::env_filter_or`] precedence used at startup and swaps the active
/// filter, raising/lowering verbosity without a restart. The task is scoped to
/// `shutdown_token` so it exits cleanly when the server stops. On non-Unix
/// targets there is no `SIGHUP`; the flag is accepted but inert (logged once).
fn spawn_log_reload_handler(
    enabled: bool,
    reload_handle: telemetry::LogReloadHandle,
    shutdown_token: tokio_util::sync::CancellationToken,
) {
    if !enabled {
        return;
    }

    #[cfg(unix)]
    {
        tokio::spawn(async move {
            let mut sighup =
                match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
                    Ok(s) => s,
                    Err(e) => {
                        error!(error = %e, "failed to install SIGHUP handler; log reload disabled");
                        return;
                    }
                };
            info!("Runtime log-level reload enabled (send SIGHUP to re-read RUST_LOG)");
            loop {
                tokio::select! {
                    _ = shutdown_token.cancelled() => break,
                    sig = sighup.recv() => {
                        if sig.is_none() {
                            break;
                        }
                        match reload_handle.reload_from_env() {
                            Ok(()) => info!("Reloaded log filter from RUST_LOG (SIGHUP)"),
                            Err(e) => {
                                tracing::warn!(error = %e, "log-filter reload failed (subscriber gone?)")
                            }
                        }
                    }
                }
            }
        });
    }

    #[cfg(not(unix))]
    {
        let _ = (reload_handle, shutdown_token);
        tracing::warn!(
            "--enable-log-reload set, but SIGHUP-based reload is only supported on Unix"
        );
    }
}

/// Map each `ServerError` class to a process exit code.
///
/// Today every class is `1` (identical to the pre-extraction `Box<dyn Error>`
/// path). Kept as an explicit function so RF5 tests can lock the mapping.
fn classify_exit_code(err: &ServerError) -> i32 {
    match err {
        ServerError::SlashingDb(_)
        | ServerError::Backend(_)
        | ServerError::Tls(_)
        | ServerError::Bind(_)
        | ServerError::Config(_)
        | ServerError::Io(_) => 1,
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c().await.expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => {},
            _ = sigterm.recv() => {},
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await;
    }

    info!("Shutdown signal received");
}

/// Run the split-key subcommand.
#[cfg(feature = "dvt")]
fn run_split_key(args: SplitKeyCliArgs) -> Result<(), Box<dyn std::error::Error>> {
    use signer_server::commands::split_key::{execute, SplitKeyArgs};
    use zeroize::Zeroizing;

    let password = if let Some(ref pw) = args.password {
        Zeroizing::new(pw.clone())
    } else if let Some(ref file) = args.password_file {
        let content = std::fs::read_to_string(file)?;
        Zeroizing::new(content.trim_end_matches('\n').to_string())
    } else {
        Zeroizing::new(String::new())
    };

    let output_password = if let Some(ref pw) = args.output_password {
        Zeroizing::new(pw.clone())
    } else if let Some(ref file) = args.output_password_file {
        let content = std::fs::read_to_string(file)?;
        Zeroizing::new(content.trim_end_matches('\n').to_string())
    } else {
        Zeroizing::new(String::new())
    };

    execute(SplitKeyArgs {
        keystore: args.keystore,
        password,
        threshold: args.threshold,
        shares: args.shares,
        output_dir: args.output_dir,
        output_password,
    })?;
    info!("Split key successfully");
    Ok(())
}

#[cfg(test)]
// RF1-12: unit tests mutate env via unsafe set_var/remove_var.
#[allow(unsafe_code)]
mod tests {
    use std::io;
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::fmt::MakeWriter;

    #[derive(Clone, Default)]
    struct SharedBuf(Arc<Mutex<Vec<u8>>>);
    impl io::Write for SharedBuf {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl<'a> MakeWriter<'a> for SharedBuf {
        type Writer = SharedBuf;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    // Serialize RUST_LOG mutation (process-global). nextest runs each test in
    // its own process, but guard anyway so the suite stays correct under any
    // runner that threads tests in one process.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// With `RUST_LOG` unset, rvc-signer's reconciled init must default to
    /// `info` and emit `info!` events — the P0-5 cross-binary parity fix. Before
    /// the reconciliation it used `EnvFilter::from_default_env()`, which drops
    /// `info` to `ERROR` when `RUST_LOG` is unset (the silent-by-default footgun
    /// this issue closes). Mirrors `bin/rvc`'s `test_init_logging_no_extras_emits_events`.
    ///
    /// This builds the ACTUAL shipped composition that `init_logging()` uses:
    /// `registry().with(fmt::layer()).with(reloadable_env_filter("info"))`, i.e.
    /// the reload-wrapped reconciled filter via the same shared helper, capturing
    /// output through `.with_writer()` and `with_default` instead of `.init()`.
    /// It guards the real composition, not the removed `fmt()` builder.
    #[test]
    fn test_init_logging_emits_info_by_default() {
        use tracing_subscriber::prelude::*;

        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let prev = std::env::var("RUST_LOG").ok();
        unsafe { std::env::remove_var("RUST_LOG") };

        let buf = SharedBuf::default();
        // Same shape as production `init_logging`: the reload-wrapped reconciled
        // filter is the outer global layer over a single `fmt::layer`.
        let (filter, _handle) = telemetry::reloadable_env_filter("info");
        let subscriber = tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer().with_writer(buf.clone()))
            .with(filter);
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!("rvc-signer init regression marker");
        });

        match prev {
            Some(p) => unsafe { std::env::set_var("RUST_LOG", p) },
            None => unsafe { std::env::remove_var("RUST_LOG") },
        }

        let captured = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        assert!(
            captured.contains("rvc-signer init regression marker"),
            "reconciled init dropped an info event with RUST_LOG unset; captured: {captured:?}"
        );
    }

    // ── Issue 5.5: opt-in JSON console log output profile ─────────────────────

    /// `serve --log-format json` parses and resolves to `LogFormat::Json`; the
    /// default (flag omitted) stays `Pretty`. Same flag/semantics as `bin/rvc`.
    /// Pull the `ServeArgs` out of a parsed `Cli`, panicking on any other
    /// subcommand. Written as a `match` (not `let…else`) so it is warning-free
    /// whether or not the `dvt` feature adds a second `Command` variant.
    fn serve_args(cli: super::Cli) -> super::ServeArgs {
        match cli.command {
            super::Command::Serve(args) => args,
            #[cfg(feature = "dvt")]
            _ => panic!("expected Serve command"),
        }
    }

    #[test]
    fn test_serve_log_format_flag_parses_and_defaults_to_pretty() {
        use clap::Parser;

        let cli = super::Cli::try_parse_from(["rvc-signer", "serve", "--log-format", "json"])
            .expect("serve --log-format json should parse");
        let args = serve_args(cli);
        assert_eq!(
            telemetry::LogFormat::resolve(args.log_format.as_deref()),
            telemetry::LogFormat::Json
        );

        let cli = super::Cli::try_parse_from(["rvc-signer", "serve"])
            .expect("serve default should parse");
        let args = serve_args(cli);
        assert!(
            args.log_format.is_none(),
            "omitted --log-format must be None (resolved later to pretty)"
        );
        assert_eq!(
            telemetry::LogFormat::resolve(args.log_format.as_deref()),
            telemetry::LogFormat::Pretty
        );
    }

    /// The JSON arm of `init_logging`'s composition — `console_fmt_layer(Json, …)`
    /// under the reload-wrapped reconciled filter — emits one parseable JSON
    /// object per event with canonical fields as top-level keys. Mirrors the
    /// shipped `init_logging` shape (rvc-signer wires no extra layers, so there is
    /// no `boxed_layers`/`Identity` padding here, matching production).
    #[test]
    fn test_init_logging_json_arm_emits_parseable_json() {
        use tracing_subscriber::prelude::*;

        // Hold ENV_LOCK + clear RUST_LOG so a parallel filter test cannot drop info.
        let out = with_rust_log(None, || {
            let buf = SharedBuf::default();
            let (filter, _handle) = telemetry::reloadable_env_filter("info");
            let console_layer =
                telemetry::console_fmt_layer(telemetry::LogFormat::Json, buf.clone());
            let subscriber = tracing_subscriber::registry().with(console_layer).with(filter);

            tracing::subscriber::with_default(subscriber, || {
                tracing::info!(request_id = "abc-123", "rvc-signer json arm marker");
            });

            let captured = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
            captured
        });
        let line = out.lines().find(|l| l.contains("rvc-signer json arm marker")).expect("present");
        let v: serde_json::Value =
            serde_json::from_str(line).expect("JSON arm must emit parseable JSON");
        assert_eq!(v["request_id"], "abc-123", "canonical field must be a top-level JSON key");
        assert_eq!(v["message"], "rvc-signer json arm marker");
    }

    fn with_rust_log<T>(value: Option<&str>, f: impl FnOnce() -> T) -> T {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let prev = std::env::var("RUST_LOG").ok();
        match value {
            Some(v) => unsafe { std::env::set_var("RUST_LOG", v) },
            None => unsafe { std::env::remove_var("RUST_LOG") },
        }
        let out = f();
        match prev {
            Some(p) => unsafe { std::env::set_var("RUST_LOG", p) },
            None => unsafe { std::env::remove_var("RUST_LOG") },
        }
        out
    }

    // Cross-binary init parity (P0-5 / M3): rvc-signer must exhibit the SAME
    // default level (`info`) and RUST_LOG precedence as bin/rvc — both route
    // their filter through `telemetry::env_filter_or("info")`. These mirror the
    // bin/rvc parity tests so an operator learns one behavior, not two.
    #[test]
    fn test_rvc_signer_unset_rust_log_defaults_to_info() {
        let rendered = with_rust_log(None, || format!("{}", telemetry::env_filter_or("info")));
        assert_eq!(rendered, "info", "unset RUST_LOG must default to info, got: {rendered}");
    }

    #[test]
    fn test_rvc_signer_rust_log_overrides_default() {
        let rendered =
            with_rust_log(Some("debug"), || format!("{}", telemetry::env_filter_or("info")));
        assert!(rendered.contains("debug"), "RUST_LOG=debug must override the default: {rendered}");
    }

    #[test]
    fn test_rvc_signer_per_module_directive_preserved() {
        let rendered = with_rust_log(Some("warn,signer_server::http_api=trace"), || {
            format!("{}", telemetry::env_filter_or("info"))
        });
        assert!(rendered.contains("warn"), "global directive missing: {rendered}");
        // Assert the joined target=level token, not three independent substrings:
        // the latter green-lights a filter where the target binds to a *different*
        // level (e.g. http_api=info,foo=trace).
        assert!(
            rendered.contains("signer_server::http_api=trace"),
            "per-module directive not preserved verbatim (target must bind to trace): {rendered}"
        );
    }

    #[test]
    fn test_rvc_signer_malformed_rust_log_falls_back_to_info() {
        let rendered = with_rust_log(Some("rvc=invalidlevel"), || {
            format!("{}", telemetry::env_filter_or("info"))
        });
        assert_eq!(
            rendered, "info",
            "malformed RUST_LOG must fall back to info (no panic, no silence): {rendered}"
        );
    }

    #[test]
    fn test_rvc_signer_whitespace_padded_rust_log_honored() {
        let rendered = with_rust_log(Some("warn, signer_server::http_api=trace"), || {
            format!("{}", telemetry::env_filter_or("info"))
        });
        assert!(rendered.contains("warn"), "global directive missing: {rendered}");
        assert!(
            rendered.contains("signer_server::http_api=trace"),
            "padded per-module directive not preserved verbatim (target must bind to trace): {rendered}"
        );
    }
}
