//! rvc-signer binary entry point.
//!
//! All implementation lives in `lib.rs` (crate root for the library target).
//! This file only handles CLI parsing and wires up the library.

use rvc_signer_bin::{
    backend, config, http_api, insecure_startup, metrics, reload, service, slashing, tls,
    SignerServiceServerV2,
};
#[cfg(feature = "dvt")]
use rvc_signer_bin::{dvt, PeerSignerServiceServerV2};

use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use tracing::{error, info};
use zeroize::Zeroizing;

const DEFAULT_LISTEN_ADDRESS: &str = "127.0.0.1:50052";

/// Signing backend type.
#[derive(Clone, Debug, clap::ValueEnum)]
pub enum Backend {
    /// Local keystore-based signing
    Basic,
    /// Distributed Validator Technology (DVT) signing
    #[cfg(feature = "dvt")]
    Dvt,
}

impl std::fmt::Display for Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Basic => write!(f, "basic"),
            #[cfg(feature = "dvt")]
            Self::Dvt => write!(f, "dvt"),
        }
    }
}

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

#[derive(Parser)]
struct ServeArgs {
    /// Path to config.toml file
    #[arg(long)]
    config: Option<PathBuf>,

    /// gRPC listen address (host:port)
    #[arg(long, default_value = DEFAULT_LISTEN_ADDRESS)]
    listen_address: String,

    /// Path to the keystore directory
    #[arg(long)]
    keystore_dir: Option<PathBuf>,

    /// Path to the directory containing per-keystore password files
    #[arg(long, group = "password_source")]
    password_dir: Option<PathBuf>,

    /// Path to a single password file used for all keystores
    #[arg(long, group = "password_source")]
    password_file: Option<PathBuf>,

    /// Path to the TLS certificate file (PEM)
    #[arg(long)]
    tls_cert: Option<PathBuf>,

    /// Path to the TLS private key file (PEM)
    #[arg(long)]
    tls_key: Option<PathBuf>,

    /// Path to the TLS CA certificate file for client authentication (PEM)
    #[arg(long)]
    tls_ca_cert: Option<PathBuf>,

    /// Enable the Web3Signer HTTP Remote Signing API (opt-in; gRPC stays on).
    /// Parsed/resolved only for now; the listener is wired in a later phase.
    #[arg(long, default_value_t = false)]
    http_enabled: bool,

    /// HTTP Remote Signing API listen address (host:port). Default :9000.
    #[arg(long, default_value = config::DEFAULT_HTTP_LISTEN_ADDRESS)]
    http_listen_address: String,

    /// HTTP API TLS mode: "mtls" (default) or "server-tls-only".
    #[arg(long, default_value = config::DEFAULT_HTTP_TLS_MODE)]
    http_tls_mode: String,

    /// HTTP API server certificate (PEM). Independent of the gRPC TLS material.
    #[arg(long)]
    http_tls_cert: Option<PathBuf>,

    /// HTTP API server private key (PEM). Independent of the gRPC TLS material.
    #[arg(long)]
    http_tls_key: Option<PathBuf>,

    /// HTTP API client CA certificate (PEM). Required in both TLS modes.
    #[arg(long)]
    http_tls_ca_cert: Option<PathBuf>,

    /// Validate configuration and exit without starting the server
    #[arg(long)]
    dry_run: bool,

    /// Allow starting without TLS (NOT recommended for production)
    #[arg(long)]
    insecure: bool,

    /// Data directory for signer state (default: parent of keystore_dir).
    /// The slashing protection DB is stored here as signer-slashing.db.
    #[arg(long)]
    data_dir: Option<PathBuf>,

    /// Disable slashing protection (UNSAFE).
    /// Requires ALSO setting RVC_ALLOW_INSECURE=true in the environment.
    /// Both checks are required to prevent accidental opt-out.
    #[arg(long)]
    disable_slashing_protection: bool,

    /// Signing backend to use
    #[arg(long, value_enum, default_value_t = Backend::Basic)]
    backend: Backend,

    /// Prometheus metrics listen address (host:port)
    #[arg(long, default_value = "127.0.0.1:9101")]
    metrics_address: String,

    /// Enable keystore hot-reload (ISSUE-4.6 / L-6).
    ///
    /// Disabled by default. When enabled, the signer periodically rescans
    /// `keystore_dir` and reconciles the loaded set with files on disk —
    /// a key-injection vector if the directory is writable by anyone other
    /// than the signer UID. Requires the directory to be 0o700 and owned
    /// by the signer UID at every reload pass; otherwise the reload is
    /// skipped with a warn log.
    #[arg(long, default_value_t = false)]
    enable_hot_reload: bool,

    /// Keystore hot-reload interval in seconds (only honoured when
    /// `--enable-hot-reload` is set).
    #[arg(long, default_value = "30")]
    reload_interval: u64,

    /// Comma-separated list of DVT peer addresses (host:port)
    #[cfg(feature = "dvt")]
    #[arg(long, value_delimiter = ',')]
    dvt_peers: Vec<String>,

    /// DVT threshold for signature reconstruction
    #[cfg(feature = "dvt")]
    #[arg(long)]
    dvt_threshold: Option<u64>,

    /// This node's DVT share index
    #[cfg(feature = "dvt")]
    #[arg(long)]
    dvt_index: Option<u64>,

    /// DVT per-peer RPC timeout in milliseconds
    #[cfg(feature = "dvt")]
    #[arg(long, default_value = "2000")]
    dvt_timeout: u64,

    /// Path to the DVT allow-list TOML file (required when backend=dvt).
    /// Format: [[peer]] entries with peer_cn and share_index.
    #[cfg(feature = "dvt")]
    #[arg(long)]
    dvt_allowed_peers: Option<PathBuf>,
}

#[cfg(feature = "dvt")]
#[derive(Parser)]
struct SplitKeyCliArgs {
    /// Path to the source EIP-2335 keystore
    #[arg(long)]
    keystore: PathBuf,

    /// Password for the source keystore
    #[arg(long, group = "src_password")]
    password: Option<String>,

    /// Path to a file containing the source keystore password
    #[arg(long, group = "src_password")]
    password_file: Option<PathBuf>,

    /// Threshold (t) for Shamir secret sharing
    #[arg(long)]
    threshold: u64,

    /// Total number of shares (n) to generate
    #[arg(long)]
    shares: u64,

    /// Output directory for share keystores
    #[arg(long)]
    output_dir: PathBuf,

    /// Password for the output share keystores
    #[arg(long, group = "out_password")]
    output_password: Option<String>,

    /// Path to a file containing the password for output share keystores
    #[arg(long, group = "out_password")]
    output_password_file: Option<PathBuf>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::Serve(args) => {
            if let Err(e) = run_serve(args).await {
                error!(error = %e, "rvc-signer failed");
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

async fn run_serve(args: ServeArgs) -> Result<(), Box<dyn std::error::Error>> {
    // Install the rustls crypto provider before any TLS work. Idempotent and
    // safe even with HTTP disabled. Forward-defense (ADR-006, R1): pins a single
    // explicit default so the Phase-3 `ServerConfig::builder()` path stays
    // deterministic and never hits rustls's automatic resolution, which panics
    // if the feature graph ever compiles in more than one provider. Not
    // load-bearing in today's ring-only build; see http_api::tls for details.
    http_api::tls::install_crypto_provider();

    let resolved = resolve_config(&args)?;

    info!(
        listen_address = %resolved.listen_address,
        keystore_dir = %resolved.keystore_dir.display(),
        backend = %resolved.backend,
        "Starting rvc-signer"
    );

    let password = load_serve_password(&resolved)?;

    let tls_config = match (
        resolved.tls_cert.as_ref(),
        resolved.tls_key.as_ref(),
        resolved.tls_ca_cert.as_ref(),
    ) {
        (Some(cert), Some(key), Some(ca)) => {
            Some(rvc_signer_bin::tls::TlsConfig::new(cert.clone(), key.clone(), ca.clone()))
        }
        _ => None,
    };

    // Set up Prometheus metrics early so DVT backend can use them
    let signer_metrics = Arc::new(metrics::SignerMetrics::new());

    // Build the signing backend and optional share-map for the PeerSignerService.
    // The PeerSignerService is constructed later (after the slashing DB is opened),
    // so build_dvt_backend returns the raw share_map rather than a complete service.
    //
    // The allow-list is loaded ONCE here (DVT arm only) and shared between the
    // client-side SNI derivation (build_dvt_backend) and the server-side
    // PeerSignerService (constructed below).  This avoids a TOCTOU double-read
    // and ensures both paths see the same allow-list snapshot (ISSUE-4.1 / L-1).
    #[cfg(feature = "dvt")]
    type ShareMap = Arc<std::collections::HashMap<[u8; 48], dvt::types::ShareInfo>>;

    // Separate variable to capture the allow-list from the DVT arm without
    // pushing the match binding into clippy::type_complexity territory.
    #[cfg(feature = "dvt")]
    let mut dvt_allow_list_opt: Option<Arc<dvt::allow_list::AllowedPeers>> = None;

    #[cfg(feature = "dvt")]
    let (signing_backend, dvt_share_map_opt, basic_signer_ref): (
        Arc<dyn backend::SigningBackend>,
        Option<ShareMap>,
        Option<Arc<backend::basic::BasicSigner>>,
    ) = match parse_backend(&resolved.backend)? {
        Backend::Basic => {
            let signer =
                Arc::new(backend::basic::BasicSigner::load(&resolved.keystore_dir, &password)?);
            (Arc::clone(&signer) as Arc<dyn backend::SigningBackend>, None, Some(signer))
        }
        Backend::Dvt => {
            // Load allow-list once; shared by client SNI pinning + server peer service.
            let allow_list: Option<Arc<dvt::allow_list::AllowedPeers>> =
                if let Some(path) = args.dvt_allowed_peers.as_deref() {
                    let al = dvt::allow_list::AllowedPeers::load_from_path(path)
                        .map_err(|e| format!("failed to load DVT allow-list: {e}"))?;
                    info!(
                        path = %path.display(),
                        peer_count = al.peers.len(),
                        "Loaded DVT allow-list"
                    );
                    Some(Arc::new(al))
                } else {
                    None
                };

            let (backend, share_map) = build_dvt_backend(
                &resolved,
                &password,
                tls_config.as_ref(),
                Arc::new(signer_metrics.dvt.clone()),
                allow_list.clone(),
            )
            .await?;

            dvt_allow_list_opt = allow_list;
            (backend, Some(share_map), None)
        }
    };

    #[cfg(not(feature = "dvt"))]
    let (signing_backend, _peer_signer_service, basic_signer_ref): (
        Arc<dyn backend::SigningBackend>,
        Option<()>,
        Option<Arc<backend::basic::BasicSigner>>,
    ) = {
        let signer =
            Arc::new(backend::basic::BasicSigner::load(&resolved.keystore_dir, &password)?);
        (Arc::clone(&signer) as Arc<dyn backend::SigningBackend>, None, Some(signer))
    };

    // Validate TLS certificates if provided
    if let Some(ref tls) = tls_config {
        tls.to_server_tls_config()?;
    }

    if resolved.dry_run {
        println!("Configuration valid:");
        println!("  Backend: {}", resolved.backend);
        println!("  Keys loaded: {}", signing_backend.public_keys().len());
        if tls_config.is_some() {
            println!("  TLS: certificates valid");
        } else {
            println!("  TLS: disabled");
        }
        #[cfg(feature = "dvt")]
        if resolved.backend == "dvt" {
            println!("  DVT peers: {}", resolved.dvt_peers.len());
            if let Some(threshold) = resolved.dvt_threshold {
                println!("  DVT threshold: {}", threshold);
            }
            if let Some(index) = resolved.dvt_index {
                println!("  DVT index: {}", index);
            }
        }
        return Ok(());
    }

    // ISSUE-4.6 / L-6: keystore hot-reload is opt-in.  The reloader is only
    // spawned when `--enable-hot-reload` is set (or the equivalent TOML key
    // is true) AND `reload_interval_secs > 0`.  Each reload pass also
    // enforces a strict 0o700 / signer-UID-owned directory check before
    // touching keys (see `reload.rs::scan_and_reload`).
    if let Some(ref basic_signer) = basic_signer_ref {
        if resolved.enable_hot_reload && resolved.reload_interval_secs > 0 {
            let reloader = reload::KeystoreReloader::new(
                resolved.keystore_dir.clone(),
                password.clone(),
                std::time::Duration::from_secs(resolved.reload_interval_secs),
                Arc::clone(basic_signer),
            );

            let cancel = tokio_util::sync::CancellationToken::new();
            let cancel_clone = cancel.clone();
            tokio::spawn(async move {
                reloader.run(cancel_clone).await;
            });

            info!(
                interval_secs = resolved.reload_interval_secs,
                "Keystore hot-reload enabled (--enable-hot-reload)"
            );
        } else if resolved.reload_interval_secs > 0 {
            // Operators upgrading from a previous release where the reloader
            // ran by default with a 30s interval will see this notice once
            // at startup if they had a non-zero interval configured.
            info!(
                "Keystore hot-reload disabled (set --enable-hot-reload to opt in; \
                 ISSUE-4.6 / L-6)"
            );
        }
    }

    // Set up Prometheus metrics server
    let key_count = signing_backend.public_keys().len() as f64;
    signer_metrics.keys_loaded.with_label_values(&[&resolved.backend]).set(key_count);

    let metrics_addr: std::net::SocketAddr = args.metrics_address.parse()?;
    let (_metrics_handle, metrics_bound_addr) =
        metrics::serve_metrics(metrics_addr, Arc::clone(&signer_metrics)).await?;
    info!(address = %metrics_bound_addr, "Prometheus metrics server listening");

    // ── Slashing protection gate (OQ-A4 binding decision) ────────────────────
    //
    // rvc-signer refuses to start without a SlashingDb unless:
    //   (a) --disable-slashing-protection is on the CLI, AND
    //   (b) RVC_ALLOW_INSECURE=true is set in the environment.
    //
    // Both checks are required so a stray env-var leak cannot silently disable
    // slashing protection.
    let data_dir = args.data_dir.as_deref().or_else(|| resolved.keystore_dir.parent());

    let slashing_cfg =
        slashing::SlashingDbConfig::from_env(data_dir, args.disable_slashing_protection);
    slashing_cfg.validate().map_err(|e| {
        error!(error = %e, "slashing protection configuration error");
        e
    })?;

    let slashing_db_opt: Option<Arc<::slashing::SlashingDb>> = if slashing_cfg.mode
        == slashing::SlashingProtectionMode::DisabledBothFlags
    {
        None
    } else if let Some(ref db_path) = slashing_cfg.db_path {
        info!(path = %db_path.display(), "Opening slashing protection database");
        let db = ::slashing::SlashingDb::open(db_path)
            .map_err(|e| format!("failed to open slashing DB at {}: {}", db_path.display(), e))?;
        Some(Arc::new(db))
    } else {
        None
    };

    // Build the v2 service implementation.
    // SS-1 (Issue 2.2): the v1 raw-root service is no longer registered on the
    // live listener; `impl SignerService for SignerServiceImpl` is kept compiled
    // but all v1 methods return `Unimplemented`.
    let svc_v2 = if let Some(ref db) = slashing_db_opt {
        // Hoist (ADR-003, FR-26): build the ONE shared `SigningGate` here at the
        // composition root, then inject the same `Arc` into the gRPC service.
        let shared_gate = Arc::new(service::SignerServiceImpl::build_gate(
            Arc::clone(&signing_backend),
            Arc::clone(db),
        ));
        // TODO(phase-3): clone `shared_gate` into the HTTP `Web3SignerState` so the
        // HTTP listener shares this exact `Arc<SigningGate>` (unified slashing DB +
        // in-memory `ValidatorLockMap` across gRPC and HTTP).
        service::SignerServiceImpl::new_v2_with_gate(
            Arc::clone(&signing_backend),
            resolved.backend.clone(),
            Arc::clone(&shared_gate),
        )
        .with_metrics(Arc::clone(&signer_metrics))
    } else {
        service::SignerServiceImpl::new(Arc::clone(&signing_backend), resolved.backend.clone())
            .with_metrics(Arc::clone(&signer_metrics))
    };

    // Build the PeerSignerService (DVT) now that we have the slashing DB.
    // The allow-list was already loaded and validated above (hoisted from here
    // to avoid a double file-read — ISSUE-4.1 / L-1 DRY fix).
    #[cfg(feature = "dvt")]
    let peer_signer_service: Option<dvt::peer_service::PeerSignerServiceImpl> =
        if let Some(share_map) = dvt_share_map_opt {
            // Reuse the Arc loaded in the Backend::Dvt arm above.
            let allow_list = dvt_allow_list_opt.ok_or(
                "DVT is enabled but --dvt-allowed-peers was not provided. \
                 Create a dvt-allowed-peers.toml file and pass its path via --dvt-allowed-peers.",
            )?;
            let peer_svc = dvt::peer_service::PeerSignerServiceImpl::new(
                share_map,
                allow_list,
                slashing_db_opt.clone(),
            );
            Some(peer_svc)
        } else {
            None
        };

    let addr = resolved.listen_address.parse()?;

    // ── M-10: hardened server builder (concurrency + timeout limits) ──────────
    //
    // `hardened_server_builder()` applies per research/05 §"Recommended values":
    //   - concurrency_limit_per_connection(32) — Tower-level cap per connection
    //   - max_concurrent_streams(Some(64))     — H2 SETTINGS frame to clients
    //   - timeout(Duration::from_secs(10))     — per-request timeout via Tower
    //
    // Per-service max_decoding_message_size(1 MiB) is set on each ServiceServer
    // below (Tonic exposes it only at the service level, not the builder level).
    let mut builder = tls::server_builder::hardened_server_builder();

    if let Some(ref tls_cfg) = tls_config {
        let server_tls = tls_cfg.to_server_tls_config()?;
        builder = builder.tls_config(server_tls)?;
        info!("mTLS enabled");
    } else if args.insecure {
        // ── H-9: env-var double-confirm + loopback gate ───────────────────
        //
        // `--insecure` requires BOTH `RVC_SIGNER_ALLOW_INSECURE=true` in the
        // environment AND a loopback bind address.  Per NFR-10 / ISSUE-3.13
        // (GA tag) the gate now runs in Refuse mode: startup hard-fails when
        // the opt-in conditions are not fully met.
        insecure_startup::check_insecure_startup(true, addr, crypto::InsecureMode::Refuse)
            .map_err(|e| {
                error!(error = %e, "insecure startup refused by gate");
                e
            })?;
        tracing::warn!("TLS disabled via --insecure flag. Do NOT use in production!");
    } else {
        return Err("TLS is required. Provide --tls-cert, --tls-key, and --tls-ca-cert, \
             or use --insecure to disable (NOT recommended for production)."
            .into());
    }

    info!(address = %addr, "gRPC server listening");

    // 1 MiB per-message decode cap (M-10): blocks memory-pressure via oversized
    // request bodies.  Signing a BeaconBlock is well under 1 MiB after SSZ
    // encoding; 1 MiB is a comfortable upper bound per research/05.
    const MAX_DECODE_BYTES: usize = 1 << 20; // 1 MiB

    // SS-1 (Issue 2.2): only the v2 typed-RPC service is registered.
    // The v1 raw-root service has been removed from the live listener.
    let router = builder.add_service(
        SignerServiceServerV2::new(svc_v2).max_decoding_message_size(MAX_DECODE_BYTES),
    );

    #[cfg(feature = "dvt")]
    let router = if let Some(peer_svc) = peer_signer_service {
        info!("PeerSignerService v2 registered for DVT");
        router.add_service(
            PeerSignerServiceServerV2::new(peer_svc).max_decoding_message_size(MAX_DECODE_BYTES),
        )
    } else {
        router
    };

    router.serve_with_shutdown(addr, shutdown_signal()).await?;

    Ok(())
}

/// Returns the DVT signing backend AND the share map (for `PeerSignerService`).
/// The share map is returned separately so the caller can build `PeerSignerServiceImpl`
/// AFTER the slashing DB is opened (allowing CN-scoped slashing for DVT peers).
///
/// `allow_list`: the pre-loaded allow-list (hoisted from `run_serve` to avoid a
/// double file-read).  When TLS is enabled, `build_peer_connect_infos` requires
/// this to be `Some` and every `dvt_peers` address to have a matching entry —
/// any gap is a startup error (ISSUE-4.1 / L-1: no silent SNI bypass).
#[cfg(feature = "dvt")]
async fn build_dvt_backend(
    resolved: &config::ResolvedConfig,
    password: &Zeroizing<String>,
    tls_config: Option<&rvc_signer_bin::tls::TlsConfig>,
    dvt_metrics: Arc<metrics::DvtMetrics>,
    allow_list: Option<Arc<dvt::allow_list::AllowedPeers>>,
) -> Result<
    (
        Arc<dyn backend::SigningBackend>,
        Arc<std::collections::HashMap<[u8; 48], dvt::types::ShareInfo>>,
    ),
    Box<dyn std::error::Error>,
> {
    use std::collections::HashMap;
    use std::time::Duration;

    let dvt_index = resolved.dvt_index.ok_or("dvt_index is required when using backend dvt")?;

    let timeout = Duration::from_millis(resolved.dvt_timeout_ms);

    let shares = dvt::types::load_shares(&resolved.keystore_dir, password)
        .map_err(|e| format!("failed to load DVT shares: {}", e))?;

    if shares.is_empty() {
        return Err("no DVT shares found in keystore directory".into());
    }

    info!(
        share_count = shares.len(),
        dvt_index,
        peer_count = resolved.dvt_peers.len(),
        "Loaded DVT shares"
    );

    let share_map: HashMap<[u8; 48], dvt::types::ShareInfo> =
        shares.iter().map(|s| (s.aggregate_pubkey, s.clone())).collect();
    let share_map = Arc::new(share_map);

    // ── L-1 SNI pinning: build per-peer connection info ──────────────────────
    //
    // `build_peer_connect_infos` enforces a hard invariant: when TLS is active,
    // every dvt_peers address must have a matching `addr=` entry in the
    // allow-list.  Missing entries are startup errors — there is no silent
    // fallback to un-pinned TLS (ISSUE-4.1 / L-1 review fix).
    let peer_infos: Vec<dvt::peer_client::PeerConnectInfo> =
        dvt::peer_client::build_peer_connect_infos(
            &resolved.dvt_peers,
            allow_list.as_deref(),
            tls_config.is_some(),
        )
        .map_err(|e| format!("DVT peer SNI configuration error: {e}"))?;

    let peer_requester = if !peer_infos.is_empty() {
        let requester =
            dvt::peer_client::GrpcPeerRequester::connect(&peer_infos, tls_config, timeout)
                .await
                .map_err(|e| format!("failed to connect to DVT peers: {}", e))?;

        info!(peers = ?requester.peer_addrs(), "Connected to DVT peers");
        Some(Arc::new(requester) as Arc<dyn backend::dvt::PeerRequester>)
    } else {
        info!("No DVT peers configured; running in standalone mode");
        None
    };

    let dvt_signer = backend::dvt::DvtSigner::new(
        shares,
        dvt_index,
        resolved.dvt_peers.clone(),
        peer_requester,
        timeout,
    )
    .with_metrics(dvt_metrics);

    Ok((Arc::new(dvt_signer), share_map))
}

fn resolve_config(args: &ServeArgs) -> Result<config::ResolvedConfig, Box<dyn std::error::Error>> {
    let file_config = if let Some(ref path) = args.config {
        config::load_config(path)?
    } else {
        config::SignerConfig::default()
    };

    let has_config = args.config.is_some();
    let listen_address_is_default = has_config && args.listen_address == DEFAULT_LISTEN_ADDRESS;
    let backend_is_default = has_config && matches!(args.backend, Backend::Basic);
    let reload_interval_is_default = has_config && args.reload_interval == 30;
    let http_listen_address_is_default =
        has_config && args.http_listen_address == config::DEFAULT_HTTP_LISTEN_ADDRESS;
    let http_tls_mode_is_default =
        has_config && args.http_tls_mode == config::DEFAULT_HTTP_TLS_MODE;

    #[cfg(feature = "dvt")]
    let dvt_timeout_is_default = has_config && args.dvt_timeout == 2000;
    #[cfg(not(feature = "dvt"))]
    let dvt_timeout_is_default = true;

    #[cfg(feature = "dvt")]
    let (dvt_peers, dvt_threshold, dvt_index, dvt_timeout) =
        (&args.dvt_peers[..], args.dvt_threshold, args.dvt_index, args.dvt_timeout);
    #[cfg(not(feature = "dvt"))]
    let (dvt_peers, dvt_threshold, dvt_index, dvt_timeout): (
        &[String],
        Option<u64>,
        Option<u64>,
        u64,
    ) = (&[], None, None, 2000);

    let cli = config::CliOverrides {
        listen_address: &args.listen_address,
        listen_address_is_default,
        keystore_dir: args.keystore_dir.as_deref(),
        password_dir: args.password_dir.as_deref(),
        password_file: args.password_file.as_deref(),
        backend: &args.backend.to_string(),
        backend_is_default,
        dry_run: args.dry_run,
        tls_cert: args.tls_cert.as_deref(),
        tls_key: args.tls_key.as_deref(),
        tls_ca_cert: args.tls_ca_cert.as_deref(),
        reload_interval: args.reload_interval,
        reload_interval_is_default,
        enable_hot_reload: args.enable_hot_reload,
        dvt_peers,
        dvt_threshold,
        dvt_index,
        dvt_timeout,
        dvt_timeout_is_default,
        http_enabled: args.http_enabled,
        http_listen_address: &args.http_listen_address,
        http_listen_address_is_default,
        http_tls_mode: &args.http_tls_mode,
        http_tls_mode_is_default,
        http_tls_cert: args.http_tls_cert.as_deref(),
        http_tls_key: args.http_tls_key.as_deref(),
        http_tls_ca_cert: args.http_tls_ca_cert.as_deref(),
    };

    config::merge_with_cli(file_config, &cli)
}

fn load_serve_password(
    resolved: &config::ResolvedConfig,
) -> Result<Zeroizing<String>, Box<dyn std::error::Error>> {
    if let Some(ref dir) = resolved.password_dir {
        return Ok(Zeroizing::new(std::fs::read_to_string(dir)?));
    }
    if let Some(ref file) = resolved.password_file {
        let content = std::fs::read_to_string(file)?;
        return Ok(Zeroizing::new(content.trim_end_matches('\n').to_string()));
    }
    // No password source provided — prompt or use empty string.
    Ok(Zeroizing::new(String::new()))
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c().await.expect("failed to install Ctrl+C handler");
    info!("Shutdown signal received");
}

/// Parse the backend string into a `Backend` enum.
#[cfg(feature = "dvt")]
fn parse_backend(backend: &str) -> Result<Backend, Box<dyn std::error::Error>> {
    match backend {
        "basic" => Ok(Backend::Basic),
        "dvt" => Ok(Backend::Dvt),
        other => Err(format!("unknown backend: {other}; expected 'basic' or 'dvt'").into()),
    }
}

/// Run the split-key subcommand.
#[cfg(feature = "dvt")]
fn run_split_key(args: SplitKeyCliArgs) -> Result<(), Box<dyn std::error::Error>> {
    use rvc_signer_bin::commands::split_key::{execute, SplitKeyArgs};
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
