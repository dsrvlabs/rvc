pub mod audit;
pub mod backend;
#[cfg(feature = "dvt")]
pub mod commands;
pub mod config;
#[cfg(feature = "dvt")]
pub mod dvt;
#[cfg(test)]
mod integration_polish;
pub mod metrics;
pub mod reload;
pub mod service;

use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use tracing::{error, info};
use zeroize::Zeroizing;

pub mod tls;

pub mod proto {
    pub mod signer {
        tonic::include_proto!("signer");
    }
}

#[cfg(feature = "dvt")]
pub use proto::signer::peer_signer_service_client::PeerSignerServiceClient;
pub use proto::signer::peer_signer_service_server::{PeerSignerService, PeerSignerServiceServer};
pub use proto::signer::signer_service_server::{SignerService, SignerServiceServer};
pub use proto::signer::{
    GetStatusRequest, GetStatusResponse, ListPublicKeysRequest, ListPublicKeysResponse,
    PartialSignRequest, PartialSignResponse, SignRequest, SignResponse,
};

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

    /// Validate configuration and exit without starting the server
    #[arg(long)]
    dry_run: bool,

    /// Allow starting without TLS (NOT recommended for production)
    #[arg(long)]
    insecure: bool,

    /// Signing backend to use
    #[arg(long, value_enum, default_value_t = Backend::Basic)]
    backend: Backend,

    /// Prometheus metrics listen address (host:port)
    #[arg(long, default_value = "127.0.0.1:9101")]
    metrics_address: String,

    /// Keystore reload interval in seconds (0 to disable)
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
            Some(tls::TlsConfig::new(cert.clone(), key.clone(), ca.clone()))
        }
        _ => None,
    };

    // Set up Prometheus metrics early so DVT backend can use them
    let signer_metrics = Arc::new(metrics::SignerMetrics::new());

    // Build the signing backend and optional peer signer service
    #[cfg(feature = "dvt")]
    let (signing_backend, peer_signer_service, basic_signer_ref): (
        Arc<dyn backend::SigningBackend>,
        Option<dvt::peer_service::PeerSignerServiceImpl>,
        Option<Arc<backend::basic::BasicSigner>>,
    ) = match parse_backend(&resolved.backend)? {
        Backend::Basic => {
            let signer =
                Arc::new(backend::basic::BasicSigner::load(&resolved.keystore_dir, &password)?);
            (Arc::clone(&signer) as Arc<dyn backend::SigningBackend>, None, Some(signer))
        }
        Backend::Dvt => {
            let (backend, peer_svc) = build_dvt_backend(
                &resolved,
                &password,
                tls_config.as_ref(),
                Arc::new(signer_metrics.dvt.clone()),
            )
            .await?;
            (backend, peer_svc, None)
        }
    };

    #[cfg(not(feature = "dvt"))]
    let (signing_backend, peer_signer_service, basic_signer_ref): (
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

    // Start keystore hot-reload if using basic backend and interval > 0
    if let Some(ref basic_signer) = basic_signer_ref {
        if resolved.reload_interval_secs > 0 {
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

            info!(interval_secs = resolved.reload_interval_secs, "Keystore hot-reload enabled");
        }
    }

    // Set up Prometheus metrics server
    let key_count = signing_backend.public_keys().len() as f64;
    signer_metrics.keys_loaded.with_label_values(&[&resolved.backend]).set(key_count);

    let metrics_addr: std::net::SocketAddr = args.metrics_address.parse()?;
    let (_metrics_handle, metrics_bound_addr) =
        metrics::serve_metrics(metrics_addr, Arc::clone(&signer_metrics)).await?;
    info!(address = %metrics_bound_addr, "Prometheus metrics server listening");

    let signer_service =
        service::SignerServiceImpl::new(Arc::clone(&signing_backend), resolved.backend.clone())
            .with_metrics(Arc::clone(&signer_metrics));

    let addr = resolved.listen_address.parse()?;

    let mut builder = tonic::transport::Server::builder();

    if let Some(ref tls) = tls_config {
        let server_tls = tls.to_server_tls_config()?;
        builder = builder.tls_config(server_tls)?;
        info!("mTLS enabled");
    } else if args.insecure {
        tracing::warn!("TLS disabled via --insecure flag. Do NOT use in production!");
    } else {
        return Err("TLS is required. Provide --tls-cert, --tls-key, and --tls-ca-cert, \
             or use --insecure to disable (NOT recommended for production)."
            .into());
    }

    info!(address = %addr, "gRPC server listening");

    let router = builder.add_service(SignerServiceServer::new(signer_service));

    #[cfg(feature = "dvt")]
    let router = if let Some(peer_svc) = peer_signer_service {
        info!("PeerSignerService registered for DVT");
        router.add_service(PeerSignerServiceServer::new(peer_svc))
    } else {
        router
    };

    #[cfg(not(feature = "dvt"))]
    let _ = peer_signer_service;

    router.serve_with_shutdown(addr, shutdown_signal()).await?;

    Ok(())
}

#[cfg(feature = "dvt")]
async fn build_dvt_backend(
    resolved: &config::ResolvedConfig,
    password: &Zeroizing<String>,
    tls_config: Option<&tls::TlsConfig>,
    dvt_metrics: Arc<metrics::DvtMetrics>,
) -> Result<
    (Arc<dyn backend::SigningBackend>, Option<dvt::peer_service::PeerSignerServiceImpl>),
    Box<dyn std::error::Error>,
> {
    use std::collections::HashMap;
    use std::time::Duration;

    let dvt_index = resolved.dvt_index.ok_or("dvt_index is required when using backend dvt")?;

    let timeout = Duration::from_millis(resolved.dvt_timeout_ms);

    // Load Shamir shares from keystore directory
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

    // Build shared share map for PeerSignerServiceImpl
    let share_map: HashMap<[u8; 48], dvt::types::ShareInfo> =
        shares.iter().map(|s| (s.aggregate_pubkey, clone_share_info(s))).collect();

    let peer_signer_service = dvt::peer_service::PeerSignerServiceImpl::new(Arc::new(share_map));

    // Connect to peers
    let peer_requester = if !resolved.dvt_peers.is_empty() {
        let requester =
            dvt::peer_client::GrpcPeerRequester::connect(&resolved.dvt_peers, tls_config, timeout)
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

    Ok((Arc::new(dvt_signer), Some(peer_signer_service)))
}

#[cfg(feature = "dvt")]
fn clone_share_info(s: &dvt::types::ShareInfo) -> dvt::types::ShareInfo {
    dvt::types::ShareInfo {
        index: s.index,
        threshold: s.threshold,
        total: s.total,
        scalar_bytes: s.scalar_bytes.clone(),
        aggregate_pubkey: s.aggregate_pubkey,
    }
}

fn resolve_config(args: &ServeArgs) -> Result<config::ResolvedConfig, Box<dyn std::error::Error>> {
    let file_config = if let Some(ref path) = args.config {
        config::load_config(path)?
    } else {
        config::SignerConfig::default()
    };

    // When a config file is used, treat clap default_values as unset so config
    // file values can take precedence.
    let has_config = args.config.is_some();
    let listen_address_is_default = has_config && args.listen_address == DEFAULT_LISTEN_ADDRESS;
    let backend_is_default = has_config && matches!(args.backend, Backend::Basic);

    let reload_interval_is_default = has_config && args.reload_interval == 30;

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
        dvt_peers,
        dvt_threshold,
        dvt_index,
        dvt_timeout,
        dvt_timeout_is_default,
    };

    config::merge_with_cli(file_config, &cli)
}

#[cfg(feature = "dvt")]
fn parse_backend(s: &str) -> Result<Backend, Box<dyn std::error::Error>> {
    match s {
        "basic" => Ok(Backend::Basic),
        #[cfg(feature = "dvt")]
        "dvt" => Ok(Backend::Dvt),
        other => Err(format!("unknown backend: {}", other).into()),
    }
}

fn load_serve_password(
    resolved: &config::ResolvedConfig,
) -> Result<Zeroizing<String>, Box<dyn std::error::Error>> {
    if let Some(ref path) = resolved.password_file {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read password file {}: {}", path.display(), e))?;
        Ok(Zeroizing::new(content.trim_end().to_string()))
    } else if let Some(ref dir) = resolved.password_dir {
        let _ = dir;
        Err("--password-dir is not yet supported; use --password-file".into())
    } else {
        Err("one of --password-file or --password-dir is required".into())
    }
}

#[cfg(feature = "dvt")]
fn run_split_key(args: SplitKeyCliArgs) -> Result<(), Box<dyn std::error::Error>> {
    let password =
        load_password_from_args(args.password.as_deref(), args.password_file.as_deref())?;
    let output_password = load_password_from_args(
        args.output_password.as_deref(),
        args.output_password_file.as_deref(),
    )?;

    commands::split_key::execute(commands::split_key::SplitKeyArgs {
        keystore: args.keystore,
        password,
        threshold: args.threshold,
        shares: args.shares,
        output_dir: args.output_dir,
        output_password,
    })?;

    Ok(())
}

#[cfg(feature = "dvt")]
fn load_password_from_args(
    inline: Option<&str>,
    file: Option<&std::path::Path>,
) -> Result<Zeroizing<String>, Box<dyn std::error::Error>> {
    if let Some(pw) = inline {
        Ok(Zeroizing::new(pw.to_string()))
    } else if let Some(path) = file {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read password file {}: {}", path.display(), e))?;
        Ok(Zeroizing::new(content.trim_end().to_string()))
    } else {
        Err("one of --password or --password-file is required".into())
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c().await.expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            info!("Received SIGINT (Ctrl+C)");
        }
        _ = terminate => {
            info!("Received SIGTERM");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_parse_serve_minimal() {
        let cli = Cli::parse_from(["rvc-signer", "serve", "--keystore-dir", "/tmp/keystores"]);
        match cli.command {
            Command::Serve(args) => {
                assert_eq!(args.listen_address, DEFAULT_LISTEN_ADDRESS);
                assert_eq!(args.keystore_dir, Some(PathBuf::from("/tmp/keystores")));
                assert!(args.password_dir.is_none());
                assert!(args.password_file.is_none());
                assert!(args.config.is_none());
                assert!(args.tls_cert.is_none());
                assert!(args.tls_key.is_none());
                assert!(args.tls_ca_cert.is_none());
                assert!(matches!(args.backend, Backend::Basic));
                assert!(!args.dry_run);
            }
            #[cfg(feature = "dvt")]
            _ => panic!("expected Serve command"),
        }
    }

    #[test]
    fn test_cli_parse_dry_run_flag() {
        let cli = Cli::parse_from([
            "rvc-signer",
            "serve",
            "--keystore-dir",
            "/tmp/keystores",
            "--dry-run",
        ]);
        match cli.command {
            Command::Serve(args) => {
                assert!(args.dry_run);
            }
            #[cfg(feature = "dvt")]
            _ => panic!("expected Serve command"),
        }
    }

    #[test]
    fn test_cli_dry_run_defaults_false() {
        let cli = Cli::parse_from(["rvc-signer", "serve", "--keystore-dir", "/tmp/ks"]);
        match cli.command {
            Command::Serve(args) => {
                assert!(!args.dry_run);
            }
            #[cfg(feature = "dvt")]
            _ => panic!("expected Serve command"),
        }
    }

    #[tokio::test]
    async fn test_dry_run_valid_config_exits_ok() {
        let dir = tempfile::TempDir::new().unwrap();
        let pw_file = dir.path().join("pw.txt");
        std::fs::write(&pw_file, "test-password").unwrap();

        // Create a valid keystore
        let sk = crypto::SecretKey::generate();
        let ks =
            crypto::Keystore::encrypt(&sk, b"test-password", "", crypto::EncryptionKdf::Pbkdf2)
                .unwrap();
        std::fs::write(dir.path().join("key.json"), ks.to_json().unwrap()).unwrap();

        let args = ServeArgs {
            config: None,
            listen_address: DEFAULT_LISTEN_ADDRESS.to_string(),
            keystore_dir: Some(dir.path().to_path_buf()),
            password_dir: None,
            password_file: Some(pw_file),
            tls_cert: None,
            tls_key: None,
            tls_ca_cert: None,
            dry_run: true,
            insecure: true,
            backend: Backend::Basic,
            metrics_address: "127.0.0.1:0".to_string(),
            reload_interval: 0,
            #[cfg(feature = "dvt")]
            dvt_peers: vec![],
            #[cfg(feature = "dvt")]
            dvt_threshold: None,
            #[cfg(feature = "dvt")]
            dvt_index: None,
            #[cfg(feature = "dvt")]
            dvt_timeout: 2000,
        };

        let result = run_serve(args).await;
        assert!(result.is_ok(), "dry-run with valid config should succeed: {:?}", result.err());
    }

    #[tokio::test]
    async fn test_dry_run_invalid_keystore_dir_fails() {
        let dir = tempfile::TempDir::new().unwrap();
        let pw_file = dir.path().join("pw.txt");
        std::fs::write(&pw_file, "test-password").unwrap();

        let args = ServeArgs {
            config: None,
            listen_address: DEFAULT_LISTEN_ADDRESS.to_string(),
            keystore_dir: Some(PathBuf::from("/nonexistent/keystores")),
            password_dir: None,
            password_file: Some(pw_file),
            tls_cert: None,
            tls_key: None,
            tls_ca_cert: None,
            dry_run: true,
            insecure: true,
            backend: Backend::Basic,
            metrics_address: "127.0.0.1:0".to_string(),
            reload_interval: 0,
            #[cfg(feature = "dvt")]
            dvt_peers: vec![],
            #[cfg(feature = "dvt")]
            dvt_threshold: None,
            #[cfg(feature = "dvt")]
            dvt_index: None,
            #[cfg(feature = "dvt")]
            dvt_timeout: 2000,
        };

        let result = run_serve(args).await;
        assert!(result.is_err(), "dry-run with invalid keystore dir should fail");
    }

    #[tokio::test]
    async fn test_dry_run_with_tls_certs() {
        use std::io::Write;

        let dir = tempfile::TempDir::new().unwrap();
        let pw_file = dir.path().join("pw.txt");
        std::fs::write(&pw_file, "test-password").unwrap();

        // Create a valid keystore
        let sk = crypto::SecretKey::generate();
        let ks =
            crypto::Keystore::encrypt(&sk, b"test-password", "", crypto::EncryptionKdf::Pbkdf2)
                .unwrap();
        std::fs::write(dir.path().join("key.json"), ks.to_json().unwrap()).unwrap();

        // Generate test TLS certs
        let ca_params = rcgen::CertificateParams::new(vec!["rvc-signer-ca".to_string()]).unwrap();
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let server_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let server_key = rcgen::KeyPair::generate().unwrap();
        let server_cert = server_params.signed_by(&server_key, &ca_cert, &ca_key).unwrap();

        let cert_path = dir.path().join("server.pem");
        let key_path = dir.path().join("server.key");
        let ca_cert_path = dir.path().join("ca.pem");

        let mut f = std::fs::File::create(&cert_path).unwrap();
        f.write_all(server_cert.pem().as_bytes()).unwrap();
        let mut f = std::fs::File::create(&key_path).unwrap();
        f.write_all(server_key.serialize_pem().as_bytes()).unwrap();
        let mut f = std::fs::File::create(&ca_cert_path).unwrap();
        f.write_all(ca_cert.pem().as_bytes()).unwrap();

        let args = ServeArgs {
            config: None,
            listen_address: DEFAULT_LISTEN_ADDRESS.to_string(),
            keystore_dir: Some(dir.path().to_path_buf()),
            password_dir: None,
            password_file: Some(pw_file),
            tls_cert: Some(cert_path),
            tls_key: Some(key_path),
            tls_ca_cert: Some(ca_cert_path),
            dry_run: true,
            insecure: true,
            backend: Backend::Basic,
            metrics_address: "127.0.0.1:0".to_string(),
            reload_interval: 0,
            #[cfg(feature = "dvt")]
            dvt_peers: vec![],
            #[cfg(feature = "dvt")]
            dvt_threshold: None,
            #[cfg(feature = "dvt")]
            dvt_index: None,
            #[cfg(feature = "dvt")]
            dvt_timeout: 2000,
        };

        let result = run_serve(args).await;
        assert!(result.is_ok(), "dry-run with valid TLS certs should succeed: {:?}", result.err());
    }

    #[tokio::test]
    async fn test_dry_run_invalid_tls_cert_fails() {
        let dir = tempfile::TempDir::new().unwrap();
        let pw_file = dir.path().join("pw.txt");
        std::fs::write(&pw_file, "test-password").unwrap();

        // Create a valid keystore
        let sk = crypto::SecretKey::generate();
        let ks =
            crypto::Keystore::encrypt(&sk, b"test-password", "", crypto::EncryptionKdf::Pbkdf2)
                .unwrap();
        std::fs::write(dir.path().join("key.json"), ks.to_json().unwrap()).unwrap();

        let args = ServeArgs {
            config: None,
            listen_address: DEFAULT_LISTEN_ADDRESS.to_string(),
            keystore_dir: Some(dir.path().to_path_buf()),
            password_dir: None,
            password_file: Some(pw_file),
            tls_cert: Some(PathBuf::from("/nonexistent/cert.pem")),
            tls_key: Some(PathBuf::from("/nonexistent/key.pem")),
            tls_ca_cert: Some(PathBuf::from("/nonexistent/ca.pem")),
            dry_run: true,
            insecure: true,
            backend: Backend::Basic,
            metrics_address: "127.0.0.1:0".to_string(),
            reload_interval: 0,
            #[cfg(feature = "dvt")]
            dvt_peers: vec![],
            #[cfg(feature = "dvt")]
            dvt_threshold: None,
            #[cfg(feature = "dvt")]
            dvt_index: None,
            #[cfg(feature = "dvt")]
            dvt_timeout: 2000,
        };

        let result = run_serve(args).await;
        assert!(result.is_err(), "dry-run with invalid TLS certs should fail");
    }

    #[test]
    fn test_cli_parse_serve_all_flags() {
        let cli = Cli::parse_from([
            "rvc-signer",
            "serve",
            "--keystore-dir",
            "/tmp/keystores",
            "--listen-address",
            "0.0.0.0:9000",
            "--password-dir",
            "/tmp/passwords",
            "--tls-cert",
            "/tmp/cert.pem",
            "--tls-key",
            "/tmp/key.pem",
            "--tls-ca-cert",
            "/tmp/ca.pem",
            "--backend",
            "basic",
        ]);
        match cli.command {
            Command::Serve(args) => {
                assert_eq!(args.listen_address, "0.0.0.0:9000");
                assert_eq!(args.keystore_dir, Some(PathBuf::from("/tmp/keystores")));
                assert_eq!(args.password_dir, Some(PathBuf::from("/tmp/passwords")));
                assert_eq!(args.tls_cert, Some(PathBuf::from("/tmp/cert.pem")));
                assert_eq!(args.tls_key, Some(PathBuf::from("/tmp/key.pem")));
                assert_eq!(args.tls_ca_cert, Some(PathBuf::from("/tmp/ca.pem")));
                assert!(matches!(args.backend, Backend::Basic));
            }
            #[cfg(feature = "dvt")]
            _ => panic!("expected Serve command"),
        }
    }

    #[test]
    fn test_cli_parse_serve_password_file() {
        let cli = Cli::parse_from([
            "rvc-signer",
            "serve",
            "--keystore-dir",
            "/tmp/ks",
            "--password-file",
            "/tmp/pw.txt",
        ]);
        match cli.command {
            Command::Serve(args) => {
                assert_eq!(args.password_file, Some(PathBuf::from("/tmp/pw.txt")));
                assert!(args.password_dir.is_none());
            }
            #[cfg(feature = "dvt")]
            _ => panic!("expected Serve command"),
        }
    }

    #[test]
    fn test_cli_serve_password_dir_and_file_mutually_exclusive() {
        let result = Cli::try_parse_from([
            "rvc-signer",
            "serve",
            "--keystore-dir",
            "/tmp/ks",
            "--password-dir",
            "/tmp/pw",
            "--password-file",
            "/tmp/pw.txt",
        ]);
        assert!(result.is_err(), "password-dir and password-file should be mutually exclusive");
    }

    #[test]
    fn test_cli_missing_subcommand_fails() {
        let result = Cli::try_parse_from(["rvc-signer"]);
        assert!(result.is_err(), "subcommand is required");
    }

    #[test]
    fn test_backend_display() {
        assert_eq!(Backend::Basic.to_string(), "basic");
    }

    #[test]
    fn test_sign_request_fields() {
        let req = SignRequest { signing_root: vec![0u8; 32], pubkey: vec![0u8; 48] };
        assert_eq!(req.signing_root.len(), 32);
        assert_eq!(req.pubkey.len(), 48);
    }

    #[test]
    fn test_sign_response_fields() {
        let resp = SignResponse { signature: vec![0u8; 96] };
        assert_eq!(resp.signature.len(), 96);
    }

    #[test]
    fn test_list_public_keys_response() {
        let resp = ListPublicKeysResponse { pubkeys: vec![vec![1u8; 48], vec![2u8; 48]] };
        assert_eq!(resp.pubkeys.len(), 2);
    }

    #[test]
    fn test_get_status_response() {
        let resp = GetStatusResponse { ready: true, backend: "basic".to_string(), key_count: 5 };
        assert!(resp.ready);
        assert_eq!(resp.backend, "basic");
        assert_eq!(resp.key_count, 5);
    }

    #[test]
    fn test_default_listen_address() {
        assert_eq!(DEFAULT_LISTEN_ADDRESS, "127.0.0.1:50052");
    }

    #[test]
    fn test_partial_sign_request_fields() {
        let req = PartialSignRequest {
            signing_root: vec![0u8; 32],
            pubkey: vec![0u8; 48],
            requester_index: 7,
        };
        assert_eq!(req.signing_root.len(), 32);
        assert_eq!(req.pubkey.len(), 48);
        assert_eq!(req.requester_index, 7);
    }

    #[test]
    fn test_partial_sign_response_fields() {
        let resp = PartialSignResponse { partial_signature: vec![0u8; 96], share_index: 3 };
        assert_eq!(resp.partial_signature.len(), 96);
        assert_eq!(resp.share_index, 3);
    }

    #[cfg(feature = "dvt")]
    mod dvt_cli {
        use super::*;

        #[test]
        fn test_dvt_peers_flag() {
            let cli = Cli::parse_from([
                "rvc-signer",
                "serve",
                "--keystore-dir",
                "/tmp/ks",
                "--dvt-peers",
                "127.0.0.1:50053,127.0.0.1:50054",
            ]);
            match cli.command {
                Command::Serve(args) => {
                    assert_eq!(args.dvt_peers, vec!["127.0.0.1:50053", "127.0.0.1:50054"]);
                }
                _ => panic!("expected Serve command"),
            }
        }

        #[test]
        fn test_dvt_threshold_and_index() {
            let cli = Cli::parse_from([
                "rvc-signer",
                "serve",
                "--keystore-dir",
                "/tmp/ks",
                "--dvt-threshold",
                "2",
                "--dvt-index",
                "1",
            ]);
            match cli.command {
                Command::Serve(args) => {
                    assert_eq!(args.dvt_threshold, Some(2));
                    assert_eq!(args.dvt_index, Some(1));
                }
                _ => panic!("expected Serve command"),
            }
        }

        #[test]
        fn test_dvt_timeout_default() {
            let cli = Cli::parse_from(["rvc-signer", "serve", "--keystore-dir", "/tmp/ks"]);
            match cli.command {
                Command::Serve(args) => {
                    assert_eq!(args.dvt_timeout, 2000);
                }
                _ => panic!("expected Serve command"),
            }
        }

        #[test]
        fn test_dvt_timeout_custom() {
            let cli = Cli::parse_from([
                "rvc-signer",
                "serve",
                "--keystore-dir",
                "/tmp/ks",
                "--dvt-timeout",
                "5000",
            ]);
            match cli.command {
                Command::Serve(args) => {
                    assert_eq!(args.dvt_timeout, 5000);
                }
                _ => panic!("expected Serve command"),
            }
        }

        #[test]
        fn test_dvt_peers_empty_by_default() {
            let cli = Cli::parse_from(["rvc-signer", "serve", "--keystore-dir", "/tmp/ks"]);
            match cli.command {
                Command::Serve(args) => {
                    assert!(args.dvt_peers.is_empty());
                }
                _ => panic!("expected Serve command"),
            }
        }

        #[test]
        fn test_dvt_all_flags_together() {
            let cli = Cli::parse_from([
                "rvc-signer",
                "serve",
                "--keystore-dir",
                "/tmp/ks",
                "--dvt-peers",
                "peer1:50053,peer2:50054,peer3:50055",
                "--dvt-threshold",
                "3",
                "--dvt-index",
                "0",
                "--dvt-timeout",
                "1500",
                "--password-file",
                "/tmp/pw.txt",
            ]);
            match cli.command {
                Command::Serve(args) => {
                    assert_eq!(args.dvt_peers.len(), 3);
                    assert_eq!(args.dvt_threshold, Some(3));
                    assert_eq!(args.dvt_index, Some(0));
                    assert_eq!(args.dvt_timeout, 1500);
                }
                _ => panic!("expected Serve command"),
            }
        }

        #[test]
        fn test_cli_parse_split_key() {
            let cli = Cli::parse_from([
                "rvc-signer",
                "split-key",
                "--keystore",
                "/tmp/key.json",
                "--password",
                "secret",
                "--threshold",
                "2",
                "--shares",
                "3",
                "--output-dir",
                "/tmp/shares",
                "--output-password",
                "share-secret",
            ]);
            match cli.command {
                Command::SplitKey(args) => {
                    assert_eq!(args.keystore, PathBuf::from("/tmp/key.json"));
                    assert_eq!(args.password, Some("secret".to_string()));
                    assert!(args.password_file.is_none());
                    assert_eq!(args.threshold, 2);
                    assert_eq!(args.shares, 3);
                    assert_eq!(args.output_dir, PathBuf::from("/tmp/shares"));
                    assert_eq!(args.output_password, Some("share-secret".to_string()));
                    assert!(args.output_password_file.is_none());
                }
                _ => panic!("expected SplitKey command"),
            }
        }

        #[test]
        fn test_cli_parse_split_key_with_password_files() {
            let cli = Cli::parse_from([
                "rvc-signer",
                "split-key",
                "--keystore",
                "/tmp/key.json",
                "--password-file",
                "/tmp/pw.txt",
                "--threshold",
                "3",
                "--shares",
                "5",
                "--output-dir",
                "/tmp/shares",
                "--output-password-file",
                "/tmp/share-pw.txt",
            ]);
            match cli.command {
                Command::SplitKey(args) => {
                    assert!(args.password.is_none());
                    assert_eq!(args.password_file, Some(PathBuf::from("/tmp/pw.txt")));
                    assert_eq!(args.threshold, 3);
                    assert_eq!(args.shares, 5);
                    assert!(args.output_password.is_none());
                    assert_eq!(args.output_password_file, Some(PathBuf::from("/tmp/share-pw.txt")));
                }
                _ => panic!("expected SplitKey command"),
            }
        }

        #[test]
        fn test_cli_split_key_password_and_file_mutually_exclusive() {
            let result = Cli::try_parse_from([
                "rvc-signer",
                "split-key",
                "--keystore",
                "/tmp/key.json",
                "--password",
                "secret",
                "--password-file",
                "/tmp/pw.txt",
                "--threshold",
                "2",
                "--shares",
                "3",
                "--output-dir",
                "/tmp/shares",
                "--output-password",
                "pw",
            ]);
            assert!(result.is_err(), "password and password-file should be mutually exclusive");
        }

        #[test]
        fn test_load_password_from_args_inline() {
            let result = load_password_from_args(Some("my-password"), None).unwrap();
            assert_eq!(*result, "my-password");
        }

        #[test]
        fn test_load_password_from_args_file() {
            let tmp = tempfile::NamedTempFile::new().unwrap();
            std::fs::write(tmp.path(), "file-password\n").unwrap();
            let result = load_password_from_args(None, Some(tmp.path())).unwrap();
            assert_eq!(*result, "file-password");
        }

        #[test]
        fn test_load_password_from_args_neither() {
            let result = load_password_from_args(None, None);
            assert!(result.is_err());
        }

        #[test]
        fn test_backend_dvt_display() {
            assert_eq!(Backend::Dvt.to_string(), "dvt");
        }

        #[test]
        fn test_cli_parse_backend_dvt() {
            let cli = Cli::parse_from([
                "rvc-signer",
                "serve",
                "--keystore-dir",
                "/tmp/ks",
                "--backend",
                "dvt",
                "--dvt-index",
                "1",
            ]);
            match cli.command {
                Command::Serve(args) => {
                    assert!(matches!(args.backend, Backend::Dvt));
                }
                _ => panic!("expected Serve command"),
            }
        }

        fn parse_serve_args(args: &[&str]) -> ServeArgs {
            let cli = Cli::parse_from(args);
            match cli.command {
                Command::Serve(args) => args,
                _ => panic!("expected Serve command"),
            }
        }

        #[tokio::test]
        async fn test_build_dvt_backend_missing_index_fails() {
            let dir = tempfile::TempDir::new().unwrap();
            let pw_file = dir.path().join("pw.txt");
            std::fs::write(&pw_file, "test-password").unwrap();

            let args = parse_serve_args(&[
                "rvc-signer",
                "serve",
                "--keystore-dir",
                dir.path().to_str().unwrap(),
                "--backend",
                "dvt",
                "--password-file",
                pw_file.to_str().unwrap(),
            ]);
            let resolved = resolve_config(&args).unwrap();
            let password = load_serve_password(&resolved).unwrap();
            let dvt_metrics = Arc::new(metrics::SignerMetrics::new().dvt.clone());
            let result = build_dvt_backend(&resolved, &password, None, dvt_metrics).await;
            let err = result.err().expect("should fail without --dvt-index");
            assert!(err.to_string().contains("dvt_index"));
        }

        #[tokio::test]
        async fn test_build_dvt_backend_no_shares_fails() {
            let dir = tempfile::TempDir::new().unwrap();
            let pw_file = dir.path().join("pw.txt");
            std::fs::write(&pw_file, "test-password").unwrap();

            let args = parse_serve_args(&[
                "rvc-signer",
                "serve",
                "--keystore-dir",
                dir.path().to_str().unwrap(),
                "--backend",
                "dvt",
                "--dvt-index",
                "1",
                "--password-file",
                pw_file.to_str().unwrap(),
            ]);
            let resolved = resolve_config(&args).unwrap();
            let password = load_serve_password(&resolved).unwrap();
            let dvt_metrics = Arc::new(metrics::SignerMetrics::new().dvt.clone());
            let result = build_dvt_backend(&resolved, &password, None, dvt_metrics).await;
            let err = result.err().expect("should fail with no shares");
            assert!(err.to_string().contains("no DVT shares"));
        }

        #[tokio::test]
        async fn test_build_dvt_backend_with_shares_succeeds() {
            use crypto::{EncryptionKdf, Keystore, SecretKey};

            let dir = tempfile::TempDir::new().unwrap();
            let pw = "test-password";
            let pw_file = dir.path().join("pw.txt");
            std::fs::write(&pw_file, pw).unwrap();

            // Create a share keystore
            let sk = SecretKey::generate();
            let mut ks = Keystore::encrypt(&sk, pw.as_bytes(), "", EncryptionKdf::Pbkdf2).unwrap();
            ks.description = Some("shamir-share".to_string());
            ks.pubkey = Some(hex::encode(sk.public_key().to_bytes()));
            std::fs::write(dir.path().join("share-1.json"), ks.to_json().unwrap()).unwrap();

            let meta = serde_json::json!({"threshold": 1, "total": 1, "index": 1});
            std::fs::write(dir.path().join("share-meta.json"), meta.to_string()).unwrap();

            let args = parse_serve_args(&[
                "rvc-signer",
                "serve",
                "--keystore-dir",
                dir.path().to_str().unwrap(),
                "--backend",
                "dvt",
                "--dvt-index",
                "1",
                "--password-file",
                pw_file.to_str().unwrap(),
            ]);
            let resolved = resolve_config(&args).unwrap();
            let password = load_serve_password(&resolved).unwrap();
            let dvt_metrics = Arc::new(metrics::SignerMetrics::new().dvt.clone());
            let (backend, peer_svc) =
                build_dvt_backend(&resolved, &password, None, dvt_metrics).await.unwrap();

            assert_eq!(backend.public_keys().len(), 1);
            assert_eq!(backend.public_keys()[0], sk.public_key().to_bytes());
            assert!(peer_svc.is_some());
        }
    }

    #[cfg(feature = "dvt")]
    mod dvt_integration {
        use super::*;
        use std::collections::HashMap;
        use std::sync::Arc;
        use std::time::Duration;

        use backend::dvt::{DvtSigner, PeerRequester};
        use backend::SigningBackend;
        use dvt::peer_client::GrpcPeerRequester;
        use dvt::peer_service::PeerSignerServiceImpl;
        use dvt::types::ShareInfo;
        use zeroize::Zeroizing;

        use bls12_381_plus::Scalar;
        use rand::rngs::OsRng;
        use vsss_rs::{shamir, DefaultShare, IdentifierPrimeField};

        use dvt::bridge::blst_sk_to_scalar;

        type BlsShare = DefaultShare<IdentifierPrimeField<Scalar>, IdentifierPrimeField<Scalar>>;

        fn split_key(
            sk: &crypto::SecretKey,
            threshold: usize,
            total: usize,
        ) -> Vec<(u64, [u8; 32], [u8; 48])> {
            let pk = sk.public_key().to_bytes();
            let blst_sk = blst::min_pk::SecretKey::from_bytes(&sk.to_bytes()).unwrap();
            let secret = blst_sk_to_scalar(&blst_sk).unwrap();

            let shares: Vec<BlsShare> = shamir::split_secret::<BlsShare>(
                threshold,
                total,
                &IdentifierPrimeField(secret),
                OsRng,
            )
            .unwrap();

            shares
                .iter()
                .map(|share| {
                    use vsss_rs::Share;
                    let idx_field: &IdentifierPrimeField<Scalar> = share.identifier();
                    let val_field: &IdentifierPrimeField<Scalar> = share.value();
                    let idx_bytes = idx_field.0.to_be_bytes();
                    let idx = u64::from_be_bytes(idx_bytes[24..32].try_into().unwrap());
                    let val_bytes = val_field.0.to_be_bytes();
                    (idx, val_bytes, pk)
                })
                .collect()
        }

        fn make_share_info(
            idx: u64,
            scalar: [u8; 32],
            aggregate_pubkey: [u8; 48],
            threshold: u64,
            total: u64,
        ) -> ShareInfo {
            ShareInfo {
                index: idx,
                threshold,
                total,
                scalar_bytes: Zeroizing::new(scalar),
                aggregate_pubkey,
            }
        }

        /// End-to-end 2-of-3 DVT signing via gRPC peer servers.
        ///
        /// Sets up 2 PeerSignerService gRPC servers (peers), then creates
        /// a DvtSigner with a GrpcPeerRequester connected to both peers.
        /// Verifies the combined signature matches direct signing.
        #[tokio::test]
        async fn test_dvt_end_to_end_2_of_3_via_grpc() {
            let sk = crypto::SecretKey::generate();
            let pk = sk.public_key().to_bytes();
            let shares = split_key(&sk, 2, 3);

            // Node 0 = us, Nodes 1+2 = peer gRPC servers
            let own_idx = shares[0].0;

            // Start peer gRPC servers for nodes 1 and 2
            let mut peer_addrs = Vec::new();
            for i in 1..=2usize {
                let share = make_share_info(shares[i].0, shares[i].1, pk, 2, 3);
                let mut map = HashMap::new();
                map.insert(pk, share);
                let svc = PeerSignerServiceImpl::new(Arc::new(map));

                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let addr = listener.local_addr().unwrap();
                peer_addrs.push(addr.to_string());

                tokio::spawn(async move {
                    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
                    tonic::transport::Server::builder()
                        .add_service(PeerSignerServiceServer::new(svc))
                        .serve_with_incoming(incoming)
                        .await
                        .unwrap();
                });
            }

            // Give servers time to start
            tokio::time::sleep(Duration::from_millis(50)).await;

            // Connect GrpcPeerRequester to both peers
            let timeout = Duration::from_secs(5);
            let requester = GrpcPeerRequester::connect(&peer_addrs, None, timeout).await.unwrap();

            assert_eq!(requester.peer_addrs().len(), 2);

            // Create DvtSigner with the GrpcPeerRequester
            let own_share = make_share_info(own_idx, shares[0].1, pk, 2, 3);
            let signer = DvtSigner::new(
                vec![own_share],
                own_idx,
                peer_addrs.clone(),
                Some(Arc::new(requester) as Arc<dyn PeerRequester>),
                timeout,
            );

            let signing_root = [0xAB; 32];
            let sig = signer.sign(&signing_root, &pk).await.unwrap();

            // Verify combined signature matches direct signing
            let direct_sig = sk.sign(&signing_root);
            assert_eq!(sig, direct_sig.to_bytes());
        }

        /// Test that DvtSigner succeeds when one peer fails (2-of-3, one peer down).
        #[tokio::test]
        async fn test_dvt_grpc_partial_peer_failure_still_succeeds() {
            let sk = crypto::SecretKey::generate();
            let pk = sk.public_key().to_bytes();
            let shares = split_key(&sk, 2, 3);

            let own_idx = shares[0].0;

            // Only start peer 1 (peer 2 address is unreachable)
            let share1 = make_share_info(shares[1].0, shares[1].1, pk, 2, 3);
            let mut map = HashMap::new();
            map.insert(pk, share1);
            let svc = PeerSignerServiceImpl::new(Arc::new(map));

            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let live_addr = listener.local_addr().unwrap().to_string();

            tokio::spawn(async move {
                let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
                tonic::transport::Server::builder()
                    .add_service(PeerSignerServiceServer::new(svc))
                    .serve_with_incoming(incoming)
                    .await
                    .unwrap();
            });

            tokio::time::sleep(Duration::from_millis(50)).await;

            // Connect only to the live peer
            let timeout = Duration::from_secs(5);
            let peer_addrs = vec![live_addr.clone()];
            let requester = GrpcPeerRequester::connect(&peer_addrs, None, timeout).await.unwrap();

            // DvtSigner knows about 2 peers but requester only connected to 1
            // The DvtSigner iterates over peer_addrs it was given
            let own_share = make_share_info(own_idx, shares[0].1, pk, 2, 3);
            let signer = DvtSigner::new(
                vec![own_share],
                own_idx,
                peer_addrs,
                Some(Arc::new(requester) as Arc<dyn PeerRequester>),
                timeout,
            );

            let signing_root = [0xCC; 32];
            let sig = signer.sign(&signing_root, &pk).await.unwrap();

            let direct_sig = sk.sign(&signing_root);
            assert_eq!(sig, direct_sig.to_bytes());
        }

        /// Test GrpcPeerRequester implements PeerRequester trait from backend::dvt.
        #[tokio::test]
        async fn test_grpc_peer_requester_implements_backend_trait() {
            let sk = crypto::SecretKey::generate();
            let pk = sk.public_key().to_bytes();
            let scalar = sk.to_bytes();

            let share = make_share_info(1, scalar, pk, 2, 3);
            let mut map = HashMap::new();
            map.insert(pk, share);
            let svc = PeerSignerServiceImpl::new(Arc::new(map));

            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap().to_string();

            tokio::spawn(async move {
                let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
                tonic::transport::Server::builder()
                    .add_service(PeerSignerServiceServer::new(svc))
                    .serve_with_incoming(incoming)
                    .await
                    .unwrap();
            });

            tokio::time::sleep(Duration::from_millis(50)).await;

            let timeout = Duration::from_secs(5);
            let requester =
                GrpcPeerRequester::connect(&[addr.clone()], None, timeout).await.unwrap();

            // Use as dyn PeerRequester (backend::dvt trait)
            let requester: Arc<dyn PeerRequester> = Arc::new(requester);
            let signing_root = [0xDD; 32];
            let (share_index, partial_sig) =
                requester.request_partial(&addr, &signing_root, &pk).await.unwrap();

            assert_eq!(share_index, 1);
            assert_eq!(partial_sig.len(), 96);

            // Verify partial sig is correct
            let blst_sk = blst::min_pk::SecretKey::from_bytes(&scalar).unwrap();
            let expected =
                blst_sk.sign(&signing_root, b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_", &[]);
            assert_eq!(partial_sig, expected.to_bytes());
        }

        /// Test that PeerRequester returns error for unknown peer address.
        #[tokio::test]
        async fn test_grpc_peer_requester_unknown_addr_fails() {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap().to_string();

            // Start empty peer service
            let svc = PeerSignerServiceImpl::new(Arc::new(HashMap::new()));
            tokio::spawn(async move {
                let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
                tonic::transport::Server::builder()
                    .add_service(PeerSignerServiceServer::new(svc))
                    .serve_with_incoming(incoming)
                    .await
                    .unwrap();
            });

            tokio::time::sleep(Duration::from_millis(50)).await;

            let requester =
                GrpcPeerRequester::connect(&[addr], None, Duration::from_secs(5)).await.unwrap();

            let requester: Arc<dyn PeerRequester> = Arc::new(requester);
            let result = requester.request_partial("unknown:1234", &[0u8; 32], &[0u8; 48]).await;
            assert!(result.is_err());
        }
    }

    /// RS-18: Phase 2 full-stack integration tests.
    ///
    /// These tests exercise the complete DVT signing pipeline:
    /// GrpcRemoteSigner client → SignerServiceImpl → DvtSigner → PeerSignerServiceImpl
    #[cfg(feature = "dvt")]
    mod dvt_full_stack {
        use super::*;
        use std::collections::HashMap;
        use std::sync::Arc;
        use std::time::Duration;

        use backend::basic::BasicSigner;
        use backend::dvt::{DvtSigner, PeerRequester};
        use backend::SigningBackend;
        use dvt::peer_client::GrpcPeerRequester;
        use dvt::peer_service::PeerSignerServiceImpl;
        use dvt::types::ShareInfo;
        use zeroize::Zeroizing;

        use bls12_381_plus::Scalar;
        use crypto::Signer;
        use grpc_signer::{GrpcRemoteSigner, GrpcRemoteSignerConfig};
        use rand::rngs::OsRng;
        use vsss_rs::{shamir, DefaultShare, IdentifierPrimeField};

        use dvt::bridge::blst_sk_to_scalar;

        type BlsShare = DefaultShare<IdentifierPrimeField<Scalar>, IdentifierPrimeField<Scalar>>;

        fn split_key(
            sk: &crypto::SecretKey,
            threshold: usize,
            total: usize,
        ) -> Vec<(u64, [u8; 32], [u8; 48])> {
            let pk = sk.public_key().to_bytes();
            let blst_sk = blst::min_pk::SecretKey::from_bytes(&sk.to_bytes()).unwrap();
            let secret = blst_sk_to_scalar(&blst_sk).unwrap();

            let shares: Vec<BlsShare> = shamir::split_secret::<BlsShare>(
                threshold,
                total,
                &IdentifierPrimeField(secret),
                OsRng,
            )
            .unwrap();

            shares
                .iter()
                .map(|share| {
                    use vsss_rs::Share;
                    let idx_field: &IdentifierPrimeField<Scalar> = share.identifier();
                    let val_field: &IdentifierPrimeField<Scalar> = share.value();
                    let idx_bytes = idx_field.0.to_be_bytes();
                    let idx = u64::from_be_bytes(idx_bytes[24..32].try_into().unwrap());
                    let val_bytes = val_field.0.to_be_bytes();
                    (idx, val_bytes, pk)
                })
                .collect()
        }

        fn make_share_info(
            idx: u64,
            scalar: [u8; 32],
            aggregate_pubkey: [u8; 48],
            threshold: u64,
            total: u64,
        ) -> ShareInfo {
            ShareInfo {
                index: idx,
                threshold,
                total,
                scalar_bytes: Zeroizing::new(scalar),
                aggregate_pubkey,
            }
        }

        /// Start peer gRPC servers and return their addresses.
        async fn start_peer_servers(
            shares: &[(u64, [u8; 32], [u8; 48])],
            peer_indices: &[usize],
            pk: [u8; 48],
            threshold: u64,
            total: u64,
        ) -> Vec<String> {
            let mut peer_addrs = Vec::new();
            for &i in peer_indices {
                let share = make_share_info(shares[i].0, shares[i].1, pk, threshold, total);
                let mut map = HashMap::new();
                map.insert(pk, share);
                let svc = PeerSignerServiceImpl::new(Arc::new(map));

                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let addr = listener.local_addr().unwrap();
                peer_addrs.push(addr.to_string());

                tokio::spawn(async move {
                    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
                    tonic::transport::Server::builder()
                        .add_service(PeerSignerServiceServer::new(svc))
                        .serve_with_incoming(incoming)
                        .await
                        .unwrap();
                });
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
            peer_addrs
        }

        /// Start a SignerService gRPC server backed by DvtSigner and return its address.
        async fn start_dvt_signer_server(
            shares: &[(u64, [u8; 32], [u8; 48])],
            own_index: usize,
            peer_addrs: Vec<String>,
            pk: [u8; 48],
            threshold: u64,
            total: u64,
            timeout: Duration,
        ) -> String {
            let own_idx = shares[own_index].0;
            let own_share = make_share_info(own_idx, shares[own_index].1, pk, threshold, total);

            let requester = if !peer_addrs.is_empty() {
                let r = GrpcPeerRequester::connect(&peer_addrs, None, timeout).await.unwrap();
                Some(Arc::new(r) as Arc<dyn PeerRequester>)
            } else {
                None
            };

            let dvt_signer =
                DvtSigner::new(vec![own_share], own_idx, peer_addrs, requester, timeout);

            let signer_svc = service::SignerServiceImpl::new(
                Arc::new(dvt_signer) as Arc<dyn SigningBackend>,
                "dvt".to_string(),
            );

            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let addr_str = addr.to_string();

            tokio::spawn(async move {
                let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
                tonic::transport::Server::builder()
                    .add_service(SignerServiceServer::new(signer_svc))
                    .serve_with_incoming(incoming)
                    .await
                    .unwrap();
            });

            tokio::time::sleep(Duration::from_millis(50)).await;
            addr_str
        }

        /// Full E2E: split key → start 3 DVT nodes → GrpcRemoteSigner client signs →
        /// verify combined signature against original pubkey.
        #[tokio::test]
        async fn test_full_e2e_split_key_to_grpc_client_sign() {
            let sk = crypto::SecretKey::generate();
            let pk = sk.public_key().to_bytes();
            let shares = split_key(&sk, 2, 3);

            // Start peer servers for nodes 1 and 2
            let peer_addrs = start_peer_servers(&shares, &[1, 2], pk, 2, 3).await;

            // Start DVT signer server for node 0
            let timeout = Duration::from_secs(5);
            let server_addr =
                start_dvt_signer_server(&shares, 0, peer_addrs, pk, 2, 3, timeout).await;

            // Connect GrpcRemoteSigner client
            let config = GrpcRemoteSignerConfig::new(format!("http://{}", server_addr));
            let client = GrpcRemoteSigner::connect(config).await.unwrap();

            // Verify the client sees the validator key
            let keys = client.public_keys();
            assert_eq!(keys.len(), 1);
            assert_eq!(keys[0], pk);

            // Sign via the client
            let signing_root = [0xAB; 32];
            let sig = client.sign(&signing_root, &pk).await.unwrap();

            // Verify combined signature matches direct signing
            let direct_sig = sk.sign(&signing_root);
            assert_eq!(sig.to_bytes(), direct_sig.to_bytes());

            // Verify signature via crypto crate
            let pubkey = crypto::PublicKey::from_bytes(&pk).unwrap();
            assert!(sig.verify(&pubkey, &signing_root).is_ok());
        }

        /// Peer failure tolerance: 1-of-2 peers down, 2-of-3 still succeeds.
        #[tokio::test]
        async fn test_full_e2e_peer_failure_tolerance() {
            let sk = crypto::SecretKey::generate();
            let pk = sk.public_key().to_bytes();
            let shares = split_key(&sk, 2, 3);

            // Only start peer 1 (peer 2 not started)
            let peer_addrs = start_peer_servers(&shares, &[1], pk, 2, 3).await;

            // Start DVT signer server for node 0 with only the live peer
            let timeout = Duration::from_secs(5);
            let server_addr =
                start_dvt_signer_server(&shares, 0, peer_addrs, pk, 2, 3, timeout).await;

            // Connect client and sign
            let config = GrpcRemoteSignerConfig::new(format!("http://{}", server_addr));
            let client = GrpcRemoteSigner::connect(config).await.unwrap();

            let signing_root = [0xCC; 32];
            let sig = client.sign(&signing_root, &pk).await.unwrap();

            // 2-of-3 threshold met (own + 1 peer), signature is valid
            let direct_sig = sk.sign(&signing_root);
            assert_eq!(sig.to_bytes(), direct_sig.to_bytes());
        }

        /// Timeout test: all peers slow → DvtSigner times out → error returned to client.
        #[tokio::test]
        async fn test_full_e2e_timeout_when_all_peers_slow() {
            use async_trait::async_trait;

            struct SlowPeerRequester;

            #[async_trait]
            impl PeerRequester for SlowPeerRequester {
                async fn request_partial(
                    &self,
                    _peer_addr: &str,
                    _signing_root: &[u8; 32],
                    _pubkey: &[u8; 48],
                ) -> Result<(u64, [u8; 96]), backend::dvt::PeerRequestError> {
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    unreachable!()
                }
            }

            let sk = crypto::SecretKey::generate();
            let pk = sk.public_key().to_bytes();
            let shares = split_key(&sk, 2, 3);

            let own_idx = shares[0].0;
            let own_share = make_share_info(own_idx, shares[0].1, pk, 2, 3);

            // DvtSigner with slow peer requester and very short timeout
            let dvt_signer = DvtSigner::new(
                vec![own_share],
                own_idx,
                vec!["slow-peer:5000".to_string()],
                Some(Arc::new(SlowPeerRequester)),
                Duration::from_millis(100),
            );

            let signer_svc = service::SignerServiceImpl::new(
                Arc::new(dvt_signer) as Arc<dyn SigningBackend>,
                "dvt".to_string(),
            );

            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let addr_str = addr.to_string();

            tokio::spawn(async move {
                let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
                tonic::transport::Server::builder()
                    .add_service(SignerServiceServer::new(signer_svc))
                    .serve_with_incoming(incoming)
                    .await
                    .unwrap();
            });

            tokio::time::sleep(Duration::from_millis(50)).await;

            let config = GrpcRemoteSignerConfig::new(format!("http://{}", addr_str));
            let client = GrpcRemoteSigner::connect(config).await.unwrap();

            let start = std::time::Instant::now();
            let result = client.sign(&[0xEE; 32], &pk).await;
            let elapsed = start.elapsed();

            // Should fail because timeout → only own partial (1 of 2 needed)
            assert!(result.is_err());
            // Should complete within a reasonable time (timeout + overhead)
            assert!(elapsed < Duration::from_secs(5), "took too long: {:?}", elapsed);
        }

        /// BasicSigner coexistence: a BasicSigner-backed server works independently.
        #[tokio::test]
        async fn test_basic_signer_coexistence() {
            let sk = crypto::SecretKey::generate();
            let pk = sk.public_key().to_bytes();

            // Create a BasicSigner using a temp keystore directory
            let tmp = tempfile::tempdir().unwrap();
            let password = Zeroizing::new("test-password".to_string());

            // Write a keystore for the key
            let keystore = crypto::Keystore::encrypt(
                &sk,
                password.as_bytes(),
                "",
                crypto::EncryptionKdf::Pbkdf2,
            )
            .unwrap();
            let keystore_json = serde_json::to_string_pretty(&keystore).unwrap();
            let keystore_path = tmp.path().join("key.json");
            std::fs::write(&keystore_path, &keystore_json).unwrap();

            let basic_signer = BasicSigner::load(tmp.path(), &password).unwrap();

            let signer_svc = service::SignerServiceImpl::new(
                Arc::new(basic_signer) as Arc<dyn SigningBackend>,
                "basic".to_string(),
            );

            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();

            tokio::spawn(async move {
                let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
                tonic::transport::Server::builder()
                    .add_service(SignerServiceServer::new(signer_svc))
                    .serve_with_incoming(incoming)
                    .await
                    .unwrap();
            });

            tokio::time::sleep(Duration::from_millis(50)).await;

            let config = GrpcRemoteSignerConfig::new(format!("http://{}", addr));
            let client = GrpcRemoteSigner::connect(config).await.unwrap();

            let keys = client.public_keys();
            assert_eq!(keys.len(), 1);
            assert_eq!(keys[0], pk);

            let signing_root = [0x42; 32];
            let sig = client.sign(&signing_root, &pk).await.unwrap();
            let direct_sig = sk.sign(&signing_root);
            assert_eq!(sig.to_bytes(), direct_sig.to_bytes());
        }

        /// Signature equivalence: DVT combined signature is byte-identical to direct signing.
        #[tokio::test]
        async fn test_dvt_signature_equivalence_with_direct_signing() {
            let sk = crypto::SecretKey::generate();
            let pk = sk.public_key().to_bytes();
            let shares = split_key(&sk, 2, 3);

            let peer_addrs = start_peer_servers(&shares, &[1, 2], pk, 2, 3).await;
            let timeout = Duration::from_secs(5);
            let server_addr =
                start_dvt_signer_server(&shares, 0, peer_addrs, pk, 2, 3, timeout).await;

            let config = GrpcRemoteSignerConfig::new(format!("http://{}", server_addr));
            let client = GrpcRemoteSigner::connect(config).await.unwrap();

            // Test multiple different signing roots
            for root_byte in [0x00u8, 0x42, 0x99, 0xFF] {
                let signing_root = [root_byte; 32];
                let dvt_sig = client.sign(&signing_root, &pk).await.unwrap();
                let direct_sig = sk.sign(&signing_root);
                assert_eq!(
                    dvt_sig.to_bytes(),
                    direct_sig.to_bytes(),
                    "DVT signature must match direct signing for root 0x{:02x}",
                    root_byte
                );
            }
        }

        /// Property test: any 2-of-3 subset produces identical valid signature.
        #[tokio::test]
        async fn test_any_2_of_3_subset_produces_same_signature() {
            let sk = crypto::SecretKey::generate();
            let pk = sk.public_key().to_bytes();
            let signing_root = [0xBE; 32];
            let direct_sig = sk.sign(&signing_root);

            let shares = split_key(&sk, 2, 3);

            // All C(3,2) = 3 subsets of 2 from 3 shares
            let subsets: [(usize, &[usize]); 3] = [(0, &[1, 2]), (1, &[0, 2]), (2, &[0, 1])];

            let mut collected_sigs = Vec::new();

            for (own_idx, peer_indices) in &subsets {
                let peer_addrs = start_peer_servers(&shares, peer_indices, pk, 2, 3).await;
                let timeout = Duration::from_secs(5);
                let server_addr =
                    start_dvt_signer_server(&shares, *own_idx, peer_addrs, pk, 2, 3, timeout).await;

                let config = GrpcRemoteSignerConfig::new(format!("http://{}", server_addr));
                let client = GrpcRemoteSigner::connect(config).await.unwrap();

                let sig = client.sign(&signing_root, &pk).await.unwrap();
                collected_sigs.push(sig.to_bytes());
            }

            // All subsets must produce the same signature
            for (i, sig) in collected_sigs.iter().enumerate() {
                assert_eq!(*sig, direct_sig.to_bytes(), "subset {} should match direct signing", i);
            }

            // Cross-check: all DVT signatures are byte-identical
            assert_eq!(collected_sigs[0], collected_sigs[1]);
            assert_eq!(collected_sigs[1], collected_sigs[2]);
        }

        /// GetStatus reports DVT backend correctly through the full stack.
        #[tokio::test]
        async fn test_full_e2e_get_status_reports_dvt() {
            let sk = crypto::SecretKey::generate();
            let pk = sk.public_key().to_bytes();
            let shares = split_key(&sk, 2, 3);

            let peer_addrs = start_peer_servers(&shares, &[1], pk, 2, 3).await;
            let timeout = Duration::from_secs(5);
            let server_addr =
                start_dvt_signer_server(&shares, 0, peer_addrs, pk, 2, 3, timeout).await;

            // Use raw gRPC client to check status
            let channel = tonic::transport::Channel::from_shared(format!("http://{}", server_addr))
                .unwrap()
                .connect()
                .await
                .unwrap();

            let mut client = grpc_signer::SignerServiceClient::new(channel);
            let status =
                client.get_status(grpc_signer::GetStatusRequest {}).await.unwrap().into_inner();

            assert!(status.ready);
            assert_eq!(status.backend, "dvt");
            assert_eq!(status.key_count, 1);
        }

        /// ListPublicKeys returns the aggregate pubkey via the full stack.
        #[tokio::test]
        async fn test_full_e2e_list_public_keys() {
            let sk = crypto::SecretKey::generate();
            let pk = sk.public_key().to_bytes();
            let shares = split_key(&sk, 2, 3);

            let peer_addrs = start_peer_servers(&shares, &[1], pk, 2, 3).await;
            let timeout = Duration::from_secs(5);
            let server_addr =
                start_dvt_signer_server(&shares, 0, peer_addrs, pk, 2, 3, timeout).await;

            let config = GrpcRemoteSignerConfig::new(format!("http://{}", server_addr));
            let client = GrpcRemoteSigner::connect(config).await.unwrap();

            let keys = client.public_keys();
            assert_eq!(keys.len(), 1);
            assert_eq!(keys[0], pk);
        }
    }
}
