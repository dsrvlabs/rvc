pub mod backend;
#[cfg(feature = "dvt")]
pub mod commands;
#[cfg(feature = "dvt")]
pub mod dvt;
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
    /// gRPC listen address (host:port)
    #[arg(long, default_value = DEFAULT_LISTEN_ADDRESS)]
    listen_address: String,

    /// Path to the keystore directory
    #[arg(long)]
    keystore_dir: PathBuf,

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

    /// Signing backend to use
    #[arg(long, value_enum, default_value_t = Backend::Basic)]
    backend: Backend,

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
            info!(
                listen_address = %args.listen_address,
                keystore_dir = %args.keystore_dir.display(),
                backend = %args.backend,
                "Starting rvc-signer"
            );

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
    let password = load_serve_password(&args)?;

    let tls_config = match (args.tls_cert.as_ref(), args.tls_key.as_ref(), args.tls_ca_cert.as_ref()) {
        (Some(cert), Some(key), Some(ca)) => {
            Some(tls::TlsConfig::new(cert.clone(), key.clone(), ca.clone()))
        }
        _ => None,
    };

    // Build the signing backend and optional peer signer service
    #[cfg(feature = "dvt")]
    let (signing_backend, peer_signer_service): (
        Arc<dyn backend::SigningBackend>,
        Option<dvt::peer_service::PeerSignerServiceImpl>,
    ) = match args.backend {
        Backend::Basic => {
            let signer = backend::basic::BasicSigner::load(&args.keystore_dir, &password)?;
            (Arc::new(signer), None)
        }
        Backend::Dvt => build_dvt_backend(&args, &password, tls_config.as_ref()).await?,
    };

    #[cfg(not(feature = "dvt"))]
    let (signing_backend, peer_signer_service): (Arc<dyn backend::SigningBackend>, Option<()>) = {
        let signer = backend::basic::BasicSigner::load(&args.keystore_dir, &password)?;
        (Arc::new(signer), None)
    };

    let signer_service =
        service::SignerServiceImpl::new(Arc::clone(&signing_backend), args.backend.to_string());

    let addr = args.listen_address.parse()?;

    let mut builder = tonic::transport::Server::builder();

    if let Some(ref tls) = tls_config {
        let server_tls = tls.to_server_tls_config()?;
        builder = builder.tls_config(server_tls)?;
        info!("mTLS enabled");
    } else {
        info!("TLS disabled (no --tls-cert/--tls-key/--tls-ca-cert provided)");
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
    args: &ServeArgs,
    password: &Zeroizing<String>,
    tls_config: Option<&tls::TlsConfig>,
) -> Result<
    (Arc<dyn backend::SigningBackend>, Option<dvt::peer_service::PeerSignerServiceImpl>),
    Box<dyn std::error::Error>,
> {
    use std::collections::HashMap;
    use std::time::Duration;

    let dvt_index = args.dvt_index.ok_or("--dvt-index is required when using --backend dvt")?;

    let timeout = Duration::from_millis(args.dvt_timeout);

    // Load Shamir shares from keystore directory
    let shares = dvt::types::load_shares(&args.keystore_dir, password)
        .map_err(|e| format!("failed to load DVT shares: {}", e))?;

    if shares.is_empty() {
        return Err("no DVT shares found in keystore directory".into());
    }

    info!(
        share_count = shares.len(),
        dvt_index,
        peer_count = args.dvt_peers.len(),
        "Loaded DVT shares"
    );

    // Build shared share map for PeerSignerServiceImpl
    let share_map: HashMap<[u8; 48], dvt::types::ShareInfo> =
        shares.iter().map(|s| (s.aggregate_pubkey, clone_share_info(s))).collect();

    let peer_signer_service = dvt::peer_service::PeerSignerServiceImpl::new(Arc::new(share_map));

    // Connect to peers
    let peer_requester = if !args.dvt_peers.is_empty() {
        let requester =
            dvt::peer_client::GrpcPeerRequester::connect(&args.dvt_peers, tls_config, timeout)
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
        args.dvt_peers.clone(),
        peer_requester,
        timeout,
    );

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

fn load_serve_password(args: &ServeArgs) -> Result<Zeroizing<String>, Box<dyn std::error::Error>> {
    if let Some(ref path) = args.password_file {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read password file {}: {}", path.display(), e))?;
        Ok(Zeroizing::new(content.trim_end().to_string()))
    } else if let Some(ref dir) = args.password_dir {
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
                assert_eq!(args.keystore_dir, PathBuf::from("/tmp/keystores"));
                assert!(args.password_dir.is_none());
                assert!(args.password_file.is_none());
                assert!(args.tls_cert.is_none());
                assert!(args.tls_key.is_none());
                assert!(args.tls_ca_cert.is_none());
                assert!(matches!(args.backend, Backend::Basic));
            }
            #[cfg(feature = "dvt")]
            _ => panic!("expected Serve command"),
        }
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
                assert_eq!(args.keystore_dir, PathBuf::from("/tmp/keystores"));
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
                    assert_eq!(
                        args.output_password_file,
                        Some(PathBuf::from("/tmp/share-pw.txt"))
                    );
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
            let password = load_serve_password(&args).unwrap();
            let result = build_dvt_backend(&args, &password, None).await;
            let err = result.err().expect("should fail without --dvt-index");
            assert!(err.to_string().contains("--dvt-index"));
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
            let password = load_serve_password(&args).unwrap();
            let result = build_dvt_backend(&args, &password, None).await;
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
            let password = load_serve_password(&args).unwrap();
            let (backend, peer_svc) = build_dvt_backend(&args, &password, None).await.unwrap();

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
}
