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
}

impl std::fmt::Display for Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Basic => write!(f, "basic"),
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

    let signer = backend::basic::BasicSigner::load(&args.keystore_dir, &password)?;
    let backend: Arc<dyn backend::SigningBackend> = Arc::new(signer);

    let signer_service =
        service::SignerServiceImpl::new(Arc::clone(&backend), args.backend.to_string());

    let addr = args.listen_address.parse()?;

    let mut builder = tonic::transport::Server::builder();

    if let (Some(cert), Some(key), Some(ca)) =
        (args.tls_cert.as_ref(), args.tls_key.as_ref(), args.tls_ca_cert.as_ref())
    {
        let tls_config =
            tls::TlsConfig::new(cert.clone(), key.clone(), ca.clone()).to_server_tls_config()?;
        builder = builder.tls_config(tls_config)?;
        info!("mTLS enabled");
    } else {
        info!("TLS disabled (no --tls-cert/--tls-key/--tls-ca-cert provided)");
    }

    info!(address = %addr, "gRPC server listening");
    builder
        .add_service(SignerServiceServer::new(signer_service))
        .serve_with_shutdown(addr, shutdown_signal())
        .await?;

    Ok(())
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
    }
}
