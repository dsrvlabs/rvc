pub mod backend;
#[cfg(feature = "dvt")]
pub mod dvt;
pub mod service;

use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use tracing::{error, info};
use zeroize::Zeroizing;

pub mod tls;

pub mod proto {
    pub mod signer {
        tonic::include_proto!("signer");
    }
}

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
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    info!(
        listen_address = %cli.listen_address,
        keystore_dir = %cli.keystore_dir.display(),
        backend = %cli.backend,
        "Starting rvc-signer"
    );

    if let Err(e) = run(cli).await {
        error!(error = %e, "rvc-signer failed");
        std::process::exit(1);
    }

    info!("Shutting down rvc-signer");
}

async fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let password = load_password(&cli)?;

    let signer = backend::basic::BasicSigner::load(&cli.keystore_dir, &password)?;
    let backend: Arc<dyn backend::SigningBackend> = Arc::new(signer);

    let signer_service =
        service::SignerServiceImpl::new(Arc::clone(&backend), cli.backend.to_string());

    let addr = cli.listen_address.parse()?;

    let mut builder = tonic::transport::Server::builder();

    if let (Some(cert), Some(key), Some(ca)) =
        (cli.tls_cert.as_ref(), cli.tls_key.as_ref(), cli.tls_ca_cert.as_ref())
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

fn load_password(cli: &Cli) -> Result<Zeroizing<String>, Box<dyn std::error::Error>> {
    if let Some(ref path) = cli.password_file {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read password file {}: {}", path.display(), e))?;
        Ok(Zeroizing::new(content.trim_end().to_string()))
    } else if let Some(ref dir) = cli.password_dir {
        // For password-dir, we read the first file found as the shared password.
        // Individual per-keystore password files are handled in BasicSigner::load
        // when that feature is implemented. For now, use the directory path.
        let _ = dir;
        Err("--password-dir is not yet supported; use --password-file".into())
    } else {
        Err("one of --password-file or --password-dir is required".into())
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
    fn test_cli_parse_minimal() {
        let cli = Cli::parse_from(["rvc-signer", "--keystore-dir", "/tmp/keystores"]);
        assert_eq!(cli.listen_address, DEFAULT_LISTEN_ADDRESS);
        assert_eq!(cli.keystore_dir, PathBuf::from("/tmp/keystores"));
        assert!(cli.password_dir.is_none());
        assert!(cli.password_file.is_none());
        assert!(cli.tls_cert.is_none());
        assert!(cli.tls_key.is_none());
        assert!(cli.tls_ca_cert.is_none());
        assert!(matches!(cli.backend, Backend::Basic));
    }

    #[test]
    fn test_cli_parse_all_flags() {
        let cli = Cli::parse_from([
            "rvc-signer",
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
        assert_eq!(cli.listen_address, "0.0.0.0:9000");
        assert_eq!(cli.keystore_dir, PathBuf::from("/tmp/keystores"));
        assert_eq!(cli.password_dir, Some(PathBuf::from("/tmp/passwords")));
        assert_eq!(cli.tls_cert, Some(PathBuf::from("/tmp/cert.pem")));
        assert_eq!(cli.tls_key, Some(PathBuf::from("/tmp/key.pem")));
        assert_eq!(cli.tls_ca_cert, Some(PathBuf::from("/tmp/ca.pem")));
        assert!(matches!(cli.backend, Backend::Basic));
    }

    #[test]
    fn test_cli_parse_password_file() {
        let cli = Cli::parse_from([
            "rvc-signer",
            "--keystore-dir",
            "/tmp/ks",
            "--password-file",
            "/tmp/pw.txt",
        ]);
        assert_eq!(cli.password_file, Some(PathBuf::from("/tmp/pw.txt")));
        assert!(cli.password_dir.is_none());
    }

    #[test]
    fn test_cli_password_dir_and_file_mutually_exclusive() {
        let result = Cli::try_parse_from([
            "rvc-signer",
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
    fn test_cli_missing_keystore_dir_fails() {
        let result = Cli::try_parse_from(["rvc-signer"]);
        assert!(result.is_err(), "keystore-dir is required");
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
}
