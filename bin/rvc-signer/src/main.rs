use std::path::PathBuf;

use clap::Parser;
use tracing::info;

pub mod tls;

pub mod proto {
    pub mod signer {
        tonic::include_proto!("signer");
    }
}

pub use proto::signer::signer_service_server::{SignerService, SignerServiceServer};
pub use proto::signer::{
    GetStatusRequest, GetStatusResponse, ListPublicKeysRequest, ListPublicKeysResponse,
    SignRequest, SignResponse,
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

    // Wait for shutdown signal
    shutdown_signal().await;
    info!("Shutting down rvc-signer");
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
}
