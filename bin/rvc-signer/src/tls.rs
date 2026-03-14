use std::path::{Path, PathBuf};

use tonic::transport::server::ServerTlsConfig;
use tonic::transport::{Certificate, ClientTlsConfig, Identity};

#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("failed to read server certificate at '{}': {source}", path.display())]
    ReadCert { path: PathBuf, source: std::io::Error },

    #[error("failed to read server key at '{}': {source}", path.display())]
    ReadKey { path: PathBuf, source: std::io::Error },

    #[error("failed to read CA certificate at '{}': {source}", path.display())]
    ReadCaCert { path: PathBuf, source: std::io::Error },
}

/// TLS configuration for the rvc-signer gRPC server.
///
/// All three paths are required. The server will refuse to start
/// without valid TLS certificates (no plaintext fallback).
pub struct TlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub ca_cert_path: PathBuf,
}

impl TlsConfig {
    pub fn new(cert_path: PathBuf, key_path: PathBuf, ca_cert_path: PathBuf) -> Self {
        Self { cert_path, key_path, ca_cert_path }
    }

    /// Build a tonic `ServerTlsConfig` with mTLS enabled.
    ///
    /// Client certificates are required (not optional). Connections
    /// without a valid client certificate signed by the CA are rejected.
    /// Build a tonic `ClientTlsConfig` for mTLS peer connections.
    ///
    /// Uses the same cert/key/CA as the server: the client presents its
    /// identity and verifies the peer's certificate against the shared CA.
    pub fn to_client_tls_config(&self) -> Result<ClientTlsConfig, TlsError> {
        let cert = read_file(&self.cert_path)
            .map_err(|source| TlsError::ReadCert { path: self.cert_path.clone(), source })?;
        let key = read_file(&self.key_path)
            .map_err(|source| TlsError::ReadKey { path: self.key_path.clone(), source })?;
        let ca_cert = read_file(&self.ca_cert_path)
            .map_err(|source| TlsError::ReadCaCert { path: self.ca_cert_path.clone(), source })?;

        Ok(ClientTlsConfig::new()
            .identity(Identity::from_pem(&cert, &key))
            .ca_certificate(Certificate::from_pem(&ca_cert)))
    }

    /// Build a tonic `ServerTlsConfig` with mTLS enabled.
    ///
    /// Client certificates are required (not optional). Connections
    /// without a valid client certificate signed by the CA are rejected.
    pub fn to_server_tls_config(&self) -> Result<ServerTlsConfig, TlsError> {
        let cert = read_file(&self.cert_path)
            .map_err(|source| TlsError::ReadCert { path: self.cert_path.clone(), source })?;
        let key = read_file(&self.key_path)
            .map_err(|source| TlsError::ReadKey { path: self.key_path.clone(), source })?;
        let ca_cert = read_file(&self.ca_cert_path)
            .map_err(|source| TlsError::ReadCaCert { path: self.ca_cert_path.clone(), source })?;

        Ok(ServerTlsConfig::new()
            .identity(Identity::from_pem(&cert, &key))
            .client_ca_root(Certificate::from_pem(&ca_cert)))
    }
}

fn read_file(path: &Path) -> Result<Vec<u8>, std::io::Error> {
    std::fs::read(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Write;

    use rcgen::{CertificateParams, KeyPair};
    use tempfile::TempDir;

    struct TestCerts {
        _dir: TempDir,
        cert_path: PathBuf,
        key_path: PathBuf,
        ca_cert_path: PathBuf,
    }

    fn generate_test_certs() -> TestCerts {
        let dir = TempDir::new().unwrap();

        // Generate CA
        let ca_params = CertificateParams::new(vec!["rvc-signer-ca".to_string()]).unwrap();
        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        // Generate server cert signed by CA
        let server_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let server_key = KeyPair::generate().unwrap();
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

        TestCerts { _dir: dir, cert_path, key_path, ca_cert_path }
    }

    #[test]
    fn test_to_server_tls_config_success() {
        let certs = generate_test_certs();
        let tls = TlsConfig::new(certs.cert_path, certs.key_path, certs.ca_cert_path);
        let result = tls.to_server_tls_config();
        assert!(result.is_ok());
    }

    #[test]
    fn test_missing_cert_file() {
        let certs = generate_test_certs();
        let tls = TlsConfig::new(
            PathBuf::from("/nonexistent/server.pem"),
            certs.key_path,
            certs.ca_cert_path,
        );
        let err = tls.to_server_tls_config().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("server certificate"), "error: {msg}");
        assert!(msg.contains("/nonexistent/server.pem"), "error: {msg}");
    }

    #[test]
    fn test_missing_key_file() {
        let certs = generate_test_certs();
        let tls = TlsConfig::new(
            certs.cert_path,
            PathBuf::from("/nonexistent/server.key"),
            certs.ca_cert_path,
        );
        let err = tls.to_server_tls_config().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("server key"), "error: {msg}");
        assert!(msg.contains("/nonexistent/server.key"), "error: {msg}");
    }

    #[test]
    fn test_missing_ca_cert_file() {
        let certs = generate_test_certs();
        let tls =
            TlsConfig::new(certs.cert_path, certs.key_path, PathBuf::from("/nonexistent/ca.pem"));
        let err = tls.to_server_tls_config().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("CA certificate"), "error: {msg}");
        assert!(msg.contains("/nonexistent/ca.pem"), "error: {msg}");
    }

    #[test]
    fn test_invalid_pem_cert() {
        let dir = TempDir::new().unwrap();
        let cert_path = dir.path().join("bad.pem");
        let key_path = dir.path().join("bad.key");
        let ca_path = dir.path().join("ca.pem");

        std::fs::write(&cert_path, b"not a valid PEM").unwrap();
        std::fs::write(&key_path, b"not a valid key").unwrap();
        std::fs::write(&ca_path, b"not a valid CA").unwrap();

        let tls = TlsConfig::new(cert_path, key_path, ca_path);
        // Files are readable but contain invalid PEM. to_server_tls_config
        // reads files successfully; tonic validates PEM when the server starts.
        let result = tls.to_server_tls_config();
        assert!(result.is_ok(), "file reads succeed; PEM validation happens at server start");
    }

    #[test]
    fn test_tls_error_display() {
        let err = TlsError::ReadCert {
            path: PathBuf::from("/tmp/cert.pem"),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "file not found"),
        };
        let msg = err.to_string();
        assert!(msg.contains("/tmp/cert.pem"));
        assert!(msg.contains("file not found"));
    }
}
