//! Shared TLS file I/O with path-preserving errors.
//!
//! gRPC ([`crate::grpc_tls`]) and HTTP ([`crate::http_api::tls_config`]) both
//! load PEM material and must name the path on failure. Domain error enums wrap
//! [`TlsFileError`] so each stack keeps its richer variants (PEM parse, empty
//! cert chain, tonic `Identity`) while the I/O path uses one representation.
//!
//! Why a shared helper rather than a single error type for all TLS failures:
//! the two stacks surface different post-read failures (tonic defers PEM
//! validation to server start; HTTP decodes PEM→DER and builds a rustls
//! `ServerConfig` immediately). Unifying only the file-read step avoids a
//! grab-bag enum while still satisfying the "path through one shared
//! representation" acceptance criterion.

use std::path::{Path, PathBuf};

/// A TLS material file could not be read (missing, unreadable, etc.).
#[derive(Debug, thiserror::Error)]
#[error("cannot read TLS file {}: {source}", path.display())]
pub struct TlsFileError {
    pub path: PathBuf,
    #[source]
    pub source: std::io::Error,
}

/// Read the entire file at `path`, attaching the path to any I/O error.
pub fn read_tls_file(path: &Path) -> Result<Vec<u8>, TlsFileError> {
    std::fs::read(path).map_err(|source| TlsFileError { path: path.to_path_buf(), source })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_cert_error_includes_path() {
        let path = Path::new("/nonexistent/rvc-tls-io/server.pem");
        let err = read_tls_file(path).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("server.pem"), "error must name the path: {msg}");
        assert_eq!(err.path, path);
    }
}
