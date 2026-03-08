use std::sync::Arc;

use axum::{
    extract::Request,
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
};
use rand::RngCore;
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::Zeroizing;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Invalid token: {0}")]
    InvalidToken(String),
}

pub fn generate_token() -> Zeroizing<String> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(bytes.as_mut());
    Zeroizing::new(hex::encode(*bytes))
}

pub fn write_token_file(path: &std::path::Path, token: &str) -> Result<(), AuthError> {
    use std::io::Write;

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o400)
            .open(path)?;
        file.write_all(token.as_bytes())?;
    }

    #[cfg(not(unix))]
    {
        std::fs::write(path, token)?;
    }

    Ok(())
}

pub fn read_token_file(path: &std::path::Path) -> Result<Zeroizing<String>, AuthError> {
    let contents = Zeroizing::new(std::fs::read_to_string(path)?);
    let token = Zeroizing::new(contents.trim().to_string());
    validate_token(&token)?;
    Ok(token)
}

fn validate_token(token: &str) -> Result<(), AuthError> {
    if token.len() != 64 || !token.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AuthError::InvalidToken(format!(
            "expected 64 hex characters, got {} characters",
            token.len()
        )));
    }
    Ok(())
}

pub fn ensure_token(path: &std::path::Path) -> Result<Zeroizing<String>, AuthError> {
    use std::io::Write;

    // Attempt atomic exclusive creation (O_CREAT | O_EXCL) to avoid TOCTOU race.
    #[cfg(unix)]
    let create_result = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new().write(true).create_new(true).mode(0o400).open(path)
    };

    #[cfg(not(unix))]
    let create_result = std::fs::OpenOptions::new().write(true).create_new(true).open(path);

    match create_result {
        Ok(mut file) => {
            let token = generate_token();
            file.write_all(token.as_bytes())?;
            tracing::info!(path = %path.display(), "Generated new API token");
            Ok(token)
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => read_token_file(path),
        Err(e) => Err(AuthError::Io(e)),
    }
}

pub fn warn_if_insecure_permissions(path: &std::path::Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = std::fs::metadata(path) {
            let mode = metadata.permissions().mode();
            if mode & 0o077 != 0 {
                tracing::warn!(
                    path = %path.display(),
                    mode = format!("{:o}", mode & 0o777),
                    "API token file has insecure permissions; group/other can read or write. Consider restricting to 0o400"
                );
                return true;
            }
        }
        false
    }

    #[cfg(not(unix))]
    {
        let _ = path;
        false
    }
}

async fn bearer_auth(
    axum::extract::State(expected_token): axum::extract::State<Arc<String>>,
    request: Request,
    next: Next,
) -> Response {
    let authorized = request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(|token| token.as_bytes().ct_eq(expected_token.as_bytes()).unwrap_u8() == 1)
        .unwrap_or(false);

    if authorized {
        next.run(request).await
    } else {
        StatusCode::UNAUTHORIZED.into_response()
    }
}

pub fn with_auth(router: axum::Router, token: Arc<String>) -> axum::Router {
    router.layer(middleware::from_fn_with_state(token, bearer_auth))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_token_returns_64_hex_chars() {
        let token = generate_token();
        assert_eq!(token.len(), 64);
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_generate_token_returns_unique_values() {
        let t1 = generate_token();
        let t2 = generate_token();
        assert_ne!(t1, t2);
    }

    #[test]
    fn test_write_and_read_token_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("api-token.txt");
        let token = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

        write_token_file(&path, token).unwrap();
        let read_back = read_token_file(&path).unwrap();
        assert_eq!(&*read_back, token);
    }

    #[cfg(unix)]
    #[test]
    fn test_write_token_file_sets_permissions_0o400() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("api-token.txt");
        let token = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

        write_token_file(&path, token).unwrap();

        let metadata = std::fs::metadata(&path).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o400);
    }

    #[test]
    fn test_read_token_file_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonexistent.txt");
        let result = read_token_file(&path);
        assert!(result.is_err());
    }

    #[cfg(unix)]
    #[test]
    fn test_warn_if_insecure_permissions_world_readable() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("api-token.txt");
        std::fs::write(&path, "token").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        assert!(warn_if_insecure_permissions(&path));
    }

    #[cfg(unix)]
    #[test]
    fn test_warn_if_insecure_permissions_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("api-token.txt");
        std::fs::write(&path, "token").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();

        assert!(!warn_if_insecure_permissions(&path));
    }

    #[cfg(unix)]
    #[test]
    fn test_warn_if_insecure_permissions_group_writable() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("api-token.txt");
        std::fs::write(&path, "token").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o620)).unwrap();

        assert!(warn_if_insecure_permissions(&path));
    }

    #[cfg(unix)]
    #[test]
    fn test_warn_if_insecure_permissions_world_writable() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("api-token.txt");
        std::fs::write(&path, "token").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o602)).unwrap();

        assert!(warn_if_insecure_permissions(&path));
    }

    #[cfg(unix)]
    #[test]
    fn test_warn_if_insecure_permissions_owner_rw_ok() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("api-token.txt");
        std::fs::write(&path, "token").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        assert!(!warn_if_insecure_permissions(&path));
    }

    #[test]
    fn test_read_token_file_trims_whitespace() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("api-token.txt");
        let valid_hex = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        std::fs::write(&path, format!("  {valid_hex}  \n")).unwrap();

        let token = read_token_file(&path).unwrap();
        assert_eq!(&*token, valid_hex);
    }

    #[test]
    fn test_read_token_file_rejects_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("api-token.txt");
        std::fs::write(&path, "").unwrap();

        let result = read_token_file(&path);
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), AuthError::InvalidToken(_)),
            "Expected AuthError::InvalidToken for empty file"
        );
    }

    #[test]
    fn test_read_token_file_rejects_non_hex_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("api-token.txt");
        std::fs::write(&path, "zzzz_not_hex_at_all!").unwrap();

        let result = read_token_file(&path);
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), AuthError::InvalidToken(_)),
            "Expected AuthError::InvalidToken for non-hex content"
        );
    }

    #[test]
    fn test_read_token_file_rejects_wrong_length() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("api-token.txt");
        std::fs::write(&path, "abcdef").unwrap();

        let result = read_token_file(&path);
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), AuthError::InvalidToken(_)),
            "Expected AuthError::InvalidToken for wrong-length token"
        );
    }

    #[test]
    fn test_ensure_token_generates_new_token_when_file_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("api-token.txt");

        let token = ensure_token(&path).unwrap();
        assert_eq!(token.len(), 64);
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));

        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert_eq!(on_disk, *token);
    }

    #[test]
    fn test_ensure_token_reads_existing_token() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("api-token.txt");
        let existing = "deadbeef".repeat(8);
        std::fs::write(&path, &existing).unwrap();

        let token = ensure_token(&path).unwrap();
        assert_eq!(*token, existing);
    }

    #[cfg(unix)]
    #[test]
    fn test_ensure_token_creates_file_with_0o400_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("api-token.txt");

        let _token = ensure_token(&path).unwrap();

        let metadata = std::fs::metadata(&path).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o400);
    }

    #[test]
    fn test_ensure_token_concurrent_creation_reads_existing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("api-token.txt");
        let existing = "deadbeef".repeat(8);

        // Pre-create the file to simulate a concurrent create_new failure
        std::fs::write(&path, &existing).unwrap();

        // ensure_token should fall back to reading the existing file
        let token = ensure_token(&path).unwrap();
        assert_eq!(*token, existing);
    }

    #[tokio::test]
    async fn test_middleware_allows_valid_bearer_token() {
        use axum::{routing::get, Router};
        use http_body_util::BodyExt;
        use std::sync::Arc;
        use tower::ServiceExt;

        let token = "abc123".to_string();
        let router = Router::new().route("/test", get(|| async { "ok" }));
        let app = with_auth(router, Arc::new(token.clone()));

        let request = axum::http::Request::builder()
            .uri("/test")
            .header("Authorization", format!("Bearer {token}"))
            .body(axum::body::Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"ok");
    }

    #[tokio::test]
    async fn test_middleware_rejects_invalid_bearer_token() {
        use axum::{routing::get, Router};
        use std::sync::Arc;
        use tower::ServiceExt;

        let token = "abc123".to_string();
        let router = Router::new().route("/test", get(|| async { "ok" }));
        let app = with_auth(router, Arc::new(token));

        let request = axum::http::Request::builder()
            .uri("/test")
            .header("Authorization", "Bearer wrong_token")
            .body(axum::body::Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_middleware_rejects_missing_auth_header() {
        use axum::{routing::get, Router};
        use std::sync::Arc;
        use tower::ServiceExt;

        let token = "abc123".to_string();
        let router = Router::new().route("/test", get(|| async { "ok" }));
        let app = with_auth(router, Arc::new(token));

        let request =
            axum::http::Request::builder().uri("/test").body(axum::body::Body::empty()).unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_middleware_rejects_non_bearer_scheme() {
        use axum::{routing::get, Router};
        use std::sync::Arc;
        use tower::ServiceExt;

        let token = "abc123".to_string();
        let router = Router::new().route("/test", get(|| async { "ok" }));
        let app = with_auth(router, Arc::new(token));

        let request = axum::http::Request::builder()
            .uri("/test")
            .header("Authorization", "Basic abc123")
            .body(axum::body::Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
    }
}
